import sys
import os
import uuid
import json
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/raphael")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from orchestrator.phishing.gophish import GoPhishAPI
from orchestrator.phishing.evilginx import EvilGinx
from orchestrator.phishing.set_wrapper import SETWrapper

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phishing")

TEMPLATE_DIR = Path(os.environ.get("TEMPLATE_DIR", "/app/templates"))
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)

gophish = GoPhishAPI()
evilginx = EvilGinx()
set_tool = SETWrapper()

campaigns: dict[str, dict] = {}

app = FastAPI(title="Phishing Microservice", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request schemas ──────────────────────────────────────────────────────────

class CreateCampaignRequest(BaseModel):
    name: str
    target_email: str
    phishing_url: str
    template: str = "login.html"
    smtp_host: str
    smtp_port: int = 587
    smtp_user: str
    smtp_pass: str
    from_address: str

class LaunchCampaignRequest(BaseModel):
    campaign_id: str

class DeployEvilGinxRequest(BaseModel):
    domain: str
    phishing_url: str
    target_url: str

class CredentialHarvesterRequest(BaseModel):
    site: str
    email: str
    password: str

class SendEmailRequest(BaseModel):
    target_email: str
    sender_email: str
    smtp_server: str
    subject: str = "Security Notice"
    template: str = "/path/to/template"

class CreateTemplateRequest(BaseModel):
    name: str
    content: str

# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
def list_tools():
    return {
        "tools": [
            {
                "name": "GoPhish",
                "status": gophish.status().get("available", False),
                "description": "Open-source phishing framework for campaign management",
            },
            {
                "name": "EvilGinx",
                "status": evilginx.status().get("available", False),
                "description": "Man-in-the-middle proxy framework for phishing",
            },
            {
                "name": "SET",
                "status": set_tool.status().get("available", False),
                "description": "Social Engineering Toolkit for credential harvesting & mass mailer",
            },
        ]
    }


@app.post("/campaign/create")
def create_campaign(req: CreateCampaignRequest):
    logger.info("Creating campaign: %s -> %s", req.name, req.target_email)

    template_path = TEMPLATE_DIR / req.template
    if not template_path.exists():
        raise HTTPException(404, f"Template '{req.template}' not found")

    template_content = template_path.read_text()
    template = {"subject": req.name, "body": template_content}

    smtp = gophish.create_smtp_profile(
        host=req.smtp_host, port=req.smtp_port,
        username=req.smtp_user, password=req.smtp_pass,
        from_address=req.from_address, use_tls=True,
    )

    result = gophish.create_campaign(
        name=req.name,
        target_group=[{"email": req.target_email}],
        template=template,
        url=req.phishing_url,
    )

    campaign_id = str(uuid.uuid4())[:8]
    campaigns[campaign_id] = {
        "id": campaign_id,
        "name": req.name,
        "target_email": req.target_email,
        "phishing_url": req.phishing_url,
        "template": req.template,
        "smtp": smtp,
        "status": "created",
        "created_at": datetime.utcnow().isoformat(),
        "gophish_result": result,
    }

    return {"campaign_id": campaign_id, "status": "created", "details": result}


@app.post("/campaign/launch")
def launch_campaign(req: LaunchCampaignRequest):
    campaign = campaigns.get(req.campaign_id)
    if not campaign:
        raise HTTPException(404, f"Campaign '{req.campaign_id}' not found")

    logger.info("Launching campaign: %s", req.campaign_id)
    result = gophish.launch(int(req.campaign_id) if req.campaign_id.isdigit() else 0)
    campaign["status"] = "launched"
    campaign["launched_at"] = datetime.utcnow().isoformat()
    return {"status": "launched", "campaign_id": req.campaign_id, "details": result}


@app.get("/campaign/{campaign_id}/results")
def get_campaign_results(campaign_id: str):
    campaign = campaigns.get(campaign_id)
    if not campaign:
        raise HTTPException(404, f"Campaign '{campaign_id}' not found")

    launched = campaign.get("launched_at") is not None
    return {
        "campaign_id": campaign_id,
        "name": campaign["name"],
        "emails_sent": 1 if launched else 0,
        "emails_opened": 0,
        "clicks": 0,
        "credentials_captured": 0,
        "status": campaign["status"],
        "created_at": campaign["created_at"],
        "launched_at": campaign.get("launched_at"),
    }


@app.post("/evilginx/deploy")
def deploy_evilginx(req: DeployEvilGinxRequest):
    logger.info("Deploying EvilGinx: %s -> %s", req.domain, req.target_url)
    result = evilginx.deploy_proxy(req.domain, req.phishing_url, req.target_url)
    return result


@app.post("/set/credential_harvester")
def set_credential_harvester(req: CredentialHarvesterRequest):
    logger.info("SET credential harvester for: %s", req.site)
    result = set_tool.credential_harvester(req.site, req.email, req.password)
    return result


@app.post("/set/send_email")
def set_send_email(req: SendEmailRequest):
    logger.info("SET send email: %s -> %s", req.sender_email, req.target_email)
    result = set_tool.send_email(
        target_email=req.target_email,
        sender_email=req.sender_email,
        smtp_server=req.smtp_server,
        template_file=req.template,
        subject=req.subject,
    )
    return result


@app.post("/template/create")
def create_template(req: CreateTemplateRequest):
    if not req.name.endswith(".html"):
        req.name += ".html"

    path = TEMPLATE_DIR / req.name
    path.write_text(req.content)
    logger.info("Template created: %s", path)
    return {"status": "created", "name": req.name, "path": str(path)}


@app.get("/templates")
def list_templates():
    files = sorted(TEMPLATE_DIR.glob("*.html"))
    return {
        "templates": [
            {"name": f.name, "path": str(f), "size": f.stat().st_size}
            for f in files
        ]
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "tools": {
            "gophish": gophish.status(),
            "evilginx": evilginx.status(),
            "set": set_tool.status(),
        },
        "templates": len(list(TEMPLATE_DIR.glob("*.html"))),
        "active_campaigns": len(campaigns),
    }
