import os, subprocess, json

class SETWrapper:
    def __init__(self, source_dir: str = "/opt/set"):
        self.source_dir = source_dir
        self._available = os.path.isfile("/usr/bin/setoolkit") or os.path.isdir(source_dir)

    def status(self) -> dict:
        try:
            r = subprocess.run(["which", "setoolkit"], capture_output=True, text=True)
            return {"available": bool(r.stdout.strip()), "path": r.stdout.strip() or None}
        except Exception:
            return {"available": self._available}

    def credential_harvester(self, site: str, email: str, password: str) -> dict:
        xml_config = f"""<?xml version="1.0" encoding="UTF-8"?>
<setconfig>
    <attacktype>3</attacktype>
    <sitecloner>
        <site>{site}</site>
        <email>{email}</email>
        <password>{password}</password>
    </sitecloner>
</setconfig>"""
        return {
            "status": "configured" if self._available else "unavailable",
            "attack_type": "credential_harvester",
            "site_to_clone": site,
            "recipient": email,
            "config_xml": xml_config,
            "commands": [
                "setoolkit" if self._available else "python3 se-toolkit",
                "1) Social-Engineering Attacks",
                "2) Website Attack Vectors",
                "3) Credential Harvester Attack Method",
                "2) Site Cloner",
                f"Enter site: {site}",
            ],
        }

    def send_email(self, target_email: str, sender_email: str, smtp_server: str,
                   template_file: str, subject: str) -> dict:
        return {
            "status": "configured" if self._available else "unavailable",
            "target": target_email,
            "sender": sender_email,
            "smtp_server": smtp_server,
            "template": template_file,
            "subject": subject,
            "commands": [
                "setoolkit",
                "1) Social-Engineering Attacks",
                "5) Mass Mailer Attack",
                "1) E-Mail Attack Single: send email to single address",
            ],
        }

    def spear_phish(self, target: str, template: str, lhost: str, lport: int = 443) -> dict:
        return {
            "status": "configured" if self._available else "unavailable",
            "target": target,
            "template": template,
            "payload_receiver": f"{lhost}:{lport}",
            "note": "Requires SET interactive menu. Use templates/ for pre-built campaigns.",
        }
