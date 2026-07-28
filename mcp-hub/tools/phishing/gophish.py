from ...core.registry import BaseTool


class GoPhish(BaseTool):
    name = "gophish"
    description = "GoPhish phishing campaign management. Create and manage phishing campaigns via the GoPhish API."

    async def execute(self, params: dict) -> dict:
        api_url = params.get("api_url", "https://localhost:3333")
        api_key = params.get("api_key", "")
        action = params.get("action", "status")
        target_email = params.get("target_email", "")
        template_name = params.get("template_name", "")
        campaign_name = params.get("campaign_name", "Raphael-Phish")
        sending_profile = params.get("sending_profile", 1)

        instructions = f"""
GoPhish — {action.upper()}
  API: {api_url}

  Status check:
    curl -k {api_url}/api/groups/ -H "Authorization: {api_key[:8]}..."

  Create target group:
    curl -k -X POST {api_url}/api/groups/ \\
      -H "Authorization: Bearer {api_key}" \\
      -H "Content-Type: application/json" \\
      -d '{{
        "name": "{campaign_name}-targets",
        "targets": [{{"email": "{target_email}", "first_name": "Target", "last_name": "User"}}]
      }}'

  Launch campaign:
    curl -k -X POST {api_url}/api/campaigns/ \\
      -H "Authorization: Bearer {api_key}" \\
      -H "Content-Type: application/json" \\
      -d '{{
        "name": "{campaign_name}",
        "template": {{"name": "{template_name}"}},
        "smtp": {{"name": "profile-{sending_profile}"}}
      }}'

  Results:
    curl -k {api_url}/api/campaigns/ -H "Authorization: Bearer {api_key}"
"""
        return {"action": action, "api_url": api_url, "instructions": instructions}
