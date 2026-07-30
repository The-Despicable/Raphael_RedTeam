"""
Target-05: Simulated WAF Bypass Target for P1 Validation.

A Flask web app with a simulated WAF that blocks common SQLi patterns
via CASE-SENSITIVE pattern matching. Case variation (UnIoN SeLeCt)
bypasses the WAF, triggering the flag.

Risk: SQL Injection (simulated) behind a WAF that blocks lowercase patterns.
Bypass: Case variation (UnIoN SeLeCt) passes the WAF.
Flag: FLAG_WAF_BYPASS=SUCCESS
"""

from flask import Flask, request, abort
import os

app = Flask(__name__)

# WAF blocks LOWERCASE exact patterns only (case-sensitive matching)
# Case variation is the bypass technique.
BLOCKED_PATTERNS = [
    "union select",
    "or 1=1",
    "' or",
    "or '1'='1",
    'or "1"="1',
    "select * from",
    "drop table",
    "select password",
    "information_schema",
    "xp_cmdshell",
    "exec(",
]

FLAG = os.environ.get("FLAG_WAF_BYPASS", "FLAG_WAF_BYPASS=SUCCESS")


@app.route('/')
def index():
    id_param = request.args.get('id', '1')

    # WAF checks RAW input (case-sensitive) — case variation bypasses
    for pattern in BLOCKED_PATTERNS:
        if pattern in id_param:
            return abort(403, description=f"WAF: SQL Injection Attempt Detected (matched: {pattern})")

    # Simulated SQLi — flag returned when union+select present (any case)
    id_lower = id_param.lower()
    if id_param == '1':
        return "Article 1: Welcome to the WAF-protected site", 200
    elif "union" in id_lower and "select" in id_lower:
        return (
            f"Admin: admin@waf-bypass-lab.com\n"
            f"Users: operator, root\n"
            f"Hash: $2y$10$WAF_BYPASS_DEMO_HASH\n"
            f"{FLAG}\n",
            200,
        )
    return "No article found", 200


@app.route('/health')
def health():
    """Health check endpoint."""
    return "OK", 200


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8081))
    app.run(host='0.0.0.0', port=port)
