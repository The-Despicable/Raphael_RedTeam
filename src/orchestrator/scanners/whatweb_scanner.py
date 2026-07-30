import requests, re, shutil
from typing import Optional
from ..proxy_guard import ProxyGuard

TECH_SIGNATURES = {
    "WordPress": [r'wp-content', r'wp-includes', r'wp-json', r'/wp-login'],
    "Drupal": [r'drupal', r'Drupal.settings', r'/sites/default'],
    "Joomla": [r'joomla', r'/components/', r'/modules/', r'com_content'],
    "Laravel": [r'laravel', r'_token', r'XSRF-TOKEN'],
    "Django": [r'django', r'csrftoken', r'__admin__'],
    "Next.js": [r'__NEXT_DATA__', r'/_next/', r'__next'],
    "React": [r'react', r'createRoot', r'__REACT_'],
    "Vue.js": [r'__vue__', r'vue-router', r'Vue.create'],
    "Angular": [r'ng-app', r'ng-version', r'angular'],
    "jQuery": [r'jquery', r'\$\(', r'jQuery'],
    "Bootstrap": [r'bootstrap', r'bootstrap\.min\.css'],
    "Tailwind": [r'tailwind', r'hover:'],
    "Nginx": [r'nginx', r'Server: nginx'],
    "Apache": [r'Apache', r'Server: Apache'],
    "Cloudflare": [r'cloudflare', r'__cfduid', r'cf-ray'],
    "PHP": [r'php', r'X-PHP', r'PHPSESSID'],
    "ASP.NET": [r'asp\.net', r'__VIEWSTATE', r'ASP.NET'],
    "Node.js": [r'node.js', r'express', r'X-Powered-By: Express'],
    "MySQL": [r'mysql', r'SQL'],
    "Redis": [r'redis'],
}

class WhatwebScanner:
    def __init__(self, pg: ProxyGuard = None):
        self.pg = pg

    @property
    def available(self) -> bool:
        return True

    def scan(self, target: str, aggression: int = 1, _retries: int = 0) -> dict:
        if _retries > 2:
            return {"error": f"Connection failed: {target}", "target": target}
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        if self.pg:
            self.pg._enforce_timing()

        try:
            proxies = None
            if self.pg and self.pg._session:
                proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
            r = requests.get(target, timeout=15, verify=False, proxies=proxies, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"})
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if location and "://" in location:
                    alt = location if location.startswith(("http://", "https://")) else target
                    return self.scan(alt, aggression, _retries=_retries + 1)
            return self._detect(r, target if r.status_code < 400 else r.url)
        except requests.ConnectionError:
            alt = target.replace("http://", "https://") if "http" in target else target.replace("https://", "http://")
            if alt != target:
                return self.scan(alt, aggression, _retries=_retries + 1)
            return {"error": f"Connection failed: {target}", "target": target}
        except Exception as e:
            return {"error": str(e), "target": target}

    def _detect(self, response, target: str) -> dict:
        html = response.text.lower()
        headers_str = str(response.headers).lower()
        techs = {}

        for name, patterns in TECH_SIGNATURES.items():
            for p in patterns:
                if p.lower() in html or p.lower() in headers_str:
                    techs[name] = f"matched: {p}"
                    break

        if response.headers.get("Server"):
            techs["Server"] = response.headers["Server"]
        if response.headers.get("X-Powered-By"):
            techs["X-Powered-By"] = response.headers["X-Powered-By"]

        return {
            "target": target,
            "status": response.status_code,
            "title": self._extract_title(html),
            "technologies": techs,
            "tech_count": len(techs),
        }

    def _extract_title(self, html: str) -> str:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:200] if m else ""
