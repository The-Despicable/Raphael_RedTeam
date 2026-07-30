from pydantic import BaseModel
from typing import Optional


class NmapParams(BaseModel):
    target: str
    ports: str = "1-1000"
    aggressive: bool = False
    service_detection: bool = True
    scripts: str = ""


class NmapResult(BaseModel):
    output: str
    open_ports: list[int] = []
    services: list[dict] = []


class NucleiParams(BaseModel):
    target: str
    severity: str = "medium"
    tags: str = ""
    template: str = ""


class NucleiResult(BaseModel):
    findings: list[dict] = []
    raw_output: str = ""


class GobusterParams(BaseModel):
    url: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    extensions: str = ""
    threads: int = 10


class GobusterResult(BaseModel):
    entries: list[dict] = []
    raw_output: str = ""


class SQLMapParams(BaseModel):
    url: str
    level: int = 3
    risk: int = 2
    dbms: str = ""
    crawl: int = 0
    batch: bool = True


class SQLMapResult(BaseModel):
    vulnerabilities: list[dict] = []
    raw_output: str = ""


class SubfinderParams(BaseModel):
    domain: str
    recursive: bool = True
    sources: str = ""


class SubfinderResult(BaseModel):
    subdomains: list[str] = []
    raw_output: str = ""


class WhatWebParams(BaseModel):
    url: str
    aggression: int = 3


class WhatWebResult(BaseModel):
    technologies: list[dict] = []
    raw_output: str = ""


class FeroxbusterParams(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    depth: int = 3
    threads: int = 50
    extensions: str = "php,asp,aspx,jsp,html,txt"


class FeroxbusterResult(BaseModel):
    urls: list[dict] = []
    raw_output: str = ""


class HTTPxParams(BaseModel):
    target: str
    threads: int = 50
    status_codes: str = "200,301,302,401,403"


class HTTPxResult(BaseModel):
    results: list[dict] = []
    raw_output: str = ""


class KatanaParams(BaseModel):
    url: str
    depth: int = 3
    crawl_scope: str = "same-domain"
    headless: bool = False


class KatanaResult(BaseModel):
    endpoints: list[str] = []
    raw_output: str = ""
