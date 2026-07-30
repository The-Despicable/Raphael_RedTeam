"""Recon ingest producer — reads endpoint lists from stdin/API and inserts into case queue."""

import sys, json, logging
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from case_store import CaseStore, classify_type, generate_params_sig, extract_url_path, extract_query_params

logger = logging.getLogger("recon_ingest")


def parse_line(line: str) -> Optional[dict]:
    line = line.strip().strip("`").lstrip("- ")
    if not line:
        return None

    # JSON line
    if line.startswith("{"):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    # "GET https://..." format
    parts = line.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {"method": parts[0].upper(), "url": parts[1]}

    # Plain URL
    if line.startswith("http://") or line.startswith("https://"):
        return {"method": "GET", "url": line}

    return None


def ingest_line(store: CaseStore, line: str, source: str = "recon") -> int:
    parsed = parse_line(line)
    if not parsed:
        return 0

    url = parsed.get("url", "")
    method = parsed.get("method", "GET")
    url_path = parsed.get("url_path") or extract_url_path(url)
    case_type = parsed.get("type") or classify_type(method, url_path)
    sig = parsed.get("params_key_sig") or generate_params_sig(url)

    case = {
        "method": method,
        "url": url,
        "url_path": url_path,
        "type": case_type,
        "source": parsed.get("source", source),
        "params_key_sig": sig,
        "query_params": parsed.get("query_params") or (extract_query_params(url) if method == "GET" else "{}"),
        "body_params": parsed.get("body_params", "{}"),
        "path_params": parsed.get("path_params", "{}"),
        "cookie_params": parsed.get("cookie_params", "{}"),
        "headers": parsed.get("headers", "{}"),
        "body": parsed.get("body", ""),
        "content_type": parsed.get("content_type", ""),
        "content_length": parsed.get("content_length", 0),
        "response_status": parsed.get("response_status", 0),
        "response_headers": parsed.get("response_headers", "{}"),
        "response_size": parsed.get("response_size", 0),
        "response_snippet": parsed.get("response_snippet", ""),
    }
    return 1 if store.insert(case) else 0


def ingest_lines(lines: list[str], source: str = "recon") -> dict:
    store = CaseStore("/data/cases.db")
    count = 0
    for line in lines:
        count += ingest_line(store, line, source)
    store.close()
    return {"ingested": count, "total_lines": len(lines)}


if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else "recon"
    lines = sys.stdin.readlines()
    result = ingest_lines(lines, source)
    print(json.dumps(result))
