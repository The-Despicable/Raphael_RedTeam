"""Case collection pipeline — SQLite-backed queue with dedup, staging, and priority scoring.
Port of RedTeamAgent's dispatcher.sh to Python for Raphael 2.0."""

import sqlite3, json, hashlib, re, os, time, logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("case_store")

STAGES = {
    "ingested": 0,
    "source_analyzed": 1,
    "api_tested": 2,
    "vuln_confirmed": 3,
    "fuzz_pending": 4,
    "exploited": 5,
    "clean": 6,
    "errored": 7,
}

TERMINAL_STAGES = {"source_analyzed", "api_tested", "clean", "exploited", "errored"}
NON_TERMINAL_STAGES = {"ingested", "vuln_confirmed", "fuzz_pending"}


class CaseStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, timeout=5)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        schema = Path(__file__).parent / "schema.sql"
        if schema.exists():
            self._conn.executescript(schema.read_text())
        self._conn.commit()

    def _cursor(self):
        return self._conn.cursor()

    # ── Insert ──────────────────────────────────────────────────────

    def insert(self, case: dict) -> int:
        c = self._cursor()
        try:
            c.execute("""
                INSERT INTO cases (
                    method, url, url_path, query_params, body_params,
                    path_params, cookie_params, headers, body,
                    content_type, content_length, response_status,
                    response_headers, response_size, response_snippet,
                    type, source, params_key_sig
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(method, url_path, params_key_sig) DO UPDATE SET
                    url = excluded.url,
                    query_params = excluded.query_params,
                    body_params = excluded.body_params,
                    path_params = excluded.path_params,
                    cookie_params = excluded.cookie_params,
                    headers = excluded.headers,
                    body = excluded.body,
                    content_type = excluded.content_type,
                    content_length = excluded.content_length,
                    response_status = excluded.response_status,
                    response_headers = excluded.response_headers,
                    response_size = excluded.response_size,
                    response_snippet = excluded.response_snippet,
                    type = CASE WHEN cases.type = 'unknown' AND excluded.type != 'unknown'
                                THEN excluded.type ELSE cases.type END,
                    source = excluded.source,
                    status = CASE
                        WHEN excluded.type IN ('image','video','font','archive') THEN 'skipped'
                        ELSE 'pending'
                    END,
                    assigned_agent = NULL,
                    consumed_at = NULL
                WHERE cases.type = 'unknown'
                  AND excluded.type != 'unknown'
                  AND cases.status IN ('pending', 'processing', 'error')
            """, (
                case.get("method", "GET"), case.get("url", ""), case.get("url_path", ""),
                case.get("query_params"), case.get("body_params"),
                case.get("path_params"), case.get("cookie_params"),
                case.get("headers"), case.get("body", ""),
                case.get("content_type"), case.get("content_length", 0),
                case.get("response_status", 0), case.get("response_headers"),
                case.get("response_size", 0), case.get("response_snippet", ""),
                case.get("type", "unknown"), case.get("source", "unknown"),
                case.get("params_key_sig", ""),
            ))
            self._conn.commit()
            return c.lastrowid or 0
        except sqlite3.IntegrityError:
            return 0

    def insert_many(self, cases: list[dict]) -> int:
        count = 0
        for case in cases:
            if self.insert(case):
                count += 1
        return count

    # ── Fetch ───────────────────────────────────────────────────────

    def fetch(self, case_type: str, limit: int, agent: str, stage: Optional[str] = None) -> list[dict]:
        c = self._cursor()
        in_flight = c.execute(
            "SELECT COUNT(*) FROM cases WHERE status='processing' AND assigned_agent=? AND type=? AND (? IS NULL OR stage=?)",
            (agent, case_type, stage, stage)
        ).fetchone()[0]
        if in_flight > 0:
            logger.warning("Refusing fetch for %s (type=%s, stage=%s): %d already processing", agent, case_type, stage, in_flight)
            return []

        order_clause = _priority_order_clause()
        stage_filter = f"AND stage = '{stage}'" if stage else "AND stage IN ('ingested','vuln_confirmed','fuzz_pending')"

        rows = c.execute(f"""
            UPDATE cases
            SET status = 'processing',
                assigned_agent = ?,
                consumed_at = datetime('now')
            WHERE id IN (
                SELECT id FROM cases
                WHERE status = 'pending' AND type = ?
                      {stage_filter}
                {order_clause}
                LIMIT ?
            )
            RETURNING *
        """, (agent, case_type, limit)).fetchall()
        self._conn.commit()
        return [dict(r) for r in rows]

    # ── Done ────────────────────────────────────────────────────────

    def mark_done(self, ids: list[int], stage: Optional[str] = None):
        c = self._cursor()
        id_list = ",".join(str(i) for i in ids)
        if stage:
            if stage in TERMINAL_STAGES:
                c.execute(f"UPDATE cases SET status='done', stage=? WHERE id IN ({id_list})", (stage,))
                logger.info("Marked done (stage=%s, terminal): %s", stage, ids)
            else:
                c.execute(f"UPDATE cases SET status='pending', stage=?, assigned_agent=NULL, consumed_at=NULL WHERE id IN ({id_list})", (stage,))
                logger.info("Advanced stage=%s (re-pending): %s", stage, ids)
        else:
            c.execute(f"UPDATE cases SET status='done' WHERE id IN ({id_list})")
            logger.info("Marked done: %s", ids)
        self._conn.commit()

    def mark_error(self, ids: list[int]):
        c = self._cursor()
        id_list = ",".join(str(i) for i in ids)
        c.execute(f"UPDATE cases SET status='error', stage='errored', retry_count = COALESCE(retry_count,0) + 1 WHERE id IN ({id_list})")
        self._conn.commit()
        logger.info("Marked error: %s", ids)

    def set_stage(self, ids: list[int], stage: str):
        c = self._cursor()
        id_list = ",".join(str(i) for i in ids)
        c.execute(f"UPDATE cases SET stage=? WHERE id IN ({id_list})", (stage,))
        self._conn.commit()

    # ── Recovery ────────────────────────────────────────────────────

    def reset_stale(self, minutes: int = 10):
        c = self._cursor()
        before = c.execute(
            "SELECT COUNT(*) FROM cases WHERE status='processing' AND consumed_at < datetime('now', ?)",
            (f'-{minutes} minutes',)
        ).fetchone()[0]
        c.execute(
            "UPDATE cases SET status='pending', assigned_agent=NULL, consumed_at=NULL WHERE status='processing' AND consumed_at < datetime('now', ?)",
            (f'-{minutes} minutes',)
        )
        self._conn.commit()
        logger.info("Reset %d stale case(s) (stuck > %d min)", before, minutes)
        return before

    def retry_errors(self, max_retries: int = 2):
        c = self._cursor()
        before = c.execute(
            "SELECT COUNT(*) FROM cases WHERE status='error' AND COALESCE(retry_count,0) < ?",
            (max_retries,)
        ).fetchone()[0]
        c.execute(
            "UPDATE cases SET status='pending', stage='ingested', assigned_agent=NULL, consumed_at=NULL WHERE status='error' AND COALESCE(retry_count,0) < ?",
            (max_retries,)
        )
        self._conn.commit()
        logger.info("Retried %d error case(s)", before)
        return before

    # ── Stats ───────────────────────────────────────────────────────

    def stats(self) -> dict:
        c = self._cursor()
        by_status = {r["status"]: r["count"] for r in c.execute("SELECT status, COUNT(*) as count FROM cases GROUP BY status").fetchall()}
        by_stage = {r["stage"]: r["count"] for r in c.execute("SELECT stage, COUNT(*) as count FROM cases GROUP BY stage").fetchall()}
        total = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        return {"total": total, "by_status": by_status, "by_stage": by_stage}

    def stats_by_stage(self) -> list[dict]:
        c = self._cursor()
        return [dict(r) for r in c.execute("SELECT stage, type, COUNT(*) as count FROM cases GROUP BY stage, type ORDER BY stage, type").fetchall()]

    def close(self):
        self._conn.close()


# ── Priority Scoring ───────────────────────────────────────────────

def _priority_order_clause() -> str:
    return """
    ORDER BY (
        CASE lower(source)
            WHEN 'exploit-developer' THEN 500
            WHEN 'katana-xhr' THEN 460
            WHEN 'operator-surface-coverage' THEN 445
            WHEN 'katana' THEN 430
            WHEN 'vulnerability-analyst' THEN 380
            WHEN 'source-analyzer' THEN 280
            WHEN 'recon-specialist' THEN 220
            ELSE 0
        END
        + CASE upper(method)
            WHEN 'POST' THEN 180
            WHEN 'PUT' THEN 170
            WHEN 'PATCH' THEN 160
            WHEN 'DELETE' THEN 150
            ELSE 0
          END
        + CASE
            WHEN query_params IS NOT NULL AND query_params NOT IN ('', '{}', 'null') THEN 40
            WHEN body_params IS NOT NULL AND body_params NOT IN ('', '{}', 'null') THEN 70
            ELSE 0
          END
        + CASE
            WHEN lower(coalesce(nullif(url_path, ''), url)) LIKE '%/admin%'
              OR lower(coalesce(nullif(url_path, ''), url)) LIKE '%login%'
              OR lower(coalesce(nullif(url_path, ''), url)) LIKE '%auth%'
              OR lower(coalesce(nullif(url_path, ''), url)) LIKE '%upload%'
              OR lower(coalesce(nullif(url_path, ''), url)) LIKE '%graphql%'
              OR lower(coalesce(nullif(url_path, ''), url)) LIKE '%api%'
            THEN 180 ELSE 0
          END
    ) DESC,
    id ASC
    """


# ── Type Classification ────────────────────────────────────────────

def classify_type(method: str, url_path: str, content_type: str = "", body_snippet: str = "") -> str:
    ct = content_type.lower()
    path_no_query = url_path.split("?")[0]
    is_write = method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    if re.search(r'/graphql', url_path, re.I): return "graphql"
    if ct == 'application/graphql': return "graphql"
    if body_snippet:
        try:
            qv = json.loads(body_snippet).get("query", "")
            if re.search(r'\{.*\}', qv): return "graphql"
        except (json.JSONDecodeError, TypeError):
            pass

    if re.search(r'/ws(/|$)|^/socket\.io(/|$)', url_path, re.I): return "websocket"
    if re.search(r'^/(api-docs|openapi(\.json)?|swagger)', url_path, re.I): return "api-spec"
    if re.search(r'^/(api|rest)(/|$)|/v[0-9](/|$)', url_path, re.I): return "api"
    if is_write and 'application/json' in ct: return "api"
    if 'multipart/form-data' in ct: return "upload"
    if method.upper() in ("POST", "PUT") and 'application/x-www-form-urlencoded' in ct: return "form"

    if 'text/html' in ct or 'application/xhtml' in ct or 'image/svg+xml' in ct: return "page"
    if any(x in ct for x in ('application/json', 'application/xml', 'text/csv', 'text/plain')): return "data"
    if ct.startswith('image/') and 'svg' not in ct: return "image"
    if ct.startswith(('video/', 'audio/')): return "video"
    if ct.startswith('font/') or 'application/vnd.ms-fontobject' in ct: return "font"
    if any(x in ct for x in ('zip', 'gzip', 'tar', 'rar')): return "archive"
    if 'javascript' in ct: return "javascript"
    if 'text/css' in ct: return "stylesheet"

    if re.search(r'\.js$', path_no_query, re.I): return "javascript"
    if re.search(r'\.css$', path_no_query, re.I): return "stylesheet"
    if re.search(r'\.(html?|xhtml|php|aspx?|jsp)$', path_no_query, re.I): return "page"
    if re.search(r'\.(json|xml|csv|ya?ml|txt)$', path_no_query, re.I): return "data"
    if re.search(r'\.(png|jpg|jpeg|gif|webp|ico)$', path_no_query, re.I): return "image"
    if re.search(r'\.(mp4|webm|avi|mp3|wav|ogg)$', path_no_query, re.I): return "video"
    if re.search(r'\.(woff2?|ttf|otf|eot)$', path_no_query, re.I): return "font"

    return "unknown"


# ── Dedup Signature ────────────────────────────────────────────────

def generate_params_sig(url: str, query_params: Optional[str] = None, body_params: Optional[str] = None) -> str:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.hostname}".lower()

    qp = query_params or "{}"
    bp = body_params or "{}"
    try:
        qp_keys = sorted(json.loads(qp).keys()) if isinstance(qp, str) else sorted(qp.keys())
    except (json.JSONDecodeError, AttributeError):
        qp_keys = sorted(parse_qs(parsed.query).keys())
    try:
        bp_keys = sorted(json.loads(bp).keys()) if isinstance(bp, str) else sorted(bp.keys())
    except (json.JSONDecodeError, AttributeError):
        bp_keys = []

    control_markers = [v for k, v in (json.loads(qp).items() if isinstance(qp, str) else qp.items()) if isinstance(v, str) and v.startswith("_")]
    redirect_keys = {"next", "return", "redirect", "url", "dest", "callback", "goto", "ref", "source"}
    redirect_vals = [
        v for k, v in (json.loads(qp).items() if isinstance(qp, str) else qp.items())
        if k in redirect_keys and isinstance(v, str) and (v.startswith("http") or v.startswith("/"))
    ]

    raw = f"{origin}|{qp_keys}|{bp_keys}|{sorted(control_markers)}|{sorted(redirect_vals)}"
    return hashlib.md5(raw.encode()).hexdigest()


def extract_url_path(url: str) -> str:
    return urlparse(url).path


def extract_query_params(url: str) -> str:
    qs = urlparse(url).query
    if not qs:
        return "{}"
    return json.dumps(parse_qs(qs))
