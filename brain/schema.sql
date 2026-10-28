-- Autonomous Brain SQL schema (applied idempotently by db.py at startup).
-- Kept here for operators who want to inspect / pre-provision the schema.

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    engagement_id TEXT,
    target TEXT NOT NULL,
    goal TEXT,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    step TEXT,
    constraints_json TEXT,
    budget_limit INTEGER,
    budget_used INTEGER DEFAULT 0,
    risk TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS steps (
    step_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    name TEXT NOT NULL,
    tool TEXT,
    status TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    result_summary TEXT,
    args_json TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
CREATE INDEX IF NOT EXISTS idx_steps_task ON steps(task_id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_ref TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    kind TEXT NOT NULL,
    node_id TEXT NOT NULL,
    attributes_json TEXT,
    source TEXT,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence(task_id);
CREATE INDEX IF NOT EXISTS idx_evidence_kind ON evidence(kind);

CREATE TABLE IF NOT EXISTS evidence_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    relation TEXT NOT NULL,
    attributes_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON evidence_edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON evidence_edges(dst);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    statement TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    status TEXT DEFAULT 'open',
    evidence_refs_json TEXT,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contradictions (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    status TEXT NOT NULL,
    subjects_json TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    score REAL NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trust_subject ON trust_logs(subject);

CREATE TABLE IF NOT EXISTS notes (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    tags_json TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    task_id TEXT,
    note TEXT,
    payload_json TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON checkpoints(task_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT NOT NULL,
    subject TEXT,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject);
