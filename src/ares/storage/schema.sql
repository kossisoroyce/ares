-- SQLite schema for the local event store (spec 23.2).
-- Append-heavy event tables, indexed timestamps and process identities.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS hosts (
    host_id     TEXT PRIMARY KEY,
    role        TEXT,
    environment TEXT,
    criticality TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS boots (
    boot_id    TEXT PRIMARY KEY,
    host_id    TEXT NOT NULL,
    booted_at  TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts (host_id)
);

CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL,
    boot_id       TEXT,
    timestamp_ns  INTEGER NOT NULL,
    received_at   TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    source        TEXT,
    severity_hint REAL DEFAULT 0.0,
    process_id    TEXT,
    user_id       TEXT,
    container_id  TEXT,
    risk_band     TEXT DEFAULT 'low',    -- low | medium | high (drives retention)
    processed     INTEGER DEFAULT 0,      -- 0 until consumed by an investigation cycle
    payload       TEXT NOT NULL,          -- JSON
    enrichment    TEXT NOT NULL,          -- JSON
    redaction     TEXT NOT NULL           -- JSON
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_events_proc ON events (process_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_processed ON events (processed, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_events_band ON events (risk_band, timestamp_ns);

CREATE TABLE IF NOT EXISTS processes (
    process_id    TEXT PRIMARY KEY,
    host_id       TEXT NOT NULL,
    pid           INTEGER,
    ppid          INTEGER,
    parent_id     TEXT,
    executable    TEXT,
    exe_hash      TEXT,
    argv          TEXT,                   -- JSON (redacted)
    uid           INTEGER,
    started_at_ns INTEGER,
    exited_at_ns  INTEGER,
    container_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_processes_host ON processes (host_id);
CREATE INDEX IF NOT EXISTS idx_processes_exe ON processes (executable);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     TEXT NOT NULL,
    path        TEXT NOT NULL,
    hash        TEXT,
    size        INTEGER,
    owner       TEXT,
    permissions TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_path ON files (host_id, path);

CREATE TABLE IF NOT EXISTS network_destinations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      TEXT NOT NULL,
    destination  TEXT NOT NULL,           -- addr:port or domain:port
    first_seen   TEXT,
    last_seen    TEXT,
    seen_count   INTEGER DEFAULT 0,
    reputation   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_netdest ON network_destinations (host_id, destination);

CREATE TABLE IF NOT EXISTS findings (
    finding_id         TEXT PRIMARY KEY,
    created_at         TEXT NOT NULL,
    rule_id            TEXT NOT NULL,
    title              TEXT NOT NULL,
    severity           TEXT NOT NULL,
    risk_score         REAL NOT NULL,
    confidence         REAL NOT NULL,
    host_id            TEXT NOT NULL,
    primary_process_id TEXT,
    event_ids          TEXT NOT NULL,     -- JSON list
    reasons            TEXT NOT NULL,     -- JSON list
    status             TEXT DEFAULT 'open',
    immediate          INTEGER DEFAULT 0,
    case_id            TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings (case_id);

CREATE TABLE IF NOT EXISTS cases (
    case_id        TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    host_id        TEXT NOT NULL,
    title          TEXT,
    summary        TEXT,
    risk_score     REAL DEFAULT 0.0,
    priority       TEXT DEFAULT 'medium',
    status         TEXT DEFAULT 'open',
    dedup_key      TEXT,
    package        TEXT,                  -- JSON case package
    hit_count      INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status, priority);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_dedup ON cases (dedup_key);

CREATE TABLE IF NOT EXISTS case_events (
    case_id  TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (case_id, event_id)
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    case_id          TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    provider         TEXT,
    model            TEXT,
    tool_calls       INTEGER DEFAULT 0,
    input_tokens     INTEGER DEFAULT 0,
    output_tokens    INTEGER DEFAULT 0,
    audit_log        TEXT                 -- JSON list of tool calls
);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL,
    case_id          TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    classification   TEXT,
    confidence       REAL,
    severity         TEXT,
    title            TEXT,
    summary          TEXT,
    verdict          TEXT                 -- JSON full structured verdict (spec 19.4)
);
CREATE INDEX IF NOT EXISTS idx_verdicts_case ON verdicts (case_id);

CREATE TABLE IF NOT EXISTS actions (
    action_id       TEXT PRIMARY KEY,
    case_id         TEXT,
    created_at      TEXT NOT NULL,
    type            TEXT NOT NULL,
    target          TEXT,                 -- JSON
    reason          TEXT,
    requested_by    TEXT,
    requires_approval INTEGER DEFAULT 1,
    reversible      INTEGER DEFAULT 1,
    rollback_action TEXT,
    status          TEXT DEFAULT 'proposed',  -- proposed|approved|rejected|executed|rolled_back|failed
    result          TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions (status);

CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dimension   TEXT NOT NULL,            -- e.g. "executable_path:parent_process"
    key         TEXT NOT NULL,            -- the concrete observed key
    count       INTEGER DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT,
    reviewed    INTEGER DEFAULT 0,
    frozen      INTEGER DEFAULT 0,
    version     INTEGER DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_key ON baselines (dimension, key);

CREATE TABLE IF NOT EXISTS suppressions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,             -- global|host|workload|...
    matcher    TEXT NOT NULL,             -- JSON criteria
    reason     TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT,
    case_id     TEXT,
    label       TEXT NOT NULL,            -- confirmed_malicious|benign|...
    scope       TEXT DEFAULT 'host',
    note        TEXT,
    created_at  TEXT NOT NULL,
    created_by  TEXT
);

CREATE TABLE IF NOT EXISTS scheduler_state (
    key   TEXT PRIMARY KEY,              -- e.g. "watermark", "lock"
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_health (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    reported_at  TEXT NOT NULL,
    capabilities TEXT NOT NULL,          -- JSON
    metrics      TEXT                    -- JSON
);
