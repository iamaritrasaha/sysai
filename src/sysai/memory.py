"""Local, deterministic experience learning for SysAI.

This module stores compact structured experience, never model answers, model
reasoning, raw logs, or terminal transcripts. Automatic writes are driven only
by deterministic findings and machine facts; user feedback and outcomes stay
explicitly user-sourced. Stored text is inert data and is never executable.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path

from .config import persistent_state_dir
from .privacy import SHARED, sanitize_text
from .redact import redact

DB_FILENAME = "memory.db"
SCHEMA_VERSION = 2

TYPES = ("machine_fact", "incident", "pattern", "outcome", "user_correction",
         "preference", "diagnostic_lesson")
STATUSES = ("active", "uncertain", "contradicted", "resolved", "stale", "archived", "superseded")
SOURCES = ("user_explicit", "diagnostic", "user_feedback", "deterministic")
RELATIONSHIPS = ("outcome_for", "correction_for", "pattern_of", "supersedes", "recurrence_of")

MAX_RETRIEVE = 5
MAX_LIST = 200
MAX_SEARCH_QUERY_LEN = 200
PATTERN_MIN_SESSIONS = 2
STALE_AFTER_DAYS = 180


class MemoryError(ValueError):
    """A local experience-store problem with an actionable, non-secret message."""


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def store_path() -> Path:
    return persistent_state_dir() / DB_FILENAME


def _sanitize(text: str) -> str:
    return sanitize_text(redact(str(text or "")), SHARED)


def _normal(value: str) -> str:
    return " ".join(_sanitize(value).lower().split())


def fingerprint(type: str, *, domain: str = "", finding_id: str = "", subject: str = "") -> str:
    """Stable, non-secret identity for one logical experience family."""
    material = "|".join((type, _normal(domain), _normal(finding_id), _normal(subject)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(value: str | None, fallback):
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return fallback


def _connect() -> sqlite3.Connection:
    path = store_path()
    is_new = not path.exists()
    try:
        conn = sqlite3.connect(str(path), timeout=5)
        conn.row_factory = sqlite3.Row
        if is_new:
            path.chmod(0o600)
        _init_schema(conn)
        return conn
    except sqlite3.DatabaseError as exc:
        raise MemoryError("Experience database is unreadable; preserve it and run `sysai doctor` for recovery guidance.") from exc


_MEMORY_COLUMNS = {
    "domain": "TEXT NOT NULL DEFAULT ''",
    "finding_id": "TEXT NOT NULL DEFAULT ''",
    "fingerprint": "TEXT NOT NULL DEFAULT ''",
    "first_observed_at": "TEXT",
    "last_observed_at": "TEXT",
    "independent_sessions": "INTEGER NOT NULL DEFAULT 0",
    "last_session_id": "TEXT NOT NULL DEFAULT ''",
    "related_memory_id": "TEXT NOT NULL DEFAULT ''",
    "assessment_id": "TEXT NOT NULL DEFAULT ''",
    "outcome_summary": "TEXT NOT NULL DEFAULT ''",
}


def _init_schema(conn: sqlite3.Connection) -> None:
    """Create v2 or transactionally migrate a v1 store without deleting data."""
    try:
        conn.execute("BEGIN")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL, subject TEXT NOT NULL, statement TEXT NOT NULL,
                source TEXT NOT NULL, created_at TEXT NOT NULL, last_confirmed_at TEXT,
                confidence TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'active',
                evidence_refs TEXT NOT NULL DEFAULT '[]', times_observed INTEGER NOT NULL DEFAULT 1,
                times_confirmed INTEGER NOT NULL DEFAULT 0, times_contradicted INTEGER NOT NULL DEFAULT 0,
                domain TEXT NOT NULL DEFAULT '', finding_id TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '', first_observed_at TEXT,
                last_observed_at TEXT, independent_sessions INTEGER NOT NULL DEFAULT 0,
                last_session_id TEXT NOT NULL DEFAULT '', related_memory_id TEXT NOT NULL DEFAULT '',
                assessment_id TEXT NOT NULL DEFAULT '', outcome_summary TEXT NOT NULL DEFAULT ''
            )
        """)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(memories)")}
        for name, definition in _MEMORY_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE memories ADD COLUMN {name} {definition}")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT, memory_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL, session_id TEXT NOT NULL, assessment_id TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '',
                evidence_refs TEXT NOT NULL DEFAULT '[]', UNIQUE(memory_id, session_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, domain TEXT NOT NULL,
                finding_ids TEXT NOT NULL DEFAULT '[]', memory_ids TEXT NOT NULL DEFAULT '[]',
                history_fingerprints TEXT NOT NULL DEFAULT '[]', severity_summary TEXT NOT NULL DEFAULT '{}',
                diagnostics_collected INTEGER NOT NULL DEFAULT 0, feedback TEXT NOT NULL DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT, from_memory_id TEXT NOT NULL,
                to_memory_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(from_memory_id, to_memory_id, kind)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_fingerprint ON memories(fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_domain ON memories(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_occurrences_memory ON occurrences(memory_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at)")
        _migrate_v1_rows(conn)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    except sqlite3.DatabaseError as exc:
        conn.rollback()
        raise MemoryError("Experience database migration failed; the existing database was left unchanged.") from exc


def _migrate_v1_rows(conn: sqlite3.Connection) -> None:
    """Fill v2 identity fields for v1 rows without inventing occurrences."""
    rows = conn.execute("SELECT * FROM memories WHERE fingerprint = '' OR fingerprint IS NULL").fetchall()
    for row in rows:
        subject = str(row["subject"] or "")
        domain = subject.split(":", 1)[0] if ":" in subject and row["type"] in ("incident", "pattern") else ""
        suffix = subject.split(":", 1)[1] if domain else ""
        finding_id = suffix if "." in suffix else ""
        identity = fingerprint(row["type"], domain=domain, finding_id=finding_id, subject=subject)
        observed = row["created_at"]
        conn.execute(
            "UPDATE memories SET domain = ?, finding_id = ?, fingerprint = ?, first_observed_at = ?, "
            "last_observed_at = ?, independent_sessions = CASE WHEN times_observed > 0 THEN 1 ELSE 0 END WHERE id = ?",
            (domain, finding_id, identity, observed, observed, row["id"]),
        )


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    value = dict(row)
    for key, fallback in (("evidence_refs", []), ("finding_ids", []), ("memory_ids", []),
                          ("history_fingerprints", []), ("severity_summary", {})):
        if key in value:
            value[key] = _decode(value.get(key), fallback)
    value["id"] = str(value.get("id", value.get("assessment_id", "")))
    return value


def _insert(*, type: str, subject: str, statement: str, source: str,
            confidence: str = "medium", evidence_refs: list[str] | None = None,
            domain: str = "", finding_id: str = "", fingerprint_value: str = "",
            related_memory_id: str = "", assessment_id: str = "", status: str = "active") -> dict:
    if type not in TYPES:
        raise MemoryError(f"unknown memory type: {type}")
    if source not in SOURCES:
        raise MemoryError(f"unknown memory source: {source}")
    if status not in STATUSES:
        raise MemoryError(f"unknown memory status: {status}")
    subject, statement, domain, finding_id = (_sanitize(subject)[:200], _sanitize(statement)[:2000],
                                               _sanitize(domain)[:80], _sanitize(finding_id)[:160])
    if not statement.strip():
        raise MemoryError("a memory statement cannot be empty")
    now = _now()
    identity = fingerprint_value or fingerprint(type, domain=domain, finding_id=finding_id, subject=subject)
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO memories (type, subject, statement, source, created_at, last_confirmed_at, confidence, "
            "status, evidence_refs, times_observed, domain, finding_id, fingerprint, first_observed_at, "
            "last_observed_at, independent_sessions, related_memory_id, assessment_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 0, ?, ?)",
            (type, subject, statement, source, now, now, confidence, status, _json(sorted(set(evidence_refs or []))),
             domain, finding_id, identity, now, now, related_memory_id, assessment_id),
        )
        return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (cursor.lastrowid,)).fetchone())


def _relationship(conn: sqlite3.Connection, from_id: str, to_id: str, kind: str) -> None:
    if from_id and to_id and kind in RELATIONSHIPS:
        conn.execute("INSERT OR IGNORE INTO relationships (from_memory_id, to_memory_id, kind, created_at) VALUES (?, ?, ?, ?)",
                     (from_id, to_id, kind, _now()))


def remember(statement: str, *, type: str = "machine_fact", subject: str | None = None) -> dict:
    """Store a user assertion, not automatically verified machine truth."""
    return _insert(type=type, subject=subject or statement, statement=statement,
                   source="user_explicit", confidence="high")


def record_machine_fact(subject: str, value: str, *, domain: str = "system", session_id: str = "") -> dict:
    """Upsert a deterministic stable fact; changed values supersede old active facts."""
    subject, value = _sanitize(subject)[:200], _sanitize(value)[:2000]
    identity = fingerprint("machine_fact", domain=domain, subject=subject)
    with _connect() as conn:
        existing = conn.execute("SELECT * FROM memories WHERE type = 'machine_fact' AND fingerprint = ? AND status = 'active' ORDER BY id DESC LIMIT 1", (identity,)).fetchone()
        if existing and existing["statement"] == value:
            conn.execute("UPDATE memories SET times_observed = times_observed + 1, last_observed_at = ?, last_session_id = ?, independent_sessions = independent_sessions + ? WHERE id = ?",
                         (_now(), session_id, 1 if session_id and session_id != existing["last_session_id"] else 0, existing["id"]))
            return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (existing["id"],)).fetchone())
        if existing:
            conn.execute("UPDATE memories SET status = 'superseded' WHERE id = ?", (existing["id"],))
        now = _now()
        cursor = conn.execute(
            "INSERT INTO memories (type, subject, statement, source, created_at, last_confirmed_at, confidence, status, evidence_refs, times_observed, domain, fingerprint, first_observed_at, last_observed_at, independent_sessions, last_session_id, related_memory_id) VALUES (?, ?, ?, 'deterministic', ?, ?, 'high', 'active', '[]', 1, ?, ?, ?, ?, ?, ?, ?)",
            ("machine_fact", subject, value, now, now, domain, identity, now, now, 1 if session_id else 0,
             session_id, str(existing["id"]) if existing else ""),
        )
        row = _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if existing:
            _relationship(conn, row["id"], str(existing["id"]), "supersedes")
        return row


def learn_machine_facts(document: dict, *, session_id: str = "") -> list[dict]:
    """Persist only stable collector facts; volatile readings never enter experience."""
    system = document.get("system", {}) if isinstance(document, dict) else {}
    facts: list[tuple[str, str, str]] = []
    for key in ("platform", "architecture", "kernel"):
        if system.get(key): facts.append((key.replace("_", " "), str(system[key]), "system"))
    release = system.get("os_release", {}) or {}
    for key in ("id", "version_id", "pretty_name"):
        if release.get(key): facts.append((f"OS {key.replace('_', ' ')}", str(release[key]), "system"))
    sections = document.get("sections", {}) or {}
    gpu = sections.get("gpu", sections) if isinstance(sections, dict) else {}
    if isinstance(gpu, dict):
        for device in (gpu.get("identity", {}) or {}).get("devices", [])[:4]:
            if isinstance(device, dict) and device.get("description"): facts.append(("GPU", str(device["description"]), "gpu"))
        drivers = (gpu.get("driver", {}) or {}).get("drivers_in_use", [])
        if drivers: facts.append(("GPU driver", ", ".join(map(str, drivers[:3])), "gpu"))
    learned = []
    for subject, value, domain in facts:
        try: learned.append(record_machine_fact(subject, value, domain=domain, session_id=session_id))
        except (MemoryError, OSError): continue
    return learned


def _add_occurrence(conn: sqlite3.Connection, memory_id: int, *, session_id: str, assessment_id: str, domain: str, identity: str, evidence_refs: list[str]) -> bool:
    cursor = conn.execute("INSERT OR IGNORE INTO occurrences (memory_id, observed_at, session_id, assessment_id, domain, fingerprint, evidence_refs) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (memory_id, _now(), session_id, assessment_id, domain, identity, _json(sorted(set(evidence_refs)))))
    return cursor.rowcount > 0


def _promote_pattern(conn: sqlite3.Connection, incident: dict) -> None:
    if incident.get("independent_sessions", 0) < PATTERN_MIN_SESSIONS: return
    pattern_identity = fingerprint("pattern", domain=incident.get("domain", ""), finding_id=incident.get("finding_id", ""), subject=incident.get("subject", ""))
    existing = conn.execute("SELECT * FROM memories WHERE type = 'pattern' AND fingerprint = ?", (pattern_identity,)).fetchone()
    statement = f"Recurring association: {incident['subject']} observed across {incident['independent_sessions']} independent sessions. Historical recurrence does not establish cause."
    if existing:
        conn.execute("UPDATE memories SET times_observed = ?, independent_sessions = ?, last_observed_at = ?, statement = ?, status = 'active' WHERE id = ?",
                     (incident["times_observed"], incident["independent_sessions"], incident["last_observed_at"], statement, existing["id"]))
        pattern_id = str(existing["id"])
    else:
        now = _now()
        cursor = conn.execute("INSERT INTO memories (type, subject, statement, source, created_at, last_confirmed_at, confidence, status, evidence_refs, times_observed, domain, finding_id, fingerprint, first_observed_at, last_observed_at, independent_sessions, related_memory_id) VALUES ('pattern', ?, ?, 'deterministic', ?, ?, 'medium', 'active', '[]', ?, ?, ?, ?, ?, ?, ?, ?)",
                              (incident["subject"], _sanitize(statement), now, now, incident["times_observed"], incident["domain"], incident["finding_id"], pattern_identity, incident["first_observed_at"], incident["last_observed_at"], incident["independent_sessions"], incident["id"]))
        pattern_id = str(cursor.lastrowid)
    _relationship(conn, pattern_id, incident["id"], "pattern_of")


def record_incident(subject: str, statement: str, *, domain: str = "", confidence: str = "medium", evidence_refs: list[str] | None = None, finding_id: str = "", session_id: str = "", assessment_id: str = "") -> dict:
    """Record one deterministic incident occurrence under a stable identity."""
    subject, domain, finding_id = _sanitize(subject)[:200], _sanitize(domain)[:80], _sanitize(finding_id)[:160]
    if not finding_id and ":" in subject:
        suffix = subject.split(":", 1)[1]
        if "." in suffix: finding_id = suffix
    identity = fingerprint("incident", domain=domain, finding_id=finding_id, subject=subject)
    session_id = session_id or f"manual-{uuid.uuid4().hex}"
    refs = sorted(set(evidence_refs or []))
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE type = 'incident' AND fingerprint = ? ORDER BY id DESC LIMIT 1", (identity,)).fetchone()
        if row:
            current_refs = sorted(set(_decode(row["evidence_refs"], [])) | set(refs))
            added = _add_occurrence(conn, row["id"], session_id=session_id, assessment_id=assessment_id, domain=domain, identity=identity, evidence_refs=refs)
            if added:
                sessions = conn.execute("SELECT COUNT(DISTINCT session_id) FROM occurrences WHERE memory_id = ?", (row["id"],)).fetchone()[0]
                conn.execute("UPDATE memories SET times_observed = times_observed + 1, independent_sessions = ?, last_observed_at = ?, last_confirmed_at = ?, last_session_id = ?, status = 'active', assessment_id = ?, evidence_refs = ? WHERE id = ?",
                             (sessions, _now(), _now(), session_id, assessment_id, _json(current_refs), row["id"]))
            updated = _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (row["id"],)).fetchone())
            _promote_pattern(conn, updated)
            return updated
        now = _now()
        cursor = conn.execute("INSERT INTO memories (type, subject, statement, source, created_at, last_confirmed_at, confidence, status, evidence_refs, times_observed, domain, finding_id, fingerprint, first_observed_at, last_observed_at, independent_sessions, last_session_id, assessment_id) VALUES ('incident', ?, ?, 'deterministic', ?, ?, ?, 'active', ?, 1, ?, ?, ?, ?, ?, 1, ?, ?)",
                              (subject, _sanitize(statement)[:2000], now, now, confidence if confidence in ("low", "medium", "high") else "medium", _json(refs), domain, finding_id, identity, now, now, session_id, assessment_id))
        _add_occurrence(conn, cursor.lastrowid, session_id=session_id, assessment_id=assessment_id, domain=domain, identity=identity, evidence_refs=refs)
        return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (cursor.lastrowid,)).fetchone())


def record_assessment(*, domain: str, finding_ids: list[str] | None = None, memory_ids: list[str] | None = None, history_fingerprints: list[str] | None = None, severity_summary: dict | None = None, diagnostics_collected: bool = False) -> dict:
    """Persist only lightweight, sanitized metadata for feedback linkage."""
    now = _now()
    assessment_id = f"a-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}"
    with _connect() as conn:
        conn.execute("INSERT INTO assessments (assessment_id, created_at, domain, finding_ids, memory_ids, history_fingerprints, severity_summary, diagnostics_collected) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (assessment_id, now, _sanitize(domain)[:80], _json(sorted(set(finding_ids or []))), _json(sorted(set(map(str, memory_ids or [])))), _json(sorted(set(history_fingerprints or []))), _json(severity_summary or {}), int(bool(diagnostics_collected))))
        return _row_to_dict(conn.execute("SELECT * FROM assessments WHERE assessment_id = ?", (assessment_id,)).fetchone())


def update_assessment_memories(assessment_id: str, memory_ids: list[str]) -> None:
    with _connect() as conn:
        row = conn.execute("SELECT memory_ids FROM assessments WHERE assessment_id = ?", (assessment_id,)).fetchone()
        if row:
            merged = sorted(set(_decode(row["memory_ids"], [])) | {str(value) for value in memory_ids if value})
            conn.execute("UPDATE assessments SET memory_ids = ? WHERE assessment_id = ?", (_json(merged), assessment_id))


def latest_assessment() -> dict | None:
    with _connect() as conn:
        return _row_to_dict(conn.execute("SELECT * FROM assessments ORDER BY created_at DESC LIMIT 1").fetchone())


def _assessment_memories(conn: sqlite3.Connection, assessment: dict) -> list[sqlite3.Row]:
    ids = [str(value) for value in assessment.get("memory_ids", []) if str(value).isdigit()]
    if not ids: return []
    return conn.execute(f"SELECT * FROM memories WHERE id IN ({','.join('?' for _ in ids)})", ids).fetchall()


def apply_feedback(verdict: str, *, correction: str = "") -> dict | None:
    """Attach user feedback to the last real assessment; never create generic junk rows."""
    assessment = latest_assessment()
    if assessment is None: return None
    verdict = verdict.lower()
    if verdict not in ("yes", "no", "correction"): raise MemoryError("unknown feedback verdict")
    with _connect() as conn:
        rows = _assessment_memories(conn, assessment)
        if verdict == "yes":
            for row in rows:
                if row["type"] in ("incident", "pattern", "outcome"):
                    conn.execute("UPDATE memories SET times_confirmed = times_confirmed + 1, last_confirmed_at = ? WHERE id = ?", (_now(), row["id"]))
        elif verdict == "no":
            for row in rows:
                if row["type"] in ("incident", "pattern", "diagnostic_lesson"):
                    conn.execute("UPDATE memories SET times_contradicted = times_contradicted + 1, status = CASE WHEN status = 'active' THEN 'uncertain' ELSE status END WHERE id = ?", (row["id"],))
        else:
            if not correction.strip(): raise MemoryError("a correction cannot be empty")
            entry = _insert(type="user_correction", subject=f"Assessment {assessment['assessment_id']}", statement=correction, source="user_feedback", confidence="high", assessment_id=assessment["assessment_id"])
            for row in rows: _relationship(conn, entry["id"], str(row["id"]), "correction_for")
        conn.execute("UPDATE assessments SET feedback = ? WHERE assessment_id = ?", (verdict, assessment["assessment_id"]))
    return {"assessment": assessment, "verdict": verdict}


def resolve_latest(statement: str) -> dict | None:
    """Store a user-reported outcome attached to the last meaningful incident/assessment."""
    assessment = latest_assessment()
    if assessment is None: return None
    with _connect() as conn:
        rows = [row for row in _assessment_memories(conn, assessment) if row["type"] in ("incident", "pattern")]
        incident = next((row for row in rows if row["type"] == "incident"), None)
        if incident is None: return None
        outcome = _insert(type="outcome", subject=incident["subject"], statement=statement, source="user_feedback", confidence="high", domain=incident["domain"], finding_id=incident["finding_id"], related_memory_id=str(incident["id"]), assessment_id=assessment["assessment_id"], status="resolved")
        conn.execute("UPDATE memories SET status = 'resolved', outcome_summary = ? WHERE id = ?", (_sanitize(statement)[:2000], incident["id"]))
        _relationship(conn, outcome["id"], str(incident["id"]), "outcome_for")
    return outcome


def record_feedback(statement: str, *, positive: bool | None = None) -> dict:
    return _insert(type="user_correction", subject="User feedback", statement=statement, source="user_feedback", confidence="high" if positive else "medium")


def record_outcome(subject: str, statement: str, *, confidence: str = "medium") -> dict:
    return _insert(type="outcome", subject=subject, statement=statement, source="user_feedback", confidence=confidence, status="resolved")


def confirm(memory_id: str, *, evidence_ref: str | None = None) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None: return None
        refs = sorted(set(_decode(row["evidence_refs"], [])) | ({evidence_ref} if evidence_ref else set()))
        conn.execute("UPDATE memories SET times_confirmed = times_confirmed + 1, last_confirmed_at = ?, evidence_refs = ?, status = CASE WHEN status = 'uncertain' THEN 'active' ELSE status END WHERE id = ?", (_now(), _json(refs), memory_id))
        return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone())


def contradict(memory_id: str, note: str | None = None) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None: return None
        status = "uncertain" if row["type"] == "machine_fact" and row["source"] == "deterministic" else "contradicted"
        conn.execute("UPDATE memories SET times_contradicted = times_contradicted + 1, status = ? WHERE id = ?", (status, memory_id))
        result = _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone())
    if note: _insert(type="diagnostic_lesson", subject=result["subject"], statement=note, source="diagnostic", confidence="medium", related_memory_id=memory_id)
    return result


def resolve(memory_id: str) -> dict | None:
    with _connect() as conn:
        conn.execute("UPDATE memories SET status = 'resolved' WHERE id = ?", (memory_id,))
        return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone())


def get(memory_id: str) -> dict | None:
    with _connect() as conn:
        return _row_to_dict(conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone())


def list_memories(*, type: str | None = None, status: str | None = None, limit: int = MAX_LIST) -> list[dict]:
    limit = max(1, min(limit, MAX_LIST)); query, params = "SELECT * FROM memories WHERE 1=1", []
    if type: query += " AND type = ?"; params.append(type)
    if status: query += " AND status = ?"; params.append(status)
    query += " ORDER BY COALESCE(last_observed_at, created_at) DESC, id DESC LIMIT ?"; params.append(limit)
    with _connect() as conn: return [_row_to_dict(row) for row in conn.execute(query, params).fetchall()]


def search(query: str, *, limit: int = 20) -> list[dict]:
    query = _sanitize(str(query or "").strip())[:MAX_SEARCH_QUERY_LEN]
    words = [word for word in _normal(query).split() if len(word) > 1]
    if not words: return []
    clauses, params = [], []
    for word in words[:6]: clauses.append("(subject LIKE ? OR statement LIKE ? OR finding_id LIKE ?)"); params.extend([f"%{word}%"] * 3)
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM memories WHERE " + " OR ".join(clauses) + " ORDER BY id DESC LIMIT ?", [*params, max(1, min(limit, MAX_LIST))]).fetchall()
    return [_row_to_dict(row) for row in rows]


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _retrieval_score(record: dict, *, domain: str, keywords: set[str]) -> tuple[int, list[str]]:
    score, reasons = 0, []
    if record.get("domain") == domain: score += 60; reasons.append("same domain")
    finding_id = record.get("finding_id", "")
    if finding_id and finding_id in keywords: score += 120; reasons.append("exact finding ID")
    overlap = set(_normal(record.get("subject", "") + " " + record.get("statement", "")).split()) & keywords
    if overlap: score += min(30, len(overlap) * 10); reasons.append("matching diagnostic terms")
    if record.get("type") == "outcome" and record.get("related_memory_id"): score += 45; reasons.append("prior reported outcome")
    if record.get("outcome_summary"): score += 35; reasons.append("linked outcome")
    score += _CONFIDENCE_RANK.get(record.get("confidence"), 0) * 4 + min(20, int(record.get("times_confirmed") or 0) * 4) + min(16, int(record.get("independent_sessions") or 0) * 4)
    if record.get("status") == "resolved": score -= 4; reasons.append("resolved historical experience")
    if record.get("status") == "stale": score -= 20; reasons.append("stale")
    return score, reasons


def retrieve_relevant(*, domain: str, keywords: list[str] | None = None, limit: int = MAX_RETRIEVE) -> list[dict]:
    """Bounded structured retrieval; preferences never enter diagnostic context."""
    limit = max(1, min(limit, MAX_RETRIEVE)); terms = {_normal(domain)} | {_normal(value) for value in (keywords or []) if value}; terms.discard("")
    with _connect() as conn: rows = conn.execute("SELECT * FROM memories WHERE type != 'preference' AND status IN ('active', 'uncertain', 'resolved', 'stale')").fetchall()
    candidates = []
    for row in rows:
        record = _row_to_dict(row); score, reasons = _retrieval_score(record, domain=domain, keywords=terms)
        if score > 0: record["retrieval_reasons"], record["retrieval_score"] = reasons, score; candidates.append(record)
    candidates.sort(key=lambda item: (item["retrieval_score"], item.get("last_observed_at") or item.get("created_at") or ""), reverse=True)
    return candidates[:limit]


def maintenance() -> int:
    """Conservatively mark old low-value automatic experience stale; never delete it."""
    cutoff = (dt.datetime.now().astimezone() - dt.timedelta(days=STALE_AFTER_DAYS)).isoformat(timespec="seconds")
    with _connect() as conn:
        return conn.execute("UPDATE memories SET status = 'stale' WHERE source IN ('deterministic', 'diagnostic') AND type IN ('incident', 'pattern') AND status = 'active' AND COALESCE(last_observed_at, created_at) < ? AND times_confirmed = 0", (cutoff,)).rowcount


def forget(memory_id: str) -> bool:
    with _connect() as conn:
        conn.execute("DELETE FROM relationships WHERE from_memory_id = ? OR to_memory_id = ?", (memory_id, memory_id)); conn.execute("DELETE FROM occurrences WHERE memory_id = ?", (memory_id,))
        return conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,)).rowcount > 0


def purge() -> int:
    with _connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        conn.execute("DELETE FROM relationships"); conn.execute("DELETE FROM occurrences"); conn.execute("DELETE FROM assessments"); conn.execute("DELETE FROM memories")
    return count


def stats() -> dict:
    with _connect() as conn:
        by_type = dict(conn.execute("SELECT type, COUNT(*) FROM memories GROUP BY type").fetchall()); by_status = dict(conn.execute("SELECT status, COUNT(*) FROM memories GROUP BY status").fetchall())
        total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]; patterns = conn.execute("SELECT COUNT(*) FROM memories WHERE type = 'pattern' AND status = 'active'").fetchone()[0]; assessments = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
    return {"total": total, "by_type": by_type, "by_status": by_status, "patterns": patterns, "assessments": assessments, "schema_version": SCHEMA_VERSION}


def prior_experience_block(memories: list[dict]) -> dict:
    return {"label": "PRIOR EXPERIENCE", "note": "Structured local experience. It may be stale or superseded and is historical context, not proof of the current cause.", "memories": [{"id": item["id"], "type": item["type"], "subject": item["subject"], "statement": item["statement"], "domain": item.get("domain"), "finding_id": item.get("finding_id"), "confidence": item["confidence"], "status": item["status"], "first_observed_at": item.get("first_observed_at"), "last_observed_at": item.get("last_observed_at"), "times_observed": item.get("times_observed"), "independent_sessions": item.get("independent_sessions"), "outcome": item.get("outcome_summary"), "retrieval_reasons": item.get("retrieval_reasons", [])} for item in memories]}


def render_memory_overview() -> str:
    data = stats(); lines = ["SysAI · Experience", "", "Learning", f"  {data['total']} records · {data['assessments']} assessments · {data['patterns']} recurring patterns", ""]
    for heading, types in (("Machine", ("machine_fact",)), ("Recurring", ("pattern", "incident")), ("Resolved", ("outcome",)), ("Corrections", ("user_correction",))):
        records = [row for row in list_memories(limit=12) if row["type"] in types]
        if records:
            lines.append(heading)
            for row in records[:4]: lines.append(f"  [{row['id']}] {row['subject']}\n      {row.get('times_observed', 1)} observations · {row.get('independent_sessions', 0)} sessions · {row['status']}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_memory_list(memories: list[dict]) -> str:
    if not memories: return "SysAI · Experience\n\nNo memories recorded yet.\n"
    lines = ["SysAI · Experience", ""]
    for item in memories:
        lines += [f"[{item['id']}] {item['subject']} · {item['type']} · {item['status']}", f"    {item['statement']}", f"    observed {item.get('times_observed', 1)} time(s) across {item.get('independent_sessions', 0)} session(s)"]
        if item.get("outcome_summary"): lines.append(f"    outcome: {item['outcome_summary']}")
    return "\n".join(lines) + "\n"


def render_memory_detail(record: dict) -> str:
    lines = ["SysAI · Experience", "", f"[{record['id']}] {record['subject']}", f"  {record['statement']}", "", "Why it exists", f"  source: {record['source']} · type: {record['type']} · status: {record['status']}", f"  domain: {record.get('domain') or 'not classified'} · finding: {record.get('finding_id') or 'none'}", f"  first seen: {record.get('first_observed_at') or record.get('created_at')}", f"  last seen: {record.get('last_observed_at') or 'unknown'}", f"  observations: {record.get('times_observed', 1)} · sessions: {record.get('independent_sessions', 0)}", f"  confirmations: {record.get('times_confirmed', 0)} · contradictions: {record.get('times_contradicted', 0)}", f"  influences diagnosis: {'yes' if record.get('status') in ('active', 'uncertain', 'resolved', 'stale') and record.get('type') != 'preference' else 'no'}"]
    if record.get("outcome_summary"): lines += ["", "Associated outcome", f"  {record['outcome_summary']}"]
    if record.get("evidence_refs"): lines += ["", "Evidence identifiers", "  " + ", ".join(record["evidence_refs"])]
    return "\n".join(lines) + "\n"
