"""Local, structured experience memory.

This is operational memory, not conversation memory: durable facts,
incidents, patterns, outcomes, and user corrections about this machine,
accumulated over time. It is never raw logs and never a place the model can
write arbitrary text unsupervised — every write goes through one of the
narrow functions below, called from Python, with a fixed schema.

Storage is local-first and dependency-free: a single SQLite database under
the user's XDG state directory, mode 0600, in a directory that is mode 0700
(see `persistent_state_dir` in `config.py`). No network access, no optional
package. `MemoryStore` here is the only backend; a future optional remote
backend (e.g. Mem0) could implement the same functions without touching
callers, but none exists today and none is installed.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path

from .config import persistent_state_dir
from .privacy import SHARED, sanitize_text
from .redact import redact

DB_FILENAME = "memory.db"
SCHEMA_VERSION = 1

TYPES = ("machine_fact", "incident", "pattern", "outcome", "user_correction",
          "preference", "diagnostic_lesson")
STATUSES = ("active", "uncertain", "contradicted", "resolved", "archived")
SOURCES = ("user_explicit", "diagnostic", "user_feedback")

MAX_RETRIEVE = 5
MAX_LIST = 200
MAX_SEARCH_QUERY_LEN = 200

# Auto-recorded incidents dedupe against an existing active memory with the
# same subject within this window, so a repeated finding increments
# `times_observed` instead of accumulating duplicate rows.
_DEDUPE_WINDOW_HOURS = 24


class MemoryError(ValueError):
    pass


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def store_path() -> Path:
    return persistent_state_dir() / DB_FILENAME


def _connect() -> sqlite3.Connection:
    path = store_path()
    is_new = not path.exists()
    conn = sqlite3.connect(str(path), timeout=5)
    conn.row_factory = sqlite3.Row
    if is_new:
        path.chmod(0o600)
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            subject TEXT NOT NULL,
            statement TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_confirmed_at TEXT,
            confidence TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'active',
            evidence_refs TEXT NOT NULL DEFAULT '[]',
            times_observed INTEGER NOT NULL DEFAULT 1,
            times_confirmed INTEGER NOT NULL DEFAULT 0,
            times_contradicted INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_subject ON memories(subject)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(type)")
    conn.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
    conn.commit()


def _sanitize(text: str) -> str:
    """Every string persisted to the memory DB is redacted, then SHARED-sanitized.

    Memory can outlive the session and is read back into future model
    prompts, so it is held to the same bar as a written report.
    """
    return sanitize_text(redact(str(text or "")), SHARED)


def _row_to_dict(row: sqlite3.Row) -> dict:
    value = dict(row)
    try:
        value["evidence_refs"] = json.loads(value.get("evidence_refs") or "[]")
    except (TypeError, ValueError):
        value["evidence_refs"] = []
    value["id"] = str(value["id"])
    return value


# -------------------------------------------------------------------- writing

def _insert(
    *, type: str, subject: str, statement: str, source: str,
    confidence: str = "medium", evidence_refs: list[str] | None = None,
) -> dict:
    if type not in TYPES:
        raise MemoryError(f"unknown memory type: {type}")
    if source not in SOURCES:
        raise MemoryError(f"unknown memory source: {source}")
    subject = _sanitize(subject)[:200]
    statement = _sanitize(statement)[:2000]
    if not statement.strip():
        raise MemoryError("a memory statement cannot be empty")
    now = _now()
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO memories (type, subject, statement, source, created_at, "
            "last_confirmed_at, confidence, status, evidence_refs, times_observed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, 1)",
            (type, subject, statement, source, now, now, confidence,
             json.dumps(sorted(set(evidence_refs or [])))),
        )
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def remember(statement: str, *, type: str = "machine_fact", subject: str | None = None) -> dict:
    """Explicit user memory: `sysai remember "..."`. Always high confidence, user-sourced."""
    return _insert(type=type, subject=subject or statement, statement=statement,
                   source="user_explicit", confidence="high")


def record_feedback(statement: str, *, positive: bool | None = None) -> dict:
    """`sysai feedback ...`: a user correction or confirmation, recorded as-is."""
    type_ = "user_correction"
    return _insert(type=type_, subject=statement, statement=statement,
                   source="user_feedback", confidence="high" if positive else "medium")


def record_incident(
    subject: str, statement: str, *, domain: str = "", confidence: str = "medium",
    evidence_refs: list[str] | None = None,
) -> dict:
    """Deterministic diagnostic trigger only — never called from free model text.

    A recent active incident with the same subject is reinforced
    (`times_observed` incremented, `last_confirmed_at` refreshed) instead of
    duplicated; this is the conflict-avoidance rule for repeat findings.
    """
    subject_key = _sanitize(subject)[:200]
    with _connect() as conn:
        cutoff = (dt.datetime.now().astimezone()
                  - dt.timedelta(hours=_DEDUPE_WINDOW_HOURS)).isoformat(timespec="seconds")
        existing = conn.execute(
            "SELECT * FROM memories WHERE type = 'incident' AND subject = ? AND status = 'active' "
            "AND created_at >= ? ORDER BY id DESC LIMIT 1",
            (subject_key, cutoff),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE memories SET times_observed = times_observed + 1, "
                "last_confirmed_at = ? WHERE id = ?",
                (_now(), existing["id"]),
            )
            row = conn.execute("SELECT * FROM memories WHERE id = ?", (existing["id"],)).fetchone()
            return _row_to_dict(row)
    return _insert(type="incident", subject=subject, statement=statement, source="diagnostic",
                   confidence=confidence, evidence_refs=evidence_refs)


def record_outcome(subject: str, statement: str, *, confidence: str = "medium") -> dict:
    return _insert(type="outcome", subject=subject, statement=statement,
                   source="diagnostic", confidence=confidence)


def confirm(memory_id: str, *, evidence_ref: str | None = None) -> dict | None:
    """Reinforce a memory: another observation is consistent with it."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None:
            return None
        refs = json.loads(row["evidence_refs"] or "[]")
        if evidence_ref:
            refs = sorted(set(refs) | {evidence_ref})
        conn.execute(
            "UPDATE memories SET times_confirmed = times_confirmed + 1, last_confirmed_at = ?, "
            "evidence_refs = ?, status = CASE WHEN status = 'uncertain' THEN 'active' ELSE status END "
            "WHERE id = ?",
            (_now(), json.dumps(refs), memory_id),
        )
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
    return _row_to_dict(row)


def contradict(memory_id: str, note: str | None = None) -> dict | None:
    """Mark a memory as contradicted by newer evidence rather than deleting it.

    Prefer this over silently accumulating a conflicting duplicate: the old
    belief stays visible as history, but is no longer treated as current.
    """
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE memories SET times_contradicted = times_contradicted + 1, status = 'contradicted' "
            "WHERE id = ?",
            (memory_id,),
        )
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
    result = _row_to_dict(row)
    if note:
        _insert(type="diagnostic_lesson", subject=result["subject"],
                statement=_sanitize(note), source="diagnostic", confidence="medium",
                evidence_refs=[f"contradicts:{memory_id}"])
    return result


def resolve(memory_id: str) -> dict | None:
    with _connect() as conn:
        conn.execute("UPDATE memories SET status = 'resolved' WHERE id = ?", (memory_id,))
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
    return _row_to_dict(row) if row else None


# -------------------------------------------------------------------- reading

def get(memory_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_memories(*, type: str | None = None, status: str | None = None, limit: int = MAX_LIST) -> list[dict]:
    limit = max(1, min(limit, MAX_LIST))
    query = "SELECT * FROM memories WHERE 1=1"
    params: list = []
    if type:
        query += " AND type = ?"
        params.append(type)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(row) for row in rows]


def search(query: str, *, limit: int = 20) -> list[dict]:
    """Search sanitized structured memory only. Never touches history or logs."""
    query = str(query or "").strip()[:MAX_SEARCH_QUERY_LEN]
    if not query:
        return []
    like = f"%{query}%"
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM memories WHERE subject LIKE ? OR statement LIKE ? "
            "ORDER BY (status = 'active') DESC, id DESC LIMIT ?",
            (like, like, max(1, min(limit, MAX_LIST))),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def retrieve_relevant(*, domain: str, keywords: list[str] | None = None, limit: int = MAX_RETRIEVE) -> list[dict]:
    """Bounded retrieval for use as model context. Always labelled PRIOR EXPERIENCE by callers."""
    limit = max(1, min(limit, MAX_RETRIEVE))
    terms = {domain.lower()} | {k.lower() for k in (keywords or []) if k}
    if not terms:
        return []
    clauses = " OR ".join(["subject LIKE ? OR statement LIKE ?"] * len(terms))
    params: list = []
    for term in terms:
        like = f"%{term}%"
        params.extend([like, like])
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM memories WHERE status IN ('active', 'uncertain') AND ({clauses})",
            params,
        ).fetchall()
    candidates = [_row_to_dict(row) for row in rows]
    candidates.sort(key=lambda m: (
        _CONFIDENCE_RANK.get(m.get("confidence"), 0),
        m.get("times_confirmed", 0),
        m.get("last_confirmed_at") or m.get("created_at") or "",
    ), reverse=True)
    return candidates[:limit]


def forget(memory_id: str) -> bool:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
    return cursor.rowcount > 0


def purge() -> int:
    with _connect() as conn:
        cursor = conn.execute("DELETE FROM memories")
    return cursor.rowcount


def stats() -> dict:
    with _connect() as conn:
        by_type = dict(conn.execute("SELECT type, COUNT(*) FROM memories GROUP BY type").fetchall())
        by_status = dict(conn.execute("SELECT status, COUNT(*) FROM memories GROUP BY status").fetchall())
        total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
    return {"total": total, "by_type": by_type, "by_status": by_status}


def prior_experience_block(memories: list[dict]) -> dict:
    return {
        "label": "PRIOR EXPERIENCE",
        "note": "Past SysAI memories about this machine. They may be stale or superseded; "
                "check status and last_confirmed_at before treating them as current.",
        "memories": [
            {"id": m["id"], "type": m["type"], "subject": m["subject"], "statement": m["statement"],
             "confidence": m["confidence"], "status": m["status"],
             "last_confirmed_at": m.get("last_confirmed_at"), "times_observed": m.get("times_observed")}
            for m in memories
        ],
    }


def render_memory_overview() -> str:
    data = stats()
    lines = ["SysAI Memory", "", f"Total\n  {data['total']}", ""]
    lines.append("By type")
    for type_ in TYPES:
        lines.append(f"  {type_}: {data['by_type'].get(type_, 0)}")
    lines.append("")
    lines.append("By status")
    for status in STATUSES:
        lines.append(f"  {status}: {data['by_status'].get(status, 0)}")
    return "\n".join(lines) + "\n"


def render_memory_list(memories: list[dict]) -> str:
    if not memories:
        return "SysAI Memory\n\nNo memories recorded yet.\n"
    lines = ["SysAI Memory", ""]
    for m in memories:
        lines.append(f"[{m['id']}] ({m['type']}, {m['status']}, confidence: {m['confidence']}) {m['subject']}")
        lines.append(f"    {m['statement']}")
    return "\n".join(lines) + "\n"
