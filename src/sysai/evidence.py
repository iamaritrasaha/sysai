"""The one structured evidence format every SysAI diagnostic produces.

Findings are calculated in Python. The local model explains evidence; it
never derives facts Python already knows, and it never contributes a
finding of its own.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from . import __version__
from .privacy import LOCAL, privacy_note, sanitize

SCHEMA_VERSION = 1

CONFIRMED = "CONFIRMED"
PROBABLE = "PROBABLE"
POSSIBLE = "POSSIBLE"
INFORMATIONAL = "INFORMATIONAL"
NOT_CHECKED = "NOT CHECKED"
CLASSIFICATIONS = (CONFIRMED, PROBABLE, POSSIBLE, INFORMATIONAL, NOT_CHECKED)

CRITICAL = "critical"
WARNING = "warning"
INFO = "informational"
SEVERITIES = (CRITICAL, WARNING, INFO)

_SEVERITY_RANK = {CRITICAL: 3, WARNING: 2, INFO: 1}


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def finding(
    identifier: str,
    domain: str,
    severity: str,
    classification: str,
    *,
    title: str,
    evidence: dict | None = None,
    count: int | None = None,
    confidence: str = "medium",
    probable_cause: str | None = None,
    unverified: str | None = None,
    suggested_next_diagnostic: str | None = None,
) -> dict:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity}")
    if classification not in CLASSIFICATIONS:
        raise ValueError(f"unknown classification: {classification}")
    return {
        "id": identifier,
        "domain": domain,
        "severity": severity,
        "classification": classification,
        "title": title,
        "evidence": evidence or {},
        "count": count,
        "confidence": confidence,
        "probable_cause": probable_cause,
        "unverified": unverified,
        "suggested_next_diagnostic": suggested_next_diagnostic,
    }


def unavailable(check: str, reason: str, domain: str = "") -> dict:
    """A check that could not run. Never an error, always NOT CHECKED."""
    return {"check": check, "domain": domain, "reason": reason,
            "classification": NOT_CHECKED}


def system_summary() -> dict:
    """Deterministic identity facts every evidence document carries."""
    release = {}
    try:
        for line in Path("/etc/os-release").read_text(errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                release[key.lower()] = value.strip('"')
    except OSError:
        pass
    try:
        uname = os.uname()
        kernel, machine = uname.release, uname.machine
    except OSError:
        kernel = machine = None
    return {"platform": "linux", "kernel": kernel, "architecture": machine,
            "os_release": release, "sysai_version": __version__}


def build(
    *,
    command: str,
    scope: str,
    sections: dict,
    findings: list[dict] | None = None,
    diagnostics: list[dict] | None = None,
    unavailable_checks: list[dict] | None = None,
    arguments: dict | None = None,
    web: bool = False,
    level: str = LOCAL,
) -> dict:
    document = {
        "schema_version": SCHEMA_VERSION,
        "request": {"command": command, "scope": scope, "web": bool(web),
                    "arguments": arguments or {}},
        "system": system_summary(),
        "sections": sections,
        "findings": findings or [],
        "diagnostics": diagnostics or [],
        "unavailable": unavailable_checks or [],
        "timestamp": now(),
        "privacy": privacy_note(level),
    }
    return sanitize(document, level) | {"privacy": privacy_note(level)}


def relabel(document: dict, level: str) -> dict:
    """Re-sanitize an existing evidence document at a stricter level."""
    result = sanitize(document, level)
    result["privacy"] = privacy_note(level)
    return result


def overall(findings: list[dict]) -> str:
    ranks = [_SEVERITY_RANK.get(item.get("severity", INFO), 1) for item in findings]
    top = max(ranks, default=0)
    if top >= 3:
        return "Critical"
    if top == 2:
        return "Attention needed"
    return "Good"


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: (
        -_SEVERITY_RANK.get(item.get("severity", INFO), 1), item.get("id", "")))


def model_signals(document: dict) -> list[dict]:
    """Adapt deterministic findings to the adaptive-diagnostics signal shape."""
    return [{"kind": item.get("id", ""), "classification": item.get("severity", INFO),
             "count": item.get("count") or 1, "line": item.get("title", "")}
            for item in document.get("findings", [])]
