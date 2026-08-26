"""Sanitized diagnostic reports.

A report can leave the machine, so it is always re-sanitized at the strict
``SHARED`` level before rendering. Files are never created silently: the CLI
writes only when ``--output`` names a path, and then with mode 0600.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from . import __version__
from .evidence import CRITICAL, WARNING, overall, relabel
from .privacy import SHARED, privacy_note
from .render import title

SCOPE_TITLES = {"full_system": "Full system", "health": "Full system"}


def _heading(scope: str) -> str:
    return SCOPE_TITLES.get(scope, title(scope))


def _block(value) -> str:
    if isinstance(value, (list, tuple)):
        return "\n".join(f"  - {item}" for item in value) or "  - none"
    return f"  {value}"


def to_markdown(document: dict) -> str:
    """Render a sanitized Markdown report from a canonical evidence document."""
    document = relabel(document, SHARED)
    request = document.get("request", {})
    system = document.get("system", {})
    findings = document.get("findings", [])
    scope = request.get("scope", "unknown")
    lines = [
        "# SysAI Diagnostic Report", "",
        f"- **Generated:** {document.get('timestamp', 'unknown')}",
        f"- **Scope:** {_heading(scope)}",
        f"- **SysAI version:** {system.get('sysai_version', __version__)}",
        f"- **Schema version:** {document.get('schema_version', 1)}",
        "",
        "## System summary", "",
        f"- Kernel: `{system.get('kernel', 'unknown')}`",
        f"- Architecture: `{system.get('architecture', 'unknown')}`",
        f"- OS: {system.get('os_release', {}).get('pretty_name', 'unknown')}",
        f"- Overall: **{overall(findings)}**",
        "",
        "## Findings", "",
    ]
    if not findings:
        lines += ["No findings were produced by the collectors for this scope.", ""]
    for item in findings:
        lines += [
            f"### {item.get('title', item.get('id', 'finding'))}", "",
            f"- **Identifier:** `{item.get('id', '')}`",
            f"- **Domain:** {item.get('domain', '')}",
            f"- **Severity:** {item.get('severity', '')}",
            f"- **Classification:** {item.get('classification', '')}",
            f"- **Confidence:** {item.get('confidence', 'unknown')}",
        ]
        if item.get("count") is not None:
            lines.append(f"- **Occurrences:** {item['count']}")
        if item.get("probable_cause"):
            lines.append(f"- **Probable cause:** {item['probable_cause']}")
        if item.get("unverified"):
            lines.append(f"- **Not yet verified:** {item['unverified']}")
        if item.get("suggested_next_diagnostic"):
            lines.append(f"- **Suggested next diagnostic:** `{item['suggested_next_diagnostic']}`")
        lines.append("")
        if item.get("evidence"):
            lines += ["Evidence:", "", "```json",
                      json.dumps(item["evidence"], indent=2, sort_keys=True), "```", ""]

    lines += ["## Evidence", "", "Normalized collector sections for this scope.", "",
              "```json", json.dumps(document.get("sections", {}), indent=2, sort_keys=True)[:20_000],
              "```", "", "## Diagnostics performed", ""]
    diagnostics = document.get("diagnostics", [])
    if diagnostics:
        for item in diagnostics:
            status = item.get("status", "unknown")
            lines.append(f"- `{item.get('action_id', 'unknown')}` — {item.get('purpose', '')} ({status})")
    else:
        lines.append("- No additional audited diagnostic actions were run.")
    lines += ["", "## What was NOT checked", ""]
    missing = document.get("unavailable", [])
    if missing:
        for item in missing:
            lines.append(f"- **{item.get('check', 'unknown')}** — {item.get('reason', 'unavailable')}"
                         f" (NOT CHECKED)")
    else:
        lines.append("- Every check for this scope was available.")

    serious = [item for item in findings if item.get("severity") in (WARNING, CRITICAL)]
    confidences = sorted({item.get("confidence", "unknown") for item in serious}) or ["not applicable"]
    lines += ["", "## Confidence", "",
              f"- Findings are deterministic collector results classified as "
              f"{', '.join(sorted({item.get('classification', '') for item in findings})) or 'none'}.",
              f"- Confidence for actionable findings: {', '.join(confidences)}.",
              "- Anything absent from the evidence above was not observed and is not asserted.",
              "", "## Recommended next steps", ""]
    if serious:
        for item in serious:
            step = item.get("suggested_next_diagnostic")
            lines.append(f"- {item.get('title', item.get('id'))}: "
                         + (f"run the audited diagnostic `{step}`." if step
                            else "review the evidence above before changing anything."))
    else:
        lines.append("- No action is indicated by this evidence.")
    lines += ["- SysAI never applies repairs automatically. Review any suggested command first.",
              "", "## Privacy note", ""]
    note = privacy_note(SHARED)
    lines.append(f"{note['note']} Removed: {', '.join(note['removed'])}.")
    lines.append("")
    lines.append("This report was generated locally by SysAI and contains only the "
                 "sanitized diagnostic evidence shown above.")
    return "\n".join(lines) + "\n"


def to_json(document: dict) -> str:
    return json.dumps(relabel(document, SHARED), indent=2, sort_keys=True) + "\n"


def write(path: Path, text: str) -> Path:
    """Write a report atomically with restrictive permissions."""
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".sysai-report-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path
