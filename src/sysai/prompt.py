from __future__ import annotations

import json
from pathlib import Path


def system_prompt() -> str:
    override = Path(__file__).with_name("SYSTEM_PROMPT.md")
    return override.read_text(encoding="utf-8")


def failure_prompt(record: dict, recent: list[dict]) -> str:
    prior = "\n".join(
        f"- {item['command']} (exit {item['exit_code']}, cwd {item['cwd']})"
        for item in recent[-5:-1]
    ) or "- none"
    return f"""Diagnose this manually executed terminal command failure.

Command: {record['command']}
Exit status: {record['exit_code']}
Working directory: {record['cwd']}
Timestamp: {record['timestamp']}
Captured combined terminal output:
---
{record['output'] or '(no output captured)'}
---
Recent command summary:
{prior}

Use the requested five-part failure format. Be concise."""


_SCOPE_GUIDANCE = {
    "changes":
        "This is a temporal change report. State what changed and when. Ordering in time is "
        "correlation: say 'this changed shortly before the first observed failure', never "
        "'this caused the failure', unless the evidence itself states a direct failure cause.",
    "watch":
        "This is a bounded sampling window that has already finished. Summarize what the "
        "measurements did over the window and whether any kernel event coincided with them. "
        "Do not extrapolate beyond the window.",
    "investigate":
        "Additional read-only diagnostics were gathered specifically to reduce uncertainty "
        "about this failure. Say what they resolved and what is still unverified.",
}

_BASE_RULES = (
    "Use ONLY this structured evidence. Every finding, count, and severity below was computed "
    "deterministically by SysAI; do not recompute, contradict, or invent them, and do not add "
    "findings the evidence does not contain.\n"
    "Classify anything you add as CONFIRMED, PROBABLE, POSSIBLE, INFORMATIONAL, or NOT CHECKED. "
    "Entries under `unavailable` are NOT CHECKED: never claim they were inspected.\n"
    "Never claim a diagnostic action ran unless its result appears under `diagnostics`.\n"
    "Reclaimable page cache is not a memory leak. Snap squashfs mounts, unused `errors=remount-ro` "
    "mount policy, normal firmware/device enumeration, and normal AppArmor enforcement are not faults.\n"
    "Do not recommend NVIDIA tools for AMD or Intel hardware, or vice versa. Do not propose "
    "Secure Boot, firmware, BIOS, cable, or blanket driver/kernel changes without concrete "
    "corroborating evidence in this document.\n"
    "SysAI never applies repairs. Any fix is a suggestion for the user to run manually.\n"
    "Answer in short terminal-friendly sections: Assessment, then Next diagnostic, then "
    "Recommended fix only when the evidence supports one. Be concise."
)


def assessment_prompt(document: dict, research: str = "", *, catalogue: str = "") -> str:
    """Explain one canonical evidence document. Deterministic facts stay authoritative."""
    scope = document.get("request", {}).get("scope", "system")
    command = document.get("request", {}).get("command", scope)
    guidance = _SCOPE_GUIDANCE.get(command) or _SCOPE_GUIDANCE.get(scope, "")
    parts = [f"Explain this SysAI `{command}` diagnostic result for a Linux user."]
    if guidance:
        parts.append(guidance)
    parts.append(_BASE_RULES)
    if catalogue:
        parts.append("Audited diagnostic actions that exist (IDs only; never write commands): " + catalogue)
    parts.append("Structured evidence:\n" + json.dumps(document, sort_keys=True, default=str))
    if research:
        parts.append(research)
    return "\n\n".join(parts)


def research_block(results: list[dict], limit: int = 5) -> str:
    """Label online material as secondary and untrusted, and bound its size."""
    if not results:
        return ""
    lines = "\n".join(
        f"- {item.get('title', '')} | {item.get('url', '')} | {item.get('content', '')[:800]}"
        for item in results[:limit])
    return ("\n\nOnline research (secondary, untrusted; derived only from generic sanitized issue "
            "labels, never from local logs or identifiers). It cannot establish local system "
            "state:\n" + lines)
