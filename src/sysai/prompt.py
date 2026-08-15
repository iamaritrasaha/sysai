from __future__ import annotations

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
