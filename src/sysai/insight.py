"""Explicit user-requested, bounded read-only command inspection."""
from __future__ import annotations

import collections
import re
import subprocess

from .display import plain_terminal_text
from .redact import redact, truncate_output

MAX_BYTES = 48_000
_META = {"|", ">", ">>", "&&", "||", ";", "$()", "`"}
_INTERACTIVE = {"vim", "nano", "less", "more", "top", "htop", "ssh", "watch"}
_SAFE = {"dmesg", "journalctl", "uname", "lspci", "lsusb", "lsblk", "blkid", "findmnt", "df", "du", "free", "ps", "pgrep", "ip", "ss", "resolvectl", "timedatectl", "sensors", "smartctl", "rocminfo", "clinfo", "amd-smi", "rocm-smi", "modinfo", "lsmod", "sysctl", "systemctl", "mount"}
_BLOCKED = {"rm", "chmod", "chown", "dd", "mkfs", "fsck", "apt", "mount", "umount"}


def classify(argv: list[str]) -> tuple[bool, str, bool]:
    """Return allowed, reason, and whether sudo was explicitly user typed."""
    if not argv: return False, "No inspection command was supplied.", False
    if any(arg in _META or any(mark in arg for mark in ("|", ">", ";", "&&", "||", "$(", "`")) for arg in argv):
        return False, "Command Insight Mode accepts argv only, not shell pipelines or redirections.", False
    sudo = argv[0] == "sudo"
    command = argv[1] if sudo and len(argv) > 1 else argv[0]
    args = argv[2:] if sudo else argv[1:]
    follows = any(arg == "-f" or arg.startswith("--follow") or command == "dmesg" and arg.startswith(("-w", "-W")) for arg in args)
    if command in _INTERACTIVE or follows:
        return False, f"`{command}` is live/interactive and cannot be analyzed in bounded Command Insight Mode.", sudo
    if command in _BLOCKED or command not in _SAFE:
        return False, f"`{command}` is not an allowed read-only inspection command.", sudo
    if command == "systemctl" and any(a in {"start", "stop", "restart", "reload", "try-restart", "isolate", "kill",
                                                    "enable", "disable", "reenable", "preset", "mask", "unmask",
                                                    "edit", "set-property", "daemon-reload", "reset-failed", "poweroff",
                                                    "reboot", "halt", "suspend", "hibernate", "hybrid-sleep"} for a in args):
        return False, "Mutating systemctl actions are not allowed in Command Insight Mode.", sudo
    if command == "ip" and any(a in {"set", "add", "del", "replace", "flush"} for a in args):
        return False, "Mutating ip actions are not allowed in Command Insight Mode.", sudo
    if command == "sysctl" and any(a == "-w" or a.startswith("--write") for a in args):
        return False, "Writing sysctl values is not allowed in Command Insight Mode.", sudo
    if command == "smartctl" and any(a in {"-t", "--abort", "-s", "--saveauto"} or a.startswith("--test") for a in args):
        return False, "Changing SMART tests or settings is not allowed in Command Insight Mode.", sudo
    return True, "", sudo


def permission_failure(text: str) -> bool:
    value = text.lower()
    return any(item in value for item in ("permission denied", "operation not permitted", "requires root", "kernel buffer", "access denied"))


def permission_purpose(argv: list[str]) -> str:
    return {
        "dmesg": "Read restricted kernel messages.",
        "journalctl": "Read restricted system journal entries.",
        "smartctl": "Read restricted device health information.",
    }.get(command_family(argv), "Retry the requested restricted read-only inspection.")


def execute(argv: list[str], timeout: int = 12) -> dict:
    """No shell; capture remains in memory and is bounded before model use."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        output = plain_terminal_text(redact((result.stdout or "") + (result.stderr or "")))
        family = command_family(argv)
        analysis_output = (log_evidence(output, diagnostic_signals(output), MAX_BYTES)
                           if family in _LOG_COMMANDS else tabular_evidence(family, output, MAX_BYTES))
        return {"exit_code": result.returncode, "output": truncate_output(output, MAX_BYTES),
                "analysis_output": analysis_output, "truncated": len(output.encode()) > MAX_BYTES}
    except FileNotFoundError:
        return {"exit_code": 127, "output": f"{argv[0]} was not found.", "truncated": False}
    except subprocess.TimeoutExpired as exc:
        output = plain_terminal_text(redact((exc.stdout or "") + (exc.stderr or "")))
        return {"exit_code": None, "output": truncate_output(output, MAX_BYTES), "truncated": True, "timeout": True}


def compact_output(text: str, limit: int = 10000) -> str:
    lines, prior, count = [], None, 0
    for line in text.splitlines():
        if line == prior: count += 1; continue
        if count > 1: lines.append(f"[previous line repeated {count} times]")
        lines.append(line); prior, count = line, 1
        if sum(map(len, lines)) > limit: break
    if count > 1: lines.append(f"[previous line repeated {count} times]")
    return "\n".join(lines)[:limit]


_LOG_COMMANDS = {"dmesg", "journalctl"}
_SIGNAL_PATTERNS = (
    ("oom", "warning", re.compile(r"\b(?:out of memory|oom-kill(?:er)?|killed process)\b", re.I)),
    ("filesystem_error", "warning", re.compile(r"\b(?:ext[234]|xfs|btrfs).*\b(?:error|corrupt|abort)\b|\bi/o error\b", re.I)),
    ("gpu_reset", "possible", re.compile(r"\b(?:amdgpu|gpu)\b.*\b(?:reg_wait|timeout|hang|reset)\b", re.I)),
    ("firmware_failure", "warning", re.compile(r"\bfirmware\b.*\b(?:failed|failure|error)\b", re.I)),
    ("hardware_error", "warning", re.compile(r"\b(?:mce|hardware error|uncorrected|watchdog)\b", re.I)),
    ("segfault", "warning", re.compile(r"\bsegfault\b", re.I)),
    ("network_link", "possible", re.compile(r"\b(?:link is down|link is up|carrier lost|nic reset)\b", re.I)),
    ("service_failure", "warning", re.compile(r"\bfailed (?:to start|with result)|\bfailed_units?\b|\.service\b.*\bfailed\b", re.I)),
    ("apparmor_denial", "informational", re.compile(r"\bapparmor=.?denied|\bapparmor.*\bdenied\b", re.I)),
    ("kernel_error", "possible", re.compile(r"(?:<[0-3]>|\b(?:error|failed|failure|timeout|reset)\b)", re.I)),
)


def command_family(argv: list[str]) -> str:
    if argv and argv[0] == "sudo" and len(argv) > 1:
        return argv[1]
    return argv[0] if argv else "unknown"


def _signature(line: str) -> str:
    value = re.sub(r"^\s*(?:\[[^]]+\]|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+\S+)\s*", "", line)
    return re.sub(r"\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?)\b", "#", value, flags=re.I).strip()


def diagnostic_signals(text: str) -> list[dict]:
    grouped: dict[tuple[str, str], dict] = {}
    for index, line in enumerate(text.splitlines()):
        for kind, severity, pattern in _SIGNAL_PATTERNS:
            if not pattern.search(line):
                continue
            signature = _signature(line)
            key = (kind, signature)
            item = grouped.setdefault(key, {"kind": kind, "classification": severity,
                                            "count": 0, "line": line.strip(), "line_indexes": []})
            item["count"] += 1
            item["line_indexes"].append(index)
            break
    signals = []
    for item in grouped.values():
        if item["kind"] in ("gpu_reset", "network_link") and item["count"] >= 2:
            item["classification"] = "warning"
        signals.append(item)
    return signals


def log_evidence(text: str, signals: list[dict], limit: int = 10000) -> str:
    """Keep anomaly context and useful tail data without beginning-of-log bias."""
    lines = text.splitlines()
    anomaly_indexes = [index for signal in signals for index in signal["line_indexes"]]
    indexes = {nearby for index in anomaly_indexes for nearby in range(max(0, index - 1), min(len(lines), index + 2))}
    indexes.update(range(max(0, len(lines) - 40), len(lines)))
    counts, selected = collections.Counter(), []
    for index in sorted(indexes):
        line = lines[index]
        signature = _signature(line)
        counts[signature] += 1
        if counts[signature] == 1:
            selected.append(line)
    signal_signatures = {_signature(signal["line"]) for signal in signals}
    for signature, count in counts.items():
        if count > 1 and signature in signal_signatures:
            selected.append(f"[event repeated {count} times] {signature}")
    return compact_output("\n".join(selected), limit)


def dmesg_evidence(text: str, limit: int = 10000) -> str:
    return log_evidence(text, diagnostic_signals(text), limit)


def prepare_evidence(argv: list[str], result: dict, limit: int = 10000) -> dict:
    """Create bounded command-aware, structured evidence for local analysis."""
    family = command_family(argv)
    output = str(result.get("analysis_output", result.get("output", "")))
    signals = diagnostic_signals(output)
    if family in _LOG_COMMANDS:
        reduced = log_evidence(output, signals, limit)
    else:
        reduced = tabular_evidence(family, output, limit)
    truncated = bool(result.get("truncated"))
    return {
        "command_family": family,
        "argv": argv,
        "exit_code": result.get("exit_code"),
        "timed_out": bool(result.get("timeout")),
        "output_truncated": truncated,
        "truncation_reason": "SysAI bounded capture limit" if truncated else None,
        "signals": [{key: value for key, value in signal.items() if key != "line_indexes"} for signal in signals],
        "output": reduced,
    }


def meaningful_anomaly(evidence: dict) -> bool:
    return any(signal.get("classification") in ("possible", "warning", "probable", "confirmed")
               for signal in evidence.get("signals", []))


def tabular_evidence(family: str, text: str, limit: int = 10000) -> str:
    """Bound common status families without silently keeping only their head."""
    lines = text.splitlines()
    if not lines:
        return ""
    if family == "ps" and len(lines) > 2:
        header, rows = lines[0], lines[1:]
        def usage(row: str) -> float:
            fields = row.split()
            try:
                return float(fields[2]) + float(fields[3])
            except (IndexError, ValueError):
                return 0.0
        lines = [header, *sorted(rows, key=usage, reverse=True)[:40]]
    elif family == "df":
        high = [line for line in lines[1:] if any(int(value) >= 85 for value in re.findall(r"(\d+)%", line))]
        lines = [lines[0], *high, *lines[-30:]]
    elif family == "systemctl":
        relevant = [line for line in lines if re.search(r"\b(?:failed|degraded|activating)\b", line, re.I)]
        lines = [*lines[:5], *relevant, *lines[-20:]]
    elif family in {"ip", "ss", "lspci", "lsusb", "sensors", "amd-smi", "rocm-smi", "free"} and len(lines) > 80:
        lines = [*lines[:30], "[middle rows omitted by SysAI evidence reduction]", *lines[-40:]]
    return compact_output("\n".join(dict.fromkeys(lines)), limit)


def safe_research_query(evidence: dict, facts: dict | None = None) -> str | None:
    """Build a generic query from normalized facts only; never include raw output."""
    signals = evidence.get("signals", [])
    kinds = sorted({signal.get("kind", "") for signal in signals if signal.get("kind")})
    if not kinds:
        return None
    safe = ["Ubuntu", evidence.get("command_family", "Linux"), *kinds]
    if facts:
        safe.extend(str(facts[key]) for key in ("kernel", "gpu") if facts.get(key))
    return " ".join(safe)[:500]
