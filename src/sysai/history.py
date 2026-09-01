"""History intelligence: relevance-filtered, privacy-sanitized correlation of
recent Bash activity with current diagnostic evidence.

Raw shell history never reaches the model. Every entry is normalized,
redacted, sanitized through the canonical privacy layer, and scored
deterministically against the current diagnostic domain; only a small
bounded top-N slice is ever used as context. History is data only — it is
never executed or interpreted as shell syntax, here or anywhere downstream.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import shlex
from pathlib import Path

from .privacy import SHARED, sanitize_text
from .redact import redact

SOURCE_SESSION = "session"
SOURCE_BASH_HISTORY = "bash_history"

MODE_OFF = "off"
MODE_RELEVANT = "relevant"
MODE_RECENT = "recent"
MODE_ALL = "all"
MODES = (MODE_OFF, MODE_RELEVANT, MODE_RECENT, MODE_ALL)

DEFAULT_MAX_ENTRIES = 300
DEFAULT_LOOKBACK_HOURS = 48
DEFAULT_MAX_CONTEXT_ENTRIES = 20
MIN_RELEVANCE = 0.35

# Bounded read: never read more than this many bytes from the tail of a
# history file, however large it is on disk.
_MAX_READ_BYTES = 2_000_000

# Domain vocabulary. Matched against whole shell tokens (or their basename),
# never as a substring, so "apt" cannot match inside "laptop".
DOMAIN_TERMS: dict[str, tuple[str, ...]] = {
    "gpu": ("amdgpu", "amd", "rocm", "rocminfo", "amd-smi", "rocm-smi", "mesa", "drm",
            "modprobe", "radeon", "gpu", "display", "xrandr", "wayland", "nvidia",
            "nvidia-smi", "xorg", "glxinfo", "vulkaninfo", "xrandr"),
    "network": ("ip", "nmcli", "resolvectl", "ethtool", "networkctl", "networkmanager",
                "route", "dns", "ping", "traceroute", "dig", "nslookup", "iwconfig",
                "wpa_supplicant", "ufw", "iptables", "nft", "curl", "wget"),
    "disk": ("mount", "umount", "fsck", "smartctl", "lsblk", "fdisk", "parted", "fstrim",
             "mkfs", "ext4", "nvme", "filesystem", "df", "du", "gparted", "mdadm"),
    "memory": ("swap", "swapon", "swapoff", "sysctl", "ulimit", "oom", "memory", "zram",
               "free", "vmstat", "earlyoom"),
    "packages": ("apt", "apt-get", "nala", "dpkg", "snap", "flatpak", "aptitude",
                 "add-apt-repository", "dpkg-reconfigure"),
    "boot": ("grub", "kernel", "update-grub", "initramfs", "boot", "systemd",
             "update-initramfs", "grub-mkconfig", "reboot", "shutdown"),
    "thermal": ("sensors", "fan", "thermal", "power", "cpu", "amdgpu", "tlp",
                "cpupower", "throttled"),
    "services": ("systemctl", "service", "journalctl", "systemd-analyze"),
}

# Commands that touch configuration or drivers, regardless of domain.
_MODIFYING_COMMANDS = frozenset({
    "modprobe", "rmmod", "insmod", "systemctl", "service", "apt", "apt-get", "nala",
    "dpkg", "snap", "flatpak", "update-grub", "grub-mkconfig", "update-initramfs",
    "mount", "umount", "fsck", "mkfs", "parted", "fdisk", "nmcli", "sysctl", "swapon",
    "swapoff", "iptables", "nft", "ufw",
})

_WRAPPERS = frozenset({"sudo", "doas", "env", "command", "time", "nohup"})
_SEMANTIC_ARGUMENT_COMMANDS = frozenset({
    "apt", "apt-get", "nala", "dpkg", "snap", "flatpak", "modprobe", "rmmod", "insmod",
    "systemctl", "service", "nmcli", "mount", "umount", "fsck", "mkfs", "parted", "fdisk",
    "swapon", "swapoff", "iptables", "nft", "ufw", "reboot", "shutdown",
})

_BASH_HISTORY_TIMESTAMP = re.compile(r"^#(\d+)$")

# `mysql -pSecret...`: a password concatenated onto a short flag with no
# separator, so the shared `redact()` (which looks for `key=value` or a
# space-separated flag) does not catch it. Scoped to known DB clients so an
# unrelated `-p` flag (e.g. `grep -pattern`) is never touched.
_DB_CLIENTS = {"mysql", "mysqldump", "mariadb", "psql", "pg_dump", "pg_restore",
               "mongo", "mongosh", "mongodump", "mongorestore", "redis-cli"}
_INLINE_DB_PASSWORD = re.compile(r"(?<!\w)-p(\S{3,})")


def _redact_inline_flags(command: str) -> str:
    try:
        parts = shlex.split(command, comments=False)
    except ValueError:
        return command
    if not parts:
        return command
    program = Path(parts[0]).name.lower()
    if program not in _DB_CLIENTS:
        return command
    return _INLINE_DB_PASSWORD.sub("-p<redacted>", command)


def _now() -> dt.datetime:
    return dt.datetime.now().astimezone()


# --------------------------------------------------------------------- reading

def resolve_histfile() -> Path | None:
    """The interactive shell's own history file, never discovered by running a command.

    SysAI's own process inherits the invoking shell's environment, including
    an exported `HISTFILE`, when run from an interactive terminal. Falling
    back to `~/.bash_history` is conservative and matches Bash's own default.
    """
    configured = os.environ.get("HISTFILE")
    if configured:
        path = Path(configured).expanduser()
        if path.exists():
            return path
    default = Path.home() / ".bash_history"
    return default if default.exists() else None


def _read_bounded_tail(path: Path, limit: int = _MAX_READ_BYTES) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            data = handle.read(limit)
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    # Discard a partial first line when the file was longer than the window.
    return text.partition("\n")[2] if size > limit else text


def parse_bash_history(text: str) -> list[dict]:
    """Parse Bash history text into normalized, unsanitized entries.

    Supports both the `HISTTIMEFORMAT`-style `#<epoch>` marker line preceding
    a command, and ordinary timestamp-less history. Never executes anything;
    this is pure text parsing.
    """
    entries: list[dict] = []
    pending_epoch: int | None = None
    sequence = 0
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line:
            continue
        match = _BASH_HISTORY_TIMESTAMP.match(line.strip())
        if match:
            try:
                pending_epoch = int(match.group(1))
            except ValueError:
                pending_epoch = None
            continue
        # Bash continuation lines (a multiline command written back with
        # literal embedded newlines) are folded onto the previous entry.
        if line.startswith((" ", "\t")) and entries and pending_epoch is None:
            entries[-1]["command"] = entries[-1]["command"] + "\n" + line.strip()
            continue
        timestamp = None
        if pending_epoch is not None:
            try:
                timestamp = dt.datetime.fromtimestamp(pending_epoch).astimezone().isoformat(timespec="seconds")
            except (OSError, OverflowError, ValueError):
                timestamp = None
        sequence += 1
        entries.append({
            "timestamp": timestamp,
            "command": line.strip(),
            "cwd": None,
            "exit_status": None,
            "source": SOURCE_BASH_HISTORY,
            "sequence": sequence,
            "redacted": False,
        })
        pending_epoch = None
    return entries


def read_bash_history(
    path: Path | None = None,
    *,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> list[dict]:
    """Bounded, sanitized read of the user's Bash history file. Never executed."""
    path = path or resolve_histfile()
    if path is None:
        return []
    text = _read_bounded_tail(path)
    if not text:
        return []
    entries = parse_bash_history(text)[-max_entries:]
    cutoff = _now() - dt.timedelta(hours=lookback_hours)
    filtered = []
    for entry in entries:
        if entry["timestamp"] is not None:
            try:
                moment = dt.datetime.fromisoformat(entry["timestamp"])
            except ValueError:
                moment = None
            if moment is not None and moment < cutoff:
                continue
        filtered.append(_sanitize_entry(entry))
    return filtered[-max_entries:]


def normalize_session_records(records: list[dict]) -> list[dict]:
    """Adapt `Session.records` (already redacted at LOCAL level) into history entries."""
    entries = []
    for sequence, record in enumerate(records, start=1):
        entries.append(_sanitize_entry({
            "timestamp": record.get("timestamp"),
            "command": record.get("command", ""),
            "cwd": record.get("cwd"),
            "exit_status": record.get("exit_code"),
            "source": SOURCE_SESSION,
            "sequence": sequence,
            "redacted": False,
        }))
    return entries


def _sanitize_entry(entry: dict) -> dict:
    """Secret redaction, then SHARED-level privacy sanitization. History is data only."""
    command = _redact_inline_flags(entry.get("command") or "")
    command = sanitize_text(redact(command), SHARED)
    cwd = entry.get("cwd")
    if cwd:
        cwd = sanitize_text(redact(cwd), SHARED)
    return {**entry, "command": command, "cwd": cwd, "redacted": True}


# ------------------------------------------------------------------- relevance

def _tokens(command: str) -> list[str]:
    try:
        parts = shlex.split(command, comments=False)
    except ValueError:
        parts = command.split()
    tokens = []
    for part in parts:
        if part == "sudo":
            continue
        name = Path(part).name if "/" in part else part
        tokens.append(name.lower())
    return tokens


def _command_parts(command: str) -> tuple[str, list[str]]:
    """Find the real executable beneath harmless shell wrappers, never executing text."""
    try:
        parts = shlex.split(command, comments=False)
    except ValueError:
        return "", []
    index = 0
    while index < len(parts):
        token = Path(parts[index]).name.lower()
        if token in _WRAPPERS:
            index += 1
            # `sudo -n`, `env NAME=value`, and `time -p` are wrappers too.
            while index < len(parts) and (parts[index].startswith("-") or "=" in parts[index]):
                index += 1
            continue
        if "=" in parts[index] and not parts[index].startswith("/"):
            index += 1
            continue
        return token, [Path(value).name.lower() if "/" in value else value.lower() for value in parts[index + 1:]]
    return "", []


def _semantic_tokens(command: str) -> list[str]:
    program, arguments = _command_parts(command)
    if not program:
        return []
    # Path/string arguments are intentionally ignored for arbitrary commands:
    # `grep gpu README` and `cd ~/gpu-demo` are not GPU diagnostic events.
    return [program, *arguments] if program in _SEMANTIC_ARGUMENT_COMMANDS else [program]


def classify_event(entry: dict) -> str:
    """Small, explainable command-semantic taxonomy for the history timeline."""
    program, arguments = _command_parts(entry.get("command", ""))
    if entry.get("exit_status") not in (None, 0):
        return "failure"
    if program in ("reboot", "shutdown"):
        return "reboot"
    if program in ("apt", "apt-get", "nala"):
        action = arguments[0] if arguments else ""
        if action in ("upgrade", "full-upgrade", "dist-upgrade", "install", "remove", "purge", "autoremove"):
            return "package_change"
        if action in ("update", "search", "show", "policy", "list"):
            return "inspection"
    if program in ("systemctl", "service"):
        action = arguments[0] if arguments else ""
        return "inspection" if action in ("status", "is-active", "show", "list-units") else "service_change"
    if program in ("modprobe", "rmmod", "insmod"):
        return "driver_change"
    if program in ("mount", "umount", "fsck", "mkfs", "parted", "fdisk"):
        return "filesystem_change"
    if program in ("nmcli", "ip", "resolvectl", "iptables", "nft", "ufw"):
        return "network_change"
    return "inspection" if program in COMMAND_FAMILY_DOMAIN else "unrelated"


def event_fingerprint(entry: dict) -> str:
    program, arguments = _command_parts(entry.get("command", ""))
    material = "|".join((classify_event(entry), program, " ".join(arguments[:3])))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


# Command Insight's approved read-only inspection commands, mapped to the
# diagnostic domain whose history/memory context is relevant to them.
COMMAND_FAMILY_DOMAIN: dict[str, str] = {
    "dmesg": "boot", "journalctl": "services", "smartctl": "disk", "sensors": "thermal",
    "amd-smi": "gpu", "rocm-smi": "gpu", "rocminfo": "gpu", "clinfo": "gpu", "lspci": "gpu",
    "lsusb": "boot", "lsblk": "disk", "blkid": "disk", "findmnt": "disk", "df": "disk",
    "du": "disk", "free": "memory", "ps": "services", "pgrep": "services", "ip": "network",
    "ss": "network", "resolvectl": "network", "timedatectl": "boot", "modinfo": "boot",
    "lsmod": "boot", "sysctl": "memory", "systemctl": "services", "mount": "disk",
    "uname": "boot",
}

# Plain-language words that mark a question as plausibly diagnostic, even
# when it names no specific domain vocabulary ("why did it crash yesterday").
_GENERIC_DIAGNOSTIC_WORDS = frozenset({
    "fail", "failed", "failing", "fails", "error", "errors", "crash", "crashed",
    "crashes", "broken", "break", "slow", "slower", "issue", "issues", "problem",
    "problems", "stopped", "stopping", "changed", "change", "recently", "yesterday",
    "since", "again", "worse", "unstable", "freeze", "froze", "frozen", "hang",
    "hung", "hanging", "timeout", "timed", "unresponsive", "died", "dying",
})


def command_domain(command: str) -> str | None:
    """The best-matching diagnostic domain for a shell command, or None.

    Used to decide whether a failed command's automatic analysis, or a
    Command Insight request, should consult history/memory at all — a
    command that matches no domain vocabulary gets neither, rather than
    guessing.
    """
    tokens = set(_semantic_tokens(command))
    if not tokens:
        return None
    best, best_count = None, 0
    for domain, terms in DOMAIN_TERMS.items():
        count = len(tokens & set(terms))
        if count > best_count:
            best, best_count = domain, count
    return best


def question_domain(question: str) -> str | None:
    """The best-matching diagnostic domain for a natural-language question, or None.

    None means the question does not look diagnostic ("what is a symlink"),
    and callers should skip history/memory retrieval entirely rather than
    querying for a trivial question.
    """
    words = {match.group(0).lower() for match in re.finditer(r"[A-Za-z][A-Za-z0-9_-]*", question)}
    if not words:
        return None
    best, best_count = None, 0
    for domain, terms in DOMAIN_TERMS.items():
        count = len(words & set(terms))
        if count > best_count:
            best, best_count = domain, count
    if best is not None:
        return best
    if words & _GENERIC_DIAGNOSTIC_WORDS:
        return "system"
    return None


def _all_terms() -> set[str]:
    terms: set[str] = set()
    for values in DOMAIN_TERMS.values():
        terms.update(values)
    return terms


def _domain_hits(tokens: list[str], domain: str) -> list[str]:
    # A domain outside the known vocabulary (e.g. "system", "changes",
    # "watch") matches any domain's terms, so "relevant" still means
    # something for a generic request instead of matching nothing.
    terms = DOMAIN_TERMS.get(domain)
    terms = set(terms) if terms else _all_terms()
    return sorted({token for token in tokens if token in terms})


def _is_privileged(command: str) -> bool:
    stripped = command.strip()
    return stripped.startswith("sudo ") or stripped.startswith("doas ") or stripped == "sudo"


def _is_modifying(tokens: list[str]) -> bool:
    return any(token in _MODIFYING_COMMANDS for token in tokens)


def _entry_time(entry: dict) -> dt.datetime | None:
    timestamp = entry.get("timestamp")
    if not timestamp:
        return None
    try:
        return dt.datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def score_entry(entry: dict, domain: str, *, anchor_time: dt.datetime | None = None) -> tuple[float, list[str]]:
    """Deterministic relevance score in [0, 1] with human-readable reasons."""
    tokens = _semantic_tokens(entry.get("command", ""))
    reasons: list[str] = []
    score = 0.0

    hits = _domain_hits(tokens, domain)
    if hits:
        score += 0.45
        reasons.append(f"{domain}-related command ({', '.join(hits[:3])})")

    if _is_modifying(tokens):
        score += 0.15
        reasons.append("modifies configuration, packages, or a driver")

    if entry.get("exit_status") not in (None, 0):
        score += 0.1
        reasons.append(f"exited non-zero ({entry['exit_status']})")

    if _is_privileged(entry.get("command", "")):
        score += 0.05
        reasons.append("ran with elevated privilege")

    moment = _entry_time(entry)
    anchor = anchor_time or _now()
    if moment is not None:
        delta_minutes = abs((anchor - moment).total_seconds()) / 60
        if delta_minutes <= 180:
            proximity = max(0.0, 0.25 * (1 - delta_minutes / 180))
            if proximity > 0.01:
                score += proximity
                minutes = round(delta_minutes)
                if minutes < 60:
                    reasons.append(f"{minutes}m before the current check" if moment <= anchor
                                   else f"{minutes}m after the current check")
                else:
                    hours = round(delta_minutes / 60, 1)
                    reasons.append(f"{hours}h before the current check" if moment <= anchor
                                   else f"{hours}h after the current check")

    return min(score, 1.0), reasons


def relevant_history(
    session_records: list[dict],
    domain: str,
    *,
    mode: str = MODE_RELEVANT,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_context_entries: int = DEFAULT_MAX_CONTEXT_ENTRIES,
    anchor_time: dt.datetime | None = None,
    histfile: Path | None = None,
) -> tuple[list[dict], int]:
    """Return `(scored entries, ignored_count)`, bounded and sorted by relevance/recency.

    Safety limits (`max_entries`, `max_context_entries`) apply in every mode;
    only the ranking and filter threshold differ.
    """
    if mode == MODE_OFF:
        return [], 0
    session_entries = normalize_session_records(session_records)[-max_entries:]
    bash_entries = read_bash_history(histfile, lookback_hours=lookback_hours, max_entries=max_entries)
    combined = (session_entries + bash_entries)[-max_entries:]

    if mode in (MODE_RECENT, MODE_ALL):
        ordered = sorted(combined, key=lambda e: (_entry_time(e) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)),
                          reverse=True)
        kept = ordered[:max_context_entries]
        for entry in kept:
            entry["relevance_score"] = None
            entry["reasons"] = []
        return kept, max(0, len(combined) - len(kept))

    scored = []
    for entry in combined:
        score, reasons = score_entry(entry, domain, anchor_time=anchor_time)
        scored.append({**entry, "relevance_score": round(score, 2), "reasons": reasons})
    scored.sort(key=lambda e: e["relevance_score"], reverse=True)
    kept = [entry for entry in scored if entry["relevance_score"] >= MIN_RELEVANCE][:max_context_entries]
    ignored = len(combined) - len(kept)
    return kept, max(0, ignored)


def correlation_block(entries: list[dict], ignored_count: int) -> dict:
    """The structure attached to evidence documents, clearly labelled as correlation only."""
    return {
        "label": "HISTORICAL / CORRELATION ONLY",
        "note": ("Temporal proximity does not establish causation. Describe these as "
                 "occurring shortly before/after, never as the cause, unless the evidence "
                 "itself states a direct mechanism."),
        "entries": [
            {"timestamp": e.get("timestamp"), "command": e.get("command"),
             "source": e.get("source"), "exit_status": e.get("exit_status"),
             "fingerprint": event_fingerprint(e), "event_class": classify_event(e),
             "relevance_score": e.get("relevance_score"), "reasons": e.get("reasons", [])}
            for e in entries
        ],
        "ignored_count": ignored_count,
    }


# --------------------------------------------------------------------- display

def group_by_domain(entries: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for entry in entries:
        tokens = _semantic_tokens(entry.get("command", ""))
        matched_domain = None
        for domain in DOMAIN_TERMS:
            if _domain_hits(tokens, domain):
                matched_domain = domain
                break
        grouped.setdefault(matched_domain or "other", []).append(entry)
    return grouped


def _event_key(entry: dict) -> tuple[str, int | None]:
    """Stable semantic key for collapsing equivalent terminal events."""
    return (event_fingerprint(entry), entry.get("exit_status"))


def _event_kind(entry: dict) -> str:
    return classify_event(entry).replace("_", " ")


def summarize_events(entries: list[dict]) -> dict[str, list[dict]]:
    """Group relevant history into concise, deterministic event summaries."""
    grouped: dict[str, list[dict]] = {}
    for domain, items in group_by_domain(entries).items():
        summaries: dict[tuple[str, int | None], dict] = {}
        for entry in items:
            key = _event_key(entry)
            summary = summaries.get(key)
            if summary is None:
                summary = {"entry": entry, "count": 0, "latest": entry,
                           "kind": _event_kind(entry)}
                summaries[key] = summary
            summary["count"] += 1
            latest_time = _entry_time(summary["latest"])
            current_time = _entry_time(entry)
            if current_time is not None and (latest_time is None or current_time > latest_time):
                summary["latest"] = entry
                summary["entry"] = entry
        grouped[domain] = sorted(summaries.values(),
                                 key=lambda item: _entry_time(item["latest"]) or
                                 dt.datetime.min.replace(tzinfo=dt.timezone.utc),
                                 reverse=True)
    return grouped


def _age_label(entry: dict, anchor: dt.datetime) -> str:
    moment = _entry_time(entry)
    if moment is None:
        return "unknown time"
    delta = anchor - moment
    minutes = round(delta.total_seconds() / 60)
    if minutes < 0:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = round(minutes / 60, 1)
    if hours < 48:
        return f"{hours}h ago"
    return f"{round(hours / 24, 1)}d ago"


def render_history(entries: list[dict], ignored_count: int, *, all_mode: bool = False) -> str:
    anchor = _now()
    lines = ["SysAI History", ""]
    if not entries:
        lines.append("No recent activity is available." if all_mode else
                     "No relevant activity was found for the current context.")
        lines.append("")
        lines.append(f"Ignored\n  {ignored_count} unrelated command(s)")
        return "\n".join(lines) + "\n"
    if all_mode:
        lines.append("Recent sanitized activity")
        lines.append("─" * 26)
        for entry in entries:
            timestamp = entry.get("timestamp") or "time unavailable"
            status = entry.get("exit_status")
            result = f"exit {status}" if status is not None else "status unavailable"
            lines.append(f"  {_age_label(entry, anchor):>10}  {entry.get('command', '')}")
            lines.append(f"    {timestamp} · {entry.get('source', 'unknown')} · {result}")
        lines.append("")
        return "\n".join(lines) + "\n"
    lines.append("Recent events")
    lines.append("─" * 14)
    grouped = summarize_events(entries)
    for domain, items in grouped.items():
        lines.append("")
        lines.append(domain.upper() if domain != "other" else "Other")
        for item in items:
            entry = item["entry"]
            latest = item["latest"]
            count = f"{item['count']}× " if item["count"] > 1 else ""
            span = _age_label(latest, anchor)
            lines.append(f"  {count}{span:>10}  {item['kind'].upper()}: {entry.get('command', '')}")
            reason = "; ".join(entry.get("reasons", [])[:1])
            if reason:
                lines.append(f"    Relevance: {reason}")
    lines.append("")
    lines.append(f"Ignored\n  {ignored_count} unrelated command(s)")
    return "\n".join(lines) + "\n"
