"""`sysai changes`: what changed on this machine before behaviour changed.

Timestamps are parsed deterministically. Correlation is reported as
correlation: "this changed shortly before the first observed failure", never
as causation, unless the evidence itself is direct.
"""
from __future__ import annotations

import datetime as dt
import os
import re
from pathlib import Path

from . import collect
from .domains import dpkg_history
from .evidence import (CONFIRMED, INFO, INFORMATIONAL, POSSIBLE, WARNING, build,
                       finding, unavailable)

DEFAULT_SINCE = "last-boot"
_RELATIVE = {"today": 0, "yesterday": 1, "last-week": 7, "week": 7, "last-month": 30, "month": 30}
_APT_HISTORY = re.compile(r"^(Start-Date|Commandline|Install|Upgrade|Remove|Purge|End-Date):\s*(.*)$")
_APT_TIME = re.compile(r"^(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)$")


class ChangesError(ValueError):
    pass


def boot_time() -> dt.datetime | None:
    seconds = collect.uptime_seconds()
    if seconds is None:
        return None
    return dt.datetime.now().astimezone() - dt.timedelta(seconds=seconds)


def resolve_since(value: str | None) -> tuple[dt.datetime, str]:
    """Turn a --since value into an absolute local timestamp."""
    value = (value or DEFAULT_SINCE).strip().lower()
    now = dt.datetime.now().astimezone()
    if value in ("last-boot", "boot", "this-boot"):
        started = boot_time()
        if started is None:
            raise ChangesError("The current boot time could not be determined.")
        return started, "last-boot"
    if value in _RELATIVE:
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight - dt.timedelta(days=_RELATIVE[value]), value
    match = re.fullmatch(r"(\d+)\s*(h|hour|hours|d|day|days)", value)
    if match:
        amount = int(match.group(1))
        unit = dt.timedelta(hours=amount) if match.group(2).startswith("h") else dt.timedelta(days=amount)
        return now - unit, value
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            parsed = dt.datetime.strptime(value, pattern)
        except ValueError:
            continue
        return parsed.astimezone(), value
    raise ChangesError(
        f"Unrecognized --since value: {value!r}. Use last-boot, today, yesterday, "
        "last-week, a duration such as 48h or 7d, or a date such as 2026-08-20.")


def _parse_local(timestamp: str) -> dt.datetime | None:
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d  %H:%M:%S"):
        try:
            return dt.datetime.strptime(timestamp, pattern).astimezone()
        except ValueError:
            continue
    return None


def apt_history(since: dt.datetime, limit: int = 120) -> tuple[list[dict], bool]:
    """Parse /var/log/apt/history.log into structured, timestamped operations."""
    entries: list[dict] = []
    available = False
    for name in ("/var/log/apt/history.log.1", "/var/log/apt/history.log"):
        text = collect.read_tail(name, 1_000_000)
        if text is None:
            continue
        available = True
        current: dict = {}
        for line in text.splitlines():
            match = _APT_HISTORY.match(line.strip())
            if not match:
                continue
            field, value = match.groups()
            if field == "Start-Date":
                current = {"timestamp": None, "commandline": None, "operations": {}}
                time_match = _APT_TIME.match(value.strip())
                if time_match:
                    current["timestamp"] = _parse_local(
                        f"{time_match.group(1)} {time_match.group(2)}")
            elif field == "Commandline":
                current["commandline"] = value.strip()[:200]
            elif field in ("Install", "Upgrade", "Remove", "Purge"):
                packages = [item.split(":")[0].strip()
                            for item in re.split(r"\),\s*", value) if item.strip()]
                current.setdefault("operations", {})[field.lower()] = [
                    re.sub(r"\s*\(.*$", "", package) for package in packages][:40]
            elif field == "End-Date" and current.get("timestamp"):
                if current["timestamp"] >= since:
                    entries.append({
                        "timestamp": current["timestamp"].isoformat(timespec="seconds"),
                        "commandline": current.get("commandline"),
                        "operations": current.get("operations", {}),
                    })
                current = {}
    entries.sort(key=lambda item: item["timestamp"])
    return entries[-limit:], available


def package_changes(since: dt.datetime, limit: int = 120) -> list[dict]:
    entries = []
    for item in dpkg_history(limit=1000):
        moment = _parse_local(item["timestamp"])
        if moment is None or moment < since:
            continue
        entries.append({**item, "timestamp": moment.isoformat(timespec="seconds")})
    return entries[-limit:]


def kernel_changes(entries: list[dict]) -> list[dict]:
    return [item for item in entries
            if item["package"].startswith(("linux-image", "linux-headers", "linux-modules",
                                           "linux-firmware", "amdgpu-dkms", "nvidia-"))]


def reboot_history(since: dt.datetime) -> tuple[list[dict], bool]:
    result = collect.run(("last", "-x", "-F", "reboot", "shutdown"), timeout=8)
    if result.get("status") != "ok":
        return [], False
    events = []
    for line in collect.lines(result):
        if not line.startswith(("reboot", "shutdown")):
            continue
        events.append({"kind": line.split()[0], "entry": line.strip()[:200]})
    return events[:20], True


def _first_failure_time(since: dt.datetime) -> tuple[str | None, list[str]]:
    """Earliest error-priority journal entry in the window, if the journal allows it."""
    result = collect.journal("--since", since.strftime("%Y-%m-%d %H:%M:%S"),
                             "-p", "err", "-o", "short-iso", "-n", "200", timeout=8)
    entries = collect.lines(result)
    if not entries:
        return None, []
    first = entries[0].split(None, 1)[0]
    return (first if re.match(r"^\d{4}-\d\d-\d\d", first) else None), entries[:8]


def collect_changes(since_value: str | None = None, web: bool = False) -> dict:
    since, label = resolve_since(since_value)
    missing: list[dict] = []
    apt_entries, apt_available = apt_history(since)
    if not apt_available:
        missing.append(unavailable("apt history", "/var/log/apt/history.log is not readable", "changes"))
    dpkg_entries = package_changes(since)
    if not dpkg_entries and not Path("/var/log/dpkg.log").exists():
        missing.append(unavailable("dpkg log", "/var/log/dpkg.log is not readable", "changes"))
    reboots, reboot_available = reboot_history(since)
    if not reboot_available:
        missing.append(unavailable("reboot history", "the `last` utility is not available", "changes"))
    first_failure, failure_sample = _first_failure_time(since)
    if not failure_sample:
        missing.append(unavailable("journal errors", "no error-priority journal entries were readable "
                                                     "for this window", "changes"))
    kernel = kernel_changes(dpkg_entries)
    services = collect.run(("systemctl", "--failed", "--no-pager", "--plain", "--no-legend"), timeout=6)
    failed_units = [line.split()[0] for line in collect.lines(services) if line.split()]
    # Configuration files whose modification time falls inside the window. Only
    # /etc is examined, only names and times are recorded, never contents.
    configuration = []
    try:
        for path in sorted(Path("/etc").iterdir()):
            try:
                modified = dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()
            except OSError:
                continue
            if modified >= since:
                configuration.append({"path": str(path),
                                      "modified": modified.isoformat(timespec="seconds")})
    except OSError:
        missing.append(unavailable("/etc modification times", "/etc could not be listed", "changes"))

    sections = {
        "window": {"since": since.isoformat(timespec="seconds"), "since_value": label,
                   "until": dt.datetime.now().astimezone().isoformat(timespec="seconds")},
        "apt": {"operation_count": len(apt_entries), "operations": apt_entries[-25:]},
        "packages": {"change_count": len(dpkg_entries), "changes": dpkg_entries[-40:]},
        "kernel": {"change_count": len(kernel), "changes": kernel},
        "reboots": {"count": len(reboots), "events": reboots},
        "services": {"failed_count": len(failed_units), "failed_units": failed_units},
        "failures": {"first_error_timestamp": first_failure, "sample": failure_sample},
        "configuration": {"changed_count": len(configuration), "changed": configuration[:25]},
    }
    return build(command="changes", scope="changes", sections=sections,
                 findings=analyze_changes(sections), unavailable_checks=missing,
                 arguments={"since": label}, web=web)


def analyze_changes(sections: dict) -> list[dict]:
    findings = []
    kernel = sections.get("kernel", {})
    if kernel.get("change_count"):
        findings.append(finding(
            "changes.kernel_updated", "changes", INFO, INFORMATIONAL,
            title=f"{kernel['change_count']} kernel or driver package change(s) in this window",
            evidence={"changes": kernel.get("changes", [])[:8]}, count=kernel["change_count"],
            confidence="high",
            probable_cause="A kernel or driver package was installed, upgraded, or removed.",
            unverified="Whether the change is related to any observed behaviour."))
    packages = sections.get("packages", {})
    if packages.get("change_count"):
        findings.append(finding(
            "changes.packages_modified", "changes", INFO, INFORMATIONAL,
            title=f"{packages['change_count']} package change(s) in this window",
            evidence={"sample": [item["package"] for item in packages.get("changes", [])[:12]]},
            count=packages["change_count"], confidence="high"))
    first_failure = sections.get("failures", {}).get("first_error_timestamp")
    if first_failure and packages.get("change_count"):
        preceding = [item for item in packages.get("changes", [])
                     if item["timestamp"] <= first_failure]
        if preceding:
            findings.append(finding(
                "changes.preceded_first_error", "changes", WARNING, POSSIBLE,
                title=f"{len(preceding)} package change(s) occurred before the first "
                      "error recorded in this window",
                evidence={"first_error_timestamp": first_failure,
                          "packages": [item["package"] for item in preceding[-10:]]},
                count=len(preceding), confidence="low",
                probable_cause="Temporal correlation only. Ordering in time is not evidence of cause.",
                unverified="Whether any of these changes is actually related to the error.",
                suggested_next_diagnostic="journal.boot_errors"))
    if sections.get("services", {}).get("failed_count"):
        findings.append(finding(
            "changes.services_failing", "changes", WARNING, CONFIRMED,
            title=f"{sections['services']['failed_count']} service(s) are currently failed",
            evidence={"units": sections["services"].get("failed_units", [])[:10]},
            count=sections["services"]["failed_count"], confidence="high",
            suggested_next_diagnostic="services.list_failed"))
    return findings


def render_changes(document: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, reset = ("\033[1m", "\033[0m") if color else ("", "")
    sections = document.get("sections", {})
    window = sections.get("window", {})
    lines = [f"{bold}SysAI Changes{reset}", "",
             f"{bold}Window{reset}",
             f"  {window.get('since_value', 'unknown')}: {window.get('since', '?')}"
             f" -> {window.get('until', 'now')}", ""]
    for key, heading in (("kernel", "Kernel and driver packages"),
                         ("packages", "Package changes"),
                         ("apt", "APT operations"),
                         ("reboots", "Reboot events"),
                         ("configuration", "/etc files modified")):
        block = sections.get(key, {})
        count = block.get("change_count", block.get("operation_count", block.get(
            "count", block.get("changed_count", 0))))
        lines.append(f"{bold}{heading}{reset}")
        lines.append(f"  {count}")
        if key == "kernel":
            for item in block.get("changes", [])[:6]:
                lines.append(f"    {item['timestamp']}  {item['action']} {item['package']}"
                             f" {item.get('version') or ''}".rstrip())
        elif key == "packages":
            for item in block.get("changes", [])[-8:]:
                lines.append(f"    {item['timestamp']}  {item['action']} {item['package']}"
                             f" {item.get('version') or ''}".rstrip())
        elif key == "configuration":
            for item in block.get("changed", [])[:6]:
                lines.append(f"    {item['modified']}  {item['path']}")
        lines.append("")
    failures = sections.get("failures", {})
    lines.append(f"{bold}First error in window{reset}")
    lines.append(f"  {failures.get('first_error_timestamp') or 'none recorded'}")
    lines.append("")
    lines.append("Ordering in time is correlation, not cause.")
    return "\n".join(lines) + "\n"
