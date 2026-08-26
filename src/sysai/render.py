"""Terminal rendering for deterministic local facts.

Model prose still goes through ``AnswerRenderer``. Everything in this module
is computed locally, so it is printed directly: compact labelled sections,
never a wall of Markdown.
"""
from __future__ import annotations

import os

from .evidence import CRITICAL, WARNING, overall

OK = "✓"
ATTENTION = "!"
UNKNOWN = "–"

_TITLES = {
    "gpu": "GPU", "memory": "Memory", "disk": "Disk", "network": "Network",
    "boot": "Boot", "services": "Services", "packages": "Packages",
    "thermal": "Thermal", "full_system": "Health",
}


def _color() -> tuple[str, str, str, str]:
    if os.environ.get("NO_COLOR") or not os.isatty(1):
        return "", "", "", ""
    return "\033[1m", "\033[32m", "\033[33m", "\033[0m"


def title(scope: str) -> str:
    return _TITLES.get(scope, scope.replace("_", " ").title())


def _bytes(value) -> str:
    if not isinstance(value, (int, float)) or value <= 0:
        return "unknown"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "unknown"


def _seconds(value) -> str:
    if not isinstance(value, (int, float)):
        return "unknown"
    value = int(value)
    days, remainder = divmod(value, 86_400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _gpu_rows(sections: dict) -> list[tuple[str, str, str]]:
    identity = sections.get("identity", {})
    driver = sections.get("driver", {})
    devices = identity.get("devices", [])
    rows = [(OK if devices else UNKNOWN, "Devices",
             "; ".join(d["description"].split(": ", 1)[-1][:90] for d in devices[:2]) or "none detected")]
    drivers = driver.get("drivers_in_use", [])
    rows.append((OK if drivers else ATTENTION, "Driver", ", ".join(drivers) or "no driver bound"))
    kernel = sections.get("kernel", {})
    count = kernel.get("gpu_event_count") or 0
    # Matches the finding threshold, so the row and the overall verdict agree.
    rows.append((ATTENTION if count >= 3 else OK, "Kernel",
                 f"{count} GPU warning/error events this boot" if count else "no GPU errors this boot"))
    for card in sections.get("drm", {}).get("cards", []):
        temperature = card.get("temperature_celsius")
        if temperature is not None:
            rows.append((ATTENTION if temperature >= 90 else OK, "Temperature", f"{temperature} °C"))
        total, used = card.get("vram_total_bytes"), card.get("vram_used_bytes")
        if total:
            rows.append((OK, "VRAM", f"{_bytes(used or 0)} of {_bytes(total)}"))
    return rows


def _memory_rows(sections: dict) -> list[tuple[str, str, str]]:
    ram, swap = sections.get("ram", {}), sections.get("swap", {})
    used = ram.get("used_percent")
    rows = [(ATTENTION if (used or 0) >= 95 else OK, "RAM",
             f"{_bytes(ram.get('available_bytes'))} available of {_bytes(ram.get('total_bytes'))}"
             + (f" ({used}% used)" if used is not None else ""))]
    rows.append((OK, "Cache", f"{_bytes(ram.get('cached_bytes'))} reclaimable"))
    if swap.get("total_bytes"):
        swap_used = swap.get("used_percent")
        rows.append((ATTENTION if (swap_used or 0) >= 90 else OK, "Swap",
                     f"{swap_used}% of {_bytes(swap.get('total_bytes'))} used"))
    else:
        rows.append((OK, "Swap", "not configured"))
    oom = sections.get("oom", {}).get("event_count") or 0
    rows.append((ATTENTION if oom else OK, "OOM events", str(oom)))
    pressure = sections.get("pressure", {})
    rows.append((OK if pressure.get("available") else UNKNOWN, "Pressure",
                 (pressure.get("raw") or "").splitlines()[0] if pressure.get("available") else "not exposed"))
    return rows


def _disk_rows(sections: dict) -> list[tuple[str, str, str]]:
    rows = []
    ordered = sorted(sections.get("filesystems", []),
                     key=lambda row: row.get("capacity_percent") or 0, reverse=True)
    for row in ordered[:8]:
        capacity = row.get("capacity_percent")
        state = ATTENTION if (capacity or 0) >= 90 or row.get("currently_read_only") else OK
        detail = f"{capacity}% used" if capacity is not None else "usage unknown"
        if row.get("currently_read_only"):
            detail += ", read-only"
        rows.append((state, row.get("mountpoint", "?"), f"{detail} ({row.get('fstype', '?')})"))
    errors = sections.get("errors", {})
    io_errors = errors.get("io_error_count") or 0
    fs_errors = errors.get("filesystem_error_count") or 0
    rows.append((ATTENTION if io_errors else OK, "I/O errors", str(io_errors)))
    rows.append((ATTENTION if fs_errors else OK, "Filesystem errors", str(fs_errors)))
    smart = sections.get("smart", {})
    rows.append((UNKNOWN, "SMART",
                 "available, requires approval" if smart.get("tool_available") else "smartctl not installed"))
    return rows


def _network_rows(sections: dict) -> list[tuple[str, str, str]]:
    interfaces = sections.get("interfaces", {})
    up = interfaces.get("up", [])
    rows = [(OK if up else ATTENTION, "Interfaces up", ", ".join(up) or "none")]
    down = interfaces.get("down", [])
    if down:
        rows.append((UNKNOWN, "Interfaces down", ", ".join(down[:6])))
    routing = sections.get("routing", {})
    rows.append((OK if routing.get("default_route_present") else ATTENTION, "Default route",
                 "present" if routing.get("default_route_present") else "missing"))
    dns = sections.get("dns", {})
    resolved = dns.get("resolution_succeeded")
    rows.append((OK if resolved else (UNKNOWN if resolved is None else ATTENTION), "DNS",
                 "resolving" if resolved else ("not attempted" if resolved is None else "resolution failed")))
    sockets = sections.get("sockets", {})
    rows.append((OK, "Listening sockets",
                 f"{sockets.get('tcp_listening', 0)} tcp, {sockets.get('udp_listening', 0)} udp"))
    events = sections.get("events", {})
    link = events.get("link_event_count") or 0
    rows.append((ATTENTION if link >= 4 else OK, "Link events", str(link)))
    return rows


def _boot_rows(sections: dict) -> list[tuple[str, str, str]]:
    current = sections.get("current_boot", {})
    rows = [(OK, "Uptime", _seconds(current.get("uptime_seconds"))),
            (OK, "Kernel", current.get("kernel") or "unknown")]
    timing = sections.get("timing", {})
    if timing.get("available"):
        seconds = timing.get("seconds", {})
        total = seconds.get("to_graphical_target") or seconds.get("userspace")
        rows.append((ATTENTION if (total or 0) >= 90 else OK, "Boot time",
                     f"{total}s" if total is not None else "reported without a total"))
    else:
        rows.append((UNKNOWN, "Boot time", "systemd-analyze unavailable"))
    units = sections.get("units", {})
    rows.append((ATTENTION if units.get("failed_count") else OK, "Failed units",
                 ", ".join(units.get("failed_units", [])[:5]) or "0"))
    journal = sections.get("journal", {})
    rows.append((ATTENTION if journal.get("critical_count") else OK, "Critical entries",
                 str(journal.get("critical_count", 0))))
    rows.append((OK, "Error entries", str(journal.get("error_count", 0))))
    if sections.get("reboot_required", {}).get("required"):
        rows.append((ATTENTION, "Reboot", "required to finish updates"))
    return rows


def _services_rows(sections: dict) -> list[tuple[str, str, str]]:
    state = sections.get("state", {})
    system_state = state.get("system_state") or "unknown"
    rows = [(ATTENTION if state.get("degraded") else OK, "System state", system_state)]
    failed = sections.get("failed", {})
    rows.append((ATTENTION if failed.get("count") else OK, "Failed units",
                 ", ".join(failed.get("units", [])[:5]) or "0"))
    restarting = sections.get("restarting", {}).get("units", [])
    rows.append((ATTENTION if restarting else OK, "Restart loops",
                 ", ".join(entry["unit"] for entry in restarting[:4]) or "none detected"))
    rows.append((OK, "Recent failures", str(sections.get("recent_failures", {}).get("count", 0))))
    return rows


def _packages_rows(sections: dict) -> list[tuple[str, str, str]]:
    manager = sections.get("manager", {})
    if not manager.get("supported"):
        return [(UNKNOWN, "Package manager", "no supported package manager detected")]
    rows = [(OK, "Manager", f"{manager.get('name')} ({manager.get('installed_count') or '?'} packages)")]
    integrity = sections.get("integrity", {})
    rows.append((ATTENTION if integrity.get("dpkg_interrupted") or not integrity.get("audit_clean", True) else OK,
                 "Integrity",
                 "interrupted operation detected" if integrity.get("dpkg_interrupted")
                 else ("dpkg audit reported issues" if not integrity.get("audit_clean", True) else "clean")))
    upgrades = sections.get("upgrades", {}).get("available")
    rows.append((UNKNOWN if upgrades is None else OK, "Pending upgrades",
                 "not checked" if upgrades is None else str(upgrades)))
    held = sections.get("held", {}).get("packages", [])
    rows.append((OK, "Held packages", ", ".join(held[:5]) or "0"))
    if sections.get("reboot_required", {}).get("required"):
        rows.append((ATTENTION, "Reboot", "required to finish updates"))
    return rows


def _thermal_rows(sections: dict) -> list[tuple[str, str, str]]:
    summary = sections.get("summary", {})
    hottest = summary.get("max_celsius")
    if hottest is None:
        rows = [(UNKNOWN, "Sensors", "no temperature sensor exposed")]
    else:
        rows = [(ATTENTION if hottest >= 90 else OK, "Hottest sensor", f"{hottest} °C"),
                (OK, "Sensors", f"{summary.get('sensor_count', 0)} readings")]
    fans = sections.get("fans", {})
    rows.append((OK if fans.get("count") else UNKNOWN, "Fans",
                 f"{fans.get('count')} reporting" if fans.get("count") else "not exposed"))
    throttling = sections.get("throttling", {})
    events = throttling.get("kernel_event_count") or 0
    rows.append((ATTENTION if events else OK, "Throttling",
                 f"{events} events this boot" if events else "none this boot"))
    return rows


_ROWS = {"gpu": _gpu_rows, "memory": _memory_rows, "disk": _disk_rows,
         "network": _network_rows, "boot": _boot_rows, "services": _services_rows,
         "packages": _packages_rows, "thermal": _thermal_rows}


def domain_rows(scope: str, sections: dict) -> list[tuple[str, str, str]]:
    builder = _ROWS.get(scope)
    if builder is None:
        return []
    try:
        return builder(sections or {})
    except (AttributeError, KeyError, TypeError, ValueError):
        return [(UNKNOWN, title(scope), "collector output could not be summarized")]


def section(heading: str, rows: list[tuple[str, str, str]]) -> str:
    bold, green, yellow, reset = _color()
    lines = [f"{bold}{heading}{reset}", ""]
    for state, label, value in rows:
        tint = green if state == OK else (yellow if state == ATTENTION else "")
        lines.append(f"{tint}{state}{reset} {label}")
        for piece in str(value).splitlines() or [""]:
            lines.append(f"  {piece}")
    return "\n".join(lines)


def render_document(document: dict) -> str:
    """Render every deterministic fact SysAI collected, before model prose."""
    bold, _, yellow, reset = _color()
    scope = document.get("request", {}).get("scope", "")
    findings = document.get("findings", [])
    parts = [f"{bold}SysAI {title(scope)}{reset}", "", f"{bold}Overall{reset}",
             f"  {overall(findings)}", ""]
    if scope == "full_system":
        for domain in sorted(document.get("sections", {})):
            rows = domain_rows(domain, document["sections"][domain])
            if rows:
                parts.extend([section(title(domain), rows), ""])
    else:
        rows = domain_rows(scope, document.get("sections", {}))
        if rows:
            parts.extend([section("Checks", rows), ""])
    serious = [item for item in findings if item.get("severity") in (WARNING, CRITICAL)]
    if serious:
        parts.append(f"{bold}Findings{reset}")
        parts.append("")
        for item in serious:
            parts.append(f"{yellow}{ATTENTION}{reset} {item.get('title', item.get('id', ''))}")
            parts.append(f"  {item.get('classification', '')} · {item.get('domain', '')}"
                         f" · confidence {item.get('confidence', 'unknown')}")
            if item.get("probable_cause"):
                parts.append(f"  Probable cause: {item['probable_cause']}")
            if item.get("suggested_next_diagnostic"):
                parts.append(f"  Next diagnostic: {item['suggested_next_diagnostic']}")
        parts.append("")
    missing = document.get("unavailable", [])
    if missing:
        parts.append(f"{bold}Not checked{reset}")
        parts.append("")
        for item in missing[:12]:
            parts.append(f"{UNKNOWN} {item.get('check', '?')}")
            parts.append(f"  {item.get('reason', 'unavailable')}")
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"
