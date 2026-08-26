"""Unified Linux health facade.

`sysai health` is now "every domain, summarized": it runs the same
deterministic collectors, the same findings engine, and the same audited
action catalogue as the individual domain commands. This module keeps the
long-standing public names other modules and the CLI import.
"""
from __future__ import annotations

from .collect import MAX_OUTPUT, TIMEOUT, read_text, run as _command  # noqa: F401  (public names)
from .diagnostics import (MAX_ROUNDS, action_catalogue, action_details, known_action,
                          parse_action_plan, prompt_permission, run_action,
                          safety_floor_actions, trusted_inventory)
from .domains import DOMAINS, FULL_SYSTEM, SCOPES, collect_domain, collect_scope, trusted_values
from .evidence import model_signals, overall, sort_findings

__all__ = [
    "MAX_OUTPUT", "MAX_ROUNDS", "TIMEOUT", "DOMAINS", "FULL_SYSTEM", "SCOPES",
    "action_catalogue", "action_details", "collect_domain", "collect_health",
    "collect_scope", "known_action", "model_signals", "overall", "parse_action_plan",
    "prompt_permission", "run_action", "safety_floor_actions", "sort_findings",
    "trusted_inventory", "trusted_values", "web_queries",
]


def collect_health(progress=None, web: bool = False) -> dict:
    """Collect every domain concurrently into one canonical evidence document."""
    return collect_scope(FULL_SYSTEM, progress=progress, web=web, command="health")


# Generic, sanitized research labels. Built only from finding identifiers and
# normalized system facts: never from evidence values, paths, logs, or output.
_QUERY_LABELS = {
    "gpu.kernel_events": "GPU driver kernel reset timeout errors",
    "gpu.no_kernel_driver": "GPU has no kernel driver bound",
    "gpu.temperature_high": "GPU high temperature troubleshooting",
    "memory.oom_events": "Linux out of memory killer diagnostics",
    "memory.low_available": "Linux high memory usage diagnostics",
    "memory.swap_exhausted": "Linux swap exhaustion troubleshooting",
    "disk.full": "Linux root filesystem full troubleshooting",
    "disk.inodes_exhausted": "Linux inode exhaustion troubleshooting",
    "disk.read_only_mount": "Linux filesystem remounted read-only troubleshooting",
    "disk.io_errors": "Linux block device I/O error diagnostics",
    "disk.filesystem_errors": "Linux filesystem error diagnostics",
    "network.no_default_route": "Linux missing default route troubleshooting",
    "network.dns_failure": "systemd-resolved DNS resolution failure",
    "network.link_flapping": "Linux network link flapping troubleshooting",
    "network.driver_errors": "Linux network driver error troubleshooting",
    "boot.failed_units": "systemd failed unit troubleshooting",
    "boot.critical_journal": "systemd critical journal errors at boot",
    "boot.slow": "systemd slow boot analysis",
    "services.failed": "systemd service failed to start troubleshooting",
    "services.degraded": "systemd degraded system state",
    "services.restart_loop": "systemd service restart loop troubleshooting",
    "packages.dpkg_interrupted": "dpkg interrupted configure package troubleshooting",
    "thermal.high_temperature": "Linux high CPU temperature troubleshooting",
    "thermal.throttling": "Linux thermal throttling troubleshooting",
    # Legacy Command Insight finding kinds.
    "failed_service": "systemd service failed to start troubleshooting",
    "disk_full": "Linux root filesystem full troubleshooting",
    "oom_events": "Linux out of memory killer diagnostics",
    "dns_resolution": "systemd-resolved DNS resolution failure",
}


def web_queries(document: dict, maximum: int = 3) -> list[str]:
    """Generic issue labels only. No evidence values ever reach a search provider."""
    system = document.get("system", {})
    distribution = (system.get("os_release", {}) or {}).get("id") or "Linux"
    drivers = []
    sections = document.get("sections", {})
    gpu_sections = sections.get("gpu", sections)
    if isinstance(gpu_sections, dict):
        drivers = (gpu_sections.get("driver", {}) or {}).get("drivers_in_use", []) or []
    queries: list[str] = []
    for item in document.get("findings", []):
        identifier = item.get("id") or item.get("kind")
        label = _QUERY_LABELS.get(identifier)
        if not label or label in queries:
            continue
        if item.get("domain") == "gpu" and drivers:
            label = f"{label} {drivers[0]}"
        queries.append(f"{distribution} {label}".strip())
        if len(queries) >= maximum:
            break
    return queries
