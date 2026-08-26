"""The audited diagnostic action engine.

The local model may ask for an action **ID**. It can never supply argv.
Every ID maps to a fixed argv builder here, parameters are validated against
collector-derived trusted values, and each action carries its own timeout,
output limit, privilege level, and human-readable purpose.
"""
from __future__ import annotations

import json
import re
import socket
from pathlib import Path

from .collect import MAX_OUTPUT, run

_UNIT = re.compile(r"^[A-Za-z0-9_.@\\-]+\.service$")
_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._/-]+$")
_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,100}$")

MAX_ROUNDS = 3

# id -> (argv, purpose). Every entry is read-only and unprivileged.
FIXED_ACTIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "system.kernel_version": (("uname", "-r"), "Read the running kernel version"),
    "system.os_release": (("cat", "/etc/os-release"), "Read operating-system release metadata"),
    "gpu.pci_driver": (("lspci", "-k"), "Inspect PCI GPU devices and bound drivers"),
    "gpu.amd_status": (("amd-smi", "static", "--asic", "--driver"), "Inspect AMD GPU and driver status"),
    "gpu.rocm_status": (("rocm-smi", "--showproductname", "--showtemp", "--showuse"), "Inspect ROCm GPU status"),
    "gpu.rocm_info": (("rocminfo",), "Inspect ROCm agent and device enumeration"),
    "gpu.opencl_info": (("clinfo", "--list"), "List OpenCL platforms and devices"),
    "gpu.nvidia_status": (("nvidia-smi", "--query-gpu=name,driver_version,temperature.gpu,memory.used,memory.total",
                           "--format=csv,noheader"), "Inspect NVIDIA GPU and driver status"),
    "gpu.temperature": (("sensors",), "Inspect available hardware temperatures"),
    "thermal.sensors": (("sensors", "-A"), "Inspect all exposed thermal sensors"),
    "journal.kernel_errors": (("journalctl", "-k", "-b", "-p", "err", "--no-pager", "-n", "100"),
                              "Inspect current-boot kernel errors"),
    "journal.boot_errors": (("journalctl", "-b", "-p", "err", "--no-pager", "-n", "100"),
                            "Inspect current-boot system errors"),
    "filesystem.mount_status": (("findmnt", "-rn", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"),
                                "Inspect current filesystem mount state"),
    "filesystem.usage": (("df", "-hT"), "Inspect filesystem capacity"),
    "filesystem.inodes": (("df", "-i"), "Inspect filesystem inode usage"),
    "disk.block_layout": (("lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,RO"),
                          "Inspect block device layout"),
    "network.route": (("ip", "route", "show"), "Inspect current network routes"),
    "network.listening_sockets": (("ss", "-tulnH"), "Summarize listening sockets"),
    "dns.resolution": (("resolvectl", "status"), "Inspect DNS resolver state"),
    "package.dpkg_audit": (("dpkg", "--audit"), "Check for incomplete package operations"),
    "package.held": (("apt-mark", "showhold"), "List packages held at their current version"),
    "boot.blame": (("systemd-analyze", "blame"), "Inspect per-unit boot time contributions"),
    "boot.timing": (("systemd-analyze", "time"), "Inspect overall boot timing"),
    "services.list_failed": (("systemctl", "--failed", "--no-pager", "--plain"),
                             "List systemd units in a failed state"),
    "memory.usage": (("free", "-h"), "Inspect memory and swap usage"),
    "memory.top_consumers": (("ps", "-eo", "pid,%mem,rss,comm", "--sort=-%mem"),
                             "List the largest memory consumers"),
}

# id -> (parameter name, validating pattern, trusted-inventory key, argv builder, purpose, elevated)
_PARAMETERIZED: dict[str, tuple] = {
    "systemd.unit_status": (
        "unit", _UNIT, "units",
        lambda unit: ("systemctl", "status", unit, "--no-pager", "--full"),
        "Inspect status for {value}", False, "service-logs"),
    "systemd.unit_logs": (
        "unit", _UNIT, "units",
        lambda unit: ("journalctl", "-u", unit, "-b", "-p", "warning", "--no-pager", "-n", "100"),
        "Inspect recent warnings for {value}", False, "service-logs"),
    "journal.unit_errors": (
        "unit", _UNIT, "units",
        lambda unit: ("journalctl", "-u", unit, "-b", "-p", "warning", "--no-pager", "-n", "100"),
        "Inspect recent warnings for {value}", False, "service-logs"),
    "disk.smart_health": (
        "device", _DEVICE, "devices",
        lambda device: ("sudo", "smartctl", "-a", device),
        "Inspect SMART health for {value}", True, "device-health"),
    "network.interface_status": (
        "interface", _INTERFACE, "interfaces",
        lambda interface: ("ip", "-details", "link", "show", "dev", interface),
        "Inspect {value} network status", False, "network-local"),
    "network.interface_driver": (
        "interface", _INTERFACE, "interfaces",
        lambda interface: ("ethtool", "-i", interface),
        "Inspect {value} network driver information", False, "network-local"),
    "network.link_stats": (
        "interface", _INTERFACE, "interfaces",
        lambda interface: ("ip", "-s", "link", "show", "dev", interface),
        "Inspect {value} link statistics", False, "network-local"),
    "package.apt_policy": (
        "package", _PACKAGE, "packages",
        lambda package: ("apt-cache", "policy", package),
        "Inspect installed and candidate versions for {value}", False, "package-metadata"),
}

_TIMEOUTS = {"disk.smart_health": 8, "boot.blame": 8, "boot.timing": 8, "gpu.rocm_info": 8}


def action_details(action_id: str, params: dict, trusted: dict) -> dict:
    """Validate an action against collector-provided values; no model text is trusted."""
    if not isinstance(params, dict):
        raise ValueError("invalid diagnostic parameters")
    if action_id in FIXED_ACTIONS:
        if params:
            raise ValueError("unexpected diagnostic parameters")
        argv, purpose = FIXED_ACTIONS[action_id]
        return {"id": action_id, "argv": argv, "elevated": False, "read_only": True,
                "sensitivity": "local-system", "timeout": _TIMEOUTS.get(action_id, 5),
                "output_limit": MAX_OUTPUT, "purpose": purpose}
    if action_id in _PARAMETERIZED:
        name, pattern, key, builder, purpose, elevated, sensitivity = _PARAMETERIZED[action_id]
        value = params.get(name)
        if not isinstance(value, str) or not pattern.fullmatch(value) or value not in trusted.get(key, set()):
            raise ValueError(f"untrusted {name}")
        if set(params) - {name}:
            raise ValueError("unexpected diagnostic parameters")
        return {"id": action_id, "argv": builder(value), "elevated": elevated, "read_only": True,
                "sensitivity": sensitivity, "timeout": _TIMEOUTS.get(action_id, 5),
                "output_limit": MAX_OUTPUT, "purpose": purpose.format(value=value)}
    raise ValueError("unknown diagnostic action")


def run_action(action_id: str, params: dict, trusted: dict, approve) -> dict:
    detail = action_details(action_id, params, trusted)
    if detail["elevated"] and not approve(detail):
        return {"action_id": action_id, "status": "declined", "purpose": detail["purpose"]}
    result = run(detail["argv"], timeout=detail["timeout"], limit=detail["output_limit"])
    return {"action_id": action_id, "purpose": detail["purpose"], **result}


def action_catalogue() -> list[dict]:
    """Model-visible IDs and parameter shapes; executable argv stays internal."""
    entries = [{"id": action_id, "params": {}} for action_id in sorted(FIXED_ACTIONS)]
    entries += [{"id": action_id, "params": {spec[0]: f"trusted {spec[0]}"}}
                for action_id, spec in sorted(_PARAMETERIZED.items())]
    return entries


def known_action(action_id: str) -> bool:
    return action_id in FIXED_ACTIONS or action_id in _PARAMETERIZED


def parse_action_plan(text: str, maximum: int = MAX_ROUNDS) -> list[dict]:
    """Accept only a small JSON action envelope, never commands or prose.

    Falls back to scanning the text for an embedded JSON object when the
    model wraps its response in prose, which qwen3 occasionally does.
    """
    value = text.strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value, flags=re.IGNORECASE).strip()
    payload = None
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        decoder = json.JSONDecoder()
        for index, character in enumerate(value):
            if character != "{":
                continue
            try:
                candidate, _ = decoder.raw_decode(value, index)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(candidate, dict) and "actions" in candidate:
                payload = candidate
                break
    if not isinstance(payload, dict):
        return []
    actions = payload.get("actions")
    if not isinstance(actions, list):
        return []
    planned = []
    for item in actions[:maximum]:
        if isinstance(item, dict) and isinstance(item.get("id"), str) and isinstance(item.get("params", {}), dict):
            planned.append({"id": item["id"], "params": item.get("params", {})})
    return planned


# Deterministic first round per known signal category. Guarantees useful
# evidence even when the model's planning call returns nothing usable.
_FLOOR: dict[str, tuple[str, ...]] = {
    "gpu_reset": ("system.kernel_version", "gpu.pci_driver", "gpu.amd_status", "gpu.temperature"),
    "firmware_failure": ("system.kernel_version", "gpu.pci_driver", "gpu.amd_status", "gpu.temperature"),
    "filesystem_error": ("filesystem.mount_status",),
    "hardware_error": ("system.kernel_version", "journal.kernel_errors"),
    "oom": ("system.kernel_version",),
    "gpu.kernel_events": ("gpu.pci_driver", "journal.kernel_errors"),
    "gpu.no_kernel_driver": ("gpu.pci_driver",),
    "gpu.temperature_high": ("gpu.temperature",),
    "memory.oom_events": ("memory.usage", "memory.top_consumers"),
    "memory.low_available": ("memory.usage", "memory.top_consumers"),
    "memory.swap_exhausted": ("memory.usage",),
    "disk.full": ("filesystem.usage",),
    "disk.inodes_exhausted": ("filesystem.inodes",),
    "disk.read_only_mount": ("filesystem.mount_status",),
    "disk.io_errors": ("journal.kernel_errors", "disk.block_layout"),
    "disk.filesystem_errors": ("filesystem.mount_status", "journal.kernel_errors"),
    "network.no_default_route": ("network.route",),
    "network.dns_failure": ("dns.resolution", "network.route"),
    "network.link_flapping": ("journal.kernel_errors",),
    "network.driver_errors": ("journal.kernel_errors",),
    "boot.failed_units": ("services.list_failed",),
    "boot.critical_journal": ("journal.boot_errors",),
    "boot.slow": ("boot.blame",),
    "services.failed": ("services.list_failed",),
    "services.degraded": ("services.list_failed",),
    "services.restart_loop": ("services.list_failed",),
    "packages.dpkg_interrupted": ("package.dpkg_audit",),
    "thermal.high_temperature": ("thermal.sensors",),
    "thermal.throttling": ("thermal.sensors", "journal.kernel_errors"),
}


def safety_floor_actions(evidence: dict) -> list[dict]:
    """Predefined non-elevated read-only diagnostics for known signal categories."""
    kinds = {signal.get("kind") for signal in evidence.get("signals", [])}
    kinds.update(item.get("id") for item in evidence.get("findings", []) if isinstance(item, dict))
    ordered: list[dict] = []
    seen: set[str] = set()
    for kind in sorted(kind for kind in kinds if kind):
        for action_id in _FLOOR.get(kind, ()):
            if action_id not in seen:
                seen.add(action_id)
                ordered.append({"id": action_id, "params": {}})
    return ordered


def trusted_inventory(extra: dict | None = None) -> dict:
    extra = extra or {}
    devices = {f"/dev/{path.name}" for path in Path("/sys/block").glob("*")}
    try:
        interfaces = {name for _, name in socket.if_nameindex()}
    except OSError:
        interfaces = set()
    interfaces.update(extra.get("interfaces", ()))
    return {"units": set(extra.get("units", ())), "devices": devices,
            "interfaces": interfaces, "packages": set(extra.get("packages", ()))}


def prompt_permission(detail: dict, input_fn=input, output=print) -> bool:
    """One-shot terminal consent hook for an elevated catalogue action."""
    output("SysAI wants additional diagnostic access\n\nPurpose:\n  " + detail["purpose"] +
           "\n\nCommand:\n  " + " ".join(detail["argv"]) + "\n\nAccess:\n  Read-only, elevated")
    try:
        return input_fn("Allow once? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False
