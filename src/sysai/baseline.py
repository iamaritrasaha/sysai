"""Baselines: a small, sanitized snapshot of deterministic system facts.

A baseline holds facts, never history. No terminal transcripts, no model
reasoning, no raw dmesg or journal text, no secrets, and no private
identifiers. Comparison is arithmetic done in Python; the model may explain
the differences afterwards but never computes them.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from . import __version__
from . import collect, domains
from .config import persistent_state_dir
from .evidence import now, system_summary
from .privacy import SHARED, sanitize

SCHEMA_VERSION = 1
FILENAME = "baseline.json"

# Package versions worth tracking across upgrades. Chosen because a change in
# any of them commonly explains a change in system behaviour.
TRACKED_PACKAGES = (
    "linux-image-generic", "mesa-vulkan-drivers", "libdrm2", "libgl1-mesa-dri",
    "systemd", "network-manager", "bluez", "xserver-xorg-core", "gnome-shell",
    "libc6", "firmware-sof-signed", "amdgpu-dkms", "nvidia-driver",
)


class BaselineError(RuntimeError):
    pass


def baseline_path(directory: Path | None = None) -> Path:
    return (directory or persistent_state_dir()) / FILENAME


def _package_versions() -> dict[str, str]:
    if not collect.have("dpkg-query"):
        return {}
    result = collect.run(
        ("dpkg-query", "-f", "${binary:Package} ${Version}\n", "-W", *TRACKED_PACKAGES),
        timeout=10, limit=40_000)
    versions = {}
    for line in collect.lines(result):
        name, _, version = line.partition(" ")
        if version:
            versions[name.split(":")[0]] = version.strip()
    return versions


def snapshot() -> dict:
    """Collect only deterministic, sanitized facts. No logs, no identifiers."""
    system = system_summary()
    memory = collect.meminfo()
    gpu_sections, _ = domains.collect_gpu()
    services_sections, _ = domains.collect_services()
    boot_sections, _ = domains.collect_boot()
    packages_sections, _ = domains.collect_packages()
    filesystems = [
        {"mountpoint": row["mountpoint"], "fstype": row["fstype"],
         "total_bytes": row["total_bytes"], "capacity_percent": row["capacity_percent"]}
        for row in collect.mounts()
        if not row["mountpoint"].startswith(("/proc", "/sys", "/run", "/dev"))
    ]
    interfaces = [
        {"interface": entry["interface"],
         "kind": "wireless" if entry.get("wireless") else ("loopback" if entry.get("loopback") else "wired")}
        for entry in sorted(
            ({"interface": name,
              "wireless": Path(f"/sys/class/net/{name}/wireless").exists()
              or Path(f"/sys/class/net/{name}/phy80211").exists(),
              "loopback": name == "lo"} for name in collect.interfaces()),
            key=lambda entry: entry["interface"])
    ]
    document = {
        "schema_version": SCHEMA_VERSION,
        "created": now(),
        "sysai_version": __version__,
        "system": {"kernel": system.get("kernel"), "architecture": system.get("architecture"),
                   "os": system.get("os_release", {})},
        "gpu": {"vendors": gpu_sections.get("identity", {}).get("vendors", []),
                "drivers": gpu_sections.get("driver", {}).get("drivers_in_use", []),
                "device_count": len(gpu_sections.get("identity", {}).get("devices", []))},
        "memory": {"total_bytes": memory.get("MemTotal", 0),
                   "swap_total_bytes": memory.get("SwapTotal", 0)},
        "filesystems": filesystems,
        "network": {"interfaces": interfaces},
        "services": {"failed_count": services_sections.get("failed", {}).get("count", 0),
                     "failed_units": sorted(services_sections.get("failed", {}).get("units", [])),
                     "system_state": services_sections.get("state", {}).get("system_state")},
        "boot": {"failed_unit_count": boot_sections.get("units", {}).get("failed_count", 0),
                 "critical_journal_count": boot_sections.get("journal", {}).get("critical_count", 0),
                 "reboot_required": boot_sections.get("reboot_required", {}).get("required", False)},
        "packages": {"installed_count": packages_sections.get("manager", {}).get("installed_count"),
                     "held": sorted(packages_sections.get("held", {}).get("packages", [])),
                     "versions": _package_versions()},
    }
    # A baseline is written to disk, so it always uses the strict level.
    return sanitize(document, SHARED)


def create(directory: Path | None = None) -> tuple[Path, dict]:
    """Write a baseline atomically with mode 0600."""
    path = baseline_path(directory)
    document = snapshot()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".baseline-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path, document


def load(directory: Path | None = None) -> dict:
    path = baseline_path(directory)
    if not path.exists():
        raise BaselineError("No baseline exists yet. Create one with `sysai baseline create`.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"The baseline could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"The baseline file is corrupt ({exc.msg}). Recreate it with `sysai baseline create`.") from exc
    if not isinstance(document, dict):
        raise BaselineError("The baseline file is corrupt. Recreate it with `sysai baseline create`.")
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        raise BaselineError(
            f"The baseline uses schema version {version!r}, but this SysAI expects "
            f"{SCHEMA_VERSION}. Recreate it with `sysai baseline create`.")
    return document


def delete(directory: Path | None = None) -> bool:
    path = baseline_path(directory)
    if not path.exists():
        return False
    path.unlink()
    return True


def _flatten(document: dict, prefix: str = "") -> dict[str, object]:
    flat: dict[str, object] = {}
    for key, value in document.items():
        if key in ("created", "sysai_version", "schema_version"):
            continue
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{name}."))
        elif isinstance(value, list):
            if value and all(isinstance(item, dict) for item in value):
                for item in value:
                    label = item.get("mountpoint") or item.get("interface") or ""
                    flat.update(_flatten(item, f"{name}[{label}]."))
            else:
                flat[name] = sorted(str(item) for item in value)
        else:
            flat[name] = value
    return flat


# Facts that legitimately drift between snapshots without being a change.
_VOLATILE = ("capacity_percent",)

_LABELS = {
    "system.kernel": "Kernel", "system.architecture": "Architecture",
    "system.os.pretty_name": "OS", "system.os.version_id": "OS version",
    "gpu.drivers": "GPU driver", "gpu.vendors": "GPU vendor",
    "gpu.device_count": "GPU device count",
    "memory.total_bytes": "Total RAM", "memory.swap_total_bytes": "Swap size",
    "services.failed_count": "Failed services", "services.failed_units": "Failed units",
    "services.system_state": "systemd state",
    "boot.failed_unit_count": "Failed units at boot",
    "boot.critical_journal_count": "Critical journal entries",
    "boot.reboot_required": "Reboot required",
    "packages.installed_count": "Installed packages", "packages.held": "Held packages",
}


def label_for(key: str) -> str:
    if key in _LABELS:
        return _LABELS[key]
    if key.startswith("packages.versions."):
        return key.split(".", 2)[2]
    if key.startswith("filesystems["):
        mountpoint = key[len("filesystems["):key.index("]")]
        return f"Filesystem {mountpoint or '?'} {key.rsplit('.', 1)[-1].replace('_', ' ')}"
    if key.startswith("network.interfaces["):
        interface = key[len("network.interfaces["):key.index("]")]
        return f"Interface {interface}"
    return key.replace(".", " ").replace("_", " ")


def compare(previous: dict, current: dict | None = None) -> dict:
    """Compute differences in Python. The model never derives these."""
    current = current if current is not None else snapshot()
    before, after = _flatten(previous), _flatten(current)
    changed, added, removed = [], [], []
    for key in sorted(set(before) | set(after)):
        if any(key.endswith(name) for name in _VOLATILE):
            continue
        old, new = before.get(key), after.get(key)
        if key not in after:
            removed.append({"key": key, "label": label_for(key), "previous": old})
        elif key not in before:
            added.append({"key": key, "label": label_for(key), "current": new})
        elif old != new:
            changed.append({"key": key, "label": label_for(key), "previous": old, "current": new})
    return {
        "schema_version": SCHEMA_VERSION,
        "baseline_created": previous.get("created"),
        "compared_at": now(),
        "changed": changed, "added": added, "removed": removed,
        "change_count": len(changed) + len(added) + len(removed),
        "current": current,
    }


def _value(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "unset"
    return str(value)


def render_comparison(result: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, reset = ("\033[1m", "\033[0m") if color else ("", "")
    if not result.get("change_count"):
        return (f"{bold}Unchanged since baseline{reset}\n\n"
                f"  Baseline created {result.get('baseline_created', 'unknown')}\n"
                "  No tracked system fact has changed.\n")
    lines = [f"{bold}Changed since baseline{reset}", "",
             f"  Baseline created {result.get('baseline_created', 'unknown')}", ""]
    for item in result.get("changed", []):
        lines.append(f"{bold}{item['label']}{reset}")
        lines.append(f"  {_value(item['previous'])} -> {_value(item['current'])}")
    for item in result.get("added", []):
        lines.append(f"{bold}{item['label']}{reset}")
        lines.append(f"  added: {_value(item['current'])}")
    for item in result.get("removed", []):
        lines.append(f"{bold}{item['label']}{reset}")
        lines.append(f"  removed: {_value(item['previous'])}")
    return "\n".join(lines) + "\n"


def render_snapshot(document: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, reset = ("\033[1m", "\033[0m") if color else ("", "")
    lines = [f"{bold}SysAI Baseline{reset}", "",
             f"  Created {document.get('created', 'unknown')}",
             f"  SysAI {document.get('sysai_version', 'unknown')}", ""]
    for key, value in sorted(_flatten(document).items()):
        lines.append(f"{label_for(key)}")
        lines.append(f"  {_value(value)}")
    return "\n".join(lines) + "\n"
