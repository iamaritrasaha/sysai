"""Bounded Linux health facts and an audited diagnostic-action catalogue."""
from __future__ import annotations

import os
import json
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .display import plain_terminal_text
from .redact import redact

TIMEOUT, MAX_OUTPUT = 3, 12_000
_UNIT = re.compile(r"^[A-Za-z0-9_.@-]+\.service$")
_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._/-]+$")


def _read(path: str, limit: int = MAX_OUTPUT) -> str | None:
    try: return Path(path).read_text(errors="replace")[:limit].strip()
    except OSError: return None


def _command(argv: tuple[str, ...], timeout: int = TIMEOUT, limit: int = MAX_OUTPUT) -> dict:
    """Only callers in this module supply fixed audited argv; never a shell."""
    executable = shutil.which(argv[0])
    if not executable: return {"status": "unavailable", "reason": f"{argv[0]} not installed"}
    try:
        result = subprocess.run((executable, *argv[1:]), stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired: return {"status": "unavailable", "reason": "timed out"}
    except OSError as exc: return {"status": "unavailable", "reason": str(exc)}
    output = plain_terminal_text(redact((result.stdout or "") + (result.stderr or "")))
    return {"status": "ok", "exit_code": result.returncode,
            "output": output[:limit].strip(), "output_truncated": len(output) > limit}


def _mounts() -> list[dict]:
    rows = []
    for line in (_read("/proc/mounts") or "").splitlines():
        fields = line.split()
        if len(fields) < 4: continue
        device, point, fstype, options = fields[:4]
        # Snap squashfs is intentionally normal and not a health finding.
        if fstype == "squashfs" and point.startswith("/snap/"): continue
        try:
            stat = os.statvfs(point)
        except OSError: continue
        total = stat.f_blocks * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
        rows.append({"device": device, "mountpoint": point, "fstype": fstype,
            "currently_read_only": "ro" in options.split(","), "mount_options": options.split(","),
            "capacity_percent": round(used * 100 / total, 1) if total else None,
            "inode_percent": round((stat.f_files - stat.f_ffree) * 100 / stat.f_files, 1) if stat.f_files else None,
            "kernel_errors_detected": False})
    return rows


def _temperatures() -> list[dict]:
    result = []
    for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
        try: celsius = int((zone / "temp").read_text().strip()) / 1000
        except (OSError, ValueError): continue
        label = _read(str(zone / "type")) or "unknown"
        result.append({"sensor": zone.name, "label": label, "celsius": celsius, "component": "unknown"})
    return result


def _uptime() -> dict:
    fields = (_read("/proc/uptime") or "").split()
    return {"status": "ok", "seconds": float(fields[0]) if fields else None}  # field 2 is aggregate idle time.


def _meminfo() -> dict:
    data = {line.partition(":")[0]: int(line.partition(":")[2].split()[0]) * 1024
            for line in (_read("/proc/meminfo") or "").splitlines() if ":" in line}
    total, available = data.get("MemTotal", 0), data.get("MemAvailable", 0)
    return {"status": "ok", "total_bytes": total, "available_bytes": available,
            "used_percent": round((total - available) * 100 / total, 1) if total else None,
            "swap_total_bytes": data.get("SwapTotal", 0), "swap_free_bytes": data.get("SwapFree", 0)}


def _findings(checks: dict) -> list[dict]:
    findings = []
    for mount in checks.get("storage", {}).get("filesystems", []):
        if mount.get("fstype") == "squashfs" and mount.get("mountpoint", "").startswith("/snap/"): continue
        if mount["currently_read_only"] and not mount["mountpoint"].startswith(("/proc", "/sys")):
            findings.append({"severity": "warning", "kind": "filesystem_read_only", "evidence": {"mountpoint": mount["mountpoint"], "currently_read_only": True}})
        if (mount.get("capacity_percent") or 0) >= 90:
            findings.append({"severity": "warning", "kind": "disk_full", "evidence": {"mountpoint": mount["mountpoint"], "capacity_percent": mount["capacity_percent"]}})
    failed = checks.get("services", {}).get("failed_units", [])
    for unit in failed: findings.append({"severity": "warning", "kind": "failed_service", "evidence": {"unit": unit}})
    oom_events = checks.get("logs", {}).get("oom_events", [])
    if oom_events:
        findings.append({"severity": "warning", "kind": "oom_events", "evidence": {"count": len(oom_events)}})
    if checks.get("packages", {}).get("audit_ok") is False:
        findings.append({"severity": "warning", "kind": "package_incomplete", "evidence": {"dpkg_audit_ok": False}})
    if checks.get("network", {}).get("dns", {}).get("resolved") is False:
        findings.append({"severity": "warning", "kind": "dns_resolution", "evidence": {"resolved": False}})
    zombies = checks.get("processes", {}).get("zombie_count", 0)
    if zombies:
        findings.append({"severity": "informational", "kind": "zombie_processes", "evidence": {"count": zombies}})
    if checks.get("reboot", {}).get("required"):
        findings.append({"severity": "informational", "kind": "reboot_required", "evidence": {"required": True}})
    return findings


def collect_health(progress=None) -> dict:
    """Collect normalized facts; raw command text is not passed to the model."""
    def system():
        cpu_model = next((line.partition(":")[2].strip() for line in (_read("/proc/cpuinfo") or "").splitlines()
                          if line.lower().startswith("model name")), None)
        release = {}
        for line in (_read("/etc/os-release") or "").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("ID", "VERSION_ID", "PRETTY_NAME"):
                release[key.lower()] = value.strip('"')
        return {"uptime": _uptime(), "load": (_read("/proc/loadavg") or "").split()[:3],
                "kernel": os.uname().release, "os_release": release,
                "cpu": {"logical_count": os.cpu_count(), "model": cpu_model}}

    def services():
        raw = _command(("systemctl", "--failed", "--no-pager", "--plain"))
        units = [line.split()[0] for line in raw.get("output", "").splitlines() if _UNIT.match(line.split()[0] if line.split() else "")]
        return {"status": raw["status"], "failed_units": units,
                "system_state": _command(("systemctl", "is-system-running")).get("output")}
    def network():
        try: socket.getaddrinfo("example.com", 443); dns = {"status": "ok", "resolved": True}
        except socket.gaierror: dns = {"status": "issue", "resolved": False}
        links = _command(("ip", "-brief", "link"))
        routes = _command(("ip", "route", "show", "default"))
        return {"dns": dns, "default_route_present": bool(routes.get("output")),
                "interfaces": links, "default_route": routes}

    def processes():
        raw = _command(("ps", "-eo", "pid,stat,%cpu,%mem,comm", "--sort=-%cpu"))
        lines = raw.get("output", "").splitlines()
        zombies = [line for line in lines[1:] if len(line.split()) > 1 and "Z" in line.split()[1]]
        return {"status": raw.get("status"), "zombie_count": len(zombies), "top": lines[:12]}

    def logs():
        kernel = _command(("journalctl", "-k", "-b", "-p", "err", "--no-pager", "-n", "100"))
        oom = [line for line in kernel.get("output", "").splitlines()
               if re.search(r"\b(?:out of memory|oom-kill|killed process)\b", line, re.I)]
        return {"kernel_errors": kernel, "oom_events": oom[:20]}

    def gpu():
        pci = _command(("lspci", "-k"))
        lines = pci.get("output", "").splitlines()
        selected, include = [], 0
        for line in lines:
            if re.search(r"\b(?:vga|3d|display)\b", line, re.I):
                include = 3
            if include:
                selected.append(line)
                include -= 1
        return {"pci": {"status": pci.get("status"), "devices": selected},
                "amd": _command(("amd-smi", "static", "--asic", "--driver")),
                "rocm": _command(("rocm-smi", "--showproductname", "--showtemp", "--showuse"))}

    def clock():
        return _command(("timedatectl", "show", "--property=NTPSynchronized,Timezone"))
    def packages():
        if not shutil.which("dpkg"): return {"status": "unavailable", "manager": None}
        audit = _command(("dpkg", "--audit"))
        upgrades = _command(("apt", "list", "--upgradable"), timeout=5) if shutil.which("apt") else {"status": "unavailable"}
        lines = [x for x in upgrades.get("output", "").splitlines() if "/" in x and not x.startswith("Listing")]
        return {"manager": "dpkg", "audit_ok": audit.get("status") == "ok" and not audit.get("output"),
                "upgrade_check_status": upgrades.get("status"), "upgrade_count": len(lines) if upgrades.get("status") == "ok" else None}
    checks = {"system": system,
        "memory": _meminfo, "storage": lambda: {"filesystems": _mounts()}, "services": services,
        "network": network, "temperature": lambda: {"sensors": _temperatures()},
        "packages": packages, "processes": processes, "logs": logs, "gpu": gpu, "time": clock,
        "reboot": lambda: {"required": Path("/var/run/reboot-required").exists()}}
    result = {"platform": "linux", "checks": {}}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in checks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try: result["checks"][name] = future.result()
            except Exception as exc: result["checks"][name] = {"status": "unavailable", "reason": str(exc)}
            if progress: progress(name)
    result["findings"] = _findings(result["checks"])
    return result


def action_details(action_id: str, params: dict, trusted: dict) -> dict:
    """Validate an action against collector-provided values; no model text is trusted."""
    if not isinstance(params, dict):
        raise ValueError("invalid diagnostic parameters")
    fixed = {
        "system.kernel_version": (("uname", "-r"), "Read the running kernel version"),
        "system.os_release": (("cat", "/etc/os-release"), "Read operating-system release metadata"),
        "gpu.pci_driver": (("lspci", "-k"), "Inspect PCI GPU devices and bound drivers"),
        "gpu.amd_status": (("amd-smi", "static", "--asic", "--driver"), "Inspect AMD GPU and driver status"),
        "gpu.rocm_status": (("rocm-smi", "--showproductname", "--showtemp", "--showuse"), "Inspect ROCm GPU status"),
        "gpu.temperature": (("sensors",), "Inspect available hardware temperatures"),
        "journal.kernel_errors": (("journalctl", "-k", "-b", "-p", "err", "--no-pager", "-n", "100"), "Inspect current-boot kernel errors"),
        "filesystem.mount_status": (("findmnt", "-rn", "-o", "SOURCE,TARGET,FSTYPE,OPTIONS"), "Inspect current filesystem mount state"),
        "network.route": (("ip", "route", "show"), "Inspect current network routes"),
        "dns.resolution": (("resolvectl", "status"), "Inspect DNS resolver state"),
        "package.dpkg_audit": (("dpkg", "--audit"), "Check for incomplete package operations"),
    }
    if action_id in fixed:
        if params:
            raise ValueError("unexpected diagnostic parameters")
        argv, purpose = fixed[action_id]
        return {"id": action_id, "argv": argv, "elevated": False, "read_only": True,
                "sensitivity": "local-system", "timeout": 5, "output_limit": MAX_OUTPUT, "purpose": purpose}
    if action_id == "systemd.unit_status":
        unit = params.get("unit")
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit) or unit not in trusted.get("units", set()): raise ValueError("untrusted service unit")
        return {"id": action_id, "argv": ("systemctl", "status", unit, "--no-pager", "--full"), "elevated": False,
                "read_only": True, "sensitivity": "service-logs", "timeout": 5, "output_limit": MAX_OUTPUT,
                "purpose": f"Inspect status for {unit}"}
    if action_id in ("systemd.unit_logs", "journal.unit_errors"):
        unit = params.get("unit")
        if not isinstance(unit, str) or not _UNIT.fullmatch(unit) or unit not in trusted.get("units", set()): raise ValueError("untrusted service unit")
        return {"id": action_id, "argv": ("journalctl", "-u", unit, "-b", "-p", "warning", "--no-pager", "-n", "100"),
                "elevated": False, "read_only": True, "sensitivity": "service-logs", "timeout": 5,
                "output_limit": MAX_OUTPUT, "purpose": f"Inspect recent warnings for {unit}"}
    if action_id == "disk.smart_health":
        device = params.get("device")
        if not isinstance(device, str) or not _DEVICE.fullmatch(device) or device not in trusted.get("devices", set()): raise ValueError("untrusted device")
        return {"id": action_id, "argv": ("sudo", "smartctl", "-a", device), "elevated": True,
                "read_only": True, "sensitivity": "device-health", "timeout": 8, "output_limit": MAX_OUTPUT,
                "purpose": f"Inspect SMART health for {device}"}
    if action_id in ("network.interface_status", "network.interface_driver", "network.link_stats"):
        interface = params.get("interface")
        if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface) or interface not in trusted.get("interfaces", set()):
            raise ValueError("untrusted network interface")
        argv = {
            "network.interface_status": ("ip", "-details", "link", "show", "dev", interface),
            "network.interface_driver": ("ethtool", "-i", interface),
            "network.link_stats": ("ip", "-s", "link", "show", "dev", interface),
        }[action_id]
        return {"id": action_id, "argv": argv, "elevated": False, "read_only": True,
                "sensitivity": "network-local", "timeout": 5, "output_limit": MAX_OUTPUT,
                "purpose": f"Inspect {interface} network status"}
    if action_id == "package.apt_policy":
        package = params.get("package")
        if not isinstance(package, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,100}", package) or package not in trusted.get("packages", set()):
            raise ValueError("untrusted package")
        return {"id": action_id, "argv": ("apt-cache", "policy", package), "elevated": False,
                "read_only": True, "sensitivity": "package-metadata", "timeout": 5, "output_limit": MAX_OUTPUT,
                "purpose": f"Inspect installed and candidate versions for {package}"}
    raise ValueError("unknown diagnostic action")


def run_action(action_id: str, params: dict, trusted: dict, approve) -> dict:
    detail = action_details(action_id, params, trusted)
    if detail["elevated"] and not approve(detail): return {"status": "declined", "purpose": detail["purpose"]}
    result = _command(detail["argv"], timeout=detail["timeout"], limit=detail["output_limit"])
    return {"action_id": action_id, "purpose": detail["purpose"], **result}


def action_catalogue() -> list[dict]:
    """Model-visible IDs and parameter shapes; executable argv stays internal."""
    return [
        {"id": action_id, "params": params}
        for action_id, params in (
            ("system.kernel_version", {}), ("system.os_release", {}), ("gpu.pci_driver", {}),
            ("gpu.amd_status", {}), ("gpu.rocm_status", {}), ("gpu.temperature", {}),
            ("systemd.unit_status", {"unit": "trusted .service"}),
            ("systemd.unit_logs", {"unit": "trusted .service"}),
            ("journal.kernel_errors", {}), ("journal.unit_errors", {"unit": "trusted .service"}),
            ("disk.smart_health", {"device": "trusted /dev path"}), ("filesystem.mount_status", {}),
            ("network.interface_status", {"interface": "trusted interface"}),
            ("network.interface_driver", {"interface": "trusted interface"}),
            ("network.link_stats", {"interface": "trusted interface"}), ("network.route", {}),
            ("dns.resolution", {}), ("package.dpkg_audit", {}),
            ("package.apt_policy", {"package": "trusted package"}),
        )
    ]


def parse_action_plan(text: str, maximum: int = 3) -> list[dict]:
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
        # Scan for the first valid JSON object that contains an "actions" key.
        decoder = json.JSONDecoder()
        for i, ch in enumerate(value):
            if ch != "{":
                continue
            try:
                candidate, _ = decoder.raw_decode(value, i)
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


def safety_floor_actions(evidence: dict) -> list[dict]:
    """Predefined non-elevated read-only diagnostics for known signal categories.

    Guarantees at least one diagnostic round for well-known anomaly types
    even when the model planning call fails to produce valid JSON.
    """
    kinds = {s.get("kind") for s in evidence.get("signals", [])}
    seen: set[str] = set()
    result: list[dict] = []

    def _add(action_id: str) -> None:
        if action_id not in seen:
            seen.add(action_id)
            result.append({"id": action_id, "params": {}})

    if kinds & {"gpu_reset", "firmware_failure"}:
        for aid in ("system.kernel_version", "gpu.pci_driver", "gpu.amd_status", "gpu.temperature"):
            _add(aid)
    if "filesystem_error" in kinds:
        _add("filesystem.mount_status")
    if "hardware_error" in kinds:
        for aid in ("system.kernel_version", "journal.kernel_errors"):
            _add(aid)
    if "oom" in kinds:
        _add("system.kernel_version")
    return result


def trusted_inventory(extra: dict | None = None) -> dict:
    units = set((extra or {}).get("units", ()))
    devices = {f"/dev/{path.name}" for path in Path("/sys/block").glob("*")}
    try:
        interfaces = {name for _, name in socket.if_nameindex()}
    except OSError:
        interfaces = set()
    return {"units": units, "devices": devices, "interfaces": interfaces,
            "packages": set((extra or {}).get("packages", ()))}


def prompt_permission(detail: dict, input_fn=input, output=print) -> bool:
    """One-shot terminal consent hook for an elevated catalogue action."""
    output("SysAI wants additional diagnostic access\n\nPurpose:\n  " + detail["purpose"] +
           "\n\nCommand:\n  " + " ".join(detail["argv"]) + "\n\nAccess:\n  Read-only, elevated")
    try: return input_fn("Allow once? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt): return False


def web_queries(evidence: dict) -> list[str]:
    queries = []
    for finding in evidence.get("findings", []):
        if finding["kind"] == "failed_service": queries.append("Ubuntu systemd service known issue")
        elif finding["kind"] == "disk_full": queries.append("Ubuntu disk full troubleshooting")
        elif finding["kind"] == "oom_events": queries.append("Ubuntu Linux OOM diagnostics")
        elif finding["kind"] == "dns_resolution": queries.append("Ubuntu systemd-resolved DNS troubleshooting")
    return queries[:3]
