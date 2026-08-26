"""Deterministic per-domain collectors and the findings they support.

Every domain returns ``(sections, unavailable)``. Sections are normalized
facts; ``unavailable`` records checks that could not run, which become
NOT CHECKED rather than errors. Findings are computed here in Python so the
local model never has to infer something that can be calculated.
"""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import collect
from .evidence import (CONFIRMED, CRITICAL, INFO, INFORMATIONAL, POSSIBLE, PROBABLE,
                       WARNING, build, finding, sort_findings, unavailable)

DOMAINS = ("gpu", "memory", "disk", "network", "boot", "services", "packages", "thermal")
FULL_SYSTEM = "full_system"
SCOPES = (*DOMAINS, FULL_SYSTEM)

HIGH_TEMPERATURE = 90.0
CRITICAL_TEMPERATURE = 100.0
FULL_PERCENT = 90.0

GPU_TROUBLE = re.compile(
    r"\b(?:gpu\s+reset|ring\s+\w*\s*timeout|reg_wait|job\s+timed?\s*out|"
    r"hang|hung|soft\s+recovery|gpu\s+fault|page\s+fault|amdgpu:.*(?:error|failed)|"
    r"drm:.*(?:error|failed)|atombios\s+stuck)\b", re.I)
_IO_ERROR = re.compile(
    r"\b(?:i/o error|blk_update_request|critical (?:medium|target) error|"
    r"buffer i/o error|ata\d+\.\d+: (?:failed|exception))\b", re.I)
_FS_ERROR = re.compile(
    r"\b(?:ext[234]-fs (?:error|warning)|xfs \(|btrfs:.*(?:error|checksum)|"
    r"remounting filesystem read-only|filesystem .*(?:error|corrupt))\b", re.I)
OOM_PATTERN = re.compile(r"\b(?:out of memory|oom-kill(?:er)?|killed process)\b", re.I)
LINK_EVENT = re.compile(r"\b(?:link is (?:down|up)|carrier (?:lost|on)|"
                         r"link becomes ready|nic link is)\b", re.I)
_NET_DRIVER_ERROR = re.compile(r"\b(?:tx timeout|reset adapter|hw csum failure|"
                               r"firmware error|rx fifo overrun)\b", re.I)
_RESTART_LOOP = re.compile(r"start request repeated too quickly|"
                           r"scheduled restart job, restart counter is at (\d+)", re.I)
THROTTLE = re.compile(r"\b(?:thermal throttl|cpu\d* clock throttled|"
                       r"package temperature above threshold|critical temperature reached)\b", re.I)
_UNIT = re.compile(r"^[A-Za-z0-9_.@\\-]+\.(?:service|socket|timer|mount|target)$")


# --------------------------------------------------------------------------- GPU

def _pci_display_devices() -> tuple[list[dict], dict]:
    result = collect.run(("lspci", "-nnk"), timeout=5)
    devices: list[dict] = []
    current: dict | None = None
    for line in collect.lines(result):
        if not line.startswith((" ", "\t")):
            if re.search(r"\b(?:VGA compatible controller|3D controller|Display controller)\b", line, re.I):
                current = {"description": line.strip()[:240], "kernel_driver": None,
                           "kernel_modules": [], "vendor": _vendor_of(line)}
                devices.append(current)
            else:
                current = None
            continue
        if current is None:
            continue
        key, separator, value = line.strip().partition(":")
        if not separator:
            continue
        if key == "Kernel driver in use":
            current["kernel_driver"] = value.strip()
        elif key == "Kernel modules":
            current["kernel_modules"] = [item.strip() for item in value.split(",") if item.strip()]
    return devices, result


def _vendor_of(text: str) -> str:
    value = text.lower()
    if "nvidia" in value:
        return "nvidia"
    if "advanced micro devices" in value or "amd/ati" in value or "[amd" in value or "ati " in value:
        return "amd"
    if "intel" in value:
        return "intel"
    return "unknown"


def drm_cards() -> list[dict]:
    cards = []
    for card in sorted(Path("/sys/class/drm").glob("card[0-9]*")):
        if "-" in card.name:
            continue
        device = card / "device"
        entry = {"card": card.name,
                 "driver": (device / "driver").resolve().name if (device / "driver").exists() else None,
                 "power_state": collect.read_text(str(device / "power_state")),
                 "vram_total_bytes": collect.read_int(str(device / "mem_info_vram_total")),
                 "vram_used_bytes": collect.read_int(str(device / "mem_info_vram_used")),
                 "gpu_busy_percent": collect.read_int(str(device / "gpu_busy_percent"))}
        temperature = None
        for hwmon in sorted((device / "hwmon").glob("hwmon*")) if (device / "hwmon").is_dir() else []:
            value = collect.read_int(str(hwmon / "temp1_input"))
            if value is not None:
                temperature = round(value / 1000, 1)
                break
        entry["temperature_celsius"] = temperature
        cards.append(entry)
    return cards


def collect_gpu() -> tuple[dict, list[dict]]:
    devices, pci = _pci_display_devices()
    missing: list[dict] = []
    if pci.get("status") != "ok":
        missing.append(unavailable("lspci", pci.get("reason", "unavailable"), "gpu"))
    vendors = {device["vendor"] for device in devices}
    cards = drm_cards()

    # Vendor-neutral: only the detected vendor's tooling is ever consulted or
    # reported as missing. An AMD system never mentions NVIDIA utilities.
    tools: dict[str, dict] = {}
    candidates: list[tuple[str, tuple[str, ...]]] = []
    if "amd" in vendors:
        candidates += [("amd-smi", ("amd-smi", "static", "--asic", "--driver")),
                       ("rocm-smi", ("rocm-smi", "--showproductname", "--showtemp", "--showuse")),
                       ("rocminfo", ("rocminfo",))]
    if "nvidia" in vendors:
        candidates += [("nvidia-smi", ("nvidia-smi", "--query-gpu=name,driver_version,temperature.gpu,memory.used,memory.total",
                                       "--format=csv,noheader"))]
    if "intel" in vendors:
        candidates += [("intel_gpu_top", ("intel_gpu_top", "-L"))]
    candidates.append(("clinfo", ("clinfo", "--list")))
    for name, argv in candidates:
        result = collect.run(argv, timeout=6)
        tools[name] = result
        if result.get("status") != "ok":
            missing.append(unavailable(name, result.get("reason", "unavailable"), "gpu"))

    kernel_log = collect.journal("-k", "-b", "-p", "warning", "-n", "400")
    if kernel_log.get("status") != "ok":
        missing.append(unavailable("kernel journal", kernel_log.get("reason", "unavailable"), "gpu"))
    trouble_count, trouble_sample = collect.count_matches(kernel_log, GPU_TROUBLE)

    sections = {
        "identity": {"devices": devices, "vendors": sorted(vendors) or ["unknown"]},
        "driver": {"drivers_in_use": sorted({d["kernel_driver"] for d in devices if d["kernel_driver"]}),
                   "devices_without_driver": [d["description"] for d in devices if not d["kernel_driver"]]},
        "kernel": {"version": (collect.read_text("/proc/sys/kernel/osrelease") or "").strip() or None,
                   "gpu_event_count": trouble_count, "gpu_event_sample": trouble_sample},
        "drm": {"cards": cards},
        "vendor_tools": tools,
    }
    return sections, missing


def analyze_gpu(sections: dict) -> list[dict]:
    findings = []
    kernel = sections.get("kernel", {})
    count = kernel.get("gpu_event_count") or 0
    if count:
        findings.append(finding(
            "gpu.kernel_events", "gpu", WARNING if count >= 3 else INFO,
            CONFIRMED if count >= 3 else POSSIBLE,
            title=f"{count} GPU-related kernel warning/error events in this boot",
            evidence={"sample": kernel.get("gpu_event_sample", [])[:5]}, count=count,
            confidence="high" if count >= 3 else "low",
            probable_cause="Driver, firmware, or workload-triggered GPU recovery.",
            unverified="Whether these events coincided with a visible failure.",
            suggested_next_diagnostic="journal.kernel_errors"))
    for description in sections.get("driver", {}).get("devices_without_driver", []):
        findings.append(finding(
            "gpu.no_kernel_driver", "gpu", WARNING, CONFIRMED,
            title="A display device has no kernel driver bound",
            evidence={"device": description}, count=1, confidence="high",
            probable_cause="The matching kernel module is missing or failed to load.",
            suggested_next_diagnostic="gpu.pci_driver"))
    for card in sections.get("drm", {}).get("cards", []):
        temperature = card.get("temperature_celsius")
        if temperature is not None and temperature >= HIGH_TEMPERATURE:
            findings.append(finding(
                "gpu.temperature_high", "gpu",
                CRITICAL if temperature >= CRITICAL_TEMPERATURE else WARNING, CONFIRMED,
                title=f"{card['card']} is at {temperature} °C",
                evidence={"card": card["card"], "celsius": temperature}, count=1,
                confidence="high", probable_cause="Sustained load, poor airflow, or cooling failure.",
                suggested_next_diagnostic="gpu.temperature"))
    return findings


# ------------------------------------------------------------------------ MEMORY

def collect_memory() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    data = collect.meminfo()
    total, available = data.get("MemTotal", 0), data.get("MemAvailable", 0)
    swap_total, swap_free = data.get("SwapTotal", 0), data.get("SwapFree", 0)
    pressure = collect.read_text("/proc/pressure/memory")
    if pressure is None:
        missing.append(unavailable("memory pressure", "/proc/pressure/memory not available", "memory"))
    kernel_log = collect.journal("-k", "-b", "-p", "warning", "-n", "400")
    if kernel_log.get("status") != "ok":
        missing.append(unavailable("kernel journal", kernel_log.get("reason", "unavailable"), "memory"))
    oom_count, oom_sample = collect.count_matches(kernel_log, OOM_PATTERN)
    processes = collect.run(("ps", "-eo", "pid,%mem,rss,comm", "--sort=-%mem"), timeout=5)
    if processes.get("status") != "ok":
        missing.append(unavailable("ps", processes.get("reason", "unavailable"), "memory"))
    consumers = []
    for line in collect.lines(processes)[1:11]:
        fields = line.split(None, 3)
        if len(fields) == 4:
            consumers.append({"pid": fields[0], "memory_percent": fields[1],
                              "rss_kib": fields[2], "command": fields[3][:80]})
    return {
        "ram": {"total_bytes": total, "available_bytes": available,
                "used_percent": round((total - available) * 100 / total, 1) if total else None,
                # Cache and buffers are reclaimable; reported, never a finding.
                "cached_bytes": data.get("Cached", 0), "buffers_bytes": data.get("Buffers", 0),
                "cache_is_reclaimable": True},
        "swap": {"total_bytes": swap_total, "free_bytes": swap_free,
                 "used_percent": round((swap_total - swap_free) * 100 / swap_total, 1) if swap_total else None,
                 "swappiness": collect.read_int("/proc/sys/vm/swappiness")},
        "pressure": {"raw": pressure, "available": pressure is not None},
        "oom": {"event_count": oom_count, "sample": oom_sample},
        "top_consumers": consumers,
    }, missing


def analyze_memory(sections: dict) -> list[dict]:
    findings = []
    oom_count = sections.get("oom", {}).get("event_count") or 0
    if oom_count:
        findings.append(finding(
            "memory.oom_events", "memory", CRITICAL, CONFIRMED,
            title=f"{oom_count} out-of-memory kernel events in this boot",
            evidence={"sample": sections["oom"].get("sample", [])[:5]}, count=oom_count,
            confidence="high", probable_cause="A workload exceeded available memory and swap.",
            unverified="Which workload was responsible at the time.",
            suggested_next_diagnostic="journal.kernel_errors"))
    ram = sections.get("ram", {})
    used = ram.get("used_percent")
    if used is not None and used >= 95:
        findings.append(finding(
            "memory.low_available", "memory", WARNING, CONFIRMED,
            title=f"Only {round(100 - used, 1)}% of RAM is available",
            evidence={"used_percent": used, "note": "Page cache is excluded; this is MemAvailable."},
            count=1, confidence="high",
            probable_cause="Sustained real allocation, not reclaimable page cache.",
            suggested_next_diagnostic="memory.usage"))
    swap = sections.get("swap", {})
    swap_used = swap.get("used_percent")
    if swap.get("total_bytes") and swap_used is not None and swap_used >= 90:
        findings.append(finding(
            "memory.swap_exhausted", "memory", WARNING, CONFIRMED,
            title=f"Swap is {swap_used}% used", evidence={"used_percent": swap_used},
            count=1, confidence="high",
            probable_cause="Memory demand has exceeded RAM for a sustained period.",
            suggested_next_diagnostic="memory.usage"))
    return findings


# -------------------------------------------------------------------------- DISK

# Kernel pseudo-filesystems have no capacity worth reporting and are never a
# storage finding. tmpfs is kept: /run and /dev/shm can genuinely fill up.
PSEUDO_FILESYSTEMS = frozenset({
    "devtmpfs", "devpts", "proc", "sysfs", "cgroup", "cgroup2", "pstore", "bpf",
    "tracefs", "debugfs", "securityfs", "configfs", "fusectl", "efivarfs",
    "autofs", "binfmt_misc", "mqueue", "hugetlbfs", "nsfs", "ramfs", "fuse.portal",
})


def _real_filesystem(row: dict) -> bool:
    if row.get("fstype") in PSEUDO_FILESYSTEMS:
        return False
    if row.get("mountpoint", "").startswith(("/proc", "/sys", "/run/user", "/run/credentials")):
        return False
    # A zero-size mount carries no usable capacity information.
    return bool(row.get("total_bytes"))


def collect_disk() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    filesystems = collect.mounts()
    devices = collect.block_devices()
    lsblk = collect.run(("lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,RO", "-n"), timeout=5)
    if lsblk.get("status") != "ok":
        missing.append(unavailable("lsblk", lsblk.get("reason", "unavailable"), "disk"))
    kernel_log = collect.journal("-k", "-b", "-p", "warning", "-n", "400")
    if kernel_log.get("status") != "ok":
        missing.append(unavailable("kernel journal", kernel_log.get("reason", "unavailable"), "disk"))
    io_count, io_sample = collect.count_matches(kernel_log, _IO_ERROR)
    fs_count, fs_sample = collect.count_matches(kernel_log, _FS_ERROR)
    smart_available = collect.have("smartctl")
    if not smart_available:
        missing.append(unavailable("smartctl", "smartmontools not installed", "disk"))
    return {
        "filesystems": [row for row in filesystems if _real_filesystem(row)],
        "block_devices": {"devices": devices, "layout": collect.lines(lsblk, 40)},
        "errors": {"io_error_count": io_count, "io_error_sample": io_sample,
                   "filesystem_error_count": fs_count, "filesystem_error_sample": fs_sample},
        # SMART is elevated and stays approval-gated; nothing is read here.
        "smart": {"tool_available": smart_available, "collected": False,
                  "note": "SMART requires elevated access and one-time approval."},
    }, missing


def analyze_disk(sections: dict) -> list[dict]:
    findings = []
    for row in sections.get("filesystems", []):
        capacity = row.get("capacity_percent")
        if capacity is not None and capacity >= FULL_PERCENT:
            findings.append(finding(
                "disk.full", "disk", CRITICAL if capacity >= 98 else WARNING, CONFIRMED,
                title=f"{row['mountpoint']} is {capacity}% full",
                evidence={"mountpoint": row["mountpoint"], "capacity_percent": capacity},
                count=1, confidence="high", probable_cause="Accumulated data, logs, or caches.",
                suggested_next_diagnostic="filesystem.usage"))
        inodes = row.get("inode_percent")
        if inodes is not None and inodes >= FULL_PERCENT:
            findings.append(finding(
                "disk.inodes_exhausted", "disk", WARNING, CONFIRMED,
                title=f"{row['mountpoint']} has used {inodes}% of its inodes",
                evidence={"mountpoint": row["mountpoint"], "inode_percent": inodes},
                count=1, confidence="high", probable_cause="A very large number of small files.",
                suggested_next_diagnostic="filesystem.inodes"))
        if row.get("currently_read_only"):
            findings.append(finding(
                "disk.read_only_mount", "disk", CRITICAL, CONFIRMED,
                title=f"{row['mountpoint']} is mounted read-only",
                evidence={"mountpoint": row["mountpoint"], "fstype": row.get("fstype")},
                count=1, confidence="high",
                probable_cause="A filesystem error may have forced a read-only remount.",
                suggested_next_diagnostic="filesystem.mount_status"))
    errors = sections.get("errors", {})
    if errors.get("io_error_count"):
        findings.append(finding(
            "disk.io_errors", "disk", CRITICAL, CONFIRMED,
            title=f"{errors['io_error_count']} block I/O error events in this boot",
            evidence={"sample": errors.get("io_error_sample", [])[:5]},
            count=errors["io_error_count"], confidence="high",
            probable_cause="Failing media, cabling, or controller.",
            unverified="Device health; SMART data has not been read.",
            suggested_next_diagnostic="disk.smart_health"))
    if errors.get("filesystem_error_count"):
        findings.append(finding(
            "disk.filesystem_errors", "disk", WARNING, CONFIRMED,
            title=f"{errors['filesystem_error_count']} filesystem error events in this boot",
            evidence={"sample": errors.get("filesystem_error_sample", [])[:5]},
            count=errors["filesystem_error_count"], confidence="high",
            probable_cause="Filesystem inconsistency or an underlying device problem.",
            unverified="Whether the filesystem needs an offline check.",
            suggested_next_diagnostic="filesystem.mount_status"))
    return findings


# ----------------------------------------------------------------------- NETWORK

def collect_network() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    entries = []
    for name in collect.interfaces():
        base = f"/sys/class/net/{name}"
        entries.append({
            "interface": name,
            "operstate": collect.read_text(f"{base}/operstate"),
            "carrier": collect.read_int(f"{base}/carrier"),
            "mtu": collect.read_int(f"{base}/mtu"),
            "loopback": name == "lo",
            "wireless": Path(f"{base}/wireless").exists() or Path(f"{base}/phy80211").exists(),
        })
    routes = collect.run(("ip", "route", "show", "default"), timeout=5)
    if routes.get("status") != "ok":
        missing.append(unavailable("ip route", routes.get("reason", "unavailable"), "network"))
    resolver = collect.run(("resolvectl", "status"), timeout=5)
    if resolver.get("status") != "ok":
        missing.append(unavailable("resolvectl", resolver.get("reason", "unavailable"), "network"))
    try:
        socket.getaddrinfo("example.com", 443)
        resolved = True
    except socket.gaierror:
        resolved = False
    except OSError:
        resolved = None
        missing.append(unavailable("dns resolution", "name resolution could not be attempted", "network"))
    sockets = collect.run(("ss", "-tulnH"), timeout=5)
    if sockets.get("status") != "ok":
        missing.append(unavailable("ss", sockets.get("reason", "unavailable"), "network"))
    listening = collect.lines(sockets)
    kernel_log = collect.journal("-k", "-b", "-n", "400")
    if kernel_log.get("status") != "ok":
        missing.append(unavailable("kernel journal", kernel_log.get("reason", "unavailable"), "network"))
    link_count, link_sample = collect.count_matches(kernel_log, LINK_EVENT)
    driver_count, driver_sample = collect.count_matches(kernel_log, _NET_DRIVER_ERROR)
    return {
        "interfaces": {"entries": entries,
                       "up": [e["interface"] for e in entries if e["operstate"] == "up"],
                       "down": [e["interface"] for e in entries
                                if e["operstate"] not in ("up", "unknown") and not e["loopback"]]},
        "routing": {"default_route_present": bool(collect.lines(routes)),
                    "default_routes": len(collect.lines(routes))},
        # Resolver detail is deliberately reduced to state, never addresses.
        "dns": {"resolver_configured": bool(collect.lines(resolver)),
                "resolution_succeeded": resolved},
        "sockets": {"listening_count": len(listening),
                    "tcp_listening": sum(1 for line in listening if line.startswith("tcp")),
                    "udp_listening": sum(1 for line in listening if line.startswith("udp"))},
        "events": {"link_event_count": link_count, "link_event_sample": link_sample,
                   "driver_error_count": driver_count, "driver_error_sample": driver_sample},
    }, missing


def analyze_network(sections: dict) -> list[dict]:
    findings = []
    if not sections.get("routing", {}).get("default_route_present"):
        findings.append(finding(
            "network.no_default_route", "network", WARNING, CONFIRMED,
            title="No default route is configured", evidence={"default_routes": 0},
            count=1, confidence="high", probable_cause="No usable uplink or DHCP has not completed.",
            suggested_next_diagnostic="network.route"))
    dns = sections.get("dns", {})
    if dns.get("resolution_succeeded") is False:
        findings.append(finding(
            "network.dns_failure", "network", WARNING, CONFIRMED,
            title="DNS name resolution failed", evidence={"resolution_succeeded": False},
            count=1, confidence="high", probable_cause="Resolver misconfiguration or no connectivity.",
            suggested_next_diagnostic="dns.resolution"))
    events = sections.get("events", {})
    link_count = events.get("link_event_count") or 0
    if link_count >= 4:
        findings.append(finding(
            "network.link_flapping", "network", WARNING, PROBABLE,
            title=f"{link_count} link state changes in this boot",
            evidence={"sample": events.get("link_event_sample", [])[:5]}, count=link_count,
            confidence="medium", probable_cause="Cabling, switch port, driver, or power-management instability.",
            unverified="Whether the changes were user-initiated (suspend, reconnect).",
            suggested_next_diagnostic="network.link_stats"))
    if events.get("driver_error_count"):
        findings.append(finding(
            "network.driver_errors", "network", WARNING, CONFIRMED,
            title=f"{events['driver_error_count']} network driver error events in this boot",
            evidence={"sample": events.get("driver_error_sample", [])[:5]},
            count=events["driver_error_count"], confidence="high",
            probable_cause="Network adapter driver or firmware fault.",
            suggested_next_diagnostic="network.interface_driver"))
    return findings


# -------------------------------------------------------------------------- BOOT

def _boot_timing() -> tuple[dict, str | None]:
    result = collect.run(("systemd-analyze", "time"), timeout=8)
    if result.get("status") != "ok" or result.get("exit_code") != 0:
        return {"available": False}, result.get("reason", "systemd-analyze reported no timing")
    text = " ".join(collect.lines(result))
    timings = {}
    for label in ("firmware", "loader", "kernel", "initrd", "userspace"):
        match = re.search(rf"([\d.]+)(min|ms|s)?\s*\({label}\)", text)
        if not match:
            continue
        value = float(match.group(1))
        unit = match.group(2) or "s"
        timings[label] = round(value * {"min": 60, "s": 1, "ms": 0.001}[unit], 3)
    total = re.search(r"graphical\.target reached after ([\d.]+)(min|ms|s)?", text)
    if total:
        timings["to_graphical_target"] = round(
            float(total.group(1)) * {"min": 60, "s": 1, "ms": 0.001}[total.group(2) or "s"], 3)
    return {"available": True, "seconds": timings, "raw": text[:400]}, None


def collect_boot() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    timing, timing_error = _boot_timing()
    if timing_error:
        missing.append(unavailable("systemd-analyze", timing_error, "boot"))
    failed = collect.run(("systemctl", "--failed", "--no-pager", "--plain", "--no-legend"), timeout=6)
    if failed.get("status") != "ok":
        missing.append(unavailable("systemctl --failed", failed.get("reason", "unavailable"), "boot"))
    failed_units = [line.split()[0] for line in collect.lines(failed)
                    if line.split() and _UNIT.match(line.split()[0])]
    critical = collect.journal("-b", "-p", "crit", "-n", "100")
    errors = collect.journal("-b", "-p", "err", "-n", "200")
    if errors.get("status") != "ok":
        missing.append(unavailable("journal", errors.get("reason", "unavailable"), "boot"))
    uptime = collect.uptime_seconds()
    return {
        "current_boot": {"uptime_seconds": uptime,
                         "kernel": (collect.read_text("/proc/sys/kernel/osrelease") or "").strip() or None,
                         "kernel_cmdline_present": bool(collect.read_text("/proc/cmdline"))},
        "timing": timing,
        "units": {"failed_count": len(failed_units), "failed_units": failed_units},
        "journal": {"critical_count": len(collect.lines(critical)),
                    "critical_sample": collect.lines(critical, 5),
                    "error_count": len(collect.lines(errors)),
                    "error_sample": collect.lines(errors, 8)},
        "reboot_required": {"required": Path("/var/run/reboot-required").exists(),
                            "packages": (collect.read_text("/var/run/reboot-required.pkgs") or "").splitlines()[:20]},
    }, missing


def analyze_boot(sections: dict) -> list[dict]:
    findings = []
    units = sections.get("units", {})
    if units.get("failed_count"):
        findings.append(finding(
            "boot.failed_units", "boot", WARNING, CONFIRMED,
            title=f"{units['failed_count']} unit(s) failed during this boot",
            evidence={"units": units.get("failed_units", [])[:10]}, count=units["failed_count"],
            confidence="high", probable_cause="A service failed to start or exited with an error.",
            suggested_next_diagnostic="systemd.unit_status"))
    journal = sections.get("journal", {})
    critical_count = journal.get("critical_count") or 0
    if critical_count:
        # One critical entry in a boot is common (a suspend or a firmware
        # complaint); a run of them is what actually warrants alarm.
        findings.append(finding(
            "boot.critical_journal", "boot",
            CRITICAL if critical_count >= 5 else WARNING, CONFIRMED,
            title=f"{journal['critical_count']} critical journal entries in this boot",
            evidence={"sample": journal.get("critical_sample", [])[:5]},
            count=journal["critical_count"], confidence="high",
            probable_cause="A subsystem reported a critical condition.",
            suggested_next_diagnostic="journal.kernel_errors"))
    timing = sections.get("timing", {})
    total = (timing.get("seconds") or {}).get("to_graphical_target")
    userspace = (timing.get("seconds") or {}).get("userspace")
    slowest = total or userspace
    if slowest is not None and slowest >= 90:
        findings.append(finding(
            "boot.slow", "boot", INFO, POSSIBLE,
            title=f"Boot reached its target after {slowest}s",
            evidence={"seconds": timing.get("seconds", {})}, count=1, confidence="low",
            probable_cause="A slow unit, network wait, or storage delay during startup.",
            unverified="Which unit dominated the delay.",
            suggested_next_diagnostic="boot.blame"))
    if sections.get("reboot_required", {}).get("required"):
        findings.append(finding(
            "boot.reboot_required", "boot", INFO, INFORMATIONAL,
            title="A reboot is required to finish applying updates",
            evidence={"packages": sections["reboot_required"].get("packages", [])[:10]},
            count=1, confidence="high", probable_cause="Package updates replaced running components."))
    return findings


# ---------------------------------------------------------------------- SERVICES

def collect_services() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    state = collect.run(("systemctl", "is-system-running"), timeout=5)
    if state.get("status") != "ok":
        missing.append(unavailable("systemctl", state.get("reason", "unavailable"), "services"))
    failed = collect.run(("systemctl", "--failed", "--no-pager", "--plain", "--no-legend"), timeout=6)
    failed_units = [line.split()[0] for line in collect.lines(failed)
                    if line.split() and _UNIT.match(line.split()[0])]
    log = collect.journal("-b", "-p", "warning", "-n", "400")
    if log.get("status") != "ok":
        missing.append(unavailable("journal", log.get("reason", "unavailable"), "services"))
    restart_counts: dict[str, int] = {}
    for line in collect.lines(log):
        if not _RESTART_LOOP.search(line):
            continue
        unit = re.search(r"\b([A-Za-z0-9_.@\\-]+\.service)\b", line)
        if unit:
            restart_counts[unit.group(1)] = restart_counts.get(unit.group(1), 0) + 1
    recent_failures = [line.strip()[:240] for line in collect.lines(log)
                       if re.search(r"failed (?:to start|with result)", line, re.I)][-10:]
    return {
        "state": {"system_state": (collect.lines(state) or [None])[0],
                  "degraded": (collect.lines(state) or [""])[0] == "degraded"},
        "failed": {"count": len(failed_units), "units": failed_units},
        "restarting": {"units": [{"unit": unit, "events": count}
                                 for unit, count in sorted(restart_counts.items())
                                 if count >= 2]},
        "recent_failures": {"count": len(recent_failures), "sample": recent_failures},
    }, missing


def analyze_services(sections: dict) -> list[dict]:
    findings = []
    failed = sections.get("failed", {})
    if failed.get("count"):
        findings.append(finding(
            "services.failed", "services", WARNING, CONFIRMED,
            title=f"{failed['count']} systemd unit(s) are in a failed state",
            evidence={"units": failed.get("units", [])[:10]}, count=failed["count"],
            confidence="high", probable_cause="The unit exited non-zero or its start timed out.",
            unverified="The specific failure reason for each unit.",
            suggested_next_diagnostic="systemd.unit_status"))
    elif sections.get("state", {}).get("degraded"):
        findings.append(finding(
            "services.degraded", "services", WARNING, CONFIRMED,
            title="systemd reports the system as degraded",
            evidence={"system_state": "degraded"}, count=1, confidence="high",
            suggested_next_diagnostic="services.list_failed"))
    for entry in sections.get("restarting", {}).get("units", []):
        findings.append(finding(
            "services.restart_loop", "services", WARNING, PROBABLE,
            title=f"{entry['unit']} restarted repeatedly during this boot",
            evidence=entry, count=entry["events"], confidence="medium",
            probable_cause="The unit exits immediately and systemd keeps restarting it.",
            unverified="Whether the restarts were expected for this unit.",
            suggested_next_diagnostic="systemd.unit_logs"))
    return findings


# ---------------------------------------------------------------------- PACKAGES

_DPKG_LINE = re.compile(
    r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) (install|upgrade|remove|purge) "
    r"(\S+) (\S+) (\S+)$")


def dpkg_history(limit: int = 200) -> list[dict]:
    """Parse /var/log/dpkg.log deterministically; no shell, no globbing beyond the log."""
    entries: list[dict] = []
    for name in ("/var/log/dpkg.log.1", "/var/log/dpkg.log"):
        text = collect.read_tail(name, 2_000_000)
        if not text:
            continue
        for line in text.splitlines():
            match = _DPKG_LINE.match(line.strip())
            if not match:
                continue
            date, clock, action, package, previous, current = match.groups()
            entries.append({"timestamp": f"{date} {clock}", "action": action,
                            "package": package.split(":")[0],
                            "previous_version": None if previous == "<none>" else previous,
                            "version": None if current == "<none>" else current})
    entries.sort(key=lambda item: item["timestamp"])
    return entries[-limit:]


def collect_packages() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    if not collect.have("dpkg"):
        missing.append(unavailable("dpkg", "no dpkg package manager on this system", "packages"))
        return {"manager": {"name": None, "supported": False}}, missing
    audit = collect.run(("dpkg", "--audit"), timeout=8)
    if audit.get("status") != "ok":
        missing.append(unavailable("dpkg --audit", audit.get("reason", "unavailable"), "packages"))
    interrupted_updates = []
    try:
        interrupted_updates = [path.name for path in Path("/var/lib/dpkg/updates").iterdir()][:20]
    except OSError:
        pass
    upgrades = collect.run(("apt", "list", "--upgradable"), timeout=10) if collect.have("apt") else {
        "status": "unavailable", "reason": "apt not installed"}
    if upgrades.get("status") != "ok":
        missing.append(unavailable("apt list --upgradable", upgrades.get("reason", "unavailable"), "packages"))
    upgradable = [line for line in collect.lines(upgrades)
                  if "/" in line and not line.startswith("Listing")]
    held = collect.run(("apt-mark", "showhold"), timeout=8) if collect.have("apt-mark") else {
        "status": "unavailable", "reason": "apt-mark not installed"}
    if held.get("status") != "ok":
        missing.append(unavailable("apt-mark showhold", held.get("reason", "unavailable"), "packages"))
    installed = collect.run(("dpkg-query", "-f", "${binary:Package}\n", "-W"), timeout=10, limit=400_000)
    history = dpkg_history()
    return {
        "manager": {"name": "dpkg", "supported": True,
                    "installed_count": len(collect.lines(installed)) or None},
        "integrity": {"audit_clean": audit.get("status") == "ok" and not audit.get("output"),
                      "audit_output": (audit.get("output") or "")[:1000],
                      "interrupted_updates": interrupted_updates,
                      "dpkg_interrupted": bool(interrupted_updates)},
        "upgrades": {"available": len(upgradable) if upgrades.get("status") == "ok" else None,
                     "sample": [line.split("/")[0] for line in upgradable[:15]]},
        "held": {"packages": collect.lines(held)[:20]},
        "recent_changes": {"count": len(history), "entries": history[-25:]},
        "reboot_required": {"required": Path("/var/run/reboot-required").exists()},
    }, missing


def analyze_packages(sections: dict) -> list[dict]:
    findings = []
    if not sections.get("manager", {}).get("supported"):
        return findings
    integrity = sections.get("integrity", {})
    if integrity.get("dpkg_interrupted") or not integrity.get("audit_clean", True):
        findings.append(finding(
            "packages.dpkg_interrupted", "packages", WARNING, CONFIRMED,
            title="dpkg reports an incomplete or interrupted package operation",
            evidence={"interrupted_updates": integrity.get("interrupted_updates", [])[:5],
                      "audit_output": integrity.get("audit_output", "")[:400]},
            count=1, confidence="high",
            probable_cause="A package operation was interrupted before it finished.",
            suggested_next_diagnostic="package.dpkg_audit"))
    upgrades = sections.get("upgrades", {}).get("available")
    if upgrades:
        findings.append(finding(
            "packages.pending_upgrades", "packages", INFO, INFORMATIONAL,
            title=f"{upgrades} package upgrade(s) are available",
            evidence={"sample": sections["upgrades"].get("sample", [])[:10]},
            count=upgrades, confidence="high"))
    held = sections.get("held", {}).get("packages", [])
    if held:
        findings.append(finding(
            "packages.held", "packages", INFO, INFORMATIONAL,
            title=f"{len(held)} package(s) are held at their current version",
            evidence={"packages": held[:10]}, count=len(held), confidence="high"))
    if sections.get("reboot_required", {}).get("required"):
        findings.append(finding(
            "packages.reboot_required", "packages", INFO, INFORMATIONAL,
            title="A reboot is required to finish applying updates",
            evidence={"required": True}, count=1, confidence="high"))
    return findings


# ----------------------------------------------------------------------- THERMAL

def _hwmon() -> list[dict]:
    readings = []
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        name = collect.read_text(str(hwmon / "name")) or hwmon.name
        for sensor in sorted(hwmon.glob("temp*_input")):
            value = collect.read_int(str(sensor))
            if value is None:
                continue
            label = collect.read_text(str(sensor).replace("_input", "_label"))
            readings.append({"chip": name, "sensor": sensor.name, "label": label,
                             "celsius": round(value / 1000, 1), "kind": "temperature"})
        for sensor in sorted(hwmon.glob("fan*_input")):
            value = collect.read_int(str(sensor))
            if value is None:
                continue
            readings.append({"chip": name, "sensor": sensor.name,
                             "label": collect.read_text(str(sensor).replace("_input", "_label")),
                             "rpm": value, "kind": "fan"})
    return readings


def _throttle_counters() -> dict:
    total = {}
    for name in ("core_throttle_count", "package_throttle_count"):
        counted = 0
        found = False
        for path in sorted(Path("/sys/devices/system/cpu").glob(f"cpu[0-9]*/thermal_throttle/{name}")):
            value = collect.read_int(str(path))
            if value is not None:
                found = True
                counted += value
        if found:
            total[name] = counted
    return total


def collect_thermal() -> tuple[dict, list[dict]]:
    missing: list[dict] = []
    zones = collect.thermal_zones()
    readings = _hwmon()
    if not zones and not readings:
        # Unavailable sensors are normal on many machines, never an error.
        missing.append(unavailable("thermal sensors", "no thermal zone or hwmon sensor exposed", "thermal"))
    sensors = collect.run(("sensors", "-A"), timeout=6)
    if sensors.get("status") != "ok":
        missing.append(unavailable("sensors", sensors.get("reason", "unavailable"), "thermal"))
    counters = _throttle_counters()
    if not counters:
        missing.append(unavailable("cpu throttle counters", "not exposed by this kernel/CPU", "thermal"))
    kernel_log = collect.journal("-k", "-b", "-n", "400")
    throttle_count, throttle_sample = collect.count_matches(kernel_log, THROTTLE)
    temperatures = [r["celsius"] for r in readings if r["kind"] == "temperature"]
    temperatures += [z["celsius"] for z in zones]
    fans = [r for r in readings if r["kind"] == "fan"]
    return {
        "zones": {"count": len(zones), "zones": zones},
        "sensors": {"available": bool(readings) or sensors.get("status") == "ok",
                    "readings": [r for r in readings if r["kind"] == "temperature"][:40],
                    "tool_output": collect.lines(sensors, 40)},
        "fans": {"count": len(fans), "fans": fans[:20]},
        "summary": {"max_celsius": max(temperatures) if temperatures else None,
                    "sensor_count": len(temperatures)},
        "throttling": {"counters": counters, "kernel_event_count": throttle_count,
                       "kernel_event_sample": throttle_sample},
    }, missing


def analyze_thermal(sections: dict) -> list[dict]:
    findings = []
    hottest = sections.get("summary", {}).get("max_celsius")
    if hottest is not None and hottest >= HIGH_TEMPERATURE:
        findings.append(finding(
            "thermal.high_temperature", "thermal",
            CRITICAL if hottest >= CRITICAL_TEMPERATURE else WARNING, CONFIRMED,
            title=f"Hottest reported sensor is {hottest} °C",
            evidence={"max_celsius": hottest}, count=1, confidence="high",
            probable_cause="Sustained load, restricted airflow, or degraded cooling.",
            unverified="Whether the reading was a brief peak or sustained.",
            suggested_next_diagnostic="gpu.temperature"))
    throttling = sections.get("throttling", {})
    if throttling.get("kernel_event_count"):
        findings.append(finding(
            "thermal.throttling", "thermal", WARNING, CONFIRMED,
            title=f"{throttling['kernel_event_count']} thermal throttling events in this boot",
            evidence={"sample": throttling.get("kernel_event_sample", [])[:5]},
            count=throttling["kernel_event_count"], confidence="high",
            probable_cause="The CPU or GPU reduced clocks to stay within its thermal limit.",
            suggested_next_diagnostic="journal.kernel_errors"))
    counters = throttling.get("counters", {})
    if counters.get("package_throttle_count"):
        findings.append(finding(
            "thermal.throttle_counter", "thermal", INFO, INFORMATIONAL,
            title=f"CPU package throttle counter is {counters['package_throttle_count']}",
            evidence=counters, count=counters["package_throttle_count"], confidence="high",
            probable_cause="Cumulative since boot; a non-zero counter alone is not a fault."))
    return findings


# ------------------------------------------------------------------- entry point

_COLLECTORS = {
    "gpu": (collect_gpu, analyze_gpu),
    "memory": (collect_memory, analyze_memory),
    "disk": (collect_disk, analyze_disk),
    "network": (collect_network, analyze_network),
    "boot": (collect_boot, analyze_boot),
    "services": (collect_services, analyze_services),
    "packages": (collect_packages, analyze_packages),
    "thermal": (collect_thermal, analyze_thermal),
}


def collect_domain(domain: str) -> tuple[dict, list[dict], list[dict]]:
    """Return ``(sections, findings, unavailable)`` for one domain."""
    if domain not in _COLLECTORS:
        raise ValueError(f"unknown diagnostic domain: {domain}")
    collector, analyzer = _COLLECTORS[domain]
    try:
        sections, missing = collector()
    except OSError as exc:
        return {}, [], [unavailable(domain, str(exc), domain)]
    return sections, sort_findings(analyzer(sections)), missing


def collect_scope(scope: str, progress=None, web: bool = False, command: str | None = None) -> dict:
    """Collect one domain, or every domain concurrently for ``full_system``."""
    if scope != FULL_SYSTEM:
        sections, findings, missing = collect_domain(scope)
        if progress:
            progress(scope)
        return build(command=command or scope, scope=scope, sections=sections,
                     findings=findings, unavailable_checks=missing, web=web)
    sections: dict = {}
    findings: list[dict] = []
    missing: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(DOMAINS)) as pool:
        futures = {pool.submit(collect_domain, domain): domain for domain in DOMAINS}
        for domain in DOMAINS:
            future = next(f for f, name in futures.items() if name == domain)
            try:
                domain_sections, domain_findings, domain_missing = future.result()
            except Exception as exc:  # a collector must never abort the whole scan
                sections[domain] = {}
                missing.append(unavailable(domain, str(exc), domain))
            else:
                sections[domain] = domain_sections
                findings.extend(domain_findings)
                missing.extend(domain_missing)
            if progress:
                progress(domain)
    return build(command=command or "health", scope=FULL_SYSTEM, sections=sections,
                 findings=sort_findings(findings), unavailable_checks=missing, web=web)


def trusted_values(document: dict) -> dict:
    """Collector-derived values an audited action parameter may reference."""
    scope = document.get("request", {}).get("scope")
    sections = document.get("sections", {})
    if scope == FULL_SYSTEM:
        merged: dict = {}
        for domain_sections in sections.values():
            if isinstance(domain_sections, dict):
                merged.update(domain_sections)
        sections = merged
    units = set()
    for key in ("units", "failed"):
        units.update(sections.get(key, {}).get("failed_units", []) or [])
        units.update(sections.get(key, {}).get("units", []) or [])
    for entry in sections.get("restarting", {}).get("units", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("unit"), str):
            units.add(entry["unit"])
    packages = set(sections.get("upgrades", {}).get("sample", []) or [])
    packages.update(sections.get("held", {}).get("packages", []) or [])
    interfaces = {entry.get("interface") for entry in
                  sections.get("interfaces", {}).get("entries", []) or []
                  if isinstance(entry, dict)}
    return {"units": {unit for unit in units if isinstance(unit, str)},
            "packages": {name for name in packages if isinstance(name, str)},
            "interfaces": {name for name in interfaces if isinstance(name, str)}}
