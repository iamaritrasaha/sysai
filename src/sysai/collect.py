"""Deterministic read-only collection primitives shared by every domain.

Every process here is started with a fixed argv resolved through
``shutil.which``. There is no shell, no ``bash -c``, and no string
interpolation of user or model text into a command line.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .display import plain_terminal_text
from .privacy import LOCAL, sanitize_text

TIMEOUT = 3
MAX_OUTPUT = 12_000


def have(program: str) -> bool:
    return shutil.which(program) is not None


def read_text(path: str, limit: int = MAX_OUTPUT) -> str | None:
    try:
        return Path(path).read_text(errors="replace")[:limit].strip()
    except OSError:
        return None


def read_tail(path: str, limit: int = 400_000) -> str | None:
    """Read the END of a growing log file.

    Log files are appended to, so the interesting entries are the newest ones.
    Reading the head of a multi-megabyte dpkg.log would silently return the
    oldest history instead. The first partial line is discarded.
    """
    try:
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            data = handle.read(limit)
    except OSError:
        return None
    text = data.decode("utf-8", "replace")
    return text.partition("\n")[2] if size > limit else text


def read_int(path: str) -> int | None:
    value = read_text(path, 64)
    try:
        return int((value or "").strip())
    except ValueError:
        return None


def run(argv: tuple[str, ...], timeout: int = TIMEOUT, limit: int = MAX_OUTPUT) -> dict:
    """Run one audited fixed argv. Callers in SysAI supply the argv, never a model."""
    executable = shutil.which(argv[0])
    if not executable:
        return {"status": "unavailable", "reason": f"{argv[0]} not installed"}
    try:
        result = subprocess.run(
            (executable, *argv[1:]), stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "reason": "timed out"}
    except OSError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    output = plain_terminal_text(sanitize_text((result.stdout or "") + (result.stderr or ""), LOCAL))
    return {"status": "ok", "exit_code": result.returncode,
            "output": output[:limit].strip(), "output_truncated": len(output) > limit}


def lines(result: dict, keep: int | None = None) -> list[str]:
    """Non-empty output lines of a `run` result, oldest first."""
    if result.get("status") != "ok":
        return []
    values = [line for line in result.get("output", "").splitlines() if line.strip()]
    return values[-keep:] if keep else values


def ok(result: dict) -> bool:
    return result.get("status") == "ok" and result.get("exit_code") == 0


def journal(*arguments: str, timeout: int = 6, limit: int = MAX_OUTPUT) -> dict:
    return run(("journalctl", "--no-pager", *arguments), timeout=timeout, limit=limit)


def count_matches(result: dict, pattern: re.Pattern[str], keep: int = 12) -> tuple[int, list[str]]:
    """Total matching lines plus a bounded, de-duplicated sample of them."""
    matched = [line for line in lines(result) if pattern.search(line)]
    sample, seen = [], set()
    for line in matched:
        signature = re.sub(r"\b(?:0x[0-9a-f]+|\d+(?:\.\d+)?)\b", "#", line, flags=re.I)
        if signature in seen:
            continue
        seen.add(signature)
        sample.append(line.strip()[:300])
        if len(sample) >= keep:
            break
    return len(matched), sample


def meminfo() -> dict:
    data = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            try:
                data[key] = int(value.split()[0]) * 1024
            except (IndexError, ValueError):
                continue
    return data


def uptime_seconds() -> float | None:
    fields = (read_text("/proc/uptime") or "").split()
    try:
        return float(fields[0])
    except (IndexError, ValueError):
        return None


def block_devices() -> list[str]:
    try:
        return sorted(f"/dev/{path.name}" for path in Path("/sys/block").glob("*")
                      if not path.name.startswith(("loop", "ram", "zram")))
    except OSError:
        return []


def mounts() -> list[dict]:
    rows = []
    for line in (read_text("/proc/mounts", 200_000) or "").splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        device, point, fstype, options = fields[:4]
        # Snap squashfs images are read-only by design and never a finding.
        if fstype == "squashfs" and point.startswith("/snap/"):
            continue
        try:
            info = os.statvfs(point)
        except OSError:
            continue
        total = info.f_blocks * info.f_frsize
        used = (info.f_blocks - info.f_bfree) * info.f_frsize
        rows.append({
            "device": device, "mountpoint": point, "fstype": fstype,
            "mount_options": options.split(","),
            "currently_read_only": "ro" in options.split(","),
            "capacity_percent": round(used * 100 / total, 1) if total else None,
            "inode_percent": round((info.f_files - info.f_ffree) * 100 / info.f_files, 1) if info.f_files else None,
            "total_bytes": total,
        })
    return rows


def thermal_zones() -> list[dict]:
    zones = []
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        millidegrees = read_int(str(zone / "temp"))
        if millidegrees is None:
            continue
        zones.append({"sensor": zone.name, "label": read_text(str(zone / "type")) or "unknown",
                      "celsius": round(millidegrees / 1000, 1)})
    return zones


def interfaces() -> list[str]:
    try:
        return sorted(path.name for path in Path("/sys/class/net").iterdir())
    except OSError:
        return []
