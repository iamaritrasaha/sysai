"""`sysai watch`: bounded, foreground-only sampling.

There is no daemon, no background service, no timer, and no startup unit.
Sampling runs in the foreground for a bounded window, keeps samples in
memory only, and discards them once the summary is produced. The local model
is called at most once, after sampling finishes, never per sample.
"""
from __future__ import annotations

import datetime as dt
import os
import time

from . import collect
from .domains import (GPU_TROUBLE, HIGH_TEMPERATURE, LINK_EVENT, OOM_PATTERN,
                      THROTTLE, drm_cards)
from .evidence import CONFIRMED, INFO, INFORMATIONAL, WARNING, build, finding

WATCHABLE = ("gpu", "memory", "network", "thermal", "system")
DEFAULT_DURATION = 30
MAX_DURATION = 300
MIN_DURATION = 1
MIN_INTERVAL = 1
MAX_INTERVAL = 60


class WatchError(ValueError):
    pass


def validate(duration: int, interval: int) -> tuple[int, int]:
    """Reject out-of-range windows outright rather than silently clamping."""
    if interval < MIN_INTERVAL:
        raise WatchError(f"--interval must be at least {MIN_INTERVAL} second.")
    if interval > MAX_INTERVAL:
        raise WatchError(f"--interval must be at most {MAX_INTERVAL} seconds.")
    if duration < MIN_DURATION:
        raise WatchError(f"--duration must be at least {MIN_DURATION} second.")
    if duration > MAX_DURATION:
        raise WatchError(f"--duration must be at most {MAX_DURATION} seconds "
                         "(SysAI does not run continuous monitoring).")
    if interval > duration:
        raise WatchError("--interval cannot be longer than --duration.")
    return duration, interval


# --------------------------------------------------------------------- samplers

def _sample_gpu() -> dict:
    sample = {"cards": []}
    for card in drm_cards():
        sample["cards"].append({
            "card": card["card"], "temperature_celsius": card.get("temperature_celsius"),
            "vram_used_bytes": card.get("vram_used_bytes"),
            "vram_total_bytes": card.get("vram_total_bytes"),
            "gpu_busy_percent": card.get("gpu_busy_percent"),
        })
    return sample


def _sample_memory() -> dict:
    data = collect.meminfo()
    total, available = data.get("MemTotal", 0), data.get("MemAvailable", 0)
    swap_total, swap_free = data.get("SwapTotal", 0), data.get("SwapFree", 0)
    return {"available_bytes": available, "total_bytes": total,
            "used_percent": round((total - available) * 100 / total, 1) if total else None,
            "swap_used_bytes": swap_total - swap_free, "cached_bytes": data.get("Cached", 0)}


def _sample_network() -> dict:
    entries = []
    for name in collect.interfaces():
        base = f"/sys/class/net/{name}"
        entries.append({"interface": name,
                        "operstate": collect.read_text(f"{base}/operstate"),
                        "carrier": collect.read_int(f"{base}/carrier"),
                        "rx_bytes": collect.read_int(f"{base}/statistics/rx_bytes"),
                        "tx_bytes": collect.read_int(f"{base}/statistics/tx_bytes"),
                        "rx_errors": collect.read_int(f"{base}/statistics/rx_errors"),
                        "tx_errors": collect.read_int(f"{base}/statistics/tx_errors")})
    return {"interfaces": entries}


def _sample_thermal() -> dict:
    zones = collect.thermal_zones()
    temperatures = [zone["celsius"] for zone in zones]
    return {"zones": zones, "max_celsius": max(temperatures) if temperatures else None}


def _sample_system() -> dict:
    load = (collect.read_text("/proc/loadavg") or "").split()[:3]
    return {"load": load, **_sample_memory(), "thermal": _sample_thermal()}


_SAMPLERS = {"gpu": _sample_gpu, "memory": _sample_memory, "network": _sample_network,
             "thermal": _sample_thermal, "system": _sample_system}

_KERNEL_PATTERNS = {"gpu": GPU_TROUBLE, "memory": OOM_PATTERN,
                    "network": LINK_EVENT, "thermal": THROTTLE}


def sample(domain: str) -> dict:
    sampler = _SAMPLERS.get(domain)
    if sampler is None:
        raise WatchError(f"`{domain}` cannot be watched. Choose one of: {', '.join(WATCHABLE)}.")
    return {"at": time.time(), **sampler()}


def run_watch(domain: str, duration: int, interval: int, *, on_sample=None,
              sleep=None, clock=None) -> dict:
    """Collect bounded in-memory samples. Ctrl+C stops cleanly and still summarizes."""
    # Resolved here rather than bound as defaults, so the clock stays injectable.
    sleep = sleep or time.sleep
    clock = clock or time.monotonic
    duration, interval = validate(duration, interval)
    if domain not in _SAMPLERS:
        raise WatchError(f"`{domain}` cannot be watched. Choose one of: {', '.join(WATCHABLE)}.")
    started_wall = time.time()
    deadline = clock() + duration
    samples: list[dict] = []
    interrupted = False
    try:
        while True:
            samples.append(sample(domain))
            if on_sample:
                on_sample(len(samples), samples[-1])
            remaining = deadline - clock()
            if remaining <= 0:
                break
            sleep(min(interval, remaining))
            if clock() >= deadline:
                samples.append(sample(domain))
                if on_sample:
                    on_sample(len(samples), samples[-1])
                break
    except KeyboardInterrupt:
        interrupted = True
    return {"domain": domain, "requested_duration": duration, "interval": interval,
            "samples": samples, "sample_count": len(samples), "interrupted": interrupted,
            "started_wall": started_wall, "ended_wall": time.time()}


# --------------------------------------------------------------------- summaries

def _series(samples: list[dict], reader) -> list[float]:
    values = []
    for item in samples:
        value = reader(item)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def _range(values: list[float]) -> dict | None:
    if not values:
        return None
    return {"first": values[0], "last": values[-1], "min": min(values), "max": max(values),
            "change": round(values[-1] - values[0], 3)}


def summarize(result: dict) -> dict:
    """All arithmetic is done here; the model receives the numbers, not the samples."""
    domain, samples = result["domain"], result["samples"]
    metrics: dict[str, dict] = {}
    events: list[dict] = []
    if domain == "gpu":
        names = sorted({card["card"] for item in samples for card in item.get("cards", [])})
        for name in names:
            def card_value(item, key, card_name=name):
                for card in item.get("cards", []):
                    if card["card"] == card_name:
                        return card.get(key)
                return None
            temperature = _range(_series(samples, lambda item: card_value(item, "temperature_celsius")))
            if temperature:
                metrics[f"{name} temperature (°C)"] = temperature
            vram = _range(_series(samples, lambda item: card_value(item, "vram_used_bytes")))
            if vram:
                metrics[f"{name} VRAM used (bytes)"] = vram
            busy = _range(_series(samples, lambda item: card_value(item, "gpu_busy_percent")))
            if busy:
                metrics[f"{name} busy (%)"] = busy
    elif domain in ("memory", "system"):
        for key, label in (("used_percent", "RAM used (%)"),
                           ("available_bytes", "RAM available (bytes)"),
                           ("swap_used_bytes", "Swap used (bytes)"),
                           ("cached_bytes", "Cache (bytes)")):
            value = _range(_series(samples, lambda item, key=key: item.get(key)))
            if value:
                metrics[label] = value
        if domain == "system":
            thermal = _range(_series(samples, lambda item: (item.get("thermal") or {}).get("max_celsius")))
            if thermal:
                metrics["Hottest sensor (°C)"] = thermal
    elif domain == "network":
        names = sorted({entry["interface"] for item in samples
                        for entry in item.get("interfaces", [])})
        for name in names:
            def interface_value(item, key, interface=name):
                for entry in item.get("interfaces", []):
                    if entry["interface"] == interface:
                        return entry.get(key)
                return None
            states = [interface_value(item, "operstate") for item in samples]
            transitions = sum(1 for a, b in zip(states, states[1:]) if a != b)
            if transitions:
                events.append({"kind": "link_state_change", "interface": name, "count": transitions})
            for key, label in (("rx_errors", "rx errors"), ("tx_errors", "tx errors")):
                value = _range(_series(samples, lambda item, key=key: interface_value(item, key)))
                if value and value["change"]:
                    metrics[f"{name} {label}"] = value
            for key, label in (("rx_bytes", "rx bytes"), ("tx_bytes", "tx bytes")):
                value = _range(_series(samples, lambda item, key=key: interface_value(item, key)))
                if value:
                    metrics[f"{name} {label}"] = value
    elif domain == "thermal":
        value = _range(_series(samples, lambda item: item.get("max_celsius")))
        if value:
            metrics["Hottest sensor (°C)"] = value
        for zone in sorted({z["sensor"] for item in samples for z in item.get("zones", [])}):
            series = _range(_series(samples, lambda item, zone=zone: next(
                (z["celsius"] for z in item.get("zones", []) if z["sensor"] == zone), None)))
            if series:
                metrics[f"{zone} (°C)"] = series
    return {"domain": domain, "metrics": metrics, "events": events,
            "sample_count": result["sample_count"], "interrupted": result["interrupted"]}


def kernel_events_during(result: dict) -> dict:
    """Kernel events whose window overlaps the sampling window only."""
    started = result.get("started_wall")
    if not started:
        return {"available": False, "count": 0, "sample": []}
    since = dt.datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S")
    log = collect.journal("-k", "--since", since, "-n", "300", timeout=8)
    if log.get("status") != "ok":
        return {"available": False, "count": 0, "sample": [],
                "reason": log.get("reason", "journal unavailable")}
    pattern = _KERNEL_PATTERNS.get(result["domain"])
    if pattern is None:
        entries = collect.lines(log)
        return {"available": True, "count": len(entries), "sample": entries[-5:]}
    count, entries = collect.count_matches(log, pattern, keep=6)
    return {"available": True, "count": count, "sample": entries}


def build_evidence(result: dict, summary: dict, kernel: dict, web: bool = False) -> dict:
    findings = []
    for label, value in summary.get("metrics", {}).items():
        if "°C" in label and value["max"] >= HIGH_TEMPERATURE:
            findings.append(finding(
                "watch.temperature_peak", "thermal", WARNING, CONFIRMED,
                title=f"{label} peaked at {value['max']} during the window",
                evidence={"metric": label, **value}, count=1, confidence="high",
                probable_cause="Load during the sampling window."))
    if kernel.get("count"):
        findings.append(finding(
            "watch.kernel_events", result["domain"], WARNING, CONFIRMED,
            title=f"{kernel['count']} matching kernel event(s) during the sampling window",
            evidence={"sample": kernel.get("sample", [])[:5]}, count=kernel["count"],
            confidence="high", probable_cause="Kernel activity concurrent with the samples.",
            suggested_next_diagnostic="journal.kernel_errors"))
    for event in summary.get("events", []):
        findings.append(finding(
            "watch.state_change", result["domain"], INFO, INFORMATIONAL,
            title=f"{event['count']} {event['kind'].replace('_', ' ')} on "
                  f"{event.get('interface', 'the device')}",
            evidence=event, count=event["count"], confidence="high"))
    sections = {
        "window": {"requested_duration_seconds": result["requested_duration"],
                   "interval_seconds": result["interval"],
                   "samples": result["sample_count"],
                   "stopped_early": result["interrupted"]},
        "metrics": summary.get("metrics", {}),
        "events": summary.get("events", []),
        "kernel": kernel,
        # Raw samples are deliberately absent: they stay in memory and end here.
        "raw_samples_retained": False,
    }
    return build(command="watch", scope=result["domain"], sections=sections,
                 findings=findings, arguments={"duration": result["requested_duration"],
                                               "interval": result["interval"]}, web=web)


def _format(label: str, value: float) -> str:
    if "(bytes)" not in label:
        return f"{value:g}"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value:g}"


def render_summary(result: dict, summary: dict, kernel: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, reset = ("\033[1m", "\033[0m") if color else ("", "")
    elapsed = max(0, int(result.get("ended_wall", 0) - result.get("started_wall", 0)))
    lines = [f"{bold}SysAI Watch · {result['domain']}{reset}", "",
             f"  Duration: {elapsed}s of {result['requested_duration']}s requested"
             + (" (stopped early)" if result["interrupted"] else ""),
             f"  Samples: {result['sample_count']}", ""]
    metrics = summary.get("metrics", {})
    if metrics:
        lines.append(f"{bold}Measurements{reset}")
        lines.append("")
        for label, value in metrics.items():
            display = label.replace(" (bytes)", "")
            lines.append(f"  {display}")
            lines.append(f"    {_format(label, value['first'])} -> {_format(label, value['last'])}"
                         f"  (min {_format(label, value['min'])},"
                         f" max {_format(label, value['max'])})")
        lines.append("")
    else:
        lines += [f"{bold}Measurements{reset}", "", "  No numeric metric was exposed for this domain.", ""]
    lines.append(f"{bold}Kernel events during the window{reset}")
    if kernel.get("available"):
        lines.append(f"  {kernel.get('count', 0)}")
        for entry in kernel.get("sample", [])[:3]:
            lines.append(f"    {entry}")
    else:
        lines.append(f"  not checked ({kernel.get('reason', 'journal unavailable')})")
    lines.append("")
    lines.append("Samples were held in memory only and are now discarded.")
    return "\n".join(lines) + "\n"
