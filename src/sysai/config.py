from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    model: str = "qwen3:8b"
    ollama_url: str = "http://127.0.0.1:11434"
    auto_analyze_failures: bool = True
    output_capture_bytes: int = 48_000
    context_commands: int = 8
    verbosity: str = "concise"
    # Controls both requesting reasoning tokens from Ollama (`think`) and
    # whether a live "SysAI · thinking" box is displayed for them. See
    # `sysai thinking on|off|status`.
    thinking: bool = True
    web_enabled: bool = False
    web_provider: str = "ollama"
    request_timeout_seconds: int = 120
    startup_timeout_seconds: int = 20
    # History intelligence (see history.py). Safety limits (max_entries,
    # max_context_entries) apply regardless of mode.
    history_enabled: bool = True
    history_mode: str = "relevant"
    history_max_entries: int = 300
    history_lookback_hours: int = 48
    history_max_context_entries: int = 20


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "sysai"


def state_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    path = (Path(base) / "sysai") if base else Path("/tmp") / f"sysai-{os.getuid()}"
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Unsafe SysAI runtime path (not a real directory): {path}")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"Unsafe SysAI runtime path (wrong owner): {path}")
    if info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def persistent_state_dir() -> Path:
    """XDG state directory for explicit, long-lived files (baselines, caches).

    Deliberately separate from `state_dir()`, which is volatile per-boot
    runtime state, and from the config directory, which holds settings the
    user edits rather than data SysAI writes.
    """
    base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    path = Path(base) / "sysai"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Unsafe SysAI state path (not a real directory): {path}")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"Unsafe SysAI state path (wrong owner): {path}")
    if info.st_mode & 0o077:
        path.chmod(0o700)
    return path


def load_config(path: Path | None = None) -> Config:
    path = path or config_dir() / "config.toml"
    if not path.exists():
        return Config()
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    allowed = Config.__dataclass_fields__.keys()
    values = {key: value for key, value in raw.items() if key in allowed}
    return Config(**values)


def _format_toml_value(value: bool | int | float | str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def set_config_value(key: str, value: bool | int | float | str, path: Path | None = None) -> Path:
    """Persist a single scalar key into the user's config.toml, preserving the rest of the file."""
    path = path or config_dir() / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    formatted = f"{key} = {_format_toml_value(value)}"
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = formatted
            break
    else:
        lines.append(formatted)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def load_private_env(path: Path | None = None) -> dict[str, str]:
    """Read only SysAI's private env file; do not mutate the process environment."""
    path = path or config_dir() / "env"
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "OLLAMA_API_KEY":
            values[key.strip()] = value.strip().strip("'\"")
    return values
