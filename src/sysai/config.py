from __future__ import annotations

import os
import re
import stat
import tempfile
import tomllib
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class Config:
    provider: str = "ollama"
    model: str = "qwen3:8b"
    ollama_url: str = "http://127.0.0.1:11434"
    model_endpoint: str = ""
    api_key_env: str = "SYSAI_API_KEY"
    remote_consent: bool = False
    active_model_id: str = ""
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


def model_profiles_path() -> Path:
    return config_dir() / "models.toml"


@dataclass(frozen=True)
class ModelProfile:
    id: str
    provider: str
    name: str
    base_url: str
    api_key_env: str = ""


def load_model_profiles(path: Path | None = None) -> list[ModelProfile]:
    path = path or model_profiles_path()
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    result = []
    for item in raw.get("model", []):
        try:
            profile = ModelProfile(**{key: item[key] for key in ("id", "provider", "name", "base_url")},
                                   api_key_env=item.get("api_key_env", ""))
        except (KeyError, TypeError):
            continue
        if profile.id and profile.provider and profile.name and profile.base_url:
            result.append(profile)
    return result


def save_model_profiles(profiles: list[ModelProfile], path: Path | None = None) -> Path:
    path = path or model_profiles_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lines = []
    for profile in profiles:
        lines.append("[[model]]")
        for key, value in asdict(profile).items():
            lines.append(f"{key} = {_format_toml_value(value)}")
        lines.append("")
    fd, temporary = tempfile.mkstemp(prefix=".models-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


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
    model_section = raw.get("model") if isinstance(raw.get("model"), dict) else {}
    if model_section:
        values.update({key: model_section[key] for key in ("provider", "name", "endpoint", "api_key_env", "timeout") if key in model_section})
        values["model"] = model_section.get("name", values.get("model", Config.model))
        values["provider"] = model_section.get("provider", values.get("provider", Config.provider))
        if "endpoint" in model_section:
            values["model_endpoint"] = model_section["endpoint"]
        if "timeout" in model_section:
            values["request_timeout_seconds"] = model_section["timeout"]
        values.pop("name", None)
        values.pop("endpoint", None)
        values.pop("timeout", None)
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
