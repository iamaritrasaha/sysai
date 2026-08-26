"""`sysai doctor`: diagnose SysAI itself, not the whole machine.

Every check here is deterministic. The local model is never consulted: an
installation problem is something Python can decide, and asking a model that
may itself be unreachable would be self-defeating.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .collect import have, read_text, run
from .config import Config, config_dir, load_config, load_private_env
from .display import ANSI_RE, AnswerRenderer

OK = "ok"
ATTENTION = "attention"
INFO = "info"
UNKNOWN = "unknown"

_SYMBOL = {OK: "✓", ATTENTION: "!", INFO: "·", UNKNOWN: "–"}
MIN_FREE_BYTES = 2 * 1024**3


def _check(identifier: str, label: str, status: str, detail: str) -> dict:
    return {"id": identifier, "label": label, "status": status, "detail": detail}


def _api(url: str, path: str, body: dict | None = None, timeout: float = 3) -> dict | None:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{url}{path}", data=data, method="POST" if data else "GET",
        headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        return None


def _tree_digest(directory: Path) -> str | None:
    """Stable digest of SysAI's shipped source files, for install/checkout drift."""
    try:
        names = sorted(path for path in directory.iterdir()
                       if path.is_file() and path.suffix in (".py", ".md", ".bash"))
    except OSError:
        return None
    if not names:
        return None
    digest = hashlib.sha256()
    for path in names:
        try:
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
        except OSError:
            return None
    return digest.hexdigest()


def _repository_root() -> Path | None:
    candidate = Path(__file__).resolve().parents[2]
    return candidate if (candidate / "src" / "sysai").is_dir() else None


def _installed_package() -> Path | None:
    root = Path(os.environ.get("SYSAI_INSTALL_ROOT", Path.home() / ".local"))
    package = root / "lib" / "sysai-terminal" / "sysai"
    return package if package.is_dir() else None


def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _runtime_checks() -> list[dict]:
    checks = []
    base = os.environ.get("XDG_RUNTIME_DIR")
    runtime = (Path(base) / "sysai") if base else Path("/tmp") / f"sysai-{os.getuid()}"
    if not runtime.exists():
        checks.append(_check("runtime.directory", "Runtime directory", INFO,
                             "not created yet (no session has run)"))
        return checks
    try:
        info = runtime.lstat()
    except OSError as exc:
        return [_check("runtime.directory", "Runtime directory", ATTENTION, str(exc))]
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        checks.append(_check("runtime.directory", "Runtime directory", ATTENTION,
                             f"{runtime} is not a real directory"))
    elif info.st_uid != os.getuid():
        checks.append(_check("runtime.directory", "Runtime directory", ATTENTION,
                             f"{runtime} is owned by another user"))
    elif info.st_mode & 0o077:
        checks.append(_check("runtime.directory", "Runtime permissions", ATTENTION,
                             f"{runtime} is group/world accessible"))
    else:
        checks.append(_check("runtime.directory", "Runtime permissions", OK, "0700, user-owned"))

    state = runtime / "active.json"
    if not state.exists():
        checks.append(_check("session.active", "Active session", INFO, "none running"))
        return checks
    try:
        active = json.loads(state.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(_check("session.active", "Active session state", ATTENTION,
                             "active.json is unreadable or corrupt; run `sysai stop`"))
        return checks
    pid = active.get("pid")
    alive = False
    if isinstance(pid, int):
        try:
            os.kill(pid, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        except OSError:
            alive = True
    socket_path = active.get("socket")
    socket_exists = isinstance(socket_path, str) and Path(socket_path).exists()
    if alive and socket_exists:
        checks.append(_check("session.active", "Active session", OK, f"running (pid {pid})"))
    elif alive:
        checks.append(_check("session.active", "Active session", ATTENTION,
                             f"pid {pid} is running but its control socket is missing"))
    else:
        checks.append(_check("session.active", "Stale session state", ATTENTION,
                             "active.json refers to a process that is gone; run `sysai stop` to clean up"))
    return checks


def _bash_checks() -> list[dict]:
    checks = []
    bash = "/bin/bash" if os.access("/bin/bash", os.X_OK) else shutil.which("bash")
    if not bash:
        checks.append(_check("bash.version", "Bash", ATTENTION, "no bash executable found"))
    else:
        version = run((bash, "--version"), timeout=5)
        first = (version.get("output") or "").splitlines()[:1]
        text = first[0] if first else ""
        number = text.partition("version ")[2].split()[0] if "version " in text else ""
        major = number.split(".")[0]
        status = OK if major.isdigit() and int(major) >= 5 else ATTENTION
        checks.append(_check("bash.version", "Bash", status,
                             f"{number or 'unknown version'} at {bash}"))
    integration = Path(__file__).with_name("integration.bash")
    if not integration.is_file():
        checks.append(_check("bash.integration", "Bash integration", ATTENTION,
                             "integration.bash is missing from the installed package"))
    elif bash:
        syntax = run((bash, "-n", str(integration)), timeout=5)
        checks.append(_check(
            "bash.integration", "Bash integration",
            OK if syntax.get("exit_code") == 0 else ATTENTION,
            "syntax valid" if syntax.get("exit_code") == 0 else (syntax.get("output") or "syntax check failed")))
    bashrc = Path.home() / ".bashrc"
    if not bashrc.exists():
        checks.append(_check("bash.rcfile", "~/.bashrc", INFO, "not present"))
    elif not os.access(bashrc, os.R_OK):
        checks.append(_check("bash.rcfile", "~/.bashrc", ATTENTION, "exists but is not readable"))
    else:
        content = read_text(str(bashrc), 400_000) or ""
        touched = any(marker in content for marker in ("sysai", "SysAI", "SYSAI"))
        checks.append(_check(
            "bash.rcfile", "~/.bashrc", ATTENTION if touched else OK,
            "contains a SysAI reference; SysAI never writes here, so this was added manually"
            if touched else "readable and unmodified by SysAI"))
    return checks


def _config_checks(config: Config) -> list[dict]:
    checks = []
    directory = config_dir()
    config_path = directory / "config.toml"
    if not config_path.exists():
        checks.append(_check("config.file", "Configuration", INFO,
                             f"{config_path} not present; built-in defaults are in use"))
    elif not os.access(config_path, os.R_OK):
        checks.append(_check("config.file", "Configuration", ATTENTION,
                             f"{config_path} is not readable"))
    else:
        mode = _mode(config_path)
        checks.append(_check(
            "config.file", "Configuration",
            OK if mode is not None and not mode & 0o077 else ATTENTION,
            f"{config_path} (mode {mode:04o})" if mode is not None else str(config_path)))
    env_path = directory / "env"
    if not env_path.exists():
        checks.append(_check("config.env", "Private env file", INFO, "not present"))
    elif (mode := _mode(env_path)) is None:
        checks.append(_check("config.env", "Private env file", ATTENTION, "cannot be inspected"))
    elif mode & 0o077:
        checks.append(_check("config.env", "Private env file", ATTENTION,
                             f"mode {mode:04o}; it should be 0600"))
    else:
        checks.append(_check("config.env", "Private env file", OK, f"mode {mode:04o}"))
    key_present = bool(load_private_env().get("OLLAMA_API_KEY") or os.environ.get("OLLAMA_API_KEY"))
    if config.web_enabled and not key_present:
        checks.append(_check("web.key", "Web search", ATTENTION,
                             "enabled but no API key is configured"))
    elif config.web_enabled:
        # The value is never read into the report, only its presence.
        checks.append(_check("web.key", "Web search", OK,
                             f"enabled, API key present, provider {config.web_provider}"))
    else:
        checks.append(_check("web.key", "Web search", INFO,
                             "disabled (default)" + (", API key present" if key_present else "")))
    return checks


def _ollama_checks(config: Config, probe_model: bool = True) -> list[dict]:
    checks = []
    checks.append(_check("ollama.binary", "Ollama binary",
                         OK if have("ollama") else ATTENTION,
                         shutil.which("ollama") or "not found on PATH"))
    version = _api(config.ollama_url, "/api/version")
    if version is None:
        checks.append(_check("ollama.api", "Ollama API", ATTENTION,
                             f"not reachable at {config.ollama_url}"))
        checks.append(_check("ollama.model", "Model", UNKNOWN,
                             f"{config.model} could not be verified while the API is unreachable"))
        return checks
    checks.append(_check("ollama.api", "Ollama API", OK,
                         f"reachable at {config.ollama_url} (version {version.get('version', 'unknown')})"))
    tags = _api(config.ollama_url, "/api/tags", timeout=5) or {}
    names = {entry.get("name") for entry in tags.get("models", []) if isinstance(entry, dict)}
    installed = config.model in names or f"{config.model}:latest" in names
    checks.append(_check("ollama.model", "Model", OK if installed else ATTENTION,
                         f"{config.model} installed" if installed
                         else f"{config.model} is not installed (`ollama pull {config.model}`)"))
    if not installed:
        return checks
    details = _api(config.ollama_url, "/api/show", {"model": config.model}, timeout=10) or {}
    capabilities = details.get("capabilities")
    if isinstance(capabilities, list):
        thinking = "thinking" in capabilities
        checks.append(_check("ollama.thinking", "Reasoning support", OK if thinking else INFO,
                             "model reports thinking support" if thinking
                             else "model does not report thinking support; answers only"))
    else:
        checks.append(_check("ollama.thinking", "Reasoning support", UNKNOWN,
                             "this Ollama build does not report model capabilities"))
    if not probe_model:
        return checks
    reply = _api(config.ollama_url, "/api/chat", {
        "model": config.model, "stream": False, "think": False,
        "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
        "options": {"temperature": 0, "num_predict": 8},
    }, timeout=30)
    if reply is None:
        checks.append(_check("ollama.generate", "Model response", UNKNOWN,
                             "no response within 30s (the model may still be loading)"))
    elif (reply.get("message") or {}).get("content"):
        checks.append(_check("ollama.generate", "Model response", OK, "responded to a test prompt"))
    else:
        checks.append(_check("ollama.generate", "Model response", ATTENTION,
                             "the API answered but returned no content"))
    return checks


def _install_checks() -> list[dict]:
    checks = []
    executable = os.environ.get("SYSAI_EXECUTABLE") or shutil.which("sysai")
    package = Path(__file__).resolve().parent
    checks.append(_check("install.location", "Installed at", OK,
                         f"{package} (launcher: {executable or 'not on PATH'})"))
    checks.append(_check("install.version", "Version", OK, __version__))
    repository = _repository_root()
    installed = _installed_package()
    if repository is None:
        checks.append(_check("install.source", "Source", INFO,
                             "running from an installed copy; no repository checkout detected"))
    elif installed is None:
        checks.append(_check("install.source", "Source", INFO,
                             f"running from the repository checkout at {repository}"))
    else:
        checkout_digest = _tree_digest(repository / "src" / "sysai")
        installed_digest = _tree_digest(installed)
        if checkout_digest is None or installed_digest is None:
            checks.append(_check("install.source", "Installed copy", UNKNOWN,
                                 "could not compare the installed copy with the checkout"))
        elif checkout_digest == installed_digest:
            checks.append(_check("install.source", "Installed copy", OK,
                                 "matches the repository checkout"))
        else:
            checks.append(_check("install.source", "Installed copy", ATTENTION,
                                 f"differs from the checkout at {repository}; re-run ./install.sh"))
    return checks


def _resource_checks() -> list[dict]:
    checks = []
    home = Path.home()
    try:
        usage = shutil.disk_usage(home)
        status = OK if usage.free >= MIN_FREE_BYTES else ATTENTION
        checks.append(_check("disk.free", "Free space", status,
                             f"{usage.free / 1024**3:.1f} GiB available on {home}"))
    except OSError as exc:
        checks.append(_check("disk.free", "Free space", UNKNOWN, str(exc)))
    checks.append(_check("python.version", "Python",
                         OK if sys.version_info >= (3, 11) else ATTENTION,
                         f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"))
    try:
        written: list[str] = []
        renderer = AnswerRenderer(written.append, show_thinking=False)
        renderer.content("**Renderer** check `ok`\n")
        renderer.finish()
        rendered = ANSI_RE.sub("", "".join(written))
        healthy = "Renderer" in rendered and "**" not in rendered and "\x1b" not in "".join(written)
        checks.append(_check("render.sanity", "Renderer", OK if healthy else ATTENTION,
                             "Markdown and terminal-control handling behave correctly" if healthy
                             else "renderer produced unexpected output"))
    except Exception as exc:  # a broken renderer must still produce a report
        checks.append(_check("render.sanity", "Renderer", ATTENTION, str(exc)))
    return checks


def _gpu_check() -> dict:
    """Informational only. SysAI runs fine on CPU inference."""
    devices = run(("lspci",), timeout=5)
    if devices.get("status") != "ok":
        return _check("gpu.visibility", "GPU", INFO, "lspci unavailable; not required by SysAI")
    matches = [line for line in (devices.get("output") or "").splitlines()
               if any(marker in line for marker in ("VGA compatible controller",
                                                    "3D controller", "Display controller"))]
    if not matches:
        return _check("gpu.visibility", "GPU", INFO, "no display controller detected; CPU inference is supported")
    return _check("gpu.visibility", "GPU", INFO,
                  matches[0].split(": ", 1)[-1][:70] + " (informational)")


def run_doctor(config: Config | None = None, *, probe_model: bool = True) -> dict:
    config = config or load_config()
    checks: list[dict] = []
    checks += _resource_checks()
    checks += _bash_checks()
    checks += _install_checks()
    checks += _config_checks(config)
    checks += _ollama_checks(config, probe_model=probe_model)
    checks += _runtime_checks()
    checks.append(_gpu_check())
    attention = sum(1 for item in checks if item["status"] == ATTENTION)
    return {"schema_version": 1, "sysai_version": __version__, "checks": checks,
            "attention_count": attention,
            "overall": "Attention needed" if attention else "Healthy"}


def render_doctor(result: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, green, yellow, reset = ("\033[1m", "\033[32m", "\033[33m", "\033[0m") if color else ("", "", "", "")
    lines = [f"{bold}SysAI Doctor{reset}", ""]
    for item in result.get("checks", []):
        symbol = _SYMBOL.get(item["status"], "·")
        tint = green if item["status"] == OK else (yellow if item["status"] == ATTENTION else "")
        lines.append(f"{tint}{symbol}{reset} {item['label']}")
        lines.append(f"  {item['detail']}")
    lines.append("")
    lines.append(f"{bold}Overall{reset}")
    lines.append(f"  {result.get('overall', 'Unknown')}")
    if result.get("attention_count"):
        lines.append(f"  {result['attention_count']} check(s) need attention.")
    return "\n".join(lines) + "\n"


def doctor_command(as_json: bool = False, *, probe_model: bool = True, output=print) -> int:
    result = run_doctor(probe_model=probe_model)
    if as_json:
        output(json.dumps(result, indent=2, sort_keys=True))
    else:
        output(render_doctor(result).rstrip("\n"))
    return 1 if result["attention_count"] else 0
