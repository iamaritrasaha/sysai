"""`sysai update`: SysAI self-update only, and only when it can be verified.

This never touches the operating system, APT, Ollama, or the local model. It
never pulls `main`, never runs a remote script, and never pipes a download
into a shell. An automatic update happens only when the release publishes a
checksum manifest and the downloaded artifact matches it. Otherwise SysAI
says so and prints manual instructions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import __version__
from .collect import run

REPOSITORY = "iamaritrasaha/sysai"
RELEASES_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases"
CHECKSUM_NAMES = ("SHA256SUMS", "SHA256SUMS.txt", "sha256sums.txt", "checksums.txt")
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+[* ]?(\S+)$")


class UpdateError(RuntimeError):
    pass


def parse_version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION.match(str(value).strip())
    return tuple(int(part) for part in match.groups()) if match else None


def is_newer(candidate: str, current: str = __version__) -> bool:
    left, right = parse_version(candidate), parse_version(current)
    if left is None or right is None:
        return False
    return left > right


def _fetch(url: str, timeout: float = 15, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"sysai/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError(
                f"No published release was found for {REPOSITORY}. "
                f"See {RELEASES_PAGE} for available versions.") from exc
        raise UpdateError(f"The release server returned HTTP {exc.code}.") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise UpdateError(f"Could not reach the release server: {exc}") from exc
    if len(data) > limit:
        raise UpdateError("The release artifact exceeds SysAI's size limit.")
    return data


def fetch_release(fetch=_fetch) -> dict:
    """Read published release metadata. Never modifies anything."""
    try:
        payload = json.loads(fetch(RELEASES_API))
    except json.JSONDecodeError as exc:
        raise UpdateError(f"The release metadata could not be parsed: {exc}") from exc
    if not isinstance(payload, dict) or not payload.get("tag_name"):
        raise UpdateError("No published release was found for this repository.")
    assets = [
        {"name": asset.get("name", ""), "url": asset.get("browser_download_url", ""),
         "size": asset.get("size")}
        for asset in payload.get("assets", []) if isinstance(asset, dict)
    ]
    return {
        "tag": str(payload["tag_name"]),
        "version": str(payload["tag_name"]).lstrip("v"),
        "name": str(payload.get("name") or payload["tag_name"]),
        "published": payload.get("published_at"),
        "notes": (payload.get("body") or "").strip()[:1200],
        "assets": assets,
        "prerelease": bool(payload.get("prerelease")),
        "page": payload.get("html_url") or RELEASES_PAGE,
    }


def parse_checksums(text: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for line in text.splitlines():
        match = _SHA256_LINE.match(line.strip())
        if match:
            digests[os.path.basename(match.group(2))] = match.group(1).lower()
    return digests


def select_artifact(release: dict) -> tuple[dict | None, dict | None]:
    """Return the source artifact and its checksum manifest, if both are published."""
    checksum_asset = next((asset for asset in release.get("assets", [])
                           if asset["name"] in CHECKSUM_NAMES), None)
    artifact = next((asset for asset in release.get("assets", [])
                     if asset["name"].endswith((".tar.gz", ".tgz", ".zip"))
                     and asset["name"] not in CHECKSUM_NAMES), None)
    return artifact, checksum_asset


def check(fetch=_fetch) -> dict:
    """`sysai update check`: report only. Nothing is downloaded or changed."""
    release = fetch_release(fetch)
    artifact, checksums = select_artifact(release)
    newer = is_newer(release["version"])
    return {
        "current_version": __version__,
        "latest_version": release["version"],
        "release_name": release["name"],
        "published": release["published"],
        "notes": release["notes"],
        "page": release["page"],
        "prerelease": release["prerelease"],
        "update_available": newer,
        "verifiable": bool(artifact and checksums),
        "artifact": artifact["name"] if artifact else None,
        "checksum_manifest": checksums["name"] if checksums else None,
    }


def installation_state(repository: Path | None = None) -> dict:
    """Describe how this SysAI was installed, and whether it is safe to replace."""
    root = Path(__file__).resolve().parents[2]
    checkout = repository or (root if (root / ".git").exists() and (root / "src" / "sysai").is_dir() else None)
    if checkout is None:
        return {"kind": "installed", "path": str(Path(__file__).resolve().parent),
                "dirty": False, "detail": "installed copy"}
    status = run(("git", "-C", str(checkout), "status", "--porcelain"), timeout=8)
    dirty = bool((status.get("output") or "").strip())
    return {"kind": "checkout", "path": str(checkout), "dirty": dirty,
            "detail": "development checkout with uncommitted changes" if dirty
                      else "clean development checkout"}


def _verify(data: bytes, name: str, manifest: dict[str, str]) -> None:
    expected = manifest.get(name)
    if not expected:
        raise UpdateError(f"The checksum manifest does not list {name}.")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise UpdateError(
            f"Checksum mismatch for {name}. Expected {expected}, got {actual}. "
            "SysAI refuses to install an unverified artifact.")


def _extract(data: bytes, name: str, destination: Path) -> Path:
    """Extract into a temporary directory with path traversal rejected."""
    archive_path = destination / name
    archive_path.write_bytes(data)
    target = destination / "extracted"
    target.mkdir()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.namelist():
                resolved = (target / member).resolve()
                if not str(resolved).startswith(str(target.resolve())):
                    raise UpdateError(f"The archive contains an unsafe path: {member}")
            archive.extractall(target)
    else:
        with tarfile.open(archive_path) as archive:
            for member in archive.getmembers():
                if member.issym() or member.islnk():
                    raise UpdateError(f"The archive contains a link entry: {member.name}")
                resolved = (target / member.name).resolve()
                if not str(resolved).startswith(str(target.resolve())):
                    raise UpdateError(f"The archive contains an unsafe path: {member.name}")
            try:
                archive.extractall(target, filter="data")
            except TypeError:  # Python 3.11 without the extraction filter
                archive.extractall(target)
    return target


def manual_instructions(release: dict | None = None) -> str:
    page = (release or {}).get("page", RELEASES_PAGE)
    return ("Update manually:\n"
            f"  1. Review the release notes at {page}\n"
            "  2. Download and verify the release yourself\n"
            "  3. From the extracted release directory, run ./install.sh\n"
            "SysAI will not download or install an unverified artifact for you.")


def apply(fetch=_fetch, *, install=None, repository: Path | None = None) -> dict:
    """Update only from a verified release artifact. Never from a branch."""
    status = check(fetch)
    if not status["update_available"]:
        return {"applied": False, "reason": "up-to-date", **status}
    state = installation_state(repository)
    if state["kind"] == "checkout":
        return {"applied": False,
                "reason": "development-checkout" if not state["dirty"] else "dirty-checkout",
                "installation": state, **status}
    if not status["verifiable"]:
        return {"applied": False, "reason": "no-verifiable-artifact", "installation": state, **status}

    release = fetch_release(fetch)
    artifact, checksum_asset = select_artifact(release)
    manifest = parse_checksums(fetch(checksum_asset["url"]).decode("utf-8", "replace"))
    data = fetch(artifact["url"])
    _verify(data, artifact["name"], manifest)
    with tempfile.TemporaryDirectory(prefix="sysai-update-") as temporary:
        extracted = _extract(data, artifact["name"], Path(temporary))
        roots = [path for path in extracted.iterdir() if path.is_dir()]
        source = roots[0] if len(roots) == 1 else extracted
        installer = source / "install.sh"
        if not installer.is_file():
            raise UpdateError("The verified release does not contain an install.sh script.")
        os.chmod(installer, 0o755)
        # Fixed argv, the verified release's own installer, no shell.
        result = (install or run)((str(installer),), timeout=120, limit=8000)
        if result.get("exit_code") != 0:
            raise UpdateError(f"The release installer failed: {result.get('output', 'no output')}")
    return {"applied": True, "reason": "verified", "installation": state, **status}


def render_check(status: dict) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, reset = ("\033[1m", "\033[0m") if color else ("", "")
    lines = [f"{bold}SysAI Update{reset}", "",
             f"  Installed: {status['current_version']}",
             f"  Latest:    {status['latest_version']}"
             + (" (pre-release)" if status.get("prerelease") else ""), ""]
    if not status["update_available"]:
        lines.append("  SysAI is up to date.")
        return "\n".join(lines) + "\n"
    lines += [f"{bold}{status['release_name']}{reset}"]
    if status.get("published"):
        lines.append(f"  Published {status['published']}")
    for line in (status.get("notes") or "").splitlines()[:8]:
        lines.append(f"  {line}")
    lines.append("")
    lines.append(f"{bold}Verifiable release artifact{reset}")
    lines.append(f"  {'yes: ' + str(status['artifact']) if status['verifiable'] else 'no'}")
    lines.append("")
    lines.append("Run `sysai update` to install it, or update manually from "
                 + status.get("page", RELEASES_PAGE) + ".")
    return "\n".join(lines) + "\n"
