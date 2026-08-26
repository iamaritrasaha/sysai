"""`sysai what`: explain a command without ever running it.

The supplied text is data. It is tokenized with ``shlex`` for display and
structural analysis only; nothing here starts a process, and the parsed
tokens never reach ``subprocess``, a shell, or ``eval``.
"""
from __future__ import annotations

import os
import shlex

LOW, MODERATE, HIGH = "Low", "Moderate", "High"

# program -> (purpose, modifies_system, risk, reversible, dry_run)
_PROGRAMS: dict[str, tuple[str, bool, str, str, str | None]] = {
    "apt": ("Manages Debian/Ubuntu packages.", True, MODERATE,
            "Usually reversible by reinstalling the affected packages.", "apt --dry-run"),
    "apt-get": ("Manages Debian/Ubuntu packages.", True, MODERATE,
                "Usually reversible by reinstalling the affected packages.", "apt-get --dry-run"),
    "dpkg": ("Installs and inspects Debian packages directly.", True, MODERATE,
             "Reversible by reinstalling, but broken states can need manual repair.", None),
    "snap": ("Manages snap packages.", True, MODERATE, "Snaps can usually be reinstalled or reverted.", None),
    "rm": ("Deletes files and directories.", True, HIGH,
           "Not reversible. There is no trash and no undo.", "ls"),
    "rmdir": ("Removes empty directories.", True, MODERATE, "Recreate the directory to reverse.", None),
    "mv": ("Moves or renames files.", True, MODERATE, "Reversible by moving back, unless it overwrote a file.", None),
    "cp": ("Copies files.", True, LOW, "Reversible unless it overwrote an existing file.", None),
    "dd": ("Copies raw blocks between devices and files.", True, HIGH,
           "Not reversible. Writing to the wrong device destroys data.", None),
    "mkfs": ("Creates a new filesystem, erasing the target.", True, HIGH, "Not reversible.", None),
    "fsck": ("Checks and repairs a filesystem.", True, HIGH,
             "Repairs can change or lose data. Never run on a mounted filesystem.", "fsck -n"),
    "chmod": ("Changes file permissions.", True, MODERATE,
              "Reversible only if the previous modes are known.", None),
    "chown": ("Changes file ownership.", True, MODERATE,
              "Reversible only if the previous owners are known.", None),
    "mount": ("Attaches a filesystem.", True, MODERATE, "Reversible with umount.", None),
    "umount": ("Detaches a filesystem.", True, MODERATE, "Reversible by mounting again.", None),
    "systemctl": ("Controls systemd units.", True, MODERATE, "Most unit actions can be reversed.", None),
    "ip": ("Inspects and configures network interfaces and routes.", True, MODERATE,
           "Runtime changes are lost on reboot.", None),
    "iptables": ("Configures packet filtering rules.", True, HIGH,
                 "Runtime rules are lost on reboot unless saved.", "iptables -L"),
    "ufw": ("Configures the uncomplicated firewall.", True, MODERATE, "Rules can be removed again.", "ufw status"),
    "useradd": ("Creates a user account.", True, MODERATE, "Reversible with userdel.", None),
    "userdel": ("Deletes a user account.", True, HIGH, "Not reversible; home data can be lost.", None),
    "passwd": ("Changes an account password.", True, MODERATE, "Reversible only by setting a new password.", None),
    "kill": ("Sends a signal to a process.", True, MODERATE, "The process must be restarted.", None),
    "pkill": ("Signals processes matched by name.", True, MODERATE, "The processes must be restarted.", "pgrep"),
    "killall": ("Signals every process with a given name.", True, HIGH, "The processes must be restarted.", "pgrep"),
    "reboot": ("Restarts the machine.", True, HIGH, "Unsaved work is lost.", None),
    "shutdown": ("Powers off or restarts the machine.", True, HIGH, "Unsaved work is lost.", None),
    "truncate": ("Changes a file's size, discarding data.", True, HIGH, "Not reversible.", None),
    "tee": ("Writes standard input to files.", True, MODERATE, "Overwrites unless -a is used.", None),
    "sed": ("Edits a stream of text.", False, LOW, "In-place editing with -i modifies files.", None),
    "find": ("Searches the filesystem.", False, LOW, "Read-only unless -delete or -exec is used.", None),
    "du": ("Reports disk usage.", False, LOW, "Read-only.", None),
    "df": ("Reports filesystem capacity.", False, LOW, "Read-only.", None),
    "ls": ("Lists directory contents.", False, LOW, "Read-only.", None),
    "cat": ("Prints file contents.", False, LOW, "Read-only.", None),
    "grep": ("Searches text for a pattern.", False, LOW, "Read-only.", None),
    "ps": ("Lists processes.", False, LOW, "Read-only.", None),
    "journalctl": ("Reads the systemd journal.", False, LOW, "Read-only.", None),
    "dmesg": ("Reads the kernel ring buffer.", False, LOW, "Read-only.", None),
    "lsblk": ("Lists block devices.", False, LOW, "Read-only.", None),
    "smartctl": ("Reads or controls device SMART data.", False, MODERATE,
                 "Read-only unless a test or setting flag is given.", None),
    "curl": ("Transfers data over a network.", False, MODERATE,
             "Downloads can overwrite files; piping output to a shell executes remote code.", None),
    "wget": ("Downloads files over a network.", True, MODERATE, "Downloads can overwrite files.", None),
    "git": ("Runs a Git version-control operation.", True, MODERATE,
            "Most operations are recoverable through the reflog.", None),
}

# argument -> why it matters. Matched exactly against a token.
_FLAGS: dict[str, str] = {
    "-r": "Recursive: applies to directories and everything inside them.",
    "-R": "Recursive: applies to directories and everything inside them.",
    "--recursive": "Recursive: applies to directories and everything inside them.",
    "-f": "Force: suppresses prompts and ignores missing files.",
    "--force": "Force: suppresses prompts and ignores errors.",
    "-rf": "Recursive and forced deletion with no confirmation.",
    "-fr": "Recursive and forced deletion with no confirmation.",
    "-y": "Assumes yes to every prompt.",
    "--yes": "Assumes yes to every prompt.",
    "--purge": "Also removes configuration files, not only the package.",
    "--no-preserve-root": "Removes the safety check that protects /.",
    "-9": "SIGKILL: the process cannot clean up or save state.",
    "--hard": "Discards local changes irrecoverably.",
    "--delete": "Deletes every matched path.",
    "-i": "In-place: modifies the files themselves.",
    "--dry-run": "Dry run: reports what would happen without changing anything.",
    "-n": "Often means dry run or no-change for this program; confirm in its manual page.",
}

_DANGEROUS_COMBINATIONS = (
    (("rm",), ("-rf", "-fr", "-r"), "Recursive forced deletion cannot be undone."),
    (("dd",), ("of=",), "Writing to the wrong `of=` target destroys the whole device."),
    (("chmod", "chown"), ("-R", "-r", "--recursive"),
     "Recursive ownership or permission changes across system paths are hard to reverse."),
    (("git",), ("--hard",), "A hard reset discards uncommitted work."),
)

_SUBCOMMAND_RISK = {
    ("apt", "autoremove"): ("Removes packages APT considers no longer required.", MODERATE,
                            "apt autoremove --dry-run"),
    ("apt", "remove"): ("Removes the named packages.", MODERATE, "apt remove --dry-run"),
    ("apt", "purge"): ("Removes the named packages and their configuration.", HIGH,
                       "apt purge --dry-run"),
    ("apt", "upgrade"): ("Upgrades installed packages.", MODERATE, "apt upgrade --dry-run"),
    ("apt", "update"): ("Refreshes package lists only.", LOW, None),
    ("apt", "install"): ("Installs the named packages.", MODERATE, "apt install --dry-run"),
    ("apt-get", "autoremove"): ("Removes packages APT considers no longer required.", MODERATE,
                                "apt-get autoremove --dry-run"),
    ("systemctl", "stop"): ("Stops a running unit.", MODERATE, "systemctl status"),
    ("systemctl", "disable"): ("Prevents a unit from starting at boot.", MODERATE, "systemctl is-enabled"),
    ("systemctl", "mask"): ("Makes a unit impossible to start until unmasked.", HIGH, "systemctl status"),
    ("git", "clean"): ("Deletes untracked files.", HIGH, "git clean -n"),
    ("git", "reset"): ("Moves the branch pointer, optionally discarding changes.", MODERATE, "git status"),
}

_RISK_ORDER = {LOW: 0, MODERATE: 1, HIGH: 2}


def _highest(*risks: str) -> str:
    return max(risks, key=lambda risk: _RISK_ORDER.get(risk, 0))


def _is_short_cluster(argument: str) -> bool:
    """A bundled short-option cluster such as `-rf`, never a long option like `-type`.

    Every letter must be a flag SysAI actually knows, so single-dash long
    options belonging to programs like `find` and `tar` are left alone.
    """
    if not argument.startswith("-") or argument.startswith("--") or len(argument) < 3:
        return False
    return all(f"-{letter}" in _FLAGS for letter in argument[1:])


def explain(text: str) -> dict:
    """Describe a command. This function never executes anything."""
    original = str(text).strip()
    result: dict = {"command": original, "executed": False, "parse_error": None}
    if not original:
        result["parse_error"] = "No command was supplied."
        return result
    try:
        tokens = shlex.split(original)
    except ValueError as exc:
        result["parse_error"] = f"The command could not be tokenized: {exc}"
        tokens = []
    result["tokens"] = tokens
    if not tokens:
        result.setdefault("parse_error", "The command contained no tokens.")
        return result

    shell_operators = [token for token in tokens
                       if token in ("|", "||", "&&", ";", ">", ">>", "<", "&")]
    elevated = tokens[0] in ("sudo", "doas", "pkexec")
    body = tokens[1:] if elevated else tokens
    # `sudo -u name cmd` and similar: skip sudo's own options.
    index = 0
    while elevated and index < len(body) and body[index].startswith("-"):
        index += 2 if body[index] in ("-u", "-g", "-p", "--user", "--group") else 1
    body = body[index:]
    program = os.path.basename(body[0]) if body else ""
    arguments = body[1:]

    purpose, modifies, risk, reversible, dry_run = _PROGRAMS.get(
        program, (f"`{program}` is not in SysAI's command reference.", None, MODERATE,
                  "Unknown. Check the program's manual page.", None))
    subcommand = next((argument for argument in arguments if not argument.startswith("-")), None)
    if subcommand and (program, subcommand) in _SUBCOMMAND_RISK:
        purpose, subcommand_risk, subcommand_dry_run = _SUBCOMMAND_RISK[(program, subcommand)]
        risk = _highest(risk, subcommand_risk)
        dry_run = subcommand_dry_run or dry_run
        modifies = True

    significant = []
    previous = ""
    for argument in arguments:
        note = _FLAGS.get(argument)
        if note:
            significant.append({"argument": argument, "meaning": note})
        elif _is_short_cluster(argument):
            significant.append({"argument": argument, "meaning": " ".join(
                _FLAGS[f"-{letter}"] for letter in argument[1:])})
        elif argument.startswith("-"):
            significant.append({"argument": argument,
                                "meaning": "Option: see this program's manual page."})
        else:
            # A known flag never takes a value, so what follows it is an operand.
            ambiguous = previous.startswith("-") and previous not in _FLAGS \
                and not _is_short_cluster(previous)
            significant.append({
                "argument": argument,
                "meaning": ("Operand, or the value for the preceding option." if ambiguous
                            else "Operand: the target this command acts on.")})
        previous = argument

    dangerous = []
    for programs, markers, reason in _DANGEROUS_COMBINATIONS:
        if program in programs and any(
                any(token == marker or token.startswith(marker) for token in arguments)
                for marker in markers):
            dangerous.append(reason)
            risk = HIGH
    if program == "find" and any(token in ("-delete", "-exec", "-execdir", "-ok") for token in arguments):
        modifies = True
        risk = HIGH
        dangerous.append("`find` is being asked to delete or execute, not only to search.")
    # A system path only raises risk for a command that can change something.
    if modifies is not False and any(
            token in ("/", "/*", "/etc", "/usr", "/var", "/boot", "/home") for token in arguments):
        dangerous.append("A system-level path is named directly as an operand.")
        risk = _highest(risk, HIGH)
    if shell_operators:
        dangerous.append("Shell operators are present; the real effect depends on the whole pipeline.")
    if program in ("curl", "wget") and any("|" == token for token in tokens):
        dangerous.append("Piping a download into a shell executes remote code without review.")
        risk = HIGH
    if elevated:
        risk = _highest(risk, MODERATE)

    if dry_run is None and modifies is False:
        dry_run = None
    result.update({
        "program": program,
        "purpose": purpose,
        "subcommand": subcommand,
        "privilege": "Root" if elevated else "Current user",
        "elevated": elevated,
        "modifies_system": modifies,
        "risk": risk,
        "reversibility": reversible,
        "reads": _reads(program, modifies),
        "arguments": significant,
        "dangerous": dangerous,
        "shell_operators": shell_operators,
        "safer_alternative": dry_run,
        "known_program": program in _PROGRAMS,
    })
    return result


def _reads(program: str, modifies: bool | None) -> str:
    if program in ("journalctl", "dmesg"):
        return "Kernel and system log buffers."
    if program in ("df", "du", "lsblk", "findmnt"):
        return "Filesystem and block-device metadata."
    if program in ("apt", "apt-get", "dpkg", "apt-cache", "apt-mark"):
        return "The package database and configured repositories."
    if program in ("ps", "top", "pgrep"):
        return "Process table entries in /proc."
    if modifies is False:
        return "The paths given on its command line."
    return "The paths and resources named on its command line."


def render(result: dict) -> str:
    """Compact terminal output. The command is quoted, never executed."""
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    bold, yellow, reset = ("\033[1m", "\033[33m", "\033[0m") if color else ("", "", "")
    lines = [f"{bold}Command{reset}", f"  {result.get('command', '')}", ""]
    if result.get("parse_error"):
        lines += [f"{bold}Not analyzed{reset}", f"  {result['parse_error']}", "",
                  "SysAI did not run this command."]
        return "\n".join(lines) + "\n"
    lines += [f"{bold}Purpose{reset}", f"  {result['purpose']}", ""]
    if not result.get("known_program"):
        lines += ["  SysAI has no reference entry for this program, so the assessment below",
                  "  is structural only. Read its manual page before running it.", ""]
    modifies = result.get("modifies_system")
    lines += [f"{bold}Modifies system{reset}",
              f"  {'Yes' if modifies else ('No' if modifies is False else 'Unknown')}", "",
              f"{bold}Privilege{reset}", f"  {result['privilege']}", "",
              f"{bold}Reads{reset}", f"  {result['reads']}", "",
              f"{bold}Risk{reset}", f"  {result['risk']}", "",
              f"{bold}Reversibility{reset}", f"  {result['reversibility']}", ""]
    if result.get("arguments"):
        lines.append(f"{bold}Arguments{reset}")
        for item in result["arguments"][:12]:
            lines.append(f"  {item['argument']}")
            lines.append(f"    {item['meaning']}")
        lines.append("")
    if result.get("dangerous"):
        lines.append(f"{yellow}{bold}Dangerous parts{reset}")
        for reason in result["dangerous"]:
            lines.append(f"  ! {reason}")
        lines.append("")
    if result.get("safer_alternative"):
        lines += [f"{bold}Before running{reset}", f"  {result['safer_alternative']}", ""]
    lines.append("SysAI explained this command and did not run it.")
    return "\n".join(lines) + "\n"
