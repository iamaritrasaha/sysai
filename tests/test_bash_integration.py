"""Real-Bash regression tests for SysAI's session-only shell integration.

Every test starts a genuine interactive Bash under a PTY with the same
temporary rcfile the session builds, and records the hook argv the shell
produces. A stand-in executable replaces the real SysAI binary so the
tests assert on the exact `__hook begin` / `__hook complete` lifecycle
without needing Ollama, a socket, or a running session.
"""

from __future__ import annotations

import hashlib
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sysai.session import bash_executable, write_session_rcfile


ROOT = Path(__file__).resolve().parents[1]
UNIT = "\x1f"
RECORD = "\x1e"
TIMEOUT = 30.0

# Records the hook argv it is given, one record per invocation. Field and
# record separators are control characters so that a multi-line command
# stays a single parsable field.
FAKE_SYSAI = f"""#!{sys.executable}
import os
import sys

with open(os.environ["SYSAI_TEST_LOG"], "a", encoding="utf-8") as handle:
    handle.write({UNIT!r}.join(sys.argv[1:]) + {RECORD!r})
    handle.flush()
"""

BASH_MAJOR, BASH_MINOR = (
    int(part) for part in
    subprocess.run([bash_executable(), "--version"], capture_output=True, text=True, check=True)
    .stdout.splitlines()[0].split("version ")[1].split("(")[0].split(".")[:2]
)


class BashSession:
    """A real interactive Bash driven through a PTY."""

    def __init__(self, temp: Path, bashrc: str):
        self.temp = temp
        self.home = temp / "home"
        self.home.mkdir()
        self.bashrc = self.home / ".bashrc"
        self.bashrc.write_text(bashrc, encoding="utf-8")
        self.log = temp / "hooks.log"
        self.log.write_text("", encoding="utf-8")
        self.fake = temp / "sysai"
        self.fake.write_text(FAKE_SYSAI, encoding="utf-8")
        self.fake.chmod(0o755)
        # Build the rcfile through the session's own code path so the tests
        # exercise what SysAI actually writes.
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            self.rcfile = write_session_rcfile(temp)
        self.output = bytearray()
        self.pid, self.master = pty.fork()
        if self.pid == 0:  # pragma: no cover - replaced by exec
            try:
                os.chdir(str(self.home))
                os.execve(bash_executable(), [bash_executable(), "--rcfile", str(self.rcfile), "-i"], {
                    "HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "TERM": "dumb", "PS1": "$ ", "LC_ALL": "C", "SYSAI_SESSION": "1",
                    "SYSAI_EXECUTABLE": str(self.fake), "SYSAI_TEST_LOG": str(self.log),
                    "SYSAI_TEST_HOME": str(self.home),
                })
            except BaseException:
                os._exit(127)

    def _drain(self) -> None:
        while select.select([self.master], [], [], 0)[0]:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output.extend(chunk)

    def send(self, text: str) -> None:
        os.write(self.master, text.encode())

    def records(self) -> list[list[str]]:
        data = self.log.read_text(encoding="utf-8")
        return [item.split(UNIT) for item in data.split(RECORD) if item]

    def wait_for_records(self, count: int, *, timeout: float = TIMEOUT) -> list[list[str]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._drain()
            records = self.records()
            if len(records) >= count:
                # Give a straggling hook a moment so duplicate-record
                # assertions cannot pass by simply reading too early.
                time.sleep(0.2)
                self._drain()
                return self.records()
            time.sleep(0.05)
        raise AssertionError(
            f"expected {count} hook records, saw {len(self.records())}: {self.records()}\n"
            f"terminal output:\n{self.text()}"
        )

    def run(self, command: str, *, records: int = 2) -> list[list[str]]:
        """Send one entry and wait until its begin/complete pair arrives."""
        before = len(self.records())
        self.send(command if command.endswith("\n") else command + "\n")
        return self.wait_for_records(before + records)[before:]

    def text(self) -> str:
        self._drain()
        return self.output.decode("utf-8", "replace")

    def wait_for_exit(self, *, timeout: float = TIMEOUT) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._drain()
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited == self.pid:
                self.pid = 0
                return status
            time.sleep(0.05)
        raise AssertionError(f"Bash did not exit within {timeout}s")

    def close(self) -> None:
        if self.pid:
            try:
                self.send("exit\n")
                self.wait_for_exit(timeout=5)
            except (AssertionError, OSError):
                try:
                    os.kill(self.pid, signal.SIGKILL)
                    os.waitpid(self.pid, 0)
                except OSError:
                    pass
        try:
            os.close(self.master)
        except OSError:
            pass


class BashIntegrationTestCase(unittest.TestCase):
    def session(self, bashrc: str = "") -> BashSession:
        temp = Path(tempfile.mkdtemp(prefix="sysai-bash-test-"))
        self.addCleanup(shutil.rmtree, temp, True)
        shell = BashSession(temp, bashrc)
        self.addCleanup(shell.close)
        return shell

    def assertBeginComplete(self, records, command, status, *, cwd=None):
        self.assertEqual(len(records), 2, records)
        begin, complete = records
        self.assertEqual(begin[:2], ["__hook", "begin"], begin)
        self.assertEqual(begin[2], command)
        self.assertEqual(complete[:2], ["__hook", "complete"], complete)
        self.assertEqual(complete[2], str(status))
        if cwd is not None:
            self.assertEqual(complete[3], cwd)


class LifecycleTests(BashIntegrationTestCase):
    def test_successful_command_reports_begin_and_zero_status(self):
        shell = self.session()
        self.assertBeginComplete(shell.run("echo hello"), "echo hello", 0)

    def test_failed_command_reports_its_status(self):
        shell = self.session()
        self.assertBeginComplete(shell.run("/bin/false"), "/bin/false", 1)

    def test_exit_status_is_captured_exactly(self):
        shell = self.session()
        records = shell.run("sh -c 'exit 7'")
        self.assertBeginComplete(records, "sh -c 'exit 7'", 7)

    def test_cwd_is_reported_before_and_after_cd(self):
        shell = self.session()
        home = str(shell.home)
        begin, complete = shell.run("cd /tmp")
        self.assertEqual(begin[3], home)
        self.assertEqual(complete[3], "/tmp")
        begin, complete = shell.run("pwd")
        self.assertEqual(begin[3], "/tmp")
        self.assertEqual(complete[3], "/tmp")

    def test_pipeline_is_one_command(self):
        shell = self.session()
        self.assertBeginComplete(
            shell.run("printf 'a\\nb\\n' | grep b"), "printf 'a\\nb\\n' | grep b", 0,
        )

    def test_and_list_is_one_command_with_final_status(self):
        shell = self.session()
        self.assertBeginComplete(shell.run("true && echo done"), "true && echo done", 0)

    def test_or_list_is_one_command_and_recovers_status(self):
        shell = self.session()
        self.assertBeginComplete(
            shell.run("/bin/false || echo recovered"), "/bin/false || echo recovered", 0,
        )

    def test_multiline_command_is_one_command(self):
        shell = self.session()
        records = shell.run("for value in 1 2\ndo\n  echo $value\ndone")
        self.assertEqual(len(records), 2, records)
        self.assertEqual(records[0][:2], ["__hook", "begin"])
        for fragment in ("for value in 1 2", "echo $value", "done"):
            self.assertIn(fragment, records[0][2])
        self.assertEqual(records[1][2], "0")
        self.assertIn("1", shell.text())

    def test_shell_function_is_one_command_not_its_body(self):
        shell = self.session("sysai_demo() { echo one; echo two; /bin/true; }\n")
        self.assertBeginComplete(shell.run("sysai_demo"), "sysai_demo", 0)
        self.assertIn("two", shell.text())

    def test_alias_is_one_command(self):
        shell = self.session("alias sysai_ll='ls -l'\n")
        self.assertBeginComplete(shell.run("sysai_ll >/dev/null"), "sysai_ll >/dev/null", 0)

    def test_command_substitution_stays_one_command(self):
        shell = self.session()
        self.assertBeginComplete(
            shell.run("echo $(basename /usr/bin/env)"), "echo $(basename /usr/bin/env)", 0,
        )
        self.assertIn("env", shell.text())

    def test_no_duplicate_records_from_the_debug_trap(self):
        shell = self.session()
        for index in range(4):
            shell.run(f"echo line-{index}")
        records = shell.records()
        self.assertEqual(len(records), 8, records)
        begins = [record[2] for record in records if record[1] == "begin"]
        self.assertEqual(begins, [f"echo line-{index}" for index in range(4)])

    def test_empty_prompt_line_records_nothing(self):
        shell = self.session()
        shell.run("echo first")
        shell.send("\n\n\n")
        time.sleep(0.6)
        shell.run("echo second")
        self.assertEqual([record[2] for record in shell.records() if record[1] == "begin"],
                         ["echo first", "echo second"])

    def test_internal_hook_invocations_never_become_records(self):
        shell = self.session()
        shell.run("echo watched")
        shell.run("cd /tmp")
        for record in shell.records():
            self.assertNotIn("__hook", record[2:])
            self.assertNotIn("__session", record[2:])
            self.assertNotIn(str(shell.fake), record[2:])

    def test_internal_hooks_do_not_leak_job_notifications(self):
        shell = self.session("set -m\n")
        shell.run("echo watched")
        output = shell.text()
        self.assertNotIn("[", output)
        self.assertNotIn("Done", output)

    def test_interrupt_reports_the_interrupt_status(self):
        shell = self.session()
        shell.send("sleep 30\n")
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline and not shell.records():
            time.sleep(0.05)
        self.assertTrue(shell.records(), "no begin record for the interrupted command")
        time.sleep(0.5)
        shell.send("\x03")
        records = shell.wait_for_records(2)
        self.assertEqual(records[0][2], "sleep 30")
        self.assertEqual(records[1][:3], ["__hook", "complete", "130"])
        # The shell survives the interrupt and keeps monitoring.
        self.assertBeginComplete(shell.run("echo alive"), "echo alive", 0)


class EnvironmentTests(BashIntegrationTestCase):
    def test_user_bashrc_is_sourced(self):
        shell = self.session(
            "export SYSAI_BASHRC_MARKER=sourced\n"
            "sysai_from_bashrc() { echo from-bashrc; }\n"
            "alias sysai_alias='echo aliased'\n"
        )
        shell.run("echo $SYSAI_BASHRC_MARKER")
        shell.run("sysai_from_bashrc")
        shell.run("sysai_alias")
        text = shell.text()
        for expected in ("sourced", "from-bashrc", "aliased"):
            self.assertIn(expected, text)

    def test_user_string_prompt_command_is_preserved(self):
        shell = self.session(
            """PROMPT_COMMAND='printf "tick\\n" >> "$SYSAI_TEST_HOME/prompt.log"'\n"""
        )
        shell.run("echo one")
        shell.run("echo two")
        ticks = (shell.home / "prompt.log").read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(ticks), 3)
        self.assertTrue(all(line == "tick" for line in ticks), ticks)

    @unittest.skipUnless((BASH_MAJOR, BASH_MINOR) >= (5, 1), "array PROMPT_COMMAND needs Bash 5.1+")
    def test_user_array_prompt_command_is_preserved_as_an_array(self):
        shell = self.session(
            """PROMPT_COMMAND=("""
            """'printf "a\\n" >> "$SYSAI_TEST_HOME/prompt.log"' """
            """'printf "b\\n" >> "$SYSAI_TEST_HOME/prompt.log"')\n"""
        )
        shell.run("echo one")
        shell.run('declare -p PROMPT_COMMAND > "$HOME/pc.txt"')
        entries = (shell.home / "prompt.log").read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(entries.count("a"), 2)
        self.assertGreaterEqual(entries.count("b"), 2)
        declaration = (shell.home / "pc.txt").read_text(encoding="utf-8")
        self.assertTrue(declaration.startswith("declare -a"), declaration)
        self.assertEqual(declaration.count("__sysai_precmd"), 1, declaration)
        self.assertEqual(declaration.count("__sysai_arm"), 1, declaration)

    def test_prompt_command_hooks_are_reinstalled_if_replaced(self):
        shell = self.session()
        shell.run("echo before")
        # Wiping PROMPT_COMMAND removes both prompt hooks; only the DEBUG
        # trap is left to notice and put them back.
        shell.send("PROMPT_COMMAND=:\n")
        time.sleep(1.0)
        shell.send("echo after\n")
        time.sleep(1.0)
        self.assertBeginComplete(shell.run("echo healed"), "echo healed", 0)
        shell.run('declare -p PROMPT_COMMAND > "$HOME/pc.txt"')
        declaration = (shell.home / "pc.txt").read_text(encoding="utf-8")
        self.assertIn("__sysai_precmd", declaration)
        self.assertIn("__sysai_arm", declaration)

    def test_exit_status_survives_the_prompt_hooks(self):
        shell = self.session(
            """PROMPT_COMMAND='printf "%s\\n" "$?" >> "$SYSAI_TEST_HOME/status.log"'\n"""
        )
        shell.run("sh -c 'exit 9'")
        shell.run("true")
        seen = (shell.home / "status.log").read_text(encoding="utf-8").splitlines()
        self.assertIn("9", seen)

    def test_command_history_works(self):
        shell = self.session()
        shell.run("echo remembered-command")
        shell.run('history > "$HOME/history.txt"')
        history = (shell.home / "history.txt").read_text(encoding="utf-8")
        self.assertIn("echo remembered-command", history)

    def test_startup_files_are_never_modified(self):
        original = "export BASHRC_MARKER=sourced\n"
        shell = self.session(original)
        digest = hashlib.sha256(shell.bashrc.read_bytes()).hexdigest()
        shell.run("echo one")
        shell.run("cd /tmp")
        shell.close()
        self.assertEqual(shell.bashrc.read_text(encoding="utf-8"), original)
        self.assertEqual(hashlib.sha256(shell.bashrc.read_bytes()).hexdigest(), digest)
        self.assertNotIn("sysai", shell.bashrc.read_text(encoding="utf-8").lower())
        for name in (".profile", ".bash_profile", ".bash_login"):
            self.assertFalse((shell.home / name).exists(), name)

    def test_existing_debug_trap_is_reported_not_silently_dropped(self):
        shell = self.session("trap 'true' DEBUG\n")
        shell.run("echo after-trap")
        self.assertIn("DEBUG trap", shell.text())
        shell.run('printf "%s\\n" "$SYSAI_REPLACED_DEBUG_TRAP" > "$HOME/trap.txt"')
        self.assertIn("DEBUG", (shell.home / "trap.txt").read_text(encoding="utf-8"))

    def test_monitoring_survives_functrace(self):
        shell = self.session("set -o functrace\nsysai_traced() { echo a; echo b; }\n")
        self.assertBeginComplete(shell.run("sysai_traced"), "sysai_traced", 0)


class StopTests(BashIntegrationTestCase):
    def test_sysai_stop_asks_the_session_to_leave_and_exits_the_child(self):
        shell = self.session()
        shell.run("echo before-stop")
        shell.send("sysai stop\n")
        status = shell.wait_for_exit()
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertIn(["__session", "stop"], shell.records())

    def test_other_sysai_subcommands_call_the_executable_without_exiting(self):
        shell = self.session()
        shell.run("sysai explain")
        self.assertIn(["explain"], shell.records())
        self.assertBeginComplete(shell.run("echo still-here"), "echo still-here", 0)


class IntegrationFileTests(unittest.TestCase):
    def test_integration_bash_parses(self):
        result = subprocess.run(
            [bash_executable(), "-n", str(ROOT / "src/sysai/integration.bash")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_zsh_integration_is_gone(self):
        self.assertFalse((ROOT / "src/sysai/integration.zsh").exists())
        self.assertTrue((ROOT / "src/sysai/integration.bash").exists())

    def test_no_zsh_runtime_references_remain(self):
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout.split()
        # The released 0.1.0 CHANGELOG section is history and stays accurate,
        # and this file names integration.zsh only to assert it is gone.
        allowed = {"CHANGELOG.md", str(Path(__file__).resolve().relative_to(ROOT))}
        offenders = []
        for name in tracked:
            if name in allowed:
                continue
            path = ROOT / name
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if "zsh" in text.lower() or "ZDOTDIR" in text:
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_session_launches_bash_with_a_temporary_rcfile(self):
        bash = bash_executable()
        self.assertTrue(os.access(bash, os.X_OK))
        self.assertTrue(bash.endswith("bash"))
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            home.mkdir()
            (home / ".bashrc").write_text("export SYSAI_BASHRC_MARKER=1\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                rcfile = write_session_rcfile(Path(temp))
            body = rcfile.read_text(encoding="utf-8")
            self.assertEqual(rcfile.stat().st_mode & 0o777, 0o600)
            self.assertIn(str(home / ".bashrc"), body)
            self.assertIn("integration.bash", body)
            self.assertNotIn("eval", body)
        # The rcfile lives in the temporary directory only.
        self.assertFalse(rcfile.exists())

    def test_rcfile_omits_a_missing_user_bashrc(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            home.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                body = write_session_rcfile(Path(temp)).read_text(encoding="utf-8")
            self.assertNotIn(".bashrc", body)
            self.assertIn("integration.bash", body)

    def test_installer_ships_the_bash_integration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "install"
            config = Path(temp) / "config"
            subprocess.run(
                [str(ROOT / "install.sh")], check=True, capture_output=True, text=True,
                env={**os.environ, "SYSAI_INSTALL_ROOT": str(root), "XDG_CONFIG_HOME": str(config)},
            )
            installed = root / "lib/sysai-terminal/sysai"
            self.assertTrue((installed / "integration.bash").exists())
            self.assertFalse((installed / "integration.zsh").exists())


if __name__ == "__main__":
    unittest.main()
