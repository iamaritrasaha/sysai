from __future__ import annotations

import ast
import json
import os
import socket
import stat
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import sysai
from sysai import baseline, monitor, reports
from sysai.config import Config, state_dir
from sysai.diagnostics import action_catalogue, action_details, parse_action_plan
from sysai.display import box
from sysai.evidence import build
from sysai.health import web_queries
from sysai.ollama import is_owned_ollama_process
from sysai.privacy import LOCAL
from sysai.session import Session
from sysai.web import sanitize_search_query


ROOT = Path(__file__).resolve().parents[1]
# Interpreters that would turn a string into executable code. SysAI never
# builds an argv starting with one of these plus `-c`.
SHELL_INTERPRETERS = ("bash", "sh", "dash", "ksh", "/bin/bash", "/bin/sh")


class ReleaseSecurityTests(unittest.TestCase):
    def test_version_sources_match(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        self.assertEqual(project["version"], sysai.__version__)

    def test_cli_version(self):
        result = subprocess.run(
            [str(ROOT / "bin/sysai"), "--version"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        self.assertEqual(result.stdout.strip(), "sysai 0.1.0")

    def test_model_terminal_controls_are_removed(self):
        rendered = box("safe\x1b]52;c;ZXZpbA==\x07\x1b[31mred\x1b[0m")
        self.assertNotIn("\x1b", rendered)
        self.assertIn("safered", rendered)

    def test_web_sanitizer_redacts_and_removes_controls(self):
        query = "kernel\nAPI_KEY=super-secret-value\x1b[31m regression"
        cleaned = sanitize_search_query(query)
        self.assertNotIn("super-secret-value", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertLessEqual(len(cleaned), 500)

    def test_web_search_never_receives_terminal_output(self):
        session = Session(Config(web_enabled=True), "/bin/true")
        session.records.append({
            "command": "echo context", "exit_code": 0, "cwd": "/tmp",
            "output": "RAW-TRANSCRIPT-MUST-NOT-LEAVE",
        })
        provider = mock.Mock()
        provider.search.return_value = []
        server_end, client_end = socket.socketpair()
        with mock.patch("sysai.session.OllamaWebSearch", return_value=provider), \
             mock.patch("sysai.session.load_private_env", return_value={"OLLAMA_API_KEY": "fake"}), \
             mock.patch.object(session, "_ask_local", return_value="answer"):
            session._control_stream(
                {"action": "ask", "question": "release API_KEY=fake-secret", "web": True}, server_end,
            )
        server_end.close()
        client_end.settimeout(2)
        messages = [json.loads(line) for line in client_end.recv(65536).splitlines() if line]
        client_end.close()
        self.assertEqual(messages[-1], {"type": "done", "ok": True})
        sent_query = provider.search.call_args.args[0]
        self.assertNotIn("RAW-TRANSCRIPT", sent_query)
        self.assertNotIn("fake-secret", sent_query)

    def test_runtime_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            target = base / "target"
            target.mkdir()
            (base / "sysai").symlink_to(target, target_is_directory=True)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                with self.assertRaisesRegex(RuntimeError, "Unsafe SysAI runtime path"):
                    state_dir()

    def test_runtime_directory_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                path = state_dir()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_second_session_is_refused_by_runtime_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                first = Session(Config(), "/bin/true")
                second = Session(Config(), "/bin/true")
                first._acquire_session_lock()
                try:
                    with self.assertRaisesRegex(RuntimeError, "already active"):
                        second._acquire_session_lock()
                finally:
                    with mock.patch.object(first.ollama, "cleanup"):
                        first.cleanup()

    def test_state_write_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime_base = Path(temp) / "runtime"
            runtime_base.mkdir()
            victim = Path(temp) / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_base)}):
                session = Session(Config(), "/bin/true")
                session.state_path.symlink_to(victim)
                session._write_state()
                self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
                self.assertFalse(session.state_path.is_symlink())
                self.assertEqual(stat.S_IMODE(session.state_path.stat().st_mode), 0o600)
                state = json.loads(session.state_path.read_text(encoding="utf-8"))
                self.assertNotIn("records", state)
                self.assertNotIn("output", state)
                self.assertNotIn("command", state)

    def test_owned_process_check_requires_all_identity_fields(self):
        with mock.patch("sysai.ollama.Path.read_bytes", return_value=b"/usr/bin/ollama\0serve\0"), \
             mock.patch("sysai.ollama.process_start_time", return_value=777), \
             mock.patch("sysai.ollama.os.getpgid", return_value=123):
            self.assertTrue(is_owned_ollama_process(123, 777, 123))
            self.assertFalse(is_owned_ollama_process(123, 778, 123))
            self.assertFalse(is_owned_ollama_process(123, 777, 124))

    def test_model_output_has_no_execution_sink(self):
        source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src/sysai").glob("*.py"))
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)

    def test_no_module_ever_runs_bash_dash_c_or_a_shell_interpreter(self):
        for path in sorted((ROOT / "src/sysai").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Tuple, ast.List)):
                    continue
                literals = [element.value for element in node.elts
                            if isinstance(element, ast.Constant) and isinstance(element.value, str)]
                if len(literals) < 2:
                    continue
                with self.subTest(path=path.name, argv=literals[:2]):
                    self.assertFalse(literals[0] in SHELL_INTERPRETERS
                                     and literals[1] in ("-c", "-lc"),
                                     f"{path.name} builds a shell -c argv")

    def test_every_audited_action_is_read_only_and_never_a_shell(self):
        trusted = {"units": {"x.service"}, "devices": {"/dev/sda"},
                   "interfaces": {"eth0"}, "packages": {"bash"}}
        parameters = {"unit": "x.service", "device": "/dev/sda",
                      "interface": "eth0", "package": "bash"}
        for entry in action_catalogue():
            with self.subTest(action=entry["id"]):
                params = {name: parameters[name] for name in entry["params"]}
                detail = action_details(entry["id"], params, trusted)
                self.assertTrue(detail["read_only"])
                argv = detail["argv"]
                self.assertNotIn(argv[0], (*SHELL_INTERPRETERS, "eval"))
                self.assertNotIn("-c", argv[:2])
                if argv[0] == "sudo":
                    self.assertTrue(detail["elevated"])
                else:
                    self.assertFalse(detail["elevated"])

    def test_a_model_cannot_supply_argv_for_any_action(self):
        for payload in ('{"actions":[{"id":"system.kernel_version","params":{"argv":["rm","-rf","/"]}}]}',
                        '{"actions":[{"id":"bash -c \'rm -rf /\'","params":{}}]}',
                        '{"actions":[{"id":"disk.smart_health","params":{"device":"/dev/sda; rm -rf /"}}]}'):
            planned = parse_action_plan(payload)
            for item in planned:
                with self.subTest(payload=payload):
                    with self.assertRaises(ValueError):
                        action_details(item["id"], item["params"],
                                       {"units": set(), "devices": set(),
                                        "interfaces": set(), "packages": set()})

    def test_reports_and_baselines_are_sanitized_more_strictly_than_the_screen(self):
        document = build(command="gpu", scope="gpu", level=LOCAL,
                         sections={"note": "host 192.168.1.42 mac a4:bb:6d:1f:2e:3c"})
        self.assertEqual(document["privacy"]["level"], LOCAL)
        markdown = reports.to_markdown(document)
        self.assertNotIn("192.168.1.42", markdown)
        self.assertNotIn("a4:bb:6d:1f:2e:3c", markdown)
        self.assertEqual(baseline.snapshot()["schema_version"], baseline.SCHEMA_VERSION)

    def test_web_queries_are_built_from_finding_labels_not_evidence(self):
        document = build(
            command="gpu", scope="gpu",
            sections={"gpu": {"driver": {"drivers_in_use": ["amdgpu"]}}},
            findings=[{"id": "gpu.kernel_events", "domain": "gpu",
                       "evidence": {"sample": ["SECRET /home/alice 10.0.0.1 token=abc"]},
                       "title": "SECRET /home/alice"}])
        joined = " ".join(web_queries(document))
        for secret in ("SECRET", "alice", "10.0.0.1", "token"):
            self.assertNotIn(secret, joined)
        self.assertIn("amdgpu", joined)

    def test_watch_never_persists_telemetry(self):
        result = {"domain": "memory", "requested_duration": 5, "interval": 1,
                  "samples": [{"at": 1.0, "used_percent": 10.0}], "sample_count": 1,
                  "interrupted": False, "started_wall": 0.0, "ended_wall": 5.0}
        document = monitor.build_evidence(result, monitor.summarize(result),
                                          {"available": True, "count": 0, "sample": []})
        self.assertNotIn("samples", document["sections"].get("metrics", {}))
        self.assertFalse(document["sections"]["raw_samples_retained"])

    def test_only_documented_paths_are_ever_written(self):
        """Persistent writes belong to config, baselines, and explicit reports."""
        writers = {"config.py": {"set_config_value"}, "baseline.py": {"create"},
                   "reports.py": {"write"}, "session.py": {"_write_state", "write_session_rcfile"},
                   "ollama.py": {"ensure_ready"}, "updater.py": {"_extract"}}
        for path in sorted((ROOT / "src/sysai").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("write_text", "write_bytes")):
                    continue
                enclosing = [item.name for item in ast.walk(tree)
                             if isinstance(item, ast.FunctionDef)
                             and item.lineno <= node.lineno <= (item.end_lineno or item.lineno)]
                with self.subTest(path=path.name, line=node.lineno):
                    self.assertTrue(set(enclosing) & writers.get(path.name, set()),
                                    f"{path.name}:{node.lineno} writes outside a documented writer")

    def test_installer_refuses_symlinked_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            install_root = base / "install"
            config_root = base / "config"
            (install_root / "bin").mkdir(parents=True)
            victim = base / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            (install_root / "bin/sysai").symlink_to(victim)
            result = subprocess.run(
                [str(ROOT / "install.sh")], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**os.environ, "SYSAI_INSTALL_ROOT": str(install_root), "XDG_CONFIG_HOME": str(config_root)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing symlinked managed path", result.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
