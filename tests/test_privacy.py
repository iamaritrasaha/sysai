from __future__ import annotations

import unittest
from unittest import mock

from sysai.evidence import build, relabel
from sysai.privacy import LOCAL, SHARED, sanitize, sanitize_text


class PrivacyTests(unittest.TestCase):
    def test_username_and_home_path_are_removed_when_shared(self):
        with mock.patch.dict("os.environ", {"USER": "alice", "LOGNAME": "alice"}), \
             mock.patch("sysai.privacy.os.path.expanduser", return_value="/home/alice"):
            cleaned = sanitize_text("alice ran df on /home/alice/projects", SHARED)
        self.assertNotIn("alice", cleaned)
        self.assertIn("<user>", cleaned)

    def test_home_paths_of_other_users_are_removed_too(self):
        self.assertEqual(sanitize_text("/home/bob/.ssh/config", SHARED), "/home/<user>/.ssh/config")

    def test_hostname_is_removed_when_shared(self):
        with mock.patch("sysai.privacy.socket.gethostname", return_value="workstation-7"):
            cleaned = sanitize_text("Aug 26 10:00:00 workstation-7 kernel: hello", SHARED)
        self.assertNotIn("workstation-7", cleaned)
        self.assertIn("<host>", cleaned)

    def test_private_ipv4_addresses_are_removed(self):
        for address in ("10.0.0.1", "172.16.4.9", "192.168.1.42", "169.254.3.7", "127.0.0.1"):
            self.assertEqual(sanitize_text(f"peer {address} up", SHARED), "peer <ipv4> up")

    def test_ipv6_link_local_and_unique_local_are_removed(self):
        for address in ("fe80::1a2b:3c4d:5e6f:7a8b", "fd00::1", "2001:db8::1"):
            self.assertEqual(sanitize_text(f"addr {address}/64", SHARED), "addr <ipv6>")

    def test_mac_addresses_are_removed(self):
        self.assertEqual(sanitize_text("link/ether a4:bb:6d:1f:2e:3c", SHARED), "link/ether <mac>")

    def test_serial_number_fields_are_removed(self):
        self.assertIn("<serial>", sanitize_text("Serial Number: WD-WX41A99KKF12", SHARED))
        self.assertNotIn("WX41A99KKF12", sanitize_text("serial=WX41A99KKF12", SHARED))

    def test_uuids_are_removed(self):
        value = "UUID=6f3a1c2e-9b4d-4a7f-8e11-2c3d4e5f6a7b"
        self.assertEqual(sanitize_text(value, SHARED), "UUID=<uuid>")

    def test_tokens_api_keys_and_auth_headers_are_removed_at_every_level(self):
        value = ("Authorization: Bearer abcdefghijklmnopqrst\n"
                 "OLLAMA_API_KEY=super-secret-value\n"
                 "ghp_012345678901234567890123456789012345")
        for level in (LOCAL, SHARED):
            cleaned = sanitize_text(value, level)
            self.assertNotIn("abcdefghijklmnopqrst", cleaned)
            self.assertNotIn("super-secret-value", cleaned)
            self.assertNotIn("ghp_0123456789", cleaned)

    def test_private_keys_are_removed_at_every_level(self):
        value = "-----BEGIN OPENSSH PRIVATE KEY-----\nmaterial\n-----END OPENSSH PRIVATE KEY-----"
        for level in (LOCAL, SHARED):
            self.assertEqual(sanitize_text(value, level), "<redacted-private-key>")

    def test_local_level_keeps_local_identifiers(self):
        with mock.patch("sysai.privacy.socket.gethostname", return_value="workstation-7"):
            cleaned = sanitize_text("workstation-7 at 192.168.1.42", LOCAL)
        self.assertIn("workstation-7", cleaned)
        self.assertIn("192.168.1.42", cleaned)

    def test_log_timestamps_and_pci_addresses_survive_sanitization(self):
        line = "Aug 26 22:35:53 box kernel: amdgpu 0000:c5:00.0: [drm] REG_WAIT timeout"
        cleaned = sanitize_text(line, SHARED)
        self.assertIn("22:35:53", cleaned)
        self.assertIn("0000:c5:00.0", cleaned)

    def test_the_syslog_hostname_field_is_removed_from_journal_lines(self):
        for line, expected in (
            ("Aug 26 22:35:53 workstation-7 kernel: reset",
             "Aug 26 22:35:53 <host> kernel: reset"),
            ("2026-08-26T22:35:53+0530 workstation-7 systemd[1]: started",
             "2026-08-26T22:35:53+0530 <host> systemd[1]: started"),
        ):
            self.assertEqual(sanitize_text(line, SHARED), expected)

    def test_structure_is_sanitized_recursively_including_keys(self):
        value = {"hostname": "workstation-7", "serial": "WX41A99KKF12",
                 "api_key": "secret", "nested": [{"mac": "a4:bb:6d:1f:2e:3c"}]}
        cleaned = sanitize(value, SHARED)
        self.assertEqual(cleaned["hostname"], "<host>")
        self.assertEqual(cleaned["serial"], "<serial>")
        self.assertEqual(cleaned["api_key"], "<redacted>")
        self.assertEqual(cleaned["nested"][0]["mac"], "<mac>")

    def test_evidence_can_be_relabelled_to_a_stricter_level(self):
        document = build(command="test", scope="gpu",
                         sections={"note": "host 192.168.1.42"}, level=LOCAL)
        self.assertEqual(document["privacy"]["level"], LOCAL)
        stricter = relabel(document, SHARED)
        self.assertEqual(stricter["privacy"]["level"], SHARED)
        self.assertIn("<ipv4>", stricter["sections"]["note"])


if __name__ == "__main__":
    unittest.main()
