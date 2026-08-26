from __future__ import annotations

import unittest
from unittest import mock

from sysai import collect, domains
from sysai.evidence import CLASSIFICATIONS, NOT_CHECKED, SEVERITIES
from sysai.render import domain_rows, render_document


def _run(mapping):
    """Fake `collect.run` driven by the first argv element."""
    def runner(argv, timeout=3, limit=12_000):
        return mapping.get(argv[0], {"status": "unavailable", "reason": f"{argv[0]} not installed"})
    return runner


class DomainCollectorTests(unittest.TestCase):
    def test_every_domain_collects_and_produces_a_valid_document(self):
        for domain in domains.DOMAINS:
            with self.subTest(domain=domain):
                document = domains.collect_scope(domain)
                self.assertEqual(document["schema_version"], 1)
                self.assertEqual(document["request"]["scope"], domain)
                self.assertIsInstance(document["sections"], dict)
                for item in document["findings"]:
                    self.assertIn(item["severity"], SEVERITIES)
                    self.assertIn(item["classification"], CLASSIFICATIONS)
                    self.assertEqual(item["domain"], domain)
                for item in document["unavailable"]:
                    self.assertEqual(item["classification"], NOT_CHECKED)

    def test_full_system_scope_covers_every_domain(self):
        document = domains.collect_scope(domains.FULL_SYSTEM)
        self.assertEqual(set(document["sections"]), set(domains.DOMAINS))

    def test_unknown_domain_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown diagnostic domain"):
            domains.collect_domain("definitely-not-a-domain")

    def test_missing_utilities_become_not_checked_never_findings(self):
        with mock.patch("sysai.collect.shutil.which", return_value=None):
            for domain in domains.DOMAINS:
                with self.subTest(domain=domain):
                    _sections, findings, missing = domains.collect_domain(domain)
                    self.assertTrue(all(item["classification"] == NOT_CHECKED for item in missing))
                    self.assertNotIn("unavailable", {item["id"] for item in findings})

    def test_every_domain_renders_without_the_model(self):
        for domain in domains.DOMAINS:
            with self.subTest(domain=domain):
                document = domains.collect_scope(domain)
                text = render_document(document)
                self.assertIn("Overall", text)
                self.assertNotIn("**", text)


class GpuTests(unittest.TestCase):
    AMD = ("01:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. "
           "[AMD/ATI] Navi 33 [1002:7480]\n"
           "\tKernel driver in use: amdgpu\n\tKernel modules: amdgpu\n")

    def test_amd_hardware_never_consults_or_reports_nvidia_tooling(self):
        with mock.patch("sysai.collect.run", side_effect=_run({
                "lspci": {"status": "ok", "exit_code": 0, "output": self.AMD}})) as run:
            sections, missing = domains.collect_gpu()
        consulted = {call.args[0][0] for call in run.call_args_list}
        self.assertNotIn("nvidia-smi", consulted)
        self.assertNotIn("nvidia-smi", {item["check"] for item in missing})
        self.assertEqual(sections["identity"]["vendors"], ["amd"])
        self.assertEqual(sections["driver"]["drivers_in_use"], ["amdgpu"])

    def test_nvidia_hardware_never_consults_amd_tooling(self):
        nvidia = ("01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA106 [10de:2504]\n"
                  "\tKernel driver in use: nvidia\n")
        with mock.patch("sysai.collect.run", side_effect=_run({
                "lspci": {"status": "ok", "exit_code": 0, "output": nvidia}})) as run:
            sections, _missing = domains.collect_gpu()
        consulted = {call.args[0][0] for call in run.call_args_list}
        self.assertNotIn("amd-smi", consulted)
        self.assertNotIn("rocm-smi", consulted)
        self.assertEqual(sections["identity"]["vendors"], ["nvidia"])

    def test_repeated_kernel_events_become_a_confirmed_warning(self):
        findings = domains.analyze_gpu({"kernel": {"gpu_event_count": 5, "gpu_event_sample": ["x"]},
                                        "driver": {}, "drm": {"cards": []}})
        self.assertEqual(findings[0]["id"], "gpu.kernel_events")
        self.assertEqual(findings[0]["classification"], "CONFIRMED")
        self.assertEqual(findings[0]["severity"], "warning")

    def test_a_single_kernel_event_stays_a_possibility(self):
        findings = domains.analyze_gpu({"kernel": {"gpu_event_count": 1, "gpu_event_sample": ["x"]},
                                        "driver": {}, "drm": {"cards": []}})
        self.assertEqual(findings[0]["classification"], "POSSIBLE")
        self.assertEqual(findings[0]["severity"], "informational")

    def test_a_device_without_a_driver_is_a_finding(self):
        findings = domains.analyze_gpu({"kernel": {}, "drm": {"cards": []},
                                        "driver": {"devices_without_driver": ["VGA thing"]}})
        self.assertEqual(findings[0]["id"], "gpu.no_kernel_driver")


class MemoryTests(unittest.TestCase):
    def test_large_page_cache_is_never_a_leak(self):
        sections = {"ram": {"used_percent": 30.0, "cached_bytes": 10 * 1024**3,
                            "total_bytes": 16 * 1024**3, "available_bytes": 11 * 1024**3},
                    "swap": {"total_bytes": 0}, "oom": {"event_count": 0}}
        self.assertEqual(domains.analyze_memory(sections), [])

    def test_oom_events_are_critical_and_confirmed(self):
        sections = {"ram": {"used_percent": 40.0}, "swap": {"total_bytes": 0},
                    "oom": {"event_count": 3, "sample": ["Out of memory: Killed process 1"]}}
        finding = domains.analyze_memory(sections)[0]
        self.assertEqual(finding["id"], "memory.oom_events")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["count"], 3)

    def test_swappiness_is_reported_but_never_a_finding(self):
        sections, _missing = domains.collect_memory()
        self.assertIn("swappiness", sections["swap"])
        self.assertNotIn("memory.swappiness",
                         {item["id"] for item in domains.analyze_memory(sections)})


class DiskTests(unittest.TestCase):
    def test_full_filesystem_and_inode_exhaustion_are_separate_findings(self):
        sections = {"filesystems": [
            {"mountpoint": "/", "fstype": "ext4", "capacity_percent": 95.0,
             "inode_percent": 97.0, "currently_read_only": False}], "errors": {}}
        ids = {item["id"] for item in domains.analyze_disk(sections)}
        self.assertEqual(ids, {"disk.full", "disk.inodes_exhausted"})

    def test_read_only_mount_is_critical(self):
        sections = {"filesystems": [
            {"mountpoint": "/", "fstype": "ext4", "capacity_percent": 10.0,
             "inode_percent": 5.0, "currently_read_only": True}], "errors": {}}
        finding = domains.analyze_disk(sections)[0]
        self.assertEqual(finding["id"], "disk.read_only_mount")
        self.assertEqual(finding["severity"], "critical")

    def test_smart_is_never_collected_without_approval(self):
        sections, _missing = domains.collect_disk()
        self.assertFalse(sections["smart"]["collected"])

    def test_io_errors_suggest_the_approval_gated_smart_action(self):
        sections = {"filesystems": [], "errors": {"io_error_count": 4, "io_error_sample": ["x"]}}
        finding = domains.analyze_disk(sections)[0]
        self.assertEqual(finding["suggested_next_diagnostic"], "disk.smart_health")


class NetworkTests(unittest.TestCase):
    def test_missing_default_route_and_dns_failure_are_findings(self):
        sections = {"routing": {"default_route_present": False},
                    "dns": {"resolution_succeeded": False}, "events": {}}
        ids = {item["id"] for item in domains.analyze_network(sections)}
        self.assertEqual(ids, {"network.no_default_route", "network.dns_failure"})

    def test_link_flapping_needs_repeated_events(self):
        base = {"routing": {"default_route_present": True}, "dns": {"resolution_succeeded": True}}
        self.assertEqual(domains.analyze_network({**base, "events": {"link_event_count": 2}}), [])
        finding = domains.analyze_network({**base, "events": {"link_event_count": 6}})[0]
        self.assertEqual(finding["id"], "network.link_flapping")
        self.assertEqual(finding["classification"], "PROBABLE")

    def test_collected_network_facts_carry_no_addresses(self):
        sections, _missing = domains.collect_network()
        serialized = repr(sections)
        self.assertNotIn("inet ", serialized)
        for entry in sections["interfaces"]["entries"]:
            self.assertNotIn("address", entry)


class BootServicesPackagesThermalTests(unittest.TestCase):
    def test_failed_units_and_reboot_required_are_boot_findings(self):
        sections = {"units": {"failed_count": 2, "failed_units": ["a.service", "b.service"]},
                    "journal": {"critical_count": 0}, "timing": {},
                    "reboot_required": {"required": True, "packages": []}}
        ids = {item["id"] for item in domains.analyze_boot(sections)}
        self.assertEqual(ids, {"boot.failed_units", "boot.reboot_required"})

    def test_one_critical_journal_entry_is_a_warning_not_a_crisis(self):
        sections = {"units": {}, "journal": {"critical_count": 1, "critical_sample": ["x"]},
                    "timing": {}, "reboot_required": {}}
        finding = domains.analyze_boot(sections)[0]
        self.assertEqual(finding["severity"], "warning")
        sections["journal"]["critical_count"] = 9
        self.assertEqual(domains.analyze_boot(sections)[0]["severity"], "critical")

    def test_services_are_never_restarted_enabled_or_disabled(self):
        with mock.patch("sysai.collect.run", side_effect=_run({})) as run:
            domains.collect_services()
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertNotIn(argv[1] if len(argv) > 1 else "",
                             {"start", "stop", "restart", "enable", "disable", "mask"})

    def test_restart_loops_are_probable_not_confirmed(self):
        sections = {"state": {}, "failed": {"count": 0},
                    "restarting": {"units": [{"unit": "x.service", "events": 4}]},
                    "recent_failures": {"count": 0}}
        finding = domains.analyze_services(sections)[0]
        self.assertEqual(finding["id"], "services.restart_loop")
        self.assertEqual(finding["classification"], "PROBABLE")

    def test_package_collection_never_installs_or_upgrades(self):
        with mock.patch("sysai.collect.run", side_effect=_run({})) as run:
            domains.collect_packages()
        for call in run.call_args_list:
            self.assertFalse({"install", "upgrade", "remove", "purge", "autoremove",
                              "dist-upgrade", "full-upgrade"} & set(call.args[0]))

    def test_pending_upgrades_are_informational_only(self):
        sections = {"manager": {"supported": True}, "integrity": {"audit_clean": True},
                    "upgrades": {"available": 12, "sample": []}, "held": {"packages": []},
                    "reboot_required": {}}
        finding = domains.analyze_packages(sections)[0]
        self.assertEqual(finding["severity"], "informational")
        self.assertEqual(finding["classification"], "INFORMATIONAL")

    def test_interrupted_dpkg_state_is_confirmed(self):
        sections = {"manager": {"supported": True},
                    "integrity": {"audit_clean": False, "dpkg_interrupted": True,
                                  "interrupted_updates": ["0001"], "audit_output": "broken"},
                    "upgrades": {}, "held": {"packages": []}, "reboot_required": {}}
        finding = domains.analyze_packages(sections)[0]
        self.assertEqual(finding["id"], "packages.dpkg_interrupted")
        self.assertEqual(finding["classification"], "CONFIRMED")

    def test_absent_thermal_sensors_are_not_checked_rather_than_failed(self):
        with mock.patch("sysai.collect.thermal_zones", return_value=[]), \
             mock.patch("sysai.domains._hwmon", return_value=[]), \
             mock.patch("sysai.collect.run", side_effect=_run({})):
            sections, missing = domains.collect_thermal()
        self.assertEqual(domains.analyze_thermal(sections), [])
        self.assertIn("thermal sensors", {item["check"] for item in missing})
        self.assertTrue(all(item["classification"] == NOT_CHECKED for item in missing))

    def test_high_temperature_escalates_only_past_the_critical_threshold(self):
        warm = domains.analyze_thermal({"summary": {"max_celsius": 92.0}, "throttling": {}})[0]
        self.assertEqual(warm["severity"], "warning")
        hot = domains.analyze_thermal({"summary": {"max_celsius": 101.0}, "throttling": {}})[0]
        self.assertEqual(hot["severity"], "critical")


class CollectorPrimitiveTests(unittest.TestCase):
    def test_growing_logs_are_read_from_the_end(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write("\n".join(f"line {index}" for index in range(20000)))
            path = handle.name
        tail = collect.read_tail(path, 200)
        self.assertIn("line 19999", tail)
        self.assertNotIn("line 0\n", tail)

    def test_run_uses_fixed_argv_and_never_a_shell(self):
        with mock.patch("sysai.collect.shutil.which", return_value="/bin/echo"), \
             mock.patch("sysai.collect.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
            collect.run(("echo", "hello"))
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.args[0], ("/bin/echo", "hello"))

    def test_domain_rows_survive_an_unexpected_section_shape(self):
        rows = domain_rows("gpu", {"identity": "not a dict"})
        self.assertTrue(rows)
        self.assertTrue(all(len(row) == 3 for row in rows))


if __name__ == "__main__":
    unittest.main()
