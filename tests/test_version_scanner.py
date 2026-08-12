"""Tests for version_scanner: range comparison, fingerprinting, lookup, alerts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from detectors.base import Finding
from detectors.version_scanner import (
    VersionScannerDetector,
    normalize_version,
    parse_affected_range,
    parse_dpkg_output,
    parse_http_server_header,
    parse_mysql_handshake,
    parse_nvd_response,
    parse_rpm_output,
    parse_searchsploit_json,
    parse_ssh_banner,
    parse_version,
    severity_from_cvss,
    severity_from_title,
    version_in_advisory,
)
from storage.db import Database


def _db(tmp: str) -> Database:
    return Database(Path(tmp) / "t.db")


def _det(db: Database, **cfg) -> VersionScannerDetector:
    config = {
        "engine": "searchsploit",
        "scan_interval_seconds": 0,  # disable throttle in tests
        "cache_ttl_hours": 24,
        "min_severity_alert": "MEDIUM",
        "alert_on_low_confidence": False,
        "watch_packages": ["openssh", "openssh-server", "nginx", "apache", "mysql"],
        **cfg,
    }
    return VersionScannerDetector(db, config)


DPKG_SAMPLE = """\
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
||/ Name           Version                Architecture Description
+++-==============-======================-============-=================================
ii  openssh-server 1:9.1p1-1ubuntu2       amd64        secure shell (SSH) server
ii  nginx          1.18.0-6ubuntu14.4     amd64        small, powerful, scalable web/proxy server
rc  oldpkg         0.1                    amd64        removed but config remains
hi  sudo           1.9.9-1ubuntu2         amd64        Provide limited super user privileges
"""

RPM_SAMPLE = """\
openssh-server\t9.1p1
nginx\t1.20.1
"""

SEARCHSPLOIT_JSON = json.dumps({
    "RESULTS_EXPLOIT": [
        {
            "Title": "OpenSSH < 9.3 - Remote Code Execution",
            "EDB-ID": "11111",
            "Type": "remote",
            "Platform": "Linux",
        },
        {
            "Title": "OpenSSH Authentication Bypass",
            "EDB-ID": "22222",
            "Type": "local",
            "Platform": "Linux",
        },
        {
            "Title": "Apache 2.4.49-2.4.50 - Path Traversal",
            "EDB-ID": "33333",
            "Type": "remote",
            "Platform": "Linux",
        },
    ]
})


class TestNormalizeVersion(unittest.TestCase):
    def test_strips_epoch_and_ubuntu_suffix(self) -> None:
        self.assertEqual(normalize_version("1:9.3p1-1ubuntu2"), "9.3.post1")

    def test_strips_deb_suffix(self) -> None:
        self.assertEqual(normalize_version("7.9p1-10+deb11u1"), "7.9.post1")

    def test_kernel_abi_suffix(self) -> None:
        self.assertEqual(
            normalize_version("5.15.0-91-generic", kernel=True), "5.15.0"
        )

    def test_plain_semver(self) -> None:
        self.assertEqual(normalize_version("2.4.49"), "2.4.49")


class TestVersionRangeComparison(unittest.TestCase):
    """The bug-prone core: real comparisons, not substring matching."""

    def test_openssh_94_does_not_match_lt_93(self) -> None:
        matched, confidence = version_in_advisory("9.4", "OpenSSH < 9.3")
        self.assertFalse(matched)
        self.assertEqual(confidence, "high")

    def test_openssh_91_does_match_lt_93(self) -> None:
        matched, confidence = version_in_advisory("9.1", "OpenSSH < 9.3")
        self.assertTrue(matched)
        self.assertEqual(confidence, "high")

    def test_openssh_93_exclusive_upper_bound(self) -> None:
        matched, _ = version_in_advisory("9.3", "OpenSSH < 9.3")
        self.assertFalse(matched)
        matched, _ = version_in_advisory("9.3", "OpenSSH <= 9.3")
        self.assertTrue(matched)

    def test_openssh_p_patch_vs_base(self) -> None:
        # 9.3p1 is newer than 9.3, so it must not match "< 9.3"
        matched, confidence = version_in_advisory("9.3p1", "OpenSSH < 9.3")
        self.assertFalse(matched)
        self.assertEqual(confidence, "high")
        matched, _ = version_in_advisory("9.2p1", "OpenSSH < 9.3")
        self.assertTrue(matched)

    def test_distro_suffix_does_not_break_compare(self) -> None:
        matched, confidence = version_in_advisory(
            "1:9.1p1-1ubuntu2", "OpenSSH < 9.3 - Remote Code Execution"
        )
        self.assertTrue(matched)
        self.assertEqual(confidence, "high")
        matched, _ = version_in_advisory(
            "1:9.4p1-1ubuntu2", "OpenSSH < 9.3 - Remote Code Execution"
        )
        self.assertFalse(matched)

    def test_apache_inclusive_dash_range(self) -> None:
        title = "Apache 2.4.49-2.4.50 - Path Traversal"
        self.assertTrue(version_in_advisory("2.4.49", title)[0])
        self.assertTrue(version_in_advisory("2.4.50", title)[0])
        self.assertFalse(version_in_advisory("2.4.48", title)[0])
        self.assertFalse(version_in_advisory("2.4.51", title)[0])
        self.assertEqual(version_in_advisory("2.4.49", title)[1], "high")

    def test_two_sided_openssh_range(self) -> None:
        title = "OpenSSH 2.3 < 7.7 - Username Enumeration"
        self.assertTrue(version_in_advisory("5.0", title)[0])
        self.assertTrue(version_in_advisory("2.3", title)[0])
        self.assertFalse(version_in_advisory("7.7", title)[0])
        self.assertFalse(version_in_advisory("2.2", title)[0])
        self.assertFalse(version_in_advisory("8.0", title)[0])

    def test_before_and_through_wording(self) -> None:
        self.assertTrue(version_in_advisory("9.2", "OpenSSH before 9.3")[0])
        self.assertFalse(version_in_advisory("9.3", "OpenSSH before 9.3")[0])
        self.assertTrue(version_in_advisory("9.3", "OpenSSH through 9.3")[0])
        self.assertFalse(version_in_advisory("9.4", "OpenSSH through 9.3")[0])

    def test_no_range_is_low_confidence(self) -> None:
        matched, confidence = version_in_advisory(
            "9.1", "OpenSSH Authentication Bypass"
        )
        # version string "9.1" is not in the title → no substring hit
        self.assertFalse(matched)
        self.assertEqual(confidence, "low")
        rng = parse_affected_range("OpenSSH Authentication Bypass")
        self.assertIsNone(rng)

    def test_parse_version_comparable(self) -> None:
        self.assertLess(parse_version("9.1"), parse_version("9.3"))
        self.assertGreater(parse_version("9.4"), parse_version("9.3"))
        self.assertLess(parse_version("9.2p1"), parse_version("9.3"))


class TestSeverityMapping(unittest.TestCase):
    def test_cvss_buckets(self) -> None:
        self.assertEqual(severity_from_cvss(9.8), "critical")
        self.assertEqual(severity_from_cvss(9.0), "critical")
        self.assertEqual(severity_from_cvss(7.5), "high")
        self.assertEqual(severity_from_cvss(4.0), "medium")
        self.assertEqual(severity_from_cvss(3.9), "low")

    def test_title_keywords_only_when_high_confidence(self) -> None:
        self.assertEqual(
            severity_from_title("OpenSSH < 9.3 - Remote Code Execution", "high"),
            "high",
        )
        self.assertEqual(
            severity_from_title("sudo privilege escalation", "high"),
            "high",
        )
        self.assertEqual(
            severity_from_title("OpenSSH < 9.3 - Remote Code Execution", "low"),
            "medium",
        )
        self.assertEqual(severity_from_title("local info leak", "high"), "medium")


class TestPackageParsers(unittest.TestCase):
    def test_dpkg_installed_only(self) -> None:
        pkgs = parse_dpkg_output(DPKG_SAMPLE)
        names = {p["name"] for p in pkgs}
        self.assertIn("openssh-server", names)
        self.assertIn("nginx", names)
        self.assertIn("sudo", names)  # hi = hold+installed
        self.assertNotIn("oldpkg", names)  # rc = removed
        ssh = next(p for p in pkgs if p["name"] == "openssh-server")
        self.assertEqual(ssh["version"], "1:9.1p1-1ubuntu2")

    def test_rpm_tab_separated(self) -> None:
        pkgs = parse_rpm_output(RPM_SAMPLE)
        self.assertEqual(
            pkgs,
            [
                {"name": "openssh-server", "version": "9.1p1"},
                {"name": "nginx", "version": "1.20.1"},
            ],
        )

    def test_rpm_nevra(self) -> None:
        pkgs = parse_rpm_output("openssh-8.8p1-1.fc36.x86_64\n")
        self.assertEqual(pkgs, [{"name": "openssh", "version": "8.8p1"}])


class TestBannerParsers(unittest.TestCase):
    def test_ssh(self) -> None:
        self.assertEqual(
            parse_ssh_banner(b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-3\r\n"),
            {"name": "openssh", "version": "9.2p1"},
        )

    def test_nginx_and_apache(self) -> None:
        self.assertEqual(
            parse_http_server_header(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"),
            {"name": "nginx", "version": "1.18.0"},
        )
        self.assertEqual(
            parse_http_server_header(
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n"
            ),
            {"name": "apache", "version": "2.4.52"},
        )

    def test_mysql_handshake(self) -> None:
        # 4-byte header + protocol 10 + "8.0.32\0"
        payload = bytes([20, 0, 0, 0, 10]) + b"8.0.32\x00" + b"\x00" * 8
        self.assertEqual(parse_mysql_handshake(payload), {"name": "mysql", "version": "8.0.32"})


class TestSearchsploitMatching(unittest.TestCase):
    def test_range_match_and_miss(self) -> None:
        hit = parse_searchsploit_json(SEARCHSPLOIT_JSON, "openssh", "9.1")
        ids = {r.vuln_id for r in hit}
        self.assertIn("EDB-11111", ids)
        rec = next(r for r in hit if r.vuln_id == "EDB-11111")
        self.assertEqual(rec.confidence, "high")
        self.assertEqual(rec.severity, "high")  # "remote" + high confidence
        self.assertIn("exploit-db.com/exploits/11111", rec.reference)
        self.assertNotIn("Path", rec.title)

        miss = parse_searchsploit_json(SEARCHSPLOIT_JSON, "openssh", "9.4")
        ids_miss = {r.vuln_id for r in miss}
        self.assertNotIn("EDB-11111", ids_miss)
        # Title with no version boundary still recorded as low confidence
        self.assertIn("EDB-22222", ids_miss)
        low = next(r for r in miss if r.vuln_id == "EDB-22222")
        self.assertEqual(low.confidence, "low")
        self.assertEqual(low.severity, "medium")  # low confidence never exceeds MEDIUM

    def test_apache_range_from_searchsploit(self) -> None:
        hit = parse_searchsploit_json(SEARCHSPLOIT_JSON, "apache", "2.4.49")
        self.assertTrue(any(r.vuln_id == "EDB-33333" and r.confidence == "high" for r in hit))
        miss = parse_searchsploit_json(SEARCHSPLOIT_JSON, "apache", "2.4.51")
        self.assertFalse(any(r.vuln_id == "EDB-33333" for r in miss))


class TestNvdParsing(unittest.TestCase):
    def test_cpe_end_excluding(self) -> None:
        body = json.dumps({
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
                        "descriptions": [
                            {"lang": "en", "value": "OpenSSH before 9.3 issue"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                                "versionEndExcluding": "9.3",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        })
        hit = parse_nvd_response(body, "openssh", "9.1")
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].vuln_id, "CVE-2023-0001")
        self.assertEqual(hit[0].confidence, "high")
        self.assertEqual(hit[0].severity, "critical")
        miss = parse_nvd_response(body, "openssh", "9.4")
        self.assertEqual(miss, [])


class TestCollectInstalledPackages(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _db(self._tmp.name)
        self.det = _det(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_uses_dpkg_when_present(self) -> None:
        run = mock.Mock(
            return_value=SimpleNamespace(stdout=DPKG_SAMPLE, stderr="", returncode=0)
        )
        which = lambda cmd: "/usr/bin/dpkg" if cmd == "dpkg" else None
        pkgs = self.det.collect_installed_packages(run=run, which=which)
        run.assert_called_once()
        self.assertEqual(run.call_args[0][0][:2], ["dpkg", "-l"])
        names = {p["name"] for p in pkgs}
        self.assertIn("openssh-server", names)

    def test_uses_rpm_when_no_dpkg(self) -> None:
        run = mock.Mock(
            return_value=SimpleNamespace(stdout=RPM_SAMPLE, stderr="", returncode=0)
        )
        which = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
        pkgs = self.det.collect_installed_packages(run=run, which=which)
        self.assertEqual(run.call_args[0][0][0], "rpm")
        self.assertEqual(pkgs[0]["name"], "openssh-server")

    def test_kernel_uname(self) -> None:
        run = mock.Mock(
            return_value=SimpleNamespace(stdout="5.15.0-91-generic\n", returncode=0)
        )
        k = self.det.collect_kernel_version(run=run)
        self.assertEqual(k["name"], "linux-kernel")
        self.assertEqual(k["version"], "5.15.0-91-generic")
        self.assertEqual(k["source"], "kernel")


class TestBannerGrab(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _db(self._tmp.name)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_mocked_socket_banners(self) -> None:
        def fake_connect(host, port, *, probe=None, use_ssl=False, timeout=2.0):
            if port == 22:
                return b"SSH-2.0-OpenSSH_9.1p1\r\n"
            if port == 80:
                return b"HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            raise ConnectionRefusedError()

        det = VersionScannerDetector(
            self.db,
            {
                "engine": "searchsploit",
                "scan_interval_seconds": 0,
                "watch_packages": ["openssh", "nginx"],
            },
            connect=fake_connect,
        )
        found = det.collect_service_banners()
        names = {p["name"]: p["version"] for p in found}
        self.assertEqual(names["openssh"], "9.1p1")
        self.assertEqual(names["nginx"], "1.18.0")


class TestLookupCacheAndSearchsploitMissing(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _db(self._tmp.name)
        self.det = _det(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_searchsploit_missing_warns_once(self) -> None:
        self.det._run = mock.Mock(side_effect=FileNotFoundError("searchsploit"))
        with self.assertLogs("detectors.version_scanner", level="WARNING") as cm:
            first = self.det.lookup_vulnerabilities("openssh", "9.1")
            second = self.det.lookup_vulnerabilities("nginx", "1.18.0")
        self.assertEqual(first, [])
        self.assertEqual(second, [])
        warnings = [l for l in cm.output if "searchsploit not installed" in l]
        self.assertEqual(len(warnings), 1)

    def test_cache_skips_second_subprocess(self) -> None:
        result = SimpleNamespace(stdout=SEARCHSPLOIT_JSON, stderr="", returncode=0)
        self.det._run = mock.Mock(return_value=result)
        a = self.det.lookup_vulnerabilities("openssh", "9.1")
        b = self.det.lookup_vulnerabilities("openssh", "9.1")
        self.assertEqual(self.det._run.call_count, 1)
        self.assertEqual([r.vuln_id for r in a], [r.vuln_id for r in b])
        self.assertTrue(any(r.confidence == "high" for r in a))


class TestScanDiffNotify(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _db(self._tmp.name)
        self.det = _det(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def _stub_inventory(self, version: str = "9.1p1"):
        self.det.collect_installed_packages = mock.Mock(  # type: ignore[method-assign]
            return_value=[{"name": "openssh-server", "version": f"1:{version}-1ubuntu2"}]
        )
        self.det.collect_kernel_version = mock.Mock(return_value=None)  # type: ignore[method-assign]
        self.det.collect_service_banners = mock.Mock(return_value=[])  # type: ignore[method-assign]
        self.det._run = mock.Mock(
            return_value=SimpleNamespace(stdout=SEARCHSPLOIT_JSON, returncode=0)
        )

    def test_high_confidence_notifies_low_does_not(self) -> None:
        self._stub_inventory("9.1p1")
        findings = self.det.scan()
        highs = [f for f in findings if f.details["confidence"] == "high"]
        lows = [f for f in findings if f.details["confidence"] == "low"]
        self.assertTrue(highs)
        self.assertTrue(all(f.notify for f in highs))
        self.assertTrue(lows)
        self.assertTrue(all(not f.notify for f in lows))
        self.assertTrue(all(f.details.get("reference") for f in findings))
        self.assertTrue(all("package" in f.details for f in findings))

    def test_low_confidence_can_notify_when_flag_set(self) -> None:
        self.det.alert_on_low_confidence = True
        self._stub_inventory("9.4p1")  # outside < 9.3 range
        findings = self.det.scan()
        lows = [f for f in findings if f.details["confidence"] == "low"]
        self.assertTrue(lows)
        self.assertTrue(all(f.notify for f in lows))
        self.assertTrue(all(f.severity == "medium" for f in lows))

    def test_baseline_dedup_same_as_suid_pattern(self) -> None:
        self._stub_inventory("9.1p1")
        first = self.det.run_once()
        self.assertTrue(first)
        second = self.det.run_once()
        self.assertEqual(second, [])

    def test_item_key_is_package_version_id(self) -> None:
        self._stub_inventory("9.1p1")
        findings = self.det.scan()
        high = next(f for f in findings if f.details["vuln_id"] == "EDB-11111")
        self.assertIn("openssh-server", high.item_key)
        self.assertIn("EDB-11111", high.item_key)
        self.assertIn("9.1", high.item_key)

    def test_scan_interval_throttles_without_clearing_baseline(self) -> None:
        clock = {"t": 0.0}

        def mono() -> float:
            return clock["t"]

        det = _det(self.db, scan_interval_seconds=3600)
        det._monotonic = mono
        det.collect_installed_packages = mock.Mock(  # type: ignore[method-assign]
            return_value=[{"name": "openssh-server", "version": "9.1p1"}]
        )
        det.collect_kernel_version = mock.Mock(return_value=None)  # type: ignore[method-assign]
        det.collect_service_banners = mock.Mock(return_value=[])  # type: ignore[method-assign]
        det._run = mock.Mock(
            return_value=SimpleNamespace(stdout=SEARCHSPLOIT_JSON, returncode=0)
        )
        first = det.run_once()
        self.assertTrue(first)
        clock["t"] = 10.0
        skipped = det.run_once()
        self.assertEqual(skipped, [])
        # Baseline still populated — throttle must not prune
        self.assertTrue(self.db.get_baseline_hashes("version_scanner"))
        clock["t"] = 3601.0
        again = det.run_once()
        self.assertEqual(again, [])  # same inventory, already baselined

    def test_min_severity_alert_high_suppresses_medium(self) -> None:
        self.det.min_severity_alert = "high"
        # Title without remote/privesc → MEDIUM even at high confidence
        payload = json.dumps({
            "RESULTS_EXPLOIT": [
                {"Title": "OpenSSH < 9.3 - Info Leak", "EDB-ID": "44444"}
            ]
        })
        self.det.collect_installed_packages = mock.Mock(  # type: ignore[method-assign]
            return_value=[{"name": "openssh-server", "version": "9.1"}]
        )
        self.det.collect_kernel_version = mock.Mock(return_value=None)  # type: ignore[method-assign]
        self.det.collect_service_banners = mock.Mock(return_value=[])  # type: ignore[method-assign]
        self.det._run = mock.Mock(return_value=SimpleNamespace(stdout=payload, returncode=0))
        findings = self.det.scan()
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == "medium" for f in findings))
        self.assertTrue(all(not f.notify for f in findings))


class TestFindingHashExcludesNotify(unittest.TestCase):
    def test_notify_flag_does_not_change_item_hash(self) -> None:
        a = Finding(
            detector_name="version_scanner",
            severity="medium",
            message="m",
            item_key="openssh:9.1:EDB-1",
            details={"package": "openssh"},
            notify=True,
        )
        b = Finding(
            detector_name="version_scanner",
            severity="medium",
            message="m",
            item_key="openssh:9.1:EDB-1",
            details={"package": "openssh"},
            notify=False,
        )
        self.assertEqual(a.item_hash(), b.item_hash())


if __name__ == "__main__":
    unittest.main()
