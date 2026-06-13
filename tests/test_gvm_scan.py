"""
Unit tests for GVM scan workflow improvements:
- target batching
- scan preset application
- feed-sync readiness probe parsing
- parallel batch result merging
- vulnerability deduplication
- parallel batch isolation (error handling)
"""

import sys
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import xml.etree.ElementTree as ET

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from gvm_scan.main import (
    _apply_scan_preset,
    _chunked,
    _merge_batch_results,
    _deduplicate_vulnerabilities,
    _run_phase,
    _run_batch_parallel,
)
from gvm_scan.ready_probe import _parse_feeds
from gvm_scan.gvm_scanner import save_vuln_results, load_recon_file


class TestGvmBatching(unittest.TestCase):
    def test_chunked_splits_list(self):
        items = list(range(12))
        chunks = list(_chunked(items, 5))
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0], [0, 1, 2, 3, 4])
        self.assertEqual(chunks[1], [5, 6, 7, 8, 9])
        self.assertEqual(chunks[2], [10, 11])

    def test_chunked_size_zero_treated_as_one(self):
        items = [1, 2, 3]
        chunks = list(_chunked(items, 0))
        self.assertEqual(len(chunks), 3)

    def test_chunked_empty(self):
        self.assertEqual(list(_chunked([], 5)), [])

    def test_chunked_exact_divisor(self):
        items = list(range(6))
        chunks = list(_chunked(items, 3))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0], [0, 1, 2])
        self.assertEqual(chunks[1], [3, 4, 5])


class TestGvmScanPresets(unittest.TestCase):
    def test_fast_preset_overrides_defaults(self):
        settings = {
            "SCAN_PRESET": "fast",
            "SCAN_CONFIG": "Full and fast",
            "PORT_LIST": "All IANA assigned TCP and UDP",
            "POLL_INTERVAL": 30,
            "TARGET_BATCH_SIZE": 5,
            "MAX_HOSTS": 0,
            "MAX_CHECKS": 0,
        }
        _apply_scan_preset(settings)
        self.assertEqual(settings["PORT_LIST"], "All TCP and Nmap top 100 UDP")
        self.assertEqual(settings["POLL_INTERVAL"], 10)
        self.assertEqual(settings["TARGET_BATCH_SIZE"], 10)
        self.assertEqual(settings["BATCH_CONCURRENCY"], 8)
        self.assertEqual(settings["MAX_HOSTS"], 20)
        self.assertEqual(settings["MAX_CHECKS"], 10)
        self.assertEqual(settings["SCAN_CONFIG"], "Full and fast")

    def test_fast_preset_keeps_explicit_values(self):
        settings = {
            "SCAN_PRESET": "fast",
            "SCAN_CONFIG": "Discovery",
            "PORT_LIST": "All IANA assigned TCP",
            "POLL_INTERVAL": 30,
            "TARGET_BATCH_SIZE": 5,
            "MAX_HOSTS": 8,
            "MAX_CHECKS": 4,
        }
        _apply_scan_preset(settings)
        # Preset always sets its own port list / timing / batching.
        # Explicit MAX_HOSTS/MAX_CHECKS/SCAN_CONFIG values are preserved.
        self.assertEqual(settings["SCAN_CONFIG"], "Discovery")
        self.assertEqual(settings["PORT_LIST"], "All TCP and Nmap top 100 UDP")
        self.assertEqual(settings["MAX_HOSTS"], 8)
        self.assertEqual(settings["MAX_CHECKS"], 4)
        self.assertEqual(settings["POLL_INTERVAL"], 10)
        self.assertEqual(settings["TARGET_BATCH_SIZE"], 10)
        self.assertEqual(settings["BATCH_CONCURRENCY"], 8)

    def test_thorough_preset(self):
        settings = {
            "SCAN_PRESET": "thorough",
            "PORT_LIST": "All TCP and Nmap top 100 UDP",
            "POLL_INTERVAL": 10,
            "TARGET_BATCH_SIZE": 10,
            "MAX_HOSTS": 20,
            "MAX_CHECKS": 10,
        }
        _apply_scan_preset(settings)
        self.assertEqual(settings["PORT_LIST"], "All IANA assigned TCP and UDP")
        self.assertEqual(settings["POLL_INTERVAL"], 30)
        self.assertEqual(settings["TARGET_BATCH_SIZE"], 1)
        self.assertEqual(settings["BATCH_CONCURRENCY"], 1)
        self.assertEqual(settings["MAX_HOSTS"], 20)
        self.assertEqual(settings["MAX_CHECKS"], 10)

    def test_default_preset_leaves_values_intact(self):
        settings = {
            "SCAN_PRESET": "default",
            "PORT_LIST": "All IANA assigned TCP and UDP",
            "POLL_INTERVAL": 30,
            "TARGET_BATCH_SIZE": 5,
        }
        _apply_scan_preset(settings)
        self.assertEqual(settings["PORT_LIST"], "All IANA assigned TCP and UDP")
        self.assertEqual(settings["POLL_INTERVAL"], 30)
        self.assertEqual(settings["TARGET_BATCH_SIZE"], 5)
        # default preset should not set BATCH_CONCURRENCY
        self.assertNotIn("BATCH_CONCURRENCY", settings)


class TestGvmMergeBatchResults(unittest.TestCase):
    def setUp(self):
        self.results = {
            "scans": [],
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "log": 0,
                "hosts_scanned": 0,
            },
        }

    def test_merge_normal_batch(self):
        batch = {
            "batch_index": 1,
            "scan_type": "ip_scan",
            "vulnerabilities": [{"oid": "1.2.3", "host": "10.0.0.1"}],
            "hosts_scanned": 5,
            "vulnerability_count": 1,
            "severity_summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        }
        _merge_batch_results(self.results, batch)
        self.assertEqual(len(self.results["scans"]), 1)
        self.assertEqual(self.results["summary"]["total_vulnerabilities"], 1)
        self.assertEqual(self.results["summary"]["critical"], 1)
        self.assertEqual(self.results["summary"]["hosts_scanned"], 5)

    def test_merge_error_batch(self):
        error_batch = {
            "batch_index": 2,
            "scan_type": "ip_scan",
            "error": "Connection failed",
            "vulnerabilities": [],
            "hosts_scanned": 0,
            "severity_summary": {},
            "vulnerability_count": 0,
        }
        _merge_batch_results(self.results, error_batch)
        self.assertEqual(len(self.results["scans"]), 1)
        self.assertEqual(self.results["summary"]["total_vulnerabilities"], 0)

    def test_merge_multiple_batches(self):
        for i in range(3):
            _merge_batch_results(self.results, {
                "batch_index": i + 1,
                "scan_type": "ip_scan",
                "vulnerabilities": [{"oid": f"1.2.{i}", "host": f"10.0.0.{i}"}],
                "hosts_scanned": 2,
                "vulnerability_count": 1,
                "severity_summary": {"high": 1},
            })
        self.assertEqual(len(self.results["scans"]), 3)
        self.assertEqual(self.results["summary"]["total_vulnerabilities"], 3)
        self.assertEqual(self.results["summary"]["high"], 3)
        self.assertEqual(self.results["summary"]["hosts_scanned"], 6)


class TestGvmDeduplication(unittest.TestCase):
    def _make_results(self, vulns_by_batch):
        """Build results dict from list of (batch_label, [vuln_dicts]) tuples."""
        results = {"scans": []}
        for label, vulns in vulns_by_batch:
            results["scans"].append({
                "scan_type": "ip_scan",
                "vulnerabilities": vulns,
            })
        return results

    def test_no_duplicates_returns_all(self):
        vulns = [
            {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 5.0},
            {"host": "10.0.0.2", "port": "443", "oid": "1.2.4", "cves_extracted": [], "severity_float": 7.0},
        ]
        results = self._make_results([("batch1", vulns)])
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(len(deduped), 2)

    def test_exact_duplicate_deduped(self):
        vuln = {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 5.0}
        results = self._make_results([
            ("batch1", [vuln]),
            ("batch2", [dict(vuln)]),
        ])
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(len(deduped), 1)

    def test_keeps_highest_severity(self):
        low = {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 5.0}
        high = {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 9.0}
        results = self._make_results([
            ("batch1", [low]),
            ("batch2", [high]),
        ])
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["severity_float"], 9.0)

    def test_different_oids_kept_separate(self):
        vulns1 = [{"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 5.0}]
        vulns2 = [{"host": "10.0.0.1", "port": "80", "oid": "1.2.4", "cves_extracted": [], "severity_float": 7.0}]
        results = self._make_results([("batch1", vulns1), ("batch2", vulns2)])
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(len(deduped), 2)

    def test_cve_extracted_differentiation(self):
        vuln_no_cve = {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": [], "severity_float": 5.0}
        vuln_with_cve = {"host": "10.0.0.1", "port": "80", "oid": "1.2.3", "cves_extracted": ["CVE-2024-0001"], "severity_float": 5.0}
        results = self._make_results([("batch1", [vuln_no_cve]), ("batch2", [vuln_with_cve])])
        deduped = _deduplicate_vulnerabilities(results)
        # Different CVE sets → different dedup keys → both kept
        self.assertEqual(len(deduped), 2)

    def test_empty_scans_list(self):
        results = {"scans": []}
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(deduped, [])

    def test_missing_vulnerabilities_key(self):
        results = {"scans": [{"scan_type": "ip_scan"}]}
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(deduped, [])

    def test_large_batch_dedup_performance(self):
        """Verify dedup handles many identical records efficiently."""
        # 10 hosts × 5 OIDs = 50 unique combos, 10 copies each = 500 total
        vulns = [
            {"host": f"10.0.0.{h}", "port": "80", "oid": f"1.2.{o}",
             "cves_extracted": [], "severity_float": float(h + o)}
            for h in range(10) for o in range(5) for _ in range(10)
        ]
        results = self._make_results([("batch1", vulns)])
        deduped = _deduplicate_vulnerabilities(results)
        self.assertEqual(len(deduped), 50)


class TestGvmParallelPhase(unittest.TestCase):
    @patch("gvm_scan.main._run_batch_parallel")
    def test_run_phase_with_no_targets(self, mock_run):
        """With no targets no batches are submitted and save is not called."""
        results = {"scans": [], "summary": {"total_vulnerabilities": 0}}
        save_called = [False]

        def save():
            save_called[0] = True

        _run_phase(
            targets=[],
            scan_type="ip_scan",
            batch_size=5,
            batch_concurrency=4,
            cleanup=True,
            results=results,
            root_domain="test.local",
            output_file=Path("/tmp/test_out.json"),
            save_incremental=save,
        )
        mock_run.assert_not_called()
        # No targets → short-circuit before save_incremental call
        self.assertFalse(save_called[0])

    @patch("gvm_scan.main._run_batch_parallel")
    def test_run_phase_single_batch(self, mock_run):
        mock_run.return_value = {
            "batch_index": 1,
            "scan_type": "ip_scan",
            "vulnerabilities": [{"oid": "1.2.3", "host": "10.0.0.1"}],
            "hosts_scanned": 2,
            "vulnerability_count": 1,
            "severity_summary": {"critical": 1},
        }
        results = {
            "scans": [],
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "log": 0,
                "hosts_scanned": 0,
            },
        }

        _run_phase(
            targets=["10.0.0.1", "10.0.0.2"],
            scan_type="ip_scan",
            batch_size=5,
            batch_concurrency=4,
            cleanup=True,
            results=results,
            root_domain="test.local",
            output_file=Path("/tmp/test_out.json"),
            save_incremental=lambda: None,
        )
        mock_run.assert_called_once()
        self.assertEqual(results["summary"]["total_vulnerabilities"], 1)
        self.assertEqual(results["summary"]["critical"], 1)
        self.assertEqual(results["summary"]["hosts_scanned"], 2)

    @patch("gvm_scan.main._run_batch_parallel")
    def test_run_phase_failing_batch_reported_as_error(self, mock_run):
        """A batch that raises an exception should be caught and not crash the phase."""
        mock_run.side_effect = RuntimeError("GMP connection lost")

        results = {
            "scans": [],
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "log": 0,
                "hosts_scanned": 0,
            },
        }

        _run_phase(
            targets=["10.0.0.1", "10.0.0.2"],
            scan_type="ip_scan",
            batch_size=5,
            batch_concurrency=4,
            cleanup=True,
            results=results,
            root_domain="test.local",
            output_file=Path("/tmp/test_out.json"),
            save_incremental=lambda: None,
        )

        # Error should be recorded as an error-scan in results
        self.assertEqual(len(results["scans"]), 1)
        self.assertIn("error", results["scans"][0])
        self.assertIn("GMP connection lost", results["scans"][0]["error"])

    @patch("gvm_scan.main._run_batch_parallel")
    def test_run_phase_concurrency_respected(self, mock_run):
        """Verify that concurrency is capped to number of batches."""
        mock_run.return_value = {
            "batch_index": 1,
            "scan_type": "ip_scan",
            "vulnerabilities": [],
            "hosts_scanned": 0,
            "vulnerability_count": 0,
            "severity_summary": {},
        }
        results = {
            "scans": [],
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "log": 0,
                "hosts_scanned": 0,
            },
        }

        _run_phase(
            targets=["10.0.0.1"],
            scan_type="ip_scan",
            batch_size=5,
            batch_concurrency=99,  # Only 1 batch, so effective concurrency is 1
            cleanup=True,
            results=results,
            root_domain="test.local",
            output_file=Path("/tmp/test_out.json"),
            save_incremental=lambda: None,
        )
        mock_run.assert_called_once()


class TestGvmReadyProbe(unittest.TestCase):
    def test_parse_feeds_detects_syncing(self):
        xml = """
        <get_feeds_response status="200" status_text="OK">
            <feed>
                <type>NVT</type>
                <name>unknown</name>
                <version>202606121755</version>
            </feed>
            <feed>
                <type>SCAP</type>
                <name>Greenbone SCAP Data Feed</name>
                <version>202606120632</version>
                <currently_syncing><timestamp>Fri Jun 12 20:26:32 2026</timestamp></currently_syncing>
            </feed>
        </get_feeds_response>
        """
        root = ET.fromstring(xml)
        syncing_count, feeds = _parse_feeds(root)
        self.assertEqual(syncing_count, 1)
        self.assertEqual(len(feeds), 2)
        self.assertTrue(feeds[1]["syncing"])
        self.assertFalse(feeds[0]["syncing"])

    def test_parse_feeds_all_synced(self):
        xml = """
        <get_feeds_response status="200" status_text="OK">
            <feed>
                <type>NVT</type>
                <name>Greenbone NVT Feed</name>
                <version>202606121755</version>
            </feed>
        </get_feeds_response>
        """
        root = ET.fromstring(xml)
        syncing_count, feeds = _parse_feeds(root)
        self.assertEqual(syncing_count, 0)
        self.assertEqual(len(feeds), 1)
        self.assertFalse(feeds[0]["syncing"])


class TestLoadReconFile(unittest.TestCase):
    """Test load_recon_file error handling improvements."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.project_id = "test_proj"
        self.recon_file = self.tmpdir / f"recon_{self.project_id}.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_load_recon_file_not_found(self):
        """FileNotFoundError raised for missing file."""
        with self.assertRaises(FileNotFoundError):
            load_recon_file("nonexistent", recon_dir=self.tmpdir)

    def test_load_recon_file_empty(self):
        """ValueError raised for empty file."""
        self.recon_file.write_text("")
        with self.assertRaises(ValueError, msg="Recon file .* is empty"):
            load_recon_file(self.project_id, recon_dir=self.tmpdir)

    def test_load_recon_file_whitespace_only(self):
        """ValueError raised for whitespace-only file."""
        self.recon_file.write_text("   \n\n  ")
        with self.assertRaises(ValueError, msg="Recon file .* is empty"):
            load_recon_file(self.project_id, recon_dir=self.tmpdir)

    def test_load_recon_file_invalid_json(self):
        """ValueError raised for malformed JSON."""
        self.recon_file.write_text("{not json}")
        with self.assertRaises(ValueError, msg="Invalid JSON"):
            load_recon_file(self.project_id, recon_dir=self.tmpdir)

    def test_load_recon_file_null_value(self):
        """ValueError raised when file contains only null."""
        self.recon_file.write_text("null")
        with self.assertRaises(ValueError, msg="empty or contains only null"):
            load_recon_file(self.project_id, recon_dir=self.tmpdir)

    def test_load_recon_file_valid(self):
        """Valid JSON content is returned correctly."""
        data = {"targets": ["10.0.0.1"]}
        self.recon_file.write_text(json.dumps(data))
        result = load_recon_file(self.project_id, recon_dir=self.tmpdir)
        self.assertEqual(result, data)


class TestSaveVulnResults(unittest.TestCase):
    """Test save_vuln_results atomic write and non-serializable guard."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.project_id = "test_proj"
        self.results = {"vulnerabilities": [{"host": "10.0.0.1", "port": "22"}]}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_atomic_creates_final_file(self):
        """Final file written atomically via tmp+replace."""
        result_path = save_vuln_results(
            self.results, self.project_id, output_dir=self.tmpdir
        )
        expected = self.tmpdir / f"gvm_{self.project_id}.json"
        self.assertEqual(result_path, expected)
        self.assertTrue(expected.exists())
        # Temp file should not exist
        self.assertFalse(expected.with_suffix(".json.tmp").exists())

    def test_save_atomic_content_matches(self):
        """Content of saved file is correct."""
        result_path = save_vuln_results(
            self.results, self.project_id, output_dir=self.tmpdir
        )
        loaded = json.loads(result_path.read_text())
        self.assertEqual(loaded, self.results)

    def test_save_non_serializable_default_str(self):
        """default=str serializes non-serializable types like datetime."""
        from datetime import datetime
        results = {"timestamp": datetime(2026, 6, 12, 22, 0, 0)}
        path = save_vuln_results(results, self.project_id, output_dir=self.tmpdir)
        loaded = json.loads(path.read_text())
        self.assertIn("2026-06-12", loaded["timestamp"])

    def test_save_creates_output_dir(self):
        """Output directory created if missing."""
        deep_dir = self.tmpdir / "nested" / "gvm" / "output"
        path = save_vuln_results(self.results, self.project_id, output_dir=deep_dir)
        self.assertTrue(path.exists())

    @patch("gvm_scan.gvm_scanner.json.dump")
    def test_save_cleans_tmp_on_failure(self, mock_dump):
        """Temp file removed if json.dump fails."""
        mock_dump.side_effect = TypeError("boom")
        with self.assertRaises(TypeError):
            save_vuln_results(
                {"bad": object()}, self.project_id, output_dir=self.tmpdir
            )
        # Temp file should be cleaned up
        tmp_files = list(self.tmpdir.glob("*.json.tmp"))
        self.assertEqual(tmp_files, [])


class TestRunBatchParallel(unittest.TestCase):
    """Test _run_batch_parallel retry logic and timing metrics."""

    def setUp(self):
        self.batch = ["10.0.0.1"]
        self.kwargs = dict(
            batch=self.batch,
            batch_index=1,
            total_batches=1,
            scan_type="ip_scan",
            cleanup=False,
        )

    @patch("gvm_scan.main.GVMScanner")
    def test_duration_seconds_present_on_success(self, mock_scanner_cls):
        """duration_seconds field present in successful batch result."""
        mock_instance = mock_scanner_cls.return_value
        mock_instance.connect.return_value = True
        mock_instance.scan_targets.return_value = {"vulnerabilities": []}

        result = _run_batch_parallel(**self.kwargs)
        self.assertIn("duration_seconds", result)
        self.assertIsInstance(result["duration_seconds"], (int, float))
        self.assertGreaterEqual(result["duration_seconds"], 0)

    @patch("gvm_scan.main.GVMScanner")
    def test_duration_seconds_present_on_failure(self, mock_scanner_cls):
        """duration_seconds field present even when batch fails."""
        mock_instance = mock_scanner_cls.return_value
        mock_instance.connect.return_value = True
        mock_instance.scan_targets.side_effect = RuntimeError("scan failed")

        result = _run_batch_parallel(**self.kwargs)
        self.assertIn("error", result)
        self.assertIn("duration_seconds", result)

    @patch("gvm_scan.main.GVMScanner")
    def test_retries_on_connection_failure(self, mock_scanner_cls):
        """Retries on connection failure, succeeds eventually."""
        mock_instance = mock_scanner_cls.return_value
        # Fail connection twice, succeed on third
        mock_instance.connect.side_effect = [False, False, True]
        mock_instance.scan_targets.return_value = {"vulnerabilities": []}

        result = _run_batch_parallel(**self.kwargs)
        self.assertNotIn("error", result)
        # connect called 3 times (2 fails + 1 success)
        self.assertEqual(mock_instance.connect.call_count, 3)

    @patch("gvm_scan.main.GVMScanner")
    def test_retries_exhaustion_returns_error(self, mock_scanner_cls):
        """Error returned when all retries exhausted."""
        mock_instance = mock_scanner_cls.return_value
        mock_instance.connect.return_value = True
        mock_instance.scan_targets.side_effect = RuntimeError("persistent failure")

        result = _run_batch_parallel(**self.kwargs)
        self.assertIn("error", result)
        self.assertEqual(result["error"], "persistent failure")
        # 3 attempts total (initial + 2 retries)
        self.assertEqual(mock_instance.scan_targets.call_count, 3)


if __name__ == "__main__":
    unittest.main()
