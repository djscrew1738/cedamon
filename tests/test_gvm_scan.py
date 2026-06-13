"""
Unit tests for GVM scan workflow improvements:
- target batching
- scan preset application
- feed-sync readiness probe parsing
"""

import sys
import unittest
from pathlib import Path

import xml.etree.ElementTree as ET

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from gvm_scan.main import _apply_scan_preset, _chunked
from gvm_scan.ready_probe import _parse_feeds


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


if __name__ == "__main__":
    unittest.main()
