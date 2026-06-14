"""Unit tests for the GVM scanner module.

These tests exercise helper/utility paths that do not require a live GVM
instance.  They run with the project root on sys.path so `graph_db` and
`gvm_scan` imports resolve.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _PROJECT_ROOT)

from gvm_scan.gvm_scanner import GVMScanner, extract_targets_from_recon
from gvm_scan.main import _chunked


class ChunkedTests(unittest.TestCase):
    def test_chunked_splits_items(self):
        self.assertEqual(list(_chunked([1, 2, 3, 4, 5], 2)), [[1, 2], [3, 4], [5]])

    def test_chunked_yields_all_for_non_positive_size(self):
        self.assertEqual(list(_chunked([1, 2, 3], 0)), [[1, 2, 3]])
        self.assertEqual(list(_chunked([1, 2, 3], -1)), [[1, 2, 3]])

    def test_chunked_handles_empty_list(self):
        self.assertEqual(list(_chunked([], 2)), [])


class ExtractTargetsTests(unittest.TestCase):
    def test_extracts_from_dns(self):
        recon = {
            "metadata": {"root_domain": "example.com"},
            "dns": {
                "domain": {"has_records": True, "ips": {"ipv4": ["1.2.3.4"]}},
                "subdomains": {
                    "www.example.com": {"has_records": True, "ips": {"ipv4": ["1.2.3.5"]}},
                },
            },
        }
        ips, hostnames = extract_targets_from_recon(recon)
        self.assertIn("1.2.3.4", ips)
        self.assertIn("1.2.3.5", ips)
        self.assertIn("example.com", hostnames)
        self.assertIn("www.example.com", hostnames)

    def test_falls_back_to_port_scan(self):
        recon = {
            "metadata": {"root_domain": "example.com"},
            "port_scan": {
                "by_ip": {"10.0.0.1": {"ports": [80]}},
                "by_host": {"web.example.com": {"ports": [443]}},
                "ip_to_hostnames": {"10.0.0.2": ["api.example.com"]},
            },
        }
        ips, hostnames = extract_targets_from_recon(recon)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)
        self.assertIn("web.example.com", hostnames)
        self.assertIn("api.example.com", hostnames)

    def test_empty_recon_returns_empty_sets(self):
        ips, hostnames = extract_targets_from_recon({})
        self.assertEqual(ips, set())
        self.assertEqual(hostnames, set())


class CacheAllIdsTests(unittest.TestCase):
    """Tests for GVMScanner._cache_all_ids.

    The original implementation used a nested ThreadPoolExecutor, which
    caused ``BrokenThreadPool`` / ``AttributeError`` problems and shared
    a non-thread-safe GMP connection across worker threads.  The current
    implementation runs the cache calls sequentially and propagates the
    first real error.
    """

    def _scanner(self):
        """Return a bare GVMScanner-like object without instantiating the class."""
        obj = MagicMock()
        # Attach the real method so it drives the mocked cache helpers.
        obj._cache_all_ids = GVMScanner._cache_all_ids.__get__(obj, MagicMock)
        return obj

    def test_cache_all_ids_calls_all_four_helpers(self):
        scanner = self._scanner()
        scanner._cache_all_ids()
        scanner._cache_scanner_id.assert_called_once()
        scanner._cache_config_id.assert_called_once()
        scanner._cache_report_format_id.assert_called_once()
        scanner._cache_port_list_id.assert_called_once()

    def test_cache_all_ids_propagates_first_error(self):
        scanner = self._scanner()
        scanner._cache_config_id.side_effect = RuntimeError("scan config not found")
        scanner._cache_port_list_id.side_effect = RuntimeError("port list missing")

        with self.assertRaises(RuntimeError) as ctx:
            scanner._cache_all_ids()

        self.assertIn("scan config not found", str(ctx.exception))
        scanner._cache_scanner_id.assert_called_once()
        scanner._cache_config_id.assert_called_once()
        scanner._cache_report_format_id.assert_called_once()
        scanner._cache_port_list_id.assert_called_once()

    def test_cache_all_ids_succeeds_when_helpers_succeed(self):
        scanner = self._scanner()
        # Should not raise.
        scanner._cache_all_ids()


if __name__ == "__main__":
    unittest.main()
