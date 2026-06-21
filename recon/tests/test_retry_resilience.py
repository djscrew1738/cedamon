"""
RedAmon Retry & Resilience Audit — Tier 1.4
=============================================

Audit summary of retry coverage across the recon pipeline:

[✓] Areas WITH retry coverage
-----------------------------
1. recon/helpers/smart_retry.py
   - Full-featured decorator: exponential backoff + jitter, failure
     classification (transient vs permanent), circuit breaker, stats tracking.
   - Convenience wrappers: retry_api_call, retry_dns_lookup,
     retry_network_request.
   - Exported via recon/helpers/__init__.py.
   - Currently used by: graphql_scan (urllib3 Retry adapter), whois_recon
     (manual loop), domain_recon (manual DNS retry), criminalip_enrich /
     virustotal_enrich (simple 429 retry), anonymity helper (urllib3 Retry).

2. recon_orchestrator/container_manager.py
   - _ensure_recon_image: 3-retry loop with exponential backoff (1s, 4s, 16s)
     for Docker image builds.
   - ensure_gvm_scanner_image: same 3-retry pattern for GVM scanner image.

[✗] Areas LACKING retry
-------------------------
1. Subprocess calls in main_recon_modules (no retry, mostly no try/except):
   - domain_recon.py: 5x subprocess.run (amass, asnmap, bbot, chaos, alterx)
   - port_scan.py: 3x subprocess.run (naabu, rustscan)
   - vuln_scan.py: subprocess.Popen + subprocess.run (nuclei)
   - subdomain_takeover.py: 6x subprocess.run (subjack, nuclei, baddns)
   - nmap_scan.py: subprocess.Popen
   - http_probe.py: 3x subprocess.run + Popen (httpx)
   - vhost_sni_enum.py: 2x subprocess.run
   - uncover_enrich.py: subprocess.run
   - masscan_scan.py: subprocess.Popen
   - graphql_scan/misconfig.py: subprocess.run

2. HTTP API calls with bare try/except but no retry:
   - urlscan_enrich.py, otx_enrich.py

Recommendations
----------------
1. Wrap all subprocess.run/Popen calls with smart_retry or at minimum a
   retry wrapper that catches CalledProcessError / TimeoutExpired for
   transient failures (network blips, resource contention).
2. Add retry_api_call decorator to URLScan, OTX, and similar enrichment
   modules where 429/5xx can occur.
3. Consider a shared helper like `safe_subprocess(cmd, retries=2)` in
   recon/helpers/ to avoid duplicating retry logic across 10+ modules.
4. container_manager.py image-ensure methods are adequate but could be
   simplified by using the smart_retry decorator directly.
"""

import ast
import sys
import os
import time
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

# Path setup for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from recon.helpers.smart_retry import (
    smart_retry,
    RetryConfig,
    RetryStats,
    ErrorClass,
    CircuitBreaker,
    CircuitBreakerOpen,
    classify_error,
    calculate_delay,
    retry_api_call,
    retry_dns_lookup,
    retry_network_request,
    get_retry_stats,
    get_all_retry_stats,
)


class TestSmartRetryDecorator(unittest.TestCase):
    """Verify the core smart_retry decorator behavior."""

    def setUp(self):
        # Clear global state between tests
        from recon.helpers.smart_retry import _retry_stats, _retry_stats_lock
        with _retry_stats_lock:
            _retry_stats.clear()

    def test_success_no_retry(self):
        """Function succeeds on first attempt — no retry should occur."""
        call_count = 0

        @smart_retry(max_attempts=3, base_delay=0.01)
        def ok():
            nonlocal call_count
            call_count += 1
            return "done"

        result = ok()
        self.assertEqual(result, "done")
        self.assertEqual(call_count, 1)

    def test_transient_error_triggers_retry_then_succeeds(self):
        """Transient failure followed by success should retry and recover."""
        call_count = 0

        @smart_retry(max_attempts=3, base_delay=0.01)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("transient failure")
            return "recovered"

        result = flaky()
        self.assertEqual(result, "recovered")
        self.assertEqual(call_count, 3)

    def test_permanent_error_does_not_retry(self):
        """Permanent error (e.g. HTTP 404) should fail fast without retry."""
        call_count = 0

        @smart_retry(
            max_attempts=3, permanent_errors=[404],
            base_delay=0.01, reraise_permanent=False,
        )
        def bad_request():
            nonlocal call_count
            call_count += 1
            exc = RuntimeError("404 Not Found")
            exc.response = MagicMock(status_code=404)
            raise exc

        result = bad_request()
        self.assertIsNone(result)
        # Only 1 call because the error is classified as permanent
        self.assertEqual(call_count, 1)

    def test_retry_exhausted_raises(self):
        """When all transient retry attempts fail, the last exception is raised."""
        call_count = 0

        @smart_retry(max_attempts=3, base_delay=0.01, reraise_permanent=True)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise TimeoutError("timeout")

        with self.assertRaises(TimeoutError):
            always_fails()
        self.assertEqual(call_count, 3)

    def test_circuit_breaker_opens_after_threshold(self):
        """Circuit breaker should open after N consecutive failures."""
        call_count = 0

        @smart_retry(
            max_attempts=2, base_delay=0.01,
            circuit_breaker=True, circuit_threshold=2,
        )
        def failing():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("fail")

        # Call 1 — 2 attempts both fail, 1 failure recorded (only last attempt)
        with self.assertRaises(ConnectionError):
            failing()
        self.assertEqual(call_count, 2)

        # Call 2 — 2 attempts both fail, failure_count=2 → circuit opens
        with self.assertRaises(ConnectionError):
            failing()
        self.assertEqual(call_count, 4)

        # Call 3 — circuit is open, should raise CircuitBreakerOpen
        with self.assertRaises(CircuitBreakerOpen):
            failing()
        # Call count should NOT increase because the circuit is open
        self.assertEqual(call_count, 4)

    def test_circuit_breaker_recovers_after_timeout(self):
        """After circuit breaker timeout elapses, a half-open probe is allowed."""
        call_count = 0

        @smart_retry(
            max_attempts=1, base_delay=0.01,
            circuit_breaker=True, circuit_threshold=2,
            circuit_timeout=0.05,  # very short timeout
        )
        def sometimes_fails():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("fail")
            return "recovered"

        # Call 1: fail (1 attempt, circuit counts as failure)
        with self.assertRaises(ConnectionError):
            sometimes_fails()
        self.assertEqual(call_count, 1)

        # Call 2: fail again — circuit opens
        with self.assertRaises(ConnectionError):
            sometimes_fails()
        self.assertEqual(call_count, 2)

        # Call 3: circuit is open, should get CircuitBreakerOpen
        with self.assertRaises(CircuitBreakerOpen):
            sometimes_fails()
        self.assertEqual(call_count, 2)  # not incremented

        # Wait for circuit breaker timeout
        time.sleep(0.06)

        # Call 4: half-open, probe allowed, succeeds this time
        result = sometimes_fails()
        self.assertEqual(result, "recovered")
        self.assertEqual(call_count, 3)

    def test_classify_error_transient(self):
        """Classification: transient errors should be retried."""
        config = RetryConfig()

        # ConnectionError is in transient_exceptions
        self.assertEqual(
            classify_error(ConnectionError("reset"), config),
            ErrorClass.TRANSIENT,
        )

        # 503 via response attribute
        exc = RuntimeError("Service Unavailable")
        exc.response = MagicMock(status_code=503)
        self.assertEqual(
            classify_error(exc, config),
            ErrorClass.TRANSIENT,
        )

    def test_classify_error_permanent(self):
        """Classification: permanent errors should not be retried."""
        config = RetryConfig()

        exc = RuntimeError("Not Found")
        exc.response = MagicMock(status_code=404)
        self.assertEqual(
            classify_error(exc, config),
            ErrorClass.PERMANENT,
        )

    def test_calculate_delay_backoff_and_jitter(self):
        """Delay should increase exponentially with jitter applied."""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter=0.0)

        d0 = calculate_delay(0, config)
        d1 = calculate_delay(1, config)
        d2 = calculate_delay(2, config)

        # Without jitter: 1.0, 2.0, 4.0
        self.assertAlmostEqual(d0, 1.0, places=1)
        self.assertAlmostEqual(d1, 2.0, places=1)
        self.assertAlmostEqual(d2, 4.0, places=1)

    def test_calculate_delay_max_cap(self):
        """Delay should be capped at max_delay."""
        config = RetryConfig(base_delay=10.0, exponential_base=10.0, max_delay=30.0, jitter=0.0)

        d = calculate_delay(5, config)
        self.assertAlmostEqual(d, 30.0, places=1)

    def test_retry_api_call_decorator(self):
        """retry_api_call convenience wrapper works."""
        call_count = 0

        @retry_api_call(max_attempts=3, base_delay=0.01)
        def api():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                exc = RuntimeError("503")
                exc.response = MagicMock(status_code=503)
                raise exc
            return {"data": "ok"}

        result = api()
        self.assertEqual(result, {"data": "ok"})
        self.assertEqual(call_count, 2)

    def test_retry_dns_lookup_decorator(self):
        """retry_dns_lookup convenience wrapper works."""
        call_count = 0

        @retry_dns_lookup(max_attempts=3)
        def lookup():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                import socket
                raise socket.gaierror("Temporary name resolution failure")
            return "1.2.3.4"

        result = lookup()
        self.assertEqual(result, "1.2.3.4")
        self.assertEqual(call_count, 2)

    def test_retry_network_request_decorator(self):
        """retry_network_request convenience wrapper works."""
        call_count = 0

        @retry_network_request(max_attempts=3)
        def fetch():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionResetError("Connection reset")
            return "data"

        result = fetch()
        self.assertEqual(result, "data")
        self.assertEqual(call_count, 2)

    def test_stats_tracking(self):
        """Retry stats should be tracked correctly."""
        call_count = 0

        @smart_retry(max_attempts=3, base_delay=0.01)
        def tracked():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("transient")
            return "ok"

        tracked()
        stats = get_all_retry_stats()
        # Find our function's stats
        key = [k for k in stats if "tracked" in k][0]
        s = stats[key]
        self.assertEqual(s["total_calls"], 1)
        self.assertEqual(s["successful_calls"], 1)
        self.assertGreaterEqual(s["total_retries"], 2)

    def test_on_retry_callback(self):
        """on_retry callback should be invoked on each retry."""
        retry_attempts = []

        @smart_retry(max_attempts=3, base_delay=0.01, on_retry=lambda e, a: retry_attempts.append(a))
        def flaky():
            raise ConnectionError("transient")

        with self.assertRaises(ConnectionError):
            flaky()

        self.assertEqual(retry_attempts, [1, 2])


class TestContainerManagerRetryPatterns(unittest.TestCase):
    """Verify that container_manager.py has adequate error handling."""

    def _find_container_method(self, name):
        """Find a method by name in container_manager.py (sync or async)."""
        cm_path = os.path.join(
            os.path.dirname(__file__), '..', '..',
            'recon_orchestrator', 'container_manager.py',
        )
        with open(cm_path) as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == name:
                    return node
        return None

    def test_ensure_recon_image_has_retry(self):
        """_ensure_recon_image uses a retry loop with exponential backoff."""
        node = self._find_container_method('_ensure_recon_image')
        self.assertIsNotNone(
            node, "_ensure_recon_image not found in container_manager.py",
        )

        # Must have a for loop over range (retry loop)
        has_for_loop = any(isinstance(n, ast.For) for n in ast.walk(node))
        self.assertTrue(
            has_for_loop,
            "_ensure_recon_image should contain a retry loop (for)",
        )

        # Must have a try/except inside
        has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
        self.assertTrue(
            has_try,
            "_ensure_recon_image should contain try/except",
        )

        # Check for sleep/backoff
        source = ast.unparse(node)
        self.assertIn("sleep", source)
        self.assertIn("max_retries", source)

    def test_ensure_gvm_scanner_image_has_retry(self):
        """ensure_gvm_scanner_image uses a retry loop with exponential backoff."""
        node = self._find_container_method('ensure_gvm_scanner_image')
        self.assertIsNotNone(
            node, "ensure_gvm_scanner_image not found in container_manager.py",
        )

        has_for_loop = any(isinstance(n, ast.For) for n in ast.walk(node))
        self.assertTrue(
            has_for_loop,
            "ensure_gvm_scanner_image should contain a retry loop (for)",
        )

        has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
        self.assertTrue(
            has_try,
            "ensure_gvm_scanner_image should contain try/except",
        )

        source = ast.unparse(node)
        self.assertIn("sleep", source)
        self.assertIn("max_retries", source)

    def test_critical_methods_have_try_except(self):
        """Key operational methods in container_manager should have error handling."""
        critical_methods = [
            'start_recon', 'stop_recon', 'pause_recon', 'resume_recon',
            'get_status', '_recover_containers', 'shutdown',
        ]

        for name in critical_methods:
            node = self._find_container_method(name)
            self.assertIsNotNone(
                node, f"{name} not found in container_manager.py",
            )

            has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
            self.assertTrue(
                has_try,
                f"{name} should have try/except error handling",
            )


class TestSubprocessRetryGap(unittest.TestCase):
    """Document the gap: subprocess calls in recon modules lack retry."""

    def test_subprocess_calls_lack_retry(self):
        """
        Verify that subprocess.run/Popen calls in main_recon_modules
        do NOT have retry wrappers. This documents the gap.
        """
        modules_with_subprocess = {
            'domain_recon': 5,
            'port_scan': 3,
            'vuln_scan': 2,
            'subdomain_takeover': 6,
            'nmap_scan': 1,
            'http_probe': 4,
            'vhost_sni_enum': 2,
            'uncover_enrich': 1,
            'masscan_scan': 1,
        }

        import ast

        base = os.path.join(os.path.dirname(__file__), '..', 'main_recon_modules')

        for mod_name, expected_min in modules_with_subprocess.items():
            mod_path = os.path.join(base, f'{mod_name}.py')
            if not os.path.exists(mod_path):
                # Try .py extension for graphql_scan which is in a subdir
                alt_path = os.path.join(
                    os.path.dirname(__file__), '..', mod_name.split('/')[-1],
                    f'{mod_name.split("/")[-1]}.py',
                )
                if os.path.exists(alt_path):
                    mod_path = alt_path
                else:
                    continue

            with open(mod_path) as f:
                source = f.read()

            # Count subprocess.run and subprocess.Popen calls
            subprocess_calls = source.count('subprocess.run') + source.count('subprocess.Popen')

            # Check if 'retry' appears in the file
            has_retry = 'retry' in source.lower()

            # Print gap info (not assert — this is documentation)
            if subprocess_calls > 0 and not has_retry:
                print(
                    f"[GAP] {mod_name}.py: {subprocess_calls} subprocess call(s), "
                    f"NO retry logic"
                )
            elif subprocess_calls > 0 and has_retry:
                print(
                    f"[OK]  {mod_name}.py: {subprocess_calls} subprocess call(s), "
                    f"HAS retry references"
                )

            # Count try blocks as a rough proxy for error handling
            try_count = source.count('try:')
            if subprocess_calls > 0 and try_count == 0:
                print(
                    f"[WARN] {mod_name}.py: {subprocess_calls} subprocess call(s), "
                    f"NO try/except blocks at all"
                )

            self.assertGreaterEqual(
                subprocess_calls, 1,
                f"Expected subprocess calls in {mod_name}.py",
            )


if __name__ == '__main__':
    unittest.main()
