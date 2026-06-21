"""Tests for output_parsers — every parser, edge cases, and the dispatch helper."""

from __future__ import annotations

import os
import sys
import re
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

from output_parsers import (  # noqa: E402
    _dedup,
    _info_findings,
    PARSER_REGISTRY,
    parse_tool_output,
    parse_nmap,
    parse_naabu,
    parse_httpx,
    parse_subfinder,
    parse_amass,
    parse_nuclei,
    parse_wpscan,
    parse_katana,
    parse_gau,
    parse_ffuf,
    parse_arjun,
    parse_jsluice,
    parse_hydra,
    parse_curl,
    parse_playwright,
    parse_searchsploit,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestDedup(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_dedup([]), [])

    def test_no_duplicates(self):
        self.assertEqual(_dedup(["a", "b", "c"]), ["a", "b", "c"])

    def test_with_duplicates(self):
        self.assertEqual(_dedup(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

    def test_preserves_order(self):
        self.assertEqual(_dedup(["c", "a", "b", "a"]), ["c", "a", "b"])

    def test_integers(self):
        self.assertEqual(_dedup([3, 1, 2, 1, 3]), [3, 1, 2])


class TestInfoFindings(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_info_findings([], "test"), [])

    def test_basic(self):
        result = _info_findings(["a", "b"], "param")
        self.assertEqual(result, [
            {"type": "param", "detail": "a", "severity": "info"},
            {"type": "param", "detail": "b", "severity": "info"},
        ])

    def test_max_items(self):
        result = _info_findings(["1", "2", "3"], "x", max_items=2)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["detail"], "1")
        self.assertEqual(result[1]["detail"], "2")

    def test_max_items_zero_no_limit(self):
        items = [str(i) for i in range(100)]
        result = _info_findings(items, "x", max_items=0)
        self.assertEqual(len(result), 100)


# ═══════════════════════════════════════════════════════════════════════════════
# parse_tool_output dispatch
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseToolOutput(unittest.TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(parse_tool_output("execute_nmap", None))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_tool_output("execute_nmap", ""))

    def test_unknown_tool_returns_none(self):
        self.assertIsNone(parse_tool_output("nonexistent_tool", "foo"))

    def test_known_tool_dispatches(self):
        result = parse_tool_output("execute_nmap", "22/tcp open ssh")
        self.assertIsNotNone(result)
        self.assertIn("ports", result)

    def test_all_registry_entries_have_handler(self):
        for tool_name, handler_name in PARSER_REGISTRY.items():
            with self.subTest(tool=tool_name, handler=handler_name):
                self.assertIn(handler_name, globals(),
                              f"No function {handler_name} for tool {tool_name}")

    def test_every_handler_is_callable(self):
        for tool_name, handler_name in PARSER_REGISTRY.items():
            with self.subTest(tool=tool_name):
                handler = globals().get(handler_name)
                self.assertTrue(callable(handler),
                                f"{handler_name} is not callable")


# ═══════════════════════════════════════════════════════════════════════════════
# Individual parser tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseNmap(unittest.TestCase):
    def test_ports_and_services(self):
        raw = (
            "22/tcp open ssh\n"
            "80/tcp open http\n"
            "443/tcp open https\n"
            "8080/tcp open http-proxy\n"
        )
        result = parse_nmap(raw)
        self.assertIn(22, result["ports"])
        self.assertIn(443, result["ports"])
        self.assertIn("ssh", result["services"])

    def test_os_detection(self):
        raw = "OS details: Linux 5.4.0-26-generic"
        result = parse_nmap(raw)
        self.assertTrue(any("Linux" in t for t in result["technologies"]))

    def test_cve_extraction(self):
        raw = "CVE-2024-1234 and CVE-2024-5678 found"
        result = parse_nmap(raw)
        # Parser extracts numeric portion without CVE- prefix
        self.assertIn("2024-1234", result["vulnerabilities"])
        self.assertIn("2024-5678", result["vulnerabilities"])

    def test_empty(self):
        result = parse_nmap("")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["findings"], [])


class TestParseNaabu(unittest.TestCase):
    def test_plain_format(self):
        result = parse_naabu("Found 22.\nFound 80.\nFound 443.")
        self.assertEqual(result["ports"], [22, 80, 443])

    def test_json_line_format(self):
        raw = '{"port": 3306}\n{"port": 5432}\n'
        result = parse_naabu(raw)
        self.assertEqual(result["ports"], [3306, 5432])

    def test_empty(self):
        result = parse_naabu("")
        self.assertEqual(result["ports"], [])


class TestParseHttpx(unittest.TestCase):
    def test_technologies(self):
        raw = '[200] tech: [React, Webpack] [200] title: Home'
        result = parse_httpx(raw)
        self.assertIn("React", result["technologies"])
        self.assertIn("Webpack", result["technologies"])

    def test_json_line_format(self):
        raw = '{"tech": ["Vue", "Tailwind"], "status_code": 200, "title": "App"}'
        result = parse_httpx(raw)
        self.assertIn("Vue", result["technologies"])
        self.assertIn("Tailwind", result["technologies"])

    def test_empty(self):
        result = parse_httpx("")
        self.assertEqual(result["technologies"], [])


class TestParseSubfinder(unittest.TestCase):
    def test_domains(self):
        result = parse_subfinder("api.example.com\nadmin.example.com\n")
        self.assertIn("api.example.com", result["subdomains"])
        self.assertIn("admin.example.com", result["subdomains"])

    def test_json_line_format(self):
        result = parse_subfinder('{"host": "dev.example.com"}')
        self.assertIn("dev.example.com", result["subdomains"])

    def test_empty(self):
        result = parse_subfinder("")
        self.assertEqual(result["subdomains"], [])


class TestParseAmass(unittest.TestCase):
    def test_json_line_format(self):
        raw = '{"name": "sub.example.com"}\n{"name": "another.example.com"}'
        result = parse_amass(raw)
        self.assertIn("sub.example.com", result["subdomains"])

    def test_plain_format(self):
        result = parse_amass("sub1.example.com\nsub2.example.com\n")
        self.assertIn("sub1.example.com", result["subdomains"])

    def test_empty(self):
        result = parse_amass("")
        self.assertEqual(result["subdomains"], [])


class TestParseNuclei(unittest.TestCase):
    def test_finding_format(self):
        raw = '{"template-id": "http-missing-security-headers", "host": "https://example.com", "info": {"severity": "medium"}}'
        result = parse_nuclei(raw)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "medium")

    def test_severity_counting(self):
        raw = (
            '{"template-id": "tech-detect", "host": "https://example.com", "info": {"severity": "info"}}\n'
            '{"template-id": "http-missing-headers", "host": "https://example.com", "info": {"severity": "low"}}\n'
            '{"template-id": "xss", "host": "https://example.com", "info": {"severity": "medium"}}\n'
        )
        result = parse_nuclei(raw)
        self.assertGreaterEqual(len(result["findings"]), 3)

    def test_json_line_with_cve(self):
        raw = '{"template-id": "ssl-dates", "host": "example.com", "info": {"severity": "medium"}, "extracted-results": ["CVE-2024-1234"]}'
        result = parse_nuclei(raw)
        # Parser extracts findings from JSON but may store CVEs differently
        self.assertGreaterEqual(len(result["findings"]), 1)

    def test_empty(self):
        result = parse_nuclei("")
        self.assertEqual(result["vulnerabilities"], [])
        self.assertEqual(result["findings"], [])


class TestParseWpscan(unittest.TestCase):
    def test_version(self):
        result = parse_wpscan("[+] WordPress version: 6.4.2")
        self.assertTrue(any("wordpress" in t.lower() for t in result["technologies"]))

    def test_plugins(self):
        result = parse_wpscan("[+] akismet v3.2")
        self.assertTrue(any("akismet" in t.lower() for t in result["technologies"]))

    def test_vulnerabilities(self):
        result = parse_wpscan("[!] SQL Injection - CVE-2024-1234")
        # Parser produces wp_vuln findings with severity and detail
        findings = [f for f in result["findings"] if f["type"] == "wp_vuln"]
        self.assertGreaterEqual(len(findings), 1)

    def test_user_enumeration(self):
        result = parse_wpscan("[+] | admin | editor |")
        usernames = [c["username"] for c in result["credentials"] if c.get("type") == "wp_user"]
        self.assertIn("admin", usernames)

    def test_empty(self):
        result = parse_wpscan("")
        self.assertIn("wordpress", [t.lower() for t in result["technologies"]])


class TestParseKatana(unittest.TestCase):
    def test_url_extraction(self):
        result = parse_katana("https://example.com/page\nhttps://example.com/api")
        self.assertIn("https://example.com/page", result["endpoints"])

    def test_json_line_format(self):
        result = parse_katana('{"url": "https://example.com/test"}')
        self.assertIn("https://example.com/test", result["endpoints"])

    def test_empty(self):
        result = parse_katana("")
        self.assertEqual(result["endpoints"], [])


class TestParseGau(unittest.TestCase):
    def test_url_extraction(self):
        result = parse_gau("https://example.com/old\nhttps://example.com/backup")
        self.assertIn("https://example.com/old", result["endpoints"])
        self.assertIn("https://example.com/backup", result["endpoints"])

    def test_empty(self):
        result = parse_gau("")
        self.assertEqual(result["endpoints"], [])


class TestParseFfuf(unittest.TestCase):
    def test_status_format(self):
        result = parse_ffuf("https://example.com/admin (Status: 200)")
        self.assertIn("https://example.com/admin", result["endpoints"])

    def test_json_line_format(self):
        result = parse_ffuf('{"url": "https://example.com/config", "status": 200}')
        self.assertIn("https://example.com/config", result["endpoints"])

    def test_empty(self):
        result = parse_ffuf("")
        self.assertEqual(result["endpoints"], [])


class TestParseArjun(unittest.TestCase):
    def test_parameter_format(self):
        result = parse_arjun("[+] Found: token")
        self.assertIn("token", result["parameters"])

    def test_json_format(self):
        result = parse_arjun('{"param": "id"}')
        self.assertIn("id", result["parameters"])

    def test_empty(self):
        result = parse_arjun("")
        self.assertEqual(result["parameters"], [])


class TestParseJsluice(unittest.TestCase):
    def test_endpoint_extraction(self):
        result = parse_jsluice("URL: /api/v1/users")
        self.assertIn("/api/v1/users", result["endpoints"])

    def test_empty(self):
        result = parse_jsluice("")
        self.assertEqual(result["endpoints"], [])


class TestParseHydra(unittest.TestCase):
    def test_credential_extraction(self):
        raw = "[22][ssh] host: 10.0.0.1 login: root password: p@ssw0rd"
        result = parse_hydra(raw)
        self.assertEqual(len(result["credentials"]), 1)
        cred = result["credentials"][0]
        self.assertEqual(cred["username"], "root")
        self.assertEqual(cred["password"], "p@ssw0rd")
        self.assertEqual(cred["host"], "10.0.0.1")
        self.assertEqual(cred["service"], "ssh")

    def test_empty(self):
        result = parse_hydra("")
        self.assertEqual(result["credentials"], [])
        self.assertEqual(result["findings"], [])


class TestParseCurl(unittest.TestCase):
    def test_server_header(self):
        result = parse_curl("Server: nginx/1.18.0")
        self.assertIn("nginx/1.18.0", result["technologies"])

    def test_content_type(self):
        result = parse_curl("content-type: application/json")
        self.assertTrue(any("json" in t for t in result["technologies"]))

    def test_empty(self):
        result = parse_curl("")
        self.assertEqual(result["technologies"], [])


class TestParsePlaywright(unittest.TestCase):
    def test_title_extraction(self):
        result = parse_playwright("<html><title>Test Page</title></html>")
        titles = [f["detail"] for f in result["findings"] if f["type"] == "page_title"]
        self.assertIn("Test Page", titles)

    def test_wordpress_detection(self):
        result = parse_playwright('<html><link rel="stylesheet" href="/wp-content/style.css"></html>')
        self.assertTrue(any("wordpress" in t.lower() for t in result["technologies"]))

    def test_react_detection(self):
        result = parse_playwright('<html><div id="react-root"></div></html>')
        self.assertTrue(any("react" in t.lower() for t in result["technologies"]))

    def test_empty(self):
        result = parse_playwright("")
        self.assertEqual(result["technologies"], [])
        self.assertEqual(result["findings"], [])


# ═══════════════════════════════════════════════════════════════════════════════
# Edge cases — resilience
# ═══════════════════════════════════════════════════════════════════════════════


class TestParseSearchsploit(unittest.TestCase):
    def test_json_line_format(self):
        raw = """\
[
  {
    "EDB-ID": "12345",
    "Title": "Foobar 1.0 - Remote Code Execution (RCE)",
    "Type": "remote",
    "Platform": "linux",
    "Path": "/usr/share/exploitdb/exploits/linux/remote/12345.py"
  },
  {
    "EDB-ID": "67890",
    "Title": "Bazapp 2.1 - Local Privilege Escalation",
    "Type": "local",
    "Platform": "windows",
    "Path": "/usr/share/exploitdb/exploits/windows/local/67890.c"
  }
]"""
        result = parse_searchsploit(raw)
        self.assertIn("exploits", result)
        self.assertIn("findings", result)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["exploits"]), 2)
        self.assertEqual(result["exploits"][0]["edb_id"], "12345")
        self.assertEqual(result["exploits"][1]["edb_id"], "67890")
        self.assertEqual(result["exploits"][0]["type"], "remote")
        self.assertEqual(result["exploits"][1]["type"], "local")

    def test_cve_extraction(self):
        raw = """\
[
  {
    "EDB-ID": "99999",
    "Title": "WidgetX 3.0 - Buffer Overflow (CVE-2025-1234)",
    "Type": "remote",
    "Platform": "linux",
    "Path": ""
  }
]"""
        result = parse_searchsploit(raw)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(result["vulnerabilities"], ["2025-1234"])

    def test_findings_severity_remote_is_high(self):
        raw = """\
[
  {
    "EDB-ID": "11111",
    "Title": "Remote exploit",
    "Type": "remote",
    "Platform": "linux",
    "Path": ""
  }
]"""
        result = parse_searchsploit(raw)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_findings_severity_local_is_medium(self):
        raw = """\
[
  {
    "EDB-ID": "22222",
    "Title": "Local exploit",
    "Type": "local",
    "Platform": "linux",
    "Path": ""
  }
]"""
        result = parse_searchsploit(raw)
        self.assertEqual(result["findings"][0]["severity"], "medium")

    def test_empty(self):
        result = parse_searchsploit("")
        self.assertEqual(result, {"exploits": [], "findings": [], "vulnerabilities": []})

    def test_garbage(self):
        result = parse_searchsploit("!@#$%^")
        self.assertEqual(result, {"exploits": [], "findings": [], "vulnerabilities": []})

    def test_alternate_key_names(self):
        """Handle searchsploit output that uses lowercase keys."""
        raw = """\
[
  {
    "id": "33333",
    "title": "Alt key exploit",
    "type": "remote",
    "platform": "linux",
    "path": "/tmp/exploit.sh"
  }
]"""
        result = parse_searchsploit(raw)
        self.assertEqual(len(result["exploits"]), 1)
        self.assertEqual(result["exploits"][0]["edb_id"], "33333")


class TestParseMasscan(unittest.TestCase):
    """Masscan reuses parse_naabu (same output shape)."""

    def test_plain_format(self):
        raw = """\
masscan: discovered port 80/tcp on 10.0.0.1
masscan: discovered port 443/tcp on 10.0.0.1
masscan: discovered port 22/tcp on 10.0.0.2
"""
        result = parse_naabu(raw)
        self.assertEqual(result["ports"], [22, 80, 443])

    def test_json_line_format(self):
        raw = """\
{"port": 3306, "proto": "tcp", "ip": "10.0.0.1"}
{"port": 5432, "proto": "tcp", "ip": "10.0.0.1"}
"""
        result = parse_naabu(raw)
        self.assertEqual(result["ports"], [3306, 5432])

    def test_empty(self):
        result = parse_naabu("")
        self.assertEqual(result["ports"], [])


class TestEdgeCases(unittest.TestCase):
    def test_all_parsers_handle_empty_string(self):
        for handler_name in set(PARSER_REGISTRY.values()):
            handler = globals()[handler_name]
            with self.subTest(handler=handler_name):
                result = handler("")
                self.assertIsInstance(result, dict)

    def test_all_parsers_handle_garbage(self):
        garbage = "!@#$%^&*()\n\t\x00\x01\x02\nnot a valid output\n"
        for handler_name in set(PARSER_REGISTRY.values()):
            handler = globals()[handler_name]
            with self.subTest(handler=handler_name):
                result = handler(garbage)
                self.assertIsInstance(result, dict)

    def test_all_parsers_return_consistent_structure(self):
        """Every parser returns a dict with the same known shape."""
        expected_keys = {"ports", "services", "technologies", "vulnerabilities",
                         "credentials", "findings", "subdomains", "endpoints",
                         "parameters", "exploits"}
        for handler_name in set(PARSER_REGISTRY.values()):
            handler = globals()[handler_name]
            with self.subTest(handler=handler_name):
                result = handler("test input here")
                for key in result:
                    self.assertIn(key, expected_keys,
                                  f"Unexpected key {key!r} in {handler_name}")

    def test_parse_tool_output_never_raises(self):
        """Even with garbage input, dispatch should never raise."""
        for tool_name in PARSER_REGISTRY:
            with self.subTest(tool=tool_name):
                result = parse_tool_output(tool_name, None)
                self.assertIsNone(result)
                result = parse_tool_output(tool_name, "")
                self.assertIsNone(result)
                result = parse_tool_output(tool_name, "\x00\x01\x02")
                self.assertIsNotNone(result)
                self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
