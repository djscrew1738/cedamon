"""
CPE resolver tests for graph_db.cpe_resolver.

Stubs neo4j at module level — no live Neo4j connection needed.
"""
import sys
from unittest.mock import MagicMock

_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())

import pytest
from graph_db import cpe_resolver


class TestParseCpeString:
    """CPE string parsing."""

    def test_parse_standard_cpe_23(self):
        result = cpe_resolver._parse_cpe_string(
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        )
        assert result is not None
        assert result["vendor"] == "apache"
        assert result["product"] == "http_server"
        assert result["version"] == "2.4.49"

    def test_parse_cpe_22(self):
        result = cpe_resolver._parse_cpe_string("cpe:/a:apache:http_server:2.4.49")
        assert result is not None
        assert result["vendor"] == "apache"
        assert result["product"] == "http_server"
        assert result["version"] == "2.4.49"

    def test_parse_cpe_empty(self):
        assert cpe_resolver._parse_cpe_string("") is None

    def test_parse_cpe_wildcard_version(self):
        result = cpe_resolver._parse_cpe_string(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        )
        assert result is not None
        assert result["vendor"] == "apache"
        assert result["product"] == "http_server"
        assert result["version"] is None or result["version"] == "*"

    def test_parse_cpe_os_type(self):
        result = cpe_resolver._parse_cpe_string(
            "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"
        )
        assert result is not None
        assert result["vendor"] == "canonical"
        assert result["product"] == "ubuntu_linux"

    def test_parse_cpe_hardware_type(self):
        result = cpe_resolver._parse_cpe_string(
            "cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*"
        )
        assert result is not None
        assert result["vendor"] == "cisco"
        assert result["product"] == "router"


class TestResolveDisplayName:
    """Technology display name resolution."""

    def test_resolve_gvm_known(self):
        name = cpe_resolver._resolve_cpe_to_display_name("openbsd", "openssh")
        assert name == "OpenSSH"

    def test_resolve_reverse_cpe_known(self):
        name = cpe_resolver._resolve_cpe_to_display_name("apache", "http_server")
        assert name == "Apache HTTP Server"

    def test_resolve_fallback_humanized(self):
        name = cpe_resolver._resolve_cpe_to_display_name("somevendor", "some_product")
        assert name is not None
        assert len(name) > 0
        assert "_" not in name.lower()

    def test_resolve_case_insensitive_vendor(self):
        name = cpe_resolver._resolve_cpe_to_display_name("openbsd", "openssh")
        assert name == "OpenSSH"


class TestGvmDisplayNames:
    """Verify GVM display name table integrity."""

    def test_all_tuples_have_two_elements(self):
        for key in cpe_resolver._GVM_DISPLAY_NAMES:
            assert len(key) == 2, f"GVM key {key} should be a 2-tuple (vendor, product)"

    def test_no_duplicate_keys(self):
        keys = list(cpe_resolver._GVM_DISPLAY_NAMES.keys())
        assert len(keys) == len(set(keys)), "Duplicate GVM display name keys"


class TestReverseCpeMappings:
    """Verify reverse CPE mapping table integrity."""

    def test_all_tuples_have_two_elements(self):
        for key in cpe_resolver._REVERSE_CPE_MAPPINGS:
            assert len(key) == 2, f"Reverse CPE key {key} should be a 2-tuple"

    def test_no_duplicate_keys(self):
        keys = list(cpe_resolver._REVERSE_CPE_MAPPINGS.keys())
        assert len(keys) == len(set(keys)), "Duplicate reverse CPE mapping keys"

    def test_all_values_are_strings(self):
        for key, value in cpe_resolver._REVERSE_CPE_MAPPINGS.items():
            assert isinstance(value, str), \
                f"Reverse CPE value for {key} should be str, got {type(value)}"
