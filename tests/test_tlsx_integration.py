"""
Tests for ProjectDiscovery TLSx integration.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import tlsx_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_tlsx_disabled_or_no_hosts():
    assert tlsx_helpers.discover_tlsx_assets("example.com", [], {}) == {}
    assert tlsx_helpers.discover_tlsx_assets("example.com", ["sub.example.com:443"], {"TLSX_ENABLED": False}) == {}


def test_tlsx_parses_output(temp_redamon_dir):
    output_file = temp_redamon_dir / "tlsx.json"
    output_file.write_text(json.dumps({
        "host": "sub.example.com",
        "port": "443",
        "subject_common_name": "sub.example.com",
        "subject_an_names": ["sub.example.com", "alt.example.com"],
        "jarm_hash": "abc123",
        "not_before": "2024-01-01",
        "not_after": "2025-01-01",
    }) + "\n")
    result = tlsx_helpers._parse_tlsx_output(output_file)
    assert "alt.example.com" in result["subdomains"]
    assert "abc123" in result["jarm_hashes"]
    assert len(result["certs"]) == 1


def test_tlsx_run_command_building(temp_redamon_dir):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        output = temp_redamon_dir / "tlsx.json"
        output.write_text(json.dumps({
            "host": "sub.example.com",
            "port": "443",
            "subject_common_name": "sub.example.com",
            "subject_an_names": [],
        }) + "\n")
        return MagicMock(returncode=0, stderr="")

    with patch.object(tlsx_helpers, "docker_available", return_value=True), \
         patch.object(tlsx_helpers, "pull_docker_image", return_value=True), \
         patch.object(tlsx_helpers, "create_temp_dir", return_value=temp_redamon_dir), \
         patch("subprocess.run", side_effect=fake_run):
        result = tlsx_helpers.run_tlsx_discovery(
            ["sub.example.com:443"], "projectdiscovery/tlsx:latest", ["443", "8443"]
        )

    assert "projectdiscovery/tlsx:latest" in captured["cmd"]
    assert "-san" in captured["cmd"]
    assert "-jarm" in captured["cmd"]
    assert "443,8443" in captured["cmd"]
    assert "sub.example.com" in result.get("subdomains", [])
