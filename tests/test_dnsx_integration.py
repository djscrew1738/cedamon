"""
Tests for ProjectDiscovery DNSx integration.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import dnsx_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_dnsx_disabled_or_no_domains():
    assert dnsx_helpers.discover_dnsx_records([], {}) == []
    assert dnsx_helpers.discover_dnsx_records(["example.com"], {"DNSX_ENABLED": False}) == []


def test_dnsx_run_command_building(temp_redamon_dir):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        output = temp_redamon_dir / "dnsx.json"
        output.write_text(
            json.dumps({"host": "example.com", "a": ["1.2.3.4"]}) + "\n"
        )
        return MagicMock(returncode=0, stderr="")

    with patch.object(dnsx_helpers, "docker_available", return_value=True), \
         patch.object(dnsx_helpers, "pull_docker_image", return_value=True), \
         patch.object(dnsx_helpers, "create_temp_dir", return_value=temp_redamon_dir), \
         patch("subprocess.run", side_effect=fake_run):
        result = dnsx_helpers.run_dnsx_enrichment(
            ["example.com"], "projectdiscovery/dnsx:latest",
            ["a", "aaaa"], wildcard_tests=3
        )

    assert "projectdiscovery/dnsx:latest" in captured["cmd"]
    assert "-a" in captured["cmd"]
    assert "-aaaa" in captured["cmd"]
    assert "-wd" in captured["cmd"]
    assert result[0]["host"] == "example.com"
