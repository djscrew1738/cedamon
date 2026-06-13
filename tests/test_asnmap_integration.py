"""
Tests for ProjectDiscovery ASNmap integration.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import asnmap_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_asnmap_disabled_or_no_targets():
    assert asnmap_helpers.discover_asnmap_assets("example.com", [], {}) == []
    assert asnmap_helpers.discover_asnmap_assets("example.com", ["1.2.3.4"], {"ASNMAP_ENABLED": False}) == []


def test_asnmap_run_command_building(temp_redamon_dir):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        output = temp_redamon_dir / "asnmap.json"
        output.write_text(
            json.dumps({"ip": "1.2.3.4", "asn": "AS12345", "org": "Example Inc"}) + "\n"
        )
        return MagicMock(returncode=0, stderr="")

    with patch.object(asnmap_helpers, "docker_available", return_value=True), \
         patch.object(asnmap_helpers, "pull_docker_image", return_value=True), \
         patch.object(asnmap_helpers, "create_temp_dir", return_value=temp_redamon_dir), \
         patch("subprocess.run", side_effect=fake_run):
        result = asnmap_helpers.run_asnmap_discovery(
            ["1.2.3.4"], "projectdiscovery/asnmap:latest"
        )

    assert "projectdiscovery/asnmap:latest" in captured["cmd"]
    assert any("targets.txt" in arg for arg in captured["cmd"])
    assert result[0]["asn"] == "AS12345"


def test_asnmap_high_level(temp_redamon_dir):
    with patch.object(asnmap_helpers, "docker_available", return_value=False):
        assert asnmap_helpers.discover_asnmap_assets(
            "example.com", ["1.2.3.4"],
            {"ASNMAP_ENABLED": True}
        ) == []
