"""
Tests for ProjectDiscovery Chaos integration.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import chaos_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_chaos_disabled_or_missing_key():
    assert chaos_helpers.discover_chaos_subdomains("example.com", {}) == set()
    assert chaos_helpers.discover_chaos_subdomains("example.com", {"CHAOS_ENABLED": True}) == set()


def test_chaos_no_docker(temp_redamon_dir):
    with patch.object(chaos_helpers, "docker_available", return_value=False):
        result = chaos_helpers.run_chaos_discovery("example.com", "projectdiscovery/chaos-client:latest", "key")
    assert result == set()


def test_chaos_parses_output(temp_redamon_dir):
    output_file = temp_redamon_dir / "chaos.json"
    output_file.write_text(
        json.dumps({"domain": "sub.example.com"}) + "\n" +
        json.dumps({"domain": "api.example.com"}) + "\n"
    )
    result = chaos_helpers._parse_chaos_output(output_file)
    assert result == {"sub.example.com", "api.example.com"}


def test_chaos_run_command_building(temp_redamon_dir):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        output = temp_redamon_dir / "chaos.json"
        output.write_text(json.dumps({"domain": "found.example.com"}) + "\n")
        return MagicMock(returncode=0, stderr="")

    with patch.object(chaos_helpers, "docker_available", return_value=True), \
         patch.object(chaos_helpers, "pull_docker_image", return_value=True), \
         patch.object(chaos_helpers, "create_temp_dir", return_value=temp_redamon_dir), \
         patch("subprocess.run", side_effect=fake_run):
        result = chaos_helpers.run_chaos_discovery(
            "example.com", "projectdiscovery/chaos-client:latest", "secret-key"
        )

    assert "projectdiscovery/chaos-client:latest" in captured["cmd"]
    assert "example.com" in captured["cmd"]
    assert "secret-key" in captured["cmd"]
    assert "chaos.json" in captured["cmd"][-1]
    assert result == {"found.example.com"}


def test_chaos_high_level_respects_enabled(temp_redamon_dir):
    with patch.object(chaos_helpers, "docker_available", return_value=False):
        assert chaos_helpers.discover_chaos_subdomains(
            "example.com",
            {"CHAOS_ENABLED": True, "CHAOS_API_KEY": "k"}
        ) == set()
