"""
Tests for BBOT integration.

These tests avoid running the real BBOT Docker image. They exercise the parser,
settings gating, and command-building behavior via monkey-patched helpers.
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import bbot_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_bbot_discovery_disabled_by_empty_settings(temp_redamon_dir):
    """When BBOT_ENABLED is False/empty, discover_bbot_assets returns {}."""
    assert bbot_helpers.discover_bbot_assets("example.com", {}) == {}


def test_discover_bbot_assets_gated_by_enabled(temp_redamon_dir):
    """The high-level wrapper must respect BBOT_ENABLED=False."""
    settings = {"BBOT_ENABLED": False}
    assert bbot_helpers.discover_bbot_assets("example.com", settings) == {}


def test_parse_bbot_output_extracts_subdomains_and_cloud_assets(temp_redamon_dir):
    """Parser extracts DNS_NAME, STORAGE_BUCKET, URL, EMAIL_ADDRESS, IP_ADDRESS."""
    output_file = temp_redamon_dir / "bbot_example.json"
    lines = [
        json.dumps({"type": "DNS_NAME", "data": "www.example.com"}),
        json.dumps({"type": "DNS_NAME", "data": "api.example.com"}),
        json.dumps({"type": "DNS_NAME", "data": "other.org"}),
        json.dumps({"type": "STORAGE_BUCKET", "data": {"name": "example-bucket", "provider": "amazon"}}),
        json.dumps({"type": "URL", "data": "https://www.example.com/path"}),
        json.dumps({"type": "EMAIL_ADDRESS", "data": "info@example.com"}),
        json.dumps({"type": "IP_ADDRESS", "data": "1.2.3.4"}),
        json.dumps({"type": "URL_UNVERIFIED", "data": "http://api.example.com/old"}),
    ]
    output_file.write_text("\n".join(lines))

    result = bbot_helpers._parse_bbot_output(output_file, "example.com")

    assert result["subdomains"] == ["api.example.com", "www.example.com"]
    assert len(result["cloud_assets"]) == 1
    assert result["cloud_assets"][0]["name"] == "example-bucket"
    assert result["cloud_assets"][0]["provider"] == "amazon"
    assert "https://www.example.com/path" in result["urls"]
    assert "http://api.example.com/old" in result["urls"]
    assert result["emails"] == ["info@example.com"]
    assert result["ips"] == ["1.2.3.4"]


def test_run_bbot_discovery_no_docker(temp_redamon_dir):
    """If docker is unavailable, run_bbot_discovery returns {} gracefully."""
    with patch.object(bbot_helpers.shutil, "which", return_value=None):
        result = bbot_helpers.run_bbot_discovery(
            "example.com", "blacklanternsecurity/bbot:stable",
            ["subdomain-enum"], ["httpx"]
        )
    assert result == {}


def test_run_bbot_discovery_command_contains_expected_args(temp_redamon_dir):
    """run_bbot_discovery builds a docker command with the expected args."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        # Create a fake output file so parsing succeeds
        output_file = temp_redamon_dir / "bbot_example.json"
        output_file.write_text(json.dumps({"type": "DNS_NAME", "data": "sub.example.com"}) + "\n")
        return MagicMock(returncode=0, stderr="")

    with patch.object(bbot_helpers.shutil, "which", return_value="/usr/bin/docker"), \
         patch.object(bbot_helpers, "pull_bbot_docker_image", return_value=True), \
         patch.object(bbot_helpers.subprocess, "run", side_effect=fake_run):
        result = bbot_helpers.run_bbot_discovery(
            "example.com", "blacklanternsecurity/bbot:stable",
            ["subdomain-enum", "cloud-enum"], ["httpx"],
            use_proxy=True, safe_mode=True
        )

    cmd = captured["cmd"]
    assert "docker" in cmd
    assert "blacklanternsecurity/bbot:stable" in cmd
    assert "example.com" in cmd
    assert "subdomain-enum" in cmd
    assert "cloud-enum" in cmd
    assert "httpx" in cmd
    assert "/output" in cmd
    assert "HTTP_PROXY=socks5://127.0.0.1:9050" in cmd
    assert "passive" in cmd and "safe" in cmd
    assert isinstance(result, dict)
