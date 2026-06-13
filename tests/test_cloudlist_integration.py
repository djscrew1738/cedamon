"""
Tests for Cloudlist integration.

These tests avoid running the real cloudlist Docker image. They exercise the
parser, settings gating, and command-building behavior via monkey-patched helpers.
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

from recon.helpers.domain_recon import cloudlist_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_cloudlist_disabled_by_default():
    """Cloudlist must be opt-in because it requires provider credentials."""
    assert cloudlist_helpers.discover_cloudlist_assets({}) == []
    assert cloudlist_helpers.discover_cloudlist_assets({"CLOUDLIST_ENABLED": False}) == []


def test_cloudlist_skips_without_provider_config(temp_redamon_dir):
    """Even when enabled, cloudlist skips if no provider config is configured."""
    settings = {"CLOUDLIST_ENABLED": True, "CLOUDLIST_PROVIDER_CONFIG": ""}
    assert cloudlist_helpers.discover_cloudlist_assets(settings) == []


def test_cloudlist_skips_missing_provider_config_file(temp_redamon_dir):
    """Cloudlist skips gracefully if the configured provider config file does not exist."""
    settings = {
        "CLOUDLIST_ENABLED": True,
        "CLOUDLIST_PROVIDER_CONFIG": "/nonexistent/provider-config.yaml"
    }
    with patch.object(cloudlist_helpers.shutil, "which", return_value="/usr/bin/docker"):
        assert cloudlist_helpers.discover_cloudlist_assets(settings) == []


def test_parse_cloudlist_output_handles_list_and_dict(temp_redamon_dir):
    """Parser normalizes both list and provider-keyed dict outputs."""
    # List format
    list_file = temp_redamon_dir / "cloudlist_list.json"
    list_file.write_text(json.dumps([
        {"provider": "aws", "service": "s3", "name": "bucket1", "host": "bucket1.s3.amazonaws.com"},
        {"provider": "gcp", "service": "storage", "name": "bucket2", "ip": "1.2.3.4"},
    ]))
    result = cloudlist_helpers._parse_cloudlist_output(list_file)
    assert len(result) == 2
    assert result[0]["provider"] == "aws"
    assert result[0]["host"] == "bucket1.s3.amazonaws.com"
    assert result[1]["ip"] == "1.2.3.4"

    # Dict format keyed by provider
    dict_file = temp_redamon_dir / "cloudlist_dict.json"
    dict_file.write_text(json.dumps({
        "azure": [
            {"service": "vm", "host": "host1.eastus.cloudapp.azure.com"},
            {"service": "storage", "name": "store1"},
        ]
    }))
    result2 = cloudlist_helpers._parse_cloudlist_output(dict_file)
    assert len(result2) == 2
    assert result2[0]["provider"] == "azure"
    assert result2[0]["host"] == "host1.eastus.cloudapp.azure.com"


def test_run_cloudlist_discovery_command(temp_redamon_dir):
    """run_cloudlist_discovery builds a docker command with provider config."""
    config_file = temp_redamon_dir / "provider-config.yaml"
    config_file.write_text("- provider: aws\n  id: test\n")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        output_file = temp_redamon_dir / "cloudlist.json"
        output_file.write_text(json.dumps([]))
        return MagicMock(returncode=0, stderr="")

    with patch.object(cloudlist_helpers.shutil, "which", return_value="/usr/bin/docker"), \
         patch.object(cloudlist_helpers, "pull_cloudlist_docker_image", return_value=True), \
         patch.object(cloudlist_helpers.subprocess, "run", side_effect=fake_run):
        cloudlist_helpers.run_cloudlist_discovery(
            docker_image="projectdiscovery/cloudlist:latest",
            provider_config=str(config_file),
            providers=["aws", "gcp"],
            services=["storage", "vm"],
            extended_metadata=True,
        )

    cmd = captured["cmd"]
    assert "docker" in cmd
    assert "projectdiscovery/cloudlist:latest" in cmd
    assert f"/config/{config_file.name}" in cmd
    assert "-p" in cmd
    assert "aws" in cmd
    assert "gcp" in cmd
    assert "storage" in cmd
    assert "vm" in cmd
    assert "-extended-metadata" in cmd
