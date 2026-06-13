"""
Tests for cloud_enum public cloud asset brute-force integration.
"""
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from recon.helpers.domain_recon import cloud_enum_helpers


@pytest.fixture
def temp_redamon_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("REDAMON_TEMP_DIR", tmp)
        yield Path(tmp)


def test_cloud_enum_disabled_by_default():
    assert cloud_enum_helpers.discover_cloud_enum_assets("example.com", {}) == []
    assert cloud_enum_helpers.discover_cloud_enum_assets("example.com", {"CLOUD_ENUM_ENABLED": False}) == []


def test_cloud_enum_parse_stdout():
    stdout = """
[+] AWS S3 bucket found: https://s3.amazonaws.com/example-bucket
[+] Google bucket found: https://storage.googleapis.com/example-assets
[+] Azure blob found: https://example.blob.core.windows.net/public
[-] Nothing found for keyword
"""
    assets = cloud_enum_helpers._parse_cloud_enum_output(stdout)
    assert len(assets) == 3
    assert assets[0]["provider"] == "aws"
    assert assets[1]["provider"] == "gcp"
    assert assets[2]["provider"] == "azure"


def test_cloud_enum_run_command_building(temp_redamon_dir):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return MagicMock(
            returncode=0,
            stderr="",
            stdout="[+] AWS S3 bucket found: https://s3.amazonaws.com/example-bucket\n"
        )

    with patch.object(cloud_enum_helpers, "docker_available", return_value=True), \
         patch.object(cloud_enum_helpers, "ensure_cloud_enum_docker_image", return_value=True), \
         patch("subprocess.run", side_effect=fake_run):
        result = cloud_enum_helpers.run_cloud_enum_discovery(
            ["example"], "redamon-cloud_enum:latest"
        )

    assert "redamon-cloud_enum:latest" in captured["cmd"]
    assert "-k" in captured["cmd"]
    assert "example" in captured["cmd"]
    assert len(result) == 1
    assert result[0]["provider"] == "aws"


def test_cloud_enum_derives_keyword_from_domain():
    with patch.object(cloud_enum_helpers, "docker_available", return_value=False):
        result = cloud_enum_helpers.discover_cloud_enum_assets(
            "example.com", {"CLOUD_ENUM_ENABLED": True}
        )
    assert result == []
