"""
Tests for recon.helpers.resource_enum.waymore_helpers
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from recon.helpers.resource_enum import waymore_helpers


def test_ensure_waymore_docker_image_builds_when_missing():
    with patch.object(waymore_helpers, "_waymore_image_built", return_value=False), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert waymore_helpers.ensure_waymore_docker_image("waymore:latest") is True
        # Should have called docker build with GitHub URL
        cmd = mock_run.call_args[0][0]
        assert "build" in cmd
        assert "https://github.com/xnl-h4ck3r/waymore.git#main" in cmd


def test_ensure_waymore_docker_image_skips_when_present():
    with patch.object(waymore_helpers, "_waymore_image_built", return_value=True), \
         patch("subprocess.run") as mock_run:
        assert waymore_helpers.ensure_waymore_docker_image("waymore:latest") is True
        mock_run.assert_not_called()


def test_run_waymore_discovery_skips_without_domains():
    result = waymore_helpers.run_waymore_discovery([], "waymore:latest")
    assert result == []


def test_run_waymore_discovery_skips_without_docker():
    with patch.object(waymore_helpers.shutil, "which", return_value=None):
        result = waymore_helpers.run_waymore_discovery(["example.com"], "waymore:latest")
        assert result == []


def test_run_waymore_discovery_filters_extensions(tmp_path, monkeypatch):
    monkeypatch.setenv("REDAMON_TEMP_DIR", str(tmp_path))
    with patch.object(waymore_helpers, "ensure_waymore_docker_image", return_value=True), \
         patch("subprocess.run") as mock_run:

        def fake_run(cmd, **kwargs):
            vol_idx = cmd.index("-v")
            host_temp = Path(cmd[vol_idx + 1].split(":", 1)[0])
            out_path = host_temp / "waymore.txt"
            out_path.write_text(
                "http://example.com/api/users\n"
                "http://example.com/image.png\n"
                "http://example.com/style.css\n"
            )
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        result = waymore_helpers.run_waymore_discovery(
            ["example.com"],
            "waymore:latest",
            blacklist_extensions=["png", "css"],
        )
        assert result == ["http://example.com/api/users"]


def test_merge_waymore_into_by_base_url_labels_new_endpoints():
    by_base_url = {
        "http://example.com": {
            "base_url": "http://example.com",
            "endpoints": {
                "/api/users": {"methods": ["GET"], "sources": ["katana"]},
            },
            "summary": {"total_endpoints": 1, "total_parameters": 0, "methods": {}, "categories": {}},
        }
    }
    updated, stats = waymore_helpers.merge_waymore_into_by_base_url(
        ["http://example.com/api/users", "http://example.com/api/posts"],
        by_base_url,
    )
    endpoints = updated["http://example.com"]["endpoints"]
    assert endpoints["/api/users"]["sources"] == ["katana", "gau"]
    assert endpoints["/api/posts"]["sources"] == ["waymore"]
    assert stats["waymore_new"] == 1
    assert stats["waymore_overlap"] == 1
