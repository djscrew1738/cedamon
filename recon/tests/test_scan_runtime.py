"""
Tests for recon.helpers.scan_runtime
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from recon.helpers import scan_runtime


def test_check_disk_space_passes_when_enough_free():
    with patch("recon.helpers.scan_runtime.shutil.disk_usage") as mock_disk:
        mock_disk.return_value = MagicMock(free=10 * (1024 ** 3), total=100 * (1024 ** 3), used=90 * (1024 ** 3))
        assert scan_runtime.check_disk_space(min_gb=5.0, path="/") is True


def test_check_disk_space_fails_when_too_low():
    with patch("recon.helpers.scan_runtime.shutil.disk_usage") as mock_disk:
        mock_disk.return_value = MagicMock(free=1 * (1024 ** 3), total=100 * (1024 ** 3), used=99 * (1024 ** 3))
        assert scan_runtime.check_disk_space(min_gb=5.0, path="/") is False


def test_is_tool_container_matches_projectdiscovery_images():
    assert scan_runtime._is_tool_container("projectdiscovery/naabu:latest") is True
    assert scan_runtime._is_tool_container("projectdiscovery/httpx:latest") is True
    assert scan_runtime._is_tool_container("redis:latest") is False


def test_is_protected_name_protects_infrastructure():
    assert scan_runtime._is_protected_name("redamon-recon-orchestrator") is True
    assert scan_runtime._is_protected_name("redamon-neo4j") is True
    assert scan_runtime._is_protected_name("redamon-recon-cmqabc123") is True
    assert scan_runtime._is_protected_name("nifty_babbage") is False


def test_cleanup_orphan_containers_skips_protected_and_current():
    ps_output = (
        "abc123|projectdiscovery/httpx:latest|nifty_babbage|running\n"
        "def456|redamon-recon:latest|redamon-recon-cmqabc123|exited\n"
        "ghi789|redamon-postgres:16-alpine|redamon-postgres|running\n"
        "jkl012|projectdiscovery/naabu:latest|elegant_ardinghelli|running\n"
    )
    with patch("recon.helpers.scan_runtime._docker") as mock_docker:
        mock_docker.return_value = MagicMock(returncode=0, stdout=ps_output, stderr="")
        removed = scan_runtime.cleanup_orphan_containers(project_id="cmqabc123", dry_run=True)
        # Should remove the two running tool containers and the exited redamon-recon for the project.
        assert removed == 3


def test_cleanup_orphan_containers_respects_project_id_for_running_tools():
    ps_output = (
        "abc123|projectdiscovery/httpx:latest|httpx-project-a|running\n"
        "def456|projectdiscovery/httpx:latest|httpx-project-b|running\n"
    )
    with patch("recon.helpers.scan_runtime._docker") as mock_docker:
        mock_docker.return_value = MagicMock(returncode=0, stdout=ps_output, stderr="")
        # Tool containers are always removed regardless of project_id.
        removed = scan_runtime.cleanup_orphan_containers(project_id="project-a", dry_run=True)
        assert removed == 2
