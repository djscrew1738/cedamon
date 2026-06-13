"""
Tests for recon.helpers.domain_recon.alterx_helpers
"""
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from recon.helpers.domain_recon import alterx_helpers


def test_resolve_alterx_candidates_returns_only_resolved():
    """Only candidates with A/AAAA records are returned."""
    with patch.object(alterx_helpers.dns.resolver, "Resolver") as MockResolver:
        resolver_instance = MagicMock()

        def side_effect(qname, rdtype):
            if qname == "dev.example.com":
                return MagicMock()
            raise Exception("NXDOMAIN")

        resolver_instance.resolve.side_effect = side_effect
        MockResolver.return_value = resolver_instance

        result = alterx_helpers.resolve_alterx_candidates(
            ["dev.example.com", "fake.example.com"],
            max_workers=2,
            dns_timeout=1.0,
        )
        assert result == ["dev.example.com"]


def test_run_alterx_discovery_filters_to_target_domain(tmp_path, monkeypatch):
    """Only permutations under the target domain are kept."""
    monkeypatch.setenv("REDAMON_TEMP_DIR", str(tmp_path))
    with patch.object(alterx_helpers, "pull_alterx_docker_image", return_value=True), \
         patch.object(alterx_helpers, "_cleanup_temp_dir"), \
         patch("subprocess.run") as mock_run:

        # Simulate docker creating an output file
        def fake_run(cmd, **kwargs):
            # Find host temp dir from the -v mount and output path from -o flag
            vol_idx = cmd.index("-v")
            host_temp = Path(cmd[vol_idx + 1].split(":", 1)[0])
            out_idx = cmd.index("-o")
            out_name = Path(cmd[out_idx + 1]).name
            out_path = host_temp / out_name
            out_path.write_text(
                "dev.example.com\n"
                "api.example.com\n"
                "other-site.com\n"
            )
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        result = alterx_helpers.run_alterx_discovery(
            domain="example.com",
            known_subdomains=["www.example.com"],
            docker_image="projectdiscovery/alterx:latest",
        )
        assert sorted(result) == ["api.example.com", "dev.example.com"]


def test_run_alterx_discovery_skips_when_no_subdomains():
    result = alterx_helpers.run_alterx_discovery(
        domain="example.com",
        known_subdomains=[],
        docker_image="projectdiscovery/alterx:latest",
    )
    assert result == []


def test_run_alterx_discovery_skips_when_docker_missing():
    with patch.object(alterx_helpers.shutil, "which", return_value=None):
        result = alterx_helpers.run_alterx_discovery(
            domain="example.com",
            known_subdomains=["www.example.com"],
            docker_image="projectdiscovery/alterx:latest",
        )
        assert result == []


def test_discover_alterx_subdomains_disabled():
    result = alterx_helpers.discover_alterx_subdomains(
        domain="example.com",
        known_subdomains=["www.example.com"],
        settings={"ALTERX_ENABLED": False},
    )
    assert result == []


def test_discover_alterx_subdomains_returns_new_valid():
    settings = {
        "ALTERX_ENABLED": True,
        "ALTERX_DOCKER_IMAGE": "projectdiscovery/alterx:latest",
        "ALTERX_ENRICH": True,
        "ALTERX_LIMIT": 100,
        "ALTERX_PATTERNS": [],
        "ALTERX_CUSTOM_WORDLIST": "",
        "ALTERX_TIMEOUT": 300,
        "ALTERX_DNS_WORKERS": 2,
        "ALTERX_DNS_TIMEOUT": 1.0,
    }
    with patch.object(alterx_helpers, "run_alterx_discovery", return_value=["dev.example.com", "fake.example.com"]), \
         patch.object(alterx_helpers, "resolve_alterx_candidates", return_value=["dev.example.com"]):
        result = alterx_helpers.discover_alterx_subdomains(
            domain="example.com",
            known_subdomains=["www.example.com"],
            settings=settings,
        )
        assert result == ["dev.example.com"]
