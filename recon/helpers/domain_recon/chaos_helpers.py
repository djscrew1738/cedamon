"""
RedAmon - Chaos Helpers
=======================
ProjectDiscovery Chaos subdomain discovery via the Chaos dataset API.
Requires a Chaos API key.
"""

import json
from pathlib import Path
from typing import Set

from recon.helpers.domain_recon._tool_docker_utils import (
    create_temp_dir,
    cleanup_temp_dir,
    docker_available,
    is_arm64_host,
    pull_docker_image,
)
from recon.helpers.subprocess_helpers import run_with_heartbeat


def run_chaos_discovery(
    domain: str,
    docker_image: str,
    api_key: str,
    timeout: int = 300,
) -> Set[str]:
    """
    Run ProjectDiscovery Chaos against a single domain.

    Returns a set of discovered subdomains.
    """
    if not docker_available():
        print("[!][Chaos] Docker not available — skipping")
        return set()

    if not api_key:
        print("[!][Chaos] No API key configured — skipping")
        return set()

    if not pull_docker_image(docker_image):
        print(f"[!][Chaos] Could not get Docker image {docker_image}")
        return set()

    temp_dir = create_temp_dir("chaos")
    output_file = temp_dir / "chaos.json"

    try:
        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{temp_dir}:/output",
            "-e", f"CHAOS_KEY={api_key}",
        ]
        if is_arm64_host():
            cmd.extend(["--platform", "linux/amd64"])

        cmd.extend([
            docker_image,
            "-d", domain,
            "-key", api_key,
            "-json", "-silent",
            "-o", "/output/chaos.json",
        ])

        print(f"[*][Chaos] Querying Chaos dataset for {domain}...")
        result = run_with_heartbeat(
            cmd, label="Chaos", timeout=timeout
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
            print(f"[!][Chaos] Failed: {err}")
            return set()

        if not output_file.exists():
            print("[*][Chaos] No output produced")
            return set()

        subdomains = _parse_chaos_output(output_file)
        print(f"[✓][Chaos] Found {len(subdomains)} subdomain(s)")
        return subdomains

    except Exception as e:
        print(f"[!][Chaos] Error: {e}")
        return set()
    finally:
        cleanup_temp_dir(temp_dir)


def _parse_chaos_output(output_file: Path) -> Set[str]:
    """Parse Chaos NDJSON output and return a set of subdomains."""
    subdomains: Set[str] = set()
    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("domain", "").strip().lower()
                if host:
                    subdomains.add(host)
            except json.JSONDecodeError:
                continue
    return subdomains


def discover_chaos_subdomains(domain: str, settings: dict) -> Set[str]:
    """High-level wrapper for Chaos subdomain discovery."""
    if not settings.get("CHAOS_ENABLED", False):
        print("[-][Chaos] Disabled — skipping")
        return set()

    api_key = settings.get("CHAOS_API_KEY", "")
    if not api_key:
        print("[-][Chaos] No CHAOS_API_KEY configured — skipping")
        return set()

    docker_image = settings.get("CHAOS_DOCKER_IMAGE", "projectdiscovery/chaos-client:latest")
    timeout = settings.get("CHAOS_TIMEOUT", 300)

    print("\n" + "=" * 50)
    print("[*][Chaos] CHAOS DATASET SUBDOMAIN DISCOVERY")
    print("=" * 50)

    return run_chaos_discovery(domain, docker_image, api_key, timeout)
