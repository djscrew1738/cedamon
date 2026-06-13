"""
RedAmon - ASNmap Helpers
========================
ProjectDiscovery ASNmap maps IPs/ASNs to CIDR ranges and AS information.
Runs against resolved IPs after DNS resolution to expand IP-mode scope.
"""

import json
from pathlib import Path
from typing import List, Set

from recon.helpers.domain_recon._tool_docker_utils import (
    create_temp_dir,
    cleanup_temp_dir,
    docker_available,
    is_arm64_host,
    pull_docker_image,
    write_lines_file,
)
from recon.helpers.subprocess_helpers import run_with_heartbeat


def run_asnmap_discovery(
    targets: List[str],
    docker_image: str,
    timeout: int = 300,
) -> List[dict]:
    """
    Run ASNmap against a list of IPs/domains and return ASN/CIDR records.

    Parameters
    ----------
    targets : list
        IPs, ASNs, or domains to map.
    docker_image : str
        ASNmap Docker image.
    timeout : int
        Docker run timeout.

    Returns
    -------
    list
        ASNmap records with asn, ip, cidr, org, etc.
    """
    if not docker_available():
        print("[!][ASNmap] Docker not available — skipping")
        return []

    if not targets:
        print("[!][ASNmap] No targets provided — skipping")
        return []

    if not pull_docker_image(docker_image):
        print(f"[!][ASNmap] Could not get Docker image {docker_image}")
        return []

    temp_dir = create_temp_dir("asnmap")
    targets_file = temp_dir / "targets.txt"
    output_file = temp_dir / "asnmap.json"
    write_lines_file(targets_file, targets)

    try:
        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{temp_dir}:/input:ro",
            "-v", f"{temp_dir}:/output",
        ]
        if is_arm64_host():
            cmd.extend(["--platform", "linux/amd64"])

        cmd.extend([
            docker_image,
            "-l", "/input/targets.txt",
            "-json", "-silent",
            "-o", "/output/asnmap.json",
        ])

        print(f"[*][ASNmap] Mapping {len(targets)} target(s)...")
        result = run_with_heartbeat(
            cmd, label="ASNmap", timeout=timeout
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
            print(f"[!][ASNmap] Failed: {err}")
            return []

        if not output_file.exists():
            print("[*][ASNmap] No output produced")
            return []

        records = []
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        print(f"[✓][ASNmap] Found {len(records)} ASN record(s)")
        return records

    except Exception as e:
        print(f"[!][ASNmap] Error: {e}")
        return []
    finally:
        cleanup_temp_dir(temp_dir)


def discover_asnmap_assets(domain: str, resolved_ips: List[str], settings: dict) -> List[dict]:
    """
    High-level wrapper to run ASNmap against resolved IPs of a domain.

    Parameters
    ----------
    domain : str
        Target domain (used for logging only).
    resolved_ips : list
        List of IPv4/IPv6 addresses discovered during DNS resolution.
    settings : dict
        Project settings.

    Returns
    -------
    list
        ASN/CIDR records.
    """
    if not settings.get("ASNMAP_ENABLED", False):
        print("[-][ASNmap] Disabled — skipping")
        return []

    if not resolved_ips:
        print("[-][ASNmap] No resolved IPs — skipping")
        return []

    docker_image = settings.get("ASNMAP_DOCKER_IMAGE", "projectdiscovery/asnmap:latest")
    timeout = settings.get("ASNMAP_TIMEOUT", 300)

    print("\n" + "=" * 50)
    print(f"[*][ASNmap] ASN/CIDR MAPPING for {domain}")
    print("=" * 50)

    return run_asnmap_discovery(resolved_ips, docker_image, timeout)
