"""
RedAmon - DNSx Helpers
======================
ProjectDiscovery DNSx high-performance DNS toolkit.
Used to enrich DNS records and detect wildcard responses for discovered subdomains.
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


def run_dnsx_enrichment(
    domains: List[str],
    docker_image: str,
    record_types: List[str],
    wildcard_tests: int,
    timeout: int = 300,
) -> List[dict]:
    """
    Run DNSx against a list of domains and return DNS records.

    Parameters
    ----------
    domains : list
        Domains/subdomains to resolve.
    docker_image : str
        DNSx Docker image.
    record_types : list
        DNS record types to query (e.g., ['a','aaaa','cname','mx','ns','txt','soa']).
    wildcard_tests : int
        Number of wildcard tests (0 = disabled).
    timeout : int
        Docker run timeout.

    Returns
    -------
    list
        DNSx JSON records.
    """
    if not docker_available():
        print("[!][DNSx] Docker not available — skipping")
        return []

    if not domains:
        print("[!][DNSx] No domains provided — skipping")
        return []

    if not pull_docker_image(docker_image):
        print(f"[!][DNSx] Could not get Docker image {docker_image}")
        return []

    temp_dir = create_temp_dir("dnsx")
    domains_file = temp_dir / "domains.txt"
    output_file = temp_dir / "dnsx.json"
    write_lines_file(domains_file, domains)

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
            "-l", "/input/domains.txt",
            "-json", "-silent",
            "-o", "/output/dnsx.json",
        ])

        # Record types
        type_map = {
            "a": "-a", "aaaa": "-aaaa", "cname": "-cname",
            "mx": "-mx", "ns": "-ns", "txt": "-txt", "soa": "-soa",
            "ptr": "-ptr",
        }
        for rtype in record_types:
            flag = type_map.get(rtype.lower())
            if flag:
                cmd.append(flag)

        if wildcard_tests > 0:
            cmd.extend(["-wd", str(wildcard_tests)])

        print(f"[*][DNSx] Resolving {len(domains)} domain(s)...")
        result = run_with_heartbeat(
            cmd, label="DNSx", timeout=timeout
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
            print(f"[!][DNSx] Failed: {err}")
            return []

        if not output_file.exists():
            print("[*][DNSx] No output produced")
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

        print(f"[✓][DNSx] Enriched {len(records)} DNS record(s)")
        return records

    except Exception as e:
        print(f"[!][DNSx] Error: {e}")
        return []
    finally:
        cleanup_temp_dir(temp_dir)


def discover_dnsx_records(domains: List[str], settings: dict) -> List[dict]:
    """High-level wrapper to enrich DNS records with DNSx."""
    if not settings.get("DNSX_ENABLED", False):
        print("[-][DNSx] Disabled — skipping")
        return []

    if not domains:
        print("[-][DNSx] No domains to resolve — skipping")
        return []

    docker_image = settings.get("DNSX_DOCKER_IMAGE", "projectdiscovery/dnsx:latest")
    record_types = list(settings.get("DNSX_RECORD_TYPES", ["a", "aaaa", "cname", "mx", "ns", "txt", "soa"]))
    wildcard_tests = settings.get("DNSX_WILDCARD_TESTS", 3)
    timeout = settings.get("DNSX_TIMEOUT", 300)

    print("\n" + "=" * 50)
    print("[*][DNSx] DNS ENRICHMENT")
    print("=" * 50)

    return run_dnsx_enrichment(domains, docker_image, record_types, wildcard_tests, timeout)
