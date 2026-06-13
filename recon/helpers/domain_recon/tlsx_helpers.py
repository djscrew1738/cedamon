"""
RedAmon - TLSx Helpers
======================
ProjectDiscovery TLSx scans TLS certificates to discover SAN subdomains,
JARM fingerprints, and certificate metadata.
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


def run_tlsx_discovery(
    hosts: List[str],
    docker_image: str,
    ports: List[str],
    timeout: int = 300,
) -> dict:
    """
    Run TLSx against a list of hosts and parse certificate intelligence.

    Parameters
    ----------
    hosts : list
        Hosts to scan (domain:port or IP:port; default port is 443).
    docker_image : str
        TLSx Docker image.
    ports : list
        Ports to scan (e.g., ['443','8443']).
    timeout : int
        Docker run timeout.

    Returns
    -------
    dict
        {subdomains: set, jarm: set, certs: list}
    """
    if not docker_available():
        print("[!][TLSx] Docker not available — skipping")
        return {}

    if not hosts:
        print("[!][TLSx] No hosts provided — skipping")
        return {}

    if not pull_docker_image(docker_image):
        print(f"[!][TLSx] Could not get Docker image {docker_image}")
        return {}

    temp_dir = create_temp_dir("tlsx")
    hosts_file = temp_dir / "hosts.txt"
    output_file = temp_dir / "tlsx.json"
    write_lines_file(hosts_file, hosts)

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
            "-l", "/input/hosts.txt",
            "-json", "-silent",
            "-san", "-cn", "-org", "-jarm",
            "-o", "/output/tlsx.json",
        ])

        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])

        print(f"[*][TLSx] Scanning {len(hosts)} host(s)...")
        result = run_with_heartbeat(
            cmd, label="TLSx", timeout=timeout
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
            print(f"[!][TLSx] Failed: {err}")
            return {}

        if not output_file.exists():
            print("[*][TLSx] No output produced")
            return {}

        return _parse_tlsx_output(output_file)

    except Exception as e:
        print(f"[!][TLSx] Error: {e}")
        return {}
    finally:
        cleanup_temp_dir(temp_dir)


def _parse_tlsx_output(output_file: Path) -> dict:
    """Parse TLSx NDJSON output."""
    subdomains: Set[str] = set()
    jarm_hashes: Set[str] = set()
    certs = []

    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Subject alternative names
            for san in entry.get("subject_an_names", []) or []:
                san = san.strip().lower()
                if san:
                    subdomains.add(san)

            # Common name
            cn = entry.get("subject_common_name", "")
            if cn:
                subdomains.add(cn.strip().lower())

            # JARM
            jarm = entry.get("jarm_hash", "")
            if jarm:
                jarm_hashes.add(jarm)

            certs.append({
                "host": entry.get("host", ""),
                "port": entry.get("port", ""),
                "subject_cn": cn,
                "subject_org": entry.get("subject_org", ""),
                "issuer": entry.get("issuer_common_name", ""),
                "jarm_hash": jarm,
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
                "source": "tlsx",
            })

    print(f"[✓][TLSx] Extracted {len(subdomains)} SAN/CN subdomain(s), {len(jarm_hashes)} JARM hash(es)")
    return {
        "subdomains": sorted(subdomains),
        "jarm_hashes": sorted(jarm_hashes),
        "certs": certs,
    }


def discover_tlsx_assets(domain: str, hosts: List[str], settings: dict) -> dict:
    """
    High-level wrapper to run TLSx against discovered hosts.

    Parameters
    ----------
    domain : str
        Target domain (for logging).
    hosts : list
        List of host:port strings (e.g., ['sub.example.com:443']).
    settings : dict
        Project settings.

    Returns
    -------
    dict
        TLSx discovery results.
    """
    if not settings.get("TLSX_ENABLED", False):
        print("[-][TLSx] Disabled — skipping")
        return {}

    if not hosts:
        print("[-][TLSx] No hosts to scan — skipping")
        return {}

    docker_image = settings.get("TLSX_DOCKER_IMAGE", "projectdiscovery/tlsx:latest")
    ports = list(settings.get("TLSX_PORTS", ["443", "8443"]))
    timeout = settings.get("TLSX_TIMEOUT", 300)

    print("\n" + "=" * 50)
    print(f"[*][TLSx] TLS CERTIFICATE INTELLIGENCE for {domain}")
    print("=" * 50)

    return run_tlsx_discovery(hosts, docker_image, ports, timeout)
