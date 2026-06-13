"""
RedAmon - Alterx Helpers
========================
Subdomain permutation generation using ProjectDiscovery's alterx.
Takes already-discovered subdomains and generates pattern-based permutations,
then resolves them to find additional valid hosts.
"""

import os
import platform
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

import dns.resolver


def _is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def _create_temp_dir(prefix: str = "alterx") -> Path:
    """Create a temp directory under /tmp/redamon for Docker-in-Docker compatibility."""
    base = Path(os.environ.get("REDAMON_TEMP_DIR", "/tmp/redamon"))
    temp_dir = base / f".{prefix}_{uuid.uuid4().hex[:8]}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def _cleanup_temp_dir(temp_dir: Path):
    """Clean up a temp directory."""
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    except Exception:
        pass


def pull_alterx_docker_image(docker_image: str) -> bool:
    """Pull the Alterx Docker image if not present."""
    print(f"[*][Alterx] Checking Docker image: {docker_image}")
    try:
        result = subprocess.run(
            ["docker", "images", "-q", docker_image],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            print(f"[✓][Alterx] Image already available")
            return True

        print(f"[*][Alterx] Pulling image...")
        pull_cmd = ["docker", "pull"]
        if _is_arm64_host():
            pull_cmd.extend(["--platform", "linux/amd64"])
        pull_cmd.append(docker_image)

        result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"[✓][Alterx] Image pulled successfully")
            return True
        print(f"[!][Alterx] Failed to pull image: {result.stderr[:200]}")
        return False
    except Exception as e:
        print(f"[!][Alterx] Error pulling image: {e}")
        return False


def _has_dns_record(subdomain: str, resolver: dns.resolver.Resolver, timeout: float = 5.0) -> bool:
    """Lightweight A/AAAA check for a single subdomain."""
    try:
        resolver.lifetime = timeout
        resolver.resolve(subdomain, "A")
        return True
    except Exception:
        try:
            resolver.resolve(subdomain, "AAAA")
            return True
        except Exception:
            return False


def resolve_alterx_candidates(
    candidates: List[str],
    max_workers: int = 50,
    dns_timeout: float = 5.0,
) -> List[str]:
    """
    Resolve a list of alterx-generated subdomains and return those with DNS records.

    Uses a thread pool for parallel A/AAAA queries against the system resolver.
    """
    if not candidates:
        return []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = dns_timeout

    valid = []
    print(f"[*][Alterx] Resolving {len(candidates)} permutation candidates...")
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="alterx-dns") as executor:
        future_to_sub = {
            executor.submit(_has_dns_record, sub, resolver, dns_timeout): sub
            for sub in candidates
        }
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                if future.result():
                    valid.append(sub)
            except Exception:
                pass

    print(f"[✓][Alterx] {len(valid)} permutations resolved to valid hosts")
    return sorted(set(valid))


def run_alterx_discovery(
    domain: str,
    known_subdomains: List[str],
    docker_image: str,
    enrich: bool = True,
    limit: int = 10000,
    patterns: Optional[List[str]] = None,
    custom_wordlist: str = "",
    timeout: int = 300,
) -> List[str]:
    """
    Run alterx to generate subdomain permutations from known subdomains.

    Parameters
    ----------
    domain : str
        Root domain being scanned.
    known_subdomains : list
        Subdomains already discovered by passive/active sources.
    docker_image : str
        Docker image for alterx.
    enrich : bool
        Pass -enrich to alterx so it extracts words from input subdomains.
    limit : int
        Maximum number of permutations to generate (0 = unlimited).
    patterns : list | None
        Optional custom DSL patterns. When empty, alterx uses its default config.
    custom_wordlist : str
        Optional path to a wordlist to use as {{word}} payload.
    timeout : int
        Docker run timeout in seconds.

    Returns
    -------
    list
        Permuted subdomains that belong to the target domain.
    """
    if not known_subdomains:
        print("[*][Alterx] No known subdomains — skipping permutation generation")
        return []

    if not shutil.which("docker"):
        print("[!][Alterx] Docker not available — skipping")
        return []

    if not pull_alterx_docker_image(docker_image):
        print("[!][Alterx] Could not get Docker image — skipping")
        return []

    temp_dir = _create_temp_dir("alterx")
    try:
        input_file = temp_dir / "input.txt"
        output_file = temp_dir / "output.txt"

        # Deduplicate and write known subdomains. Exclude the root domain itself
        # because alterx expects subdomains, not the apex.
        unique_known = sorted({s.lower() for s in known_subdomains if s and s != domain})
        if not unique_known:
            print("[*][Alterx] No valid subdomains to permute")
            return []
        input_file.write_text("\n".join(unique_known) + "\n")

        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{temp_dir}:/data",
        ]
        if _is_arm64_host():
            cmd.extend(["--platform", "linux/amd64"])

        cmd.append(docker_image)
        cmd.extend([
            "-l", "/data/input.txt",
            "-o", "/data/output.txt",
            "-silent",
        ])

        if enrich:
            cmd.append("-enrich")
        if limit > 0:
            cmd.extend(["-limit", str(limit)])
        if patterns:
            for pattern in patterns:
                cmd.extend(["-p", pattern])
        if custom_wordlist:
            # Mount the custom wordlist next to input and reference it
            cmd.extend(["-pp", f"word={custom_wordlist}"])

        print(f"[*][Alterx] Generating permutations from {len(unique_known)} subdomains...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
            print(f"[!][Alterx] Failed: {err}")
            return []

        if not output_file.exists():
            print("[*][Alterx] No output file produced")
            return []

        candidates = []
        for line in output_file.read_text().splitlines():
            sub = line.strip().lower()
            if not sub:
                continue
            if sub == domain or sub.endswith("." + domain):
                candidates.append(sub)

        unique_candidates = sorted(set(candidates))
        print(f"[*][Alterx] Generated {len(unique_candidates)} target-domain permutations")
        return unique_candidates

    except subprocess.TimeoutExpired:
        print(f"[!][Alterx] Timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][Alterx] Error: {e}")
        return []
    finally:
        _cleanup_temp_dir(temp_dir)


def discover_alterx_subdomains(
    domain: str,
    known_subdomains: List[str],
    settings: dict,
) -> List[str]:
    """
    High-level wrapper: generate alterx permutations and resolve them.

    Returns only subdomains that resolve to valid DNS records and are not
    already in ``known_subdomains``.
    """
    ALTERX_ENABLED = settings.get("ALTERX_ENABLED", True)
    if not ALTERX_ENABLED:
        print("[-][Alterx] Disabled — skipping")
        return []

    ALTERX_DOCKER_IMAGE = settings.get("ALTERX_DOCKER_IMAGE", "projectdiscovery/alterx:latest")
    ALTERX_ENRICH = settings.get("ALTERX_ENRICH", True)
    ALTERX_LIMIT = settings.get("ALTERX_LIMIT", 10000)
    ALTERX_PATTERNS = settings.get("ALTERX_PATTERNS", [])
    ALTERX_CUSTOM_WORDLIST = settings.get("ALTERX_CUSTOM_WORDLIST", "")
    ALTERX_TIMEOUT = settings.get("ALTERX_TIMEOUT", 300)
    ALTERX_DNS_WORKERS = settings.get("ALTERX_DNS_WORKERS", 50)
    ALTERX_DNS_TIMEOUT = settings.get("ALTERX_DNS_TIMEOUT", 5.0)

    print("\n" + "=" * 50)
    print("[*][Alterx] SUBDOMAIN PERMUTATION")
    print("=" * 50)

    candidates = run_alterx_discovery(
        domain=domain,
        known_subdomains=known_subdomains,
        docker_image=ALTERX_DOCKER_IMAGE,
        enrich=ALTERX_ENRICH,
        limit=ALTERX_LIMIT,
        patterns=ALTERX_PATTERNS if ALTERX_PATTERNS else None,
        custom_wordlist=ALTERX_CUSTOM_WORDLIST,
        timeout=ALTERX_TIMEOUT,
    )

    if not candidates:
        return []

    # Remove duplicates against known subdomains to avoid redundant DNS queries
    new_candidates = [c for c in candidates if c not in set(known_subdomains)]
    if not new_candidates:
        print("[*][Alterx] No new permutations to resolve")
        return []

    valid = resolve_alterx_candidates(
        new_candidates,
        max_workers=ALTERX_DNS_WORKERS,
        dns_timeout=ALTERX_DNS_TIMEOUT,
    )

    # Filter out any that somehow overlap with known subdomains again
    known_set = set(known_subdomains)
    new_valid = [s for s in valid if s not in known_set]
    if new_valid:
        print(f"[+][Alterx] Discovered {len(new_valid)} new valid subdomains")
    else:
        print("[*][Alterx] No new valid subdomains from permutations")
    return new_valid
