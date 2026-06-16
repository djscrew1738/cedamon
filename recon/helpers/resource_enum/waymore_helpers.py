"""
RedAmon - waymore Helpers
=========================
Passive URL discovery from web archives using xnl-h4ck3r's waymore.
waymore queries Wayback Machine, Common Crawl, AlienVault OTX, URLScan,
VirusTotal, GhostArchive, and Intelligence X — broader coverage than GAU.
"""

import os
import platform
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Set

from recon.helpers.resource_enum.gau_helpers import (
    filter_gau_url,
    merge_gau_into_by_base_url,
)


def _is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def _create_temp_dir(prefix: str = "waymore") -> Path:
    """Create a temp directory under REDAMON_TEMP_DIR or /tmp/redamon."""
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
        print(f"[!] _cleanup_temp_dir: if temp_dir.exists()")
        pass


def _waymore_image_built(docker_image: str) -> bool:
    """Check if the waymore Docker image already exists locally."""
    try:
        result = subprocess.run(
            ["docker", "images", "-q", docker_image],
            capture_output=True, text=True, timeout=30
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def ensure_waymore_docker_image(docker_image: str, timeout: int = 600) -> bool:
    """
    Ensure the waymore Docker image is available, building from GitHub if needed.

    waymore does not publish a pre-built image, so we build it directly from
    the official GitHub repository when it is missing.
    """
    if _waymore_image_built(docker_image):
        print(f"[✓][waymore] Docker image already available: {docker_image}")
        return True

    print(f"[*][waymore] Building Docker image from GitHub (this may take a few minutes)...")
    try:
        build_cmd = ["docker", "build", "-t", docker_image]
        if _is_arm64_host():
            build_cmd.extend(["--platform", "linux/amd64"])
        build_cmd.append("https://github.com/xnl-h4ck3r/waymore.git#main")

        result = subprocess.run(
            build_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            print(f"[✓][waymore] Docker image built successfully")
            return True
        err = result.stderr.strip().splitlines()[-1] if result.stderr else "unknown error"
        print(f"[!][waymore] Docker build failed: {err[:300]}")
        return False
    except subprocess.TimeoutExpired:
        print(f"[!][waymore] Docker build timed out after {timeout}s")
        return False
    except Exception as e:
        print(f"[!][waymore] Could not build Docker image: {e}")
        return False


def _run_waymore_for_domain(
    domain: str,
    docker_image: str,
    timeout: int,
    use_proxy: bool,
    from_date: Optional[str],
    to_date: Optional[str],
    providers: Optional[List[str]],
) -> List[str]:
    """Run waymore in URL-only mode for a single domain and return discovered URLs."""
    temp_dir = _create_temp_dir("waymore")
    output_file = temp_dir / "waymore.txt"

    try:
        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{temp_dir}:/app/results",
        ]
        if _is_arm64_host():
            cmd.extend(["--platform", "linux/amd64"])

        if use_proxy:
            cmd.extend([
                "-e", "HTTP_PROXY=socks5://127.0.0.1:9050",
                "-e", "HTTPS_PROXY=socks5://127.0.0.1:9050",
            ])

        cmd.extend([
            docker_image,
            "-i", domain,
            "-mode", "U",
            "-oU", "/app/results/waymore.txt",
            "-silent",
        ])

        if from_date:
            cmd.extend(["-from", from_date])
        if to_date:
            cmd.extend(["-to", to_date])

        # waymore excludes providers with -xwm, -xcc, -xav, -xus, -xvt, -xga, -xix
        provider_map = {
            "wayback": "-xwm",
            "commoncrawl": "-xcc",
            "alienvault": "-xav",
            "otx": "-xav",
            "urlscan": "-xus",
            "virustotal": "-xvt",
            "ghostarchive": "-xga",
            "intelligencex": "-xix",
        }
        if providers:
            selected = {p.lower() for p in providers}
            for name, flag in provider_map.items():
                if name not in selected:
                    cmd.append(flag)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-300:] if result.stderr else "unknown error"
            print(f"[!][waymore] Failed for {domain}: {err}")
            return []

        if not output_file.exists():
            return []

        urls = []
        for line in output_file.read_text().splitlines():
            url = line.strip()
            if url:
                urls.append(url)
        return urls

    except subprocess.TimeoutExpired:
        print(f"[!][waymore] Timed out for {domain} after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][waymore] Error for {domain}: {e}")
        return []
    finally:
        _cleanup_temp_dir(temp_dir)


def run_waymore_discovery(
    target_domains: List[str],
    docker_image: str,
    timeout: int = 300,
    use_proxy: bool = False,
    workers: int = 3,
    blacklist_extensions: Optional[List[str]] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    providers: Optional[List[str]] = None,
) -> List[str]:
    """
    Run waymore in URL-only mode across multiple target domains in parallel.

    Returns a deduplicated list of discovered URLs filtered by extension blacklist.
    """
    if not target_domains:
        return []

    if not shutil.which("docker"):
        print("[!][waymore] Docker not available — skipping")
        return []

    if not ensure_waymore_docker_image(docker_image):
        print("[!][waymore] Could not get Docker image — skipping")
        return []

    blacklist_extensions = blacklist_extensions or []

    print(f"[*][waymore] Running URL discovery for {len(target_domains)} domain(s) (workers={workers})...")
    discovered: Set[str] = set()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="waymore") as executor:
        futures = {
            executor.submit(
                _run_waymore_for_domain,
                domain,
                docker_image,
                timeout,
                use_proxy,
                from_date,
                to_date,
                providers,
            ): domain
            for domain in target_domains
        }
        for future in as_completed(futures):
            domain = futures[future]
            try:
                urls = future.result()
                print(f"[+]   {domain}: {len(urls)} raw URLs")
                for url in urls:
                    if filter_gau_url(url, blacklist_extensions):
                        discovered.add(url)
            except Exception as e:
                print(f"[!][waymore] {domain} failed: {e}")

    print(f"[✓][waymore] Total unique URLs after filtering: {len(discovered)}")
    return sorted(discovered)


def merge_waymore_into_by_base_url(
    waymore_urls: List[str],
    by_base_url: dict,
) -> tuple[dict, dict]:
    """
    Merge waymore URLs into the resource_enum by_base_url structure.

    waymore and GAU produce the same type of output (raw archive URLs), so we
    reuse the GAU merge logic but track waymore-specific stats.
    """
    # Capture which paths already existed per base_url before merging, so we can
    # label only newly introduced endpoints as 'waymore'.
    original_paths: dict[str, set[str]] = {
        base_url: set(base_data.get("endpoints", {}).keys())
        for base_url, base_data in by_base_url.items()
    }

    updated, stats = merge_gau_into_by_base_url(waymore_urls, by_base_url)

    # Rewrite source labels from 'gau' to 'waymore' for newly introduced endpoints.
    for base_url, base_data in updated.items():
        for path, endpoint in base_data.get("endpoints", {}).items():
            sources = endpoint.get("sources", [])
            if sources == ["gau"] and path not in original_paths.get(base_url, set()):
                endpoint["sources"] = ["waymore"]

    waymore_stats = {
        "waymore_total": stats.get("gau_total", 0),
        "waymore_parsed": stats.get("gau_parsed", 0),
        "waymore_new": stats.get("gau_new", 0),
        "waymore_overlap": stats.get("gau_overlap", 0),
        "waymore_skipped_unverified": stats.get("gau_skipped_unverified", 0),
        "waymore_skipped_dead": stats.get("gau_skipped_dead", 0),
    }
    return updated, waymore_stats
