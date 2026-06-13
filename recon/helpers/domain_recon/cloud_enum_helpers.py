"""
RedAmon - cloud_enum Helpers
============================
Public cloud asset brute-forcing (AWS S3, GCP buckets, Azure Blob,
DigitalOcean Spaces, etc.) using initstring/cloud_enum.

This is a credential-free complement to Cloudlist: it guesses public cloud
resources based on target keywords, whereas Cloudlist enumerates assets using
configured provider credentials.
"""

import re
import subprocess
from pathlib import Path
from typing import List

from recon.helpers.domain_recon._tool_docker_utils import (
    create_temp_dir,
    cleanup_temp_dir,
    docker_available,
    is_arm64_host,
    build_docker_image,
    pull_docker_image,
)
from recon.helpers.subprocess_helpers import run_with_heartbeat


DOCKERFILE_DIR = Path(__file__).parent / "cloud_enum_docker"
CLOUD_ENUM_IMAGE = "redamon-cloud_enum:latest"


def ensure_cloud_enum_docker_image() -> bool:
    """Ensure the cloud_enum Docker image is available."""
    print(f"[*][cloud_enum] Checking Docker image: {CLOUD_ENUM_IMAGE}")
    result = subprocess.run(
        ["docker", "images", "-q", CLOUD_ENUM_IMAGE],
        capture_output=True, text=True, timeout=30
    )
    if result.stdout.strip():
        print(f"[✓][cloud_enum] Image already available")
        return True

    if not DOCKERFILE_DIR.exists():
        print(f"[!][cloud_enum] Dockerfile directory missing: {DOCKERFILE_DIR}")
        return False

    print(f"[*][cloud_enum] Building image from {DOCKERFILE_DIR}...")
    result = run_with_heartbeat(
        ["docker", "build", "-t", CLOUD_ENUM_IMAGE, str(DOCKERFILE_DIR)],
        label="cloud_enum build", timeout=600
    )
    if result.returncode == 0:
        print(f"[✓][cloud_enum] Image built successfully")
        return True
    err = result.stderr.strip()[-300:] if result.stderr else "unknown error"
    print(f"[!][cloud_enum] Build failed: {err}")
    return False


def _parse_cloud_enum_output(stdout: str) -> List[dict]:
    """Parse cloud_enum stdout lines into normalized asset records."""
    assets = []
    # Example lines:
    # [+] AWS S3 bucket found: https://s3.amazonaws.com/example-bucket
    # [+] Google bucket found: https://storage.googleapis.com/example-bucket
    # [+] Azure blob found: https://example.blob.core.windows.net/
    pattern = re.compile(
        r"\[\+\]\s+(AWS S3 bucket|Google bucket|Azure blob|Azure VM|AWS App|Google App)\s+found:\s+(.*)",
        re.IGNORECASE,
    )
    for line in stdout.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        asset_type = match.group(1).lower()
        asset_url = match.group(2).strip()
        provider = "unknown"
        if "aws" in asset_type or "s3" in asset_type:
            provider = "aws"
        elif "google" in asset_type or "gcp" in asset_type:
            provider = "gcp"
        elif "azure" in asset_type:
            provider = "azure"
        assets.append({
            "type": asset_type,
            "provider": provider,
            "url": asset_url,
            "source": "cloud_enum",
        })
    return assets


def run_cloud_enum_discovery(
    keywords: List[str],
    docker_image: str,
    timeout: int = 600,
) -> List[dict]:
    """
    Run cloud_enum against a list of target keywords.

    Parameters
    ----------
    keywords : list
        Company names / keywords to search for (e.g., ['example', 'examplecorp']).
    docker_image : str
        Docker image to use (default: redamon-cloud_enum:latest).
    timeout : int
        Docker run timeout in seconds.

    Returns
    -------
    list
        Discovered public cloud assets.
    """
    if not docker_available():
        print("[!][cloud_enum] Docker not available — skipping")
        return []

    if not keywords:
        print("[!][cloud_enum] No keywords provided — skipping")
        return []

    if docker_image == CLOUD_ENUM_IMAGE:
        if not ensure_cloud_enum_docker_image():
            print("[!][cloud_enum] Could not build image — skipping")
            return []
    else:
        if not pull_docker_image(docker_image):
            print(f"[!][cloud_enum] Could not get Docker image {docker_image}")
            return []

    cmd = [
        "docker", "run", "--rm",
        "--net=host",
    ]
    if is_arm64_host():
        cmd.extend(["--platform", "linux/amd64"])

    cmd.extend([docker_image, "-k", " ".join(keywords)])

    print(f"[*][cloud_enum] Brute-forcing public cloud assets for keywords: {keywords}")
    try:
        result = run_with_heartbeat(
            cmd, label="cloud_enum", timeout=timeout
        )

        if result.returncode != 0 and not result.stdout.strip():
            err = result.stderr.strip()[-300:] if result.stderr else "unknown error"
            print(f"[!][cloud_enum] Failed: {err}")
            return []

        assets = _parse_cloud_enum_output(result.stdout)
        print(f"[✓][cloud_enum] Found {len(assets)} public cloud asset(s)")
        return assets

    except subprocess.TimeoutExpired:
        print(f"[!][cloud_enum] Timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][cloud_enum] Error: {e}")
        return []


def discover_cloud_enum_assets(domain: str, settings: dict) -> List[dict]:
    """
    High-level wrapper for cloud_enum public cloud asset discovery.

    Derives search keywords from the target domain and optional
    CLOUD_ENUM_KEYWORDS setting.
    """
    if not settings.get("CLOUD_ENUM_ENABLED", False):
        print("[-][cloud_enum] Disabled — skipping")
        return []

    docker_image = settings.get("CLOUD_ENUM_DOCKER_IMAGE", CLOUD_ENUM_IMAGE)
    timeout = settings.get("CLOUD_ENUM_TIMEOUT", 600)

    keywords = list(settings.get("CLOUD_ENUM_KEYWORDS", []))
    if not keywords:
        # Derive a keyword from the root domain (e.g., example.com -> example)
        keyword = domain.split(".")[0]
        if keyword:
            keywords = [keyword]

    if not keywords:
        print("[-][cloud_enum] No keywords to search — skipping")
        return []

    print("\n" + "=" * 50)
    print(f"[*][cloud_enum] PUBLIC CLOUD ASSET BRUTE-FORCE for {domain}")
    print("=" * 50)

    return run_cloud_enum_discovery(keywords, docker_image, timeout)
