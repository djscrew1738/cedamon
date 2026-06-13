"""
RedAmon - Cloudlist Helpers
===========================
Credential-based cloud asset enumeration using ProjectDiscovery's cloudlist.

NOTE: cloudlist is NOT a passive recon tool. It enumerates assets from cloud
providers (AWS, GCP, Azure, Cloudflare, etc.) using provider credentials
configured in a provider-config file. It is most useful in authorized
penetration tests or internal asset inventory where cloud access is available.
"""

import json
import os
import platform
import shutil
import uuid
from pathlib import Path
from typing import List, Optional

from recon.helpers.subprocess_helpers import run_with_heartbeat


def _is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def _create_temp_dir(prefix: str = "cloudlist") -> Path:
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
        pass


def pull_cloudlist_docker_image(docker_image: str) -> bool:
    """Pull the Cloudlist Docker image if not present."""
    print(f"[*][Cloudlist] Checking Docker image: {docker_image}")
    try:
        result = run_with_heartbeat(
            ["docker", "images", "-q", docker_image],
            label="cloudlist check", timeout=30
        )
        if result.stdout.strip():
            print(f"[✓][Cloudlist] Image already available")
            return True

        print(f"[*][Cloudlist] Pulling image...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            print(f"[✓][Cloudlist] Image pulled successfully")
            return True
        err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
        print(f"[!][Cloudlist] Failed to pull image: {err}")
        return False
    except Exception as e:
        print(f"[!][Cloudlist] Error pulling image: {e}")
        return False


def run_cloudlist_discovery(
    docker_image: str,
    provider_config: str,
    providers: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    timeout: int = 300,
    extended_metadata: bool = False,
) -> List[dict]:
    """
    Run cloudlist with the provided provider config and return discovered assets.

    Parameters
    ----------
    docker_image : str
        cloudlist Docker image.
    provider_config : str
        Host path to a cloudlist provider-config.yaml file.
    providers : list | None
        Restrict to specific providers (e.g., ['aws', 'gcp', 'azure']).
    services : list | None
        Restrict to specific services (e.g., ['storage', 'vm', 'dns']).
    timeout : int
        Docker run timeout.
    extended_metadata : bool
        Enable extended metadata in output.

    Returns
    -------
    list
        Discovered cloud assets with provider, service, and host/IP info.
    """
    if not shutil.which("docker"):
        print("[!][Cloudlist] Docker not available — skipping")
        return []

    if not provider_config or not Path(provider_config).exists():
        print("[!][Cloudlist] Provider config not provided or does not exist — skipping")
        return []

    if not pull_cloudlist_docker_image(docker_image):
        print("[!][Cloudlist] Could not get Docker image — skipping")
        return []

    temp_dir = _create_temp_dir("cloudlist")
    output_file = temp_dir / "cloudlist.json"

    try:
        config_path = Path(provider_config)
        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{config_path.parent}:/config:ro",
            "-v", f"{temp_dir}:/output",
        ]
        if _is_arm64_host():
            cmd.extend(["--platform", "linux/amd64"])

        cmd.extend([
            docker_image,
            "-pc", f"/config/{config_path.name}",
            "-o", "/output/cloudlist.json",
            "-json",
            "-silent",
        ])

        if providers:
            for provider in providers:
                cmd.extend(["-p", provider])
        if services:
            for service in services:
                cmd.extend(["-s", service])
        if extended_metadata:
            cmd.append("-extended-metadata")

        print(f"[*][Cloudlist] Enumerating cloud assets from configured providers...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-300:] if result.stderr else "unknown error"
            print(f"[!][Cloudlist] Failed: {err}")
            return []

        if not output_file.exists():
            print("[*][Cloudlist] No output file produced")
            return []

        return _parse_cloudlist_output(output_file)

    except subprocess.TimeoutExpired:
        print(f"[!][Cloudlist] Timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][Cloudlist] Error: {e}")
        return []
    finally:
        _cleanup_temp_dir(temp_dir)


def _parse_cloudlist_output(output_file: Path) -> List[dict]:
    """Parse cloudlist JSON output into a normalized asset list."""
    assets = []
    try:
        data = json.loads(output_file.read_text())
        # cloudlist may output either a list or an object keyed by provider
        entries = data if isinstance(data, list) else []
        if isinstance(data, dict):
            entries = []
            for provider, provider_assets in data.items():
                if isinstance(provider_assets, list):
                    for asset in provider_assets:
                        if isinstance(asset, dict):
                            asset["provider"] = provider
                        entries.append(asset)

        for asset in entries:
            if not isinstance(asset, dict):
                continue
            normalized = {
                "provider": asset.get("provider", ""),
                "service": asset.get("service", ""),
                "id": asset.get("id", ""),
                "host": asset.get("host", ""),
                "ip": asset.get("ip", ""),
                "source": "cloudlist",
                "raw": asset,
            }
            assets.append(normalized)

        print(f"[✓][Cloudlist] Discovered {len(assets)} cloud asset(s)")
        return assets

    except Exception as e:
        print(f"[!][Cloudlist] Could not parse output: {e}")
        return []


def discover_cloudlist_assets(settings: dict) -> List[dict]:
    """
    High-level wrapper to run cloudlist and return discovered cloud assets.

    Skips gracefully if no provider config is configured.
    """
    CLOUDLIST_ENABLED = settings.get("CLOUDLIST_ENABLED", False)
    if not CLOUDLIST_ENABLED:
        print("[-][Cloudlist] Disabled — skipping")
        return []

    CLOUDLIST_PROVIDER_CONFIG = settings.get("CLOUDLIST_PROVIDER_CONFIG", "")
    if not CLOUDLIST_PROVIDER_CONFIG:
        print("[-][Cloudlist] No provider config configured — skipping")
        return []

    CLOUDLIST_DOCKER_IMAGE = settings.get("CLOUDLIST_DOCKER_IMAGE", "projectdiscovery/cloudlist:latest")
    CLOUDLIST_PROVIDERS = list(settings.get("CLOUDLIST_PROVIDERS", []))
    CLOUDLIST_SERVICES = list(settings.get("CLOUDLIST_SERVICES", []))
    CLOUDLIST_TIMEOUT = settings.get("CLOUDLIST_TIMEOUT", 300)
    CLOUDLIST_EXTENDED_METADATA = settings.get("CLOUDLIST_EXTENDED_METADATA", False)

    print("\n" + "=" * 50)
    print("[*][Cloudlist] CLOUD ASSET ENUMERATION")
    print("=" * 50)

    return run_cloudlist_discovery(
        docker_image=CLOUDLIST_DOCKER_IMAGE,
        provider_config=CLOUDLIST_PROVIDER_CONFIG,
        providers=CLOUDLIST_PROVIDERS or None,
        services=CLOUDLIST_SERVICES or None,
        timeout=CLOUDLIST_TIMEOUT,
        extended_metadata=CLOUDLIST_EXTENDED_METADATA,
    )
