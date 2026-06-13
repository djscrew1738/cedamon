"""
RedAmon - BBOT Helpers
======================
Integration with Black Lantern Security's BBOT OSINT framework.
BBOT performs recursive subdomain enumeration, cloud asset discovery,
email enumeration, and basic web recon in a single tool.
"""

import json
import os
import platform
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import List, Optional, Set


def _is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def _create_temp_dir(prefix: str = "bbot") -> Path:
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


def pull_bbot_docker_image(docker_image: str) -> bool:
    """Pull the BBOT Docker image if not present."""
    print(f"[*][BBOT] Checking Docker image: {docker_image}")
    try:
        result = subprocess.run(
            ["docker", "images", "-q", docker_image],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            print(f"[✓][BBOT] Image already available")
            return True

        print(f"[*][BBOT] Pulling image...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            print(f"[✓][BBOT] Image pulled successfully")
            return True
        err = result.stderr.strip()[-200:] if result.stderr else "unknown error"
        print(f"[!][BBOT] Failed to pull image: {err}")
        return False
    except Exception as e:
        print(f"[!][BBOT] Error pulling image: {e}")
        return False


def _sanitize_name(name: str) -> str:
    """Sanitize a domain for use in a bbot scan name / filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name).strip("_")[:50]


def run_bbot_discovery(
    domain: str,
    docker_image: str,
    flags: List[str],
    modules: List[str],
    timeout: int = 600,
    use_proxy: bool = False,
    safe_mode: bool = True,
) -> dict:
    """
    Run BBOT against a single domain and return parsed results.

    Parameters
    ----------
    domain : str
        Target root domain.
    docker_image : str
        BBOT Docker image.
    flags : list
        BBOT flags/presets to enable (e.g., ['subdomain-enum', 'cloud-enum']).
    modules : list
        Additional BBOT modules to enable (e.g., ['httpx']).
    timeout : int
        Docker run timeout in seconds.
    use_proxy : bool
        Route BBOT HTTP traffic through Tor SOCKS5.
    safe_mode : bool
        When True, pass -rf passive/safe to avoid active interaction.

    Returns
    -------
    dict
        Parsed results with keys: subdomains, cloud_assets, urls, emails, ips.
    """
    if not shutil.which("docker"):
        print("[!][BBOT] Docker not available — skipping")
        return {}

    if not pull_bbot_docker_image(docker_image):
        print("[!][BBOT] Could not get Docker image — skipping")
        return {}

    temp_dir = _create_temp_dir("bbot")
    scan_name = f"bbot_{_sanitize_name(domain)}"
    output_file = temp_dir / f"{scan_name}.json"

    try:
        cmd = [
            "docker", "run", "--rm",
            "--net=host",
            "-v", f"{temp_dir}:/output",
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
            "-t", domain,
            "-om", "json",
            "-o", "/output",
            "-n", scan_name,
        ])

        for flag in flags:
            cmd.extend(["-f", flag])
        for module in modules:
            cmd.extend(["-m", module])

        if safe_mode:
            cmd.extend(["-rf", "passive", "safe"])

        print(f"[*][BBOT] Running BBOT for {domain} (flags={flags}, modules={modules})...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            err = result.stderr.strip()[-300:] if result.stderr else "unknown error"
            print(f"[!][BBOT] Failed for {domain}: {err}")
            return {}

        if not output_file.exists():
            # BBOT may write output.ndjson or a differently named file
            candidates = list(temp_dir.glob("*.json")) + list(temp_dir.glob("*.ndjson"))
            if candidates:
                output_file = candidates[0]
            else:
                print("[*][BBOT] No output file produced")
                return {}

        return _parse_bbot_output(output_file, domain)

    except subprocess.TimeoutExpired:
        print(f"[!][BBOT] Timed out for {domain} after {timeout}s")
        return {}
    except Exception as e:
        print(f"[!][BBOT] Error for {domain}: {e}")
        return {}
    finally:
        _cleanup_temp_dir(temp_dir)


def _parse_bbot_output(output_file: Path, domain: str) -> dict:
    """Parse BBOT NDJSON output and extract relevant data."""
    subdomains: Set[str] = set()
    cloud_assets: List[dict] = []
    urls: Set[str] = set()
    emails: Set[str] = set()
    ips: Set[str] = set()

    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = event.get("type", "")
                data = event.get("data", "")

                if event_type == "DNS_NAME" and isinstance(data, str):
                    sub = data.lower().strip()
                    if sub == domain or sub.endswith("." + domain):
                        subdomains.add(sub)

                elif event_type == "STORAGE_BUCKET" and isinstance(data, dict):
                    name = data.get("name", "")
                    provider = data.get("provider", "")
                    if name:
                        cloud_assets.append({
                            "type": "storage_bucket",
                            "provider": provider,
                            "name": name,
                            "source": "bbot",
                        })

                elif event_type == "URL" and isinstance(data, str):
                    urls.add(data)

                elif event_type == "URL_UNVERIFIED" and isinstance(data, str):
                    urls.add(data)

                elif event_type == "EMAIL_ADDRESS" and isinstance(data, str):
                    emails.add(data.lower())

                elif event_type == "IP_ADDRESS" and isinstance(data, str):
                    ips.add(data)

        return {
            "subdomains": sorted(subdomains),
            "cloud_assets": cloud_assets,
            "urls": sorted(urls),
            "emails": sorted(emails),
            "ips": sorted(ips),
        }

    except Exception as e:
        print(f"[!][BBOT] Could not parse output: {e}")
        return {}


def discover_bbot_assets(
    domain: str,
    settings: dict,
) -> dict:
    """
    High-level wrapper to run BBOT and return discovered assets.

    Returns a dict with subdomains, cloud_assets, urls, emails, ips.
    """
    BBOT_ENABLED = settings.get("BBOT_ENABLED", False)
    if not BBOT_ENABLED:
        print("[-][BBOT] Disabled — skipping")
        return {}

    BBOT_DOCKER_IMAGE = settings.get("BBOT_DOCKER_IMAGE", "blacklanternsecurity/bbot:stable")
    BBOT_FLAGS = list(settings.get("BBOT_FLAGS", ["subdomain-enum", "cloud-enum"]))
    BBOT_MODULES = list(settings.get("BBOT_MODULES", ["httpx"]))
    BBOT_TIMEOUT = settings.get("BBOT_TIMEOUT", 600)
    BBOT_SAFE_MODE = settings.get("BBOT_SAFE_MODE", True)
    USE_TOR_FOR_RECON = settings.get("USE_TOR_FOR_RECON", False)

    print("\n" + "=" * 50)
    print("[*][BBOT] COMPREHENSIVE OSINT")
    print("=" * 50)

    return run_bbot_discovery(
        domain=domain,
        docker_image=BBOT_DOCKER_IMAGE,
        flags=BBOT_FLAGS,
        modules=BBOT_MODULES,
        timeout=BBOT_TIMEOUT,
        use_proxy=USE_TOR_FOR_RECON,
        safe_mode=BBOT_SAFE_MODE,
    )
