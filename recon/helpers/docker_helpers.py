"""
RedAmon - Docker Helper Functions
=================================
Utilities for Docker container operations, image management, and file permissions.
"""

import os
import shutil
import subprocess
from pathlib import Path

# Shared file/process utilities
from recon.helpers._file_utils import get_real_user_ids, fix_file_ownership

# Volume name for persistent nuclei templates
NUCLEI_TEMPLATES_VOLUME = "nuclei-templates"


# =============================================================================
# Tor / Proxy Helpers
# =============================================================================

def get_proxy_env_flags(net_host: bool = False) -> list[str]:
    """
    Return Docker ``-e`` flags for HTTP_PROXY/HTTPS_PROXY env vars when Tor is
    enabled.  These are injected into sibling-container ``docker run`` commands
    so that tools without a native ``-proxy`` CLI flag (e.g. subfinder, amass)
    still route their API calls through Tor.

    Parameters
    ----------
    net_host : bool
        Set to True when the Docker command uses ``--net=host``.  The Tor HTTP
        proxy is then reachable at ``127.0.0.1:8118`` (the host-mapped port).
        When False (default), ``socks5h://127.0.0.1:9050`` is used, which
        requires the Tor container to be on a network reachable from the child
        container (e.g. ``redamon-network``).

    Returns
        list of ``-e KEY=VALUE`` strings ready to be ``extend()``-ed into a
        ``docker run`` argv, or ``[]``.
    """
    # Short-circuit if the env var isn't even set
    use_tor = os.environ.get("USE_TOR_FOR_RECON", "").lower()
    if use_tor not in ("true", "1"):
        return []

    # Dynamically import to avoid circular imports at module level
    from recon.helpers.anonymity import is_tor_running
    if not is_tor_running():
        return []

    if net_host:
        # --net=host containers share the host's network stack, so they can
        # reach the Tor HTTP proxy (dperson/torproxy) via the host-mapped port.
        proxy_url = "http://127.0.0.1:8118"
    else:
        # Non-host-network containers need SOCKS5 proxy. This works when the
        # Tor container is on a reachable network (e.g. redamon-network) or
        # when running on the host directly.
        proxy_url = "socks5h://127.0.0.1:9050"

    no_proxy = "localhost,127.0.0.1,::1"
    return [
        "-e", f"HTTP_PROXY={proxy_url}",
        "-e", f"HTTPS_PROXY={proxy_url}",
        "-e", f"ALL_PROXY={proxy_url}",
        "-e", f"NO_PROXY={no_proxy}",
        "-e", f"http_proxy={proxy_url}",
        "-e", f"https_proxy={proxy_url}",
        "-e", f"all_proxy={proxy_url}",
        "-e", f"no_proxy={no_proxy}",
    ]


def get_proxychains_prefix() -> list[str]:
    """
    Return a ``proxychains4 -q`` prefix list when Tor is running.

    Use this to wrap native-binary invocations (subjack, nmap, etc.) that
    don't have a SOCKS proxy flag::

        cmd = get_proxychains_prefix() + ["subjack", "-w", ...]

    Returns an empty list when Tor is not available so the caller doesn't
    need an explicit gate.
    """
    use_tor = os.environ.get("USE_TOR_FOR_RECON", "").lower()
    if use_tor not in ("true", "1"):
        return []
    from recon.helpers.anonymity import is_tor_running, get_proxychains_cmd
    if not is_tor_running():
        return []
    pc = get_proxychains_cmd()
    if not pc:
        return []
    return [pc, "-q"]


# =============================================================================
# Generic Docker Utilities
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed and accessible."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


# =============================================================================
# Nuclei Docker Management
# =============================================================================

def pull_nuclei_docker_image(docker_image: str) -> bool:
    """
    Pull the nuclei Docker image if not present.
    
    Args:
        docker_image: The Docker image name (e.g., 'projectdiscovery/nuclei:latest')
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[*][Docker] Pulling Docker image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            print(f"[✓][Docker] Pulled {docker_image}")
        else:
            err = result.stderr.strip().splitlines()[-1] if result.stderr else "unknown error"
            print(f"[!][Docker] Failed to pull {docker_image}: {err[:200]}")
        return result.returncode == 0
    except Exception as e:
        print(f"[!][Docker] Exception pulling {docker_image}: {e}")
        return False


def ensure_templates_volume(docker_image: str, auto_update: bool = False) -> bool:
    """
    Ensure the nuclei-templates Docker volume exists and has templates.
    Creates the volume and downloads templates if needed.
    
    Args:
        docker_image: Nuclei Docker image to use for template updates
        auto_update: Whether to check for template updates
    
    Returns:
        True if templates are ready, False otherwise
    """
    try:
        # Check if volume exists
        result = subprocess.run(
            ["docker", "volume", "inspect", NUCLEI_TEMPLATES_VOLUME],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        volume_exists = result.returncode == 0
        needs_download = False
        
        if not volume_exists:
            print(f"[*][Docker] Creating templates volume: {NUCLEI_TEMPLATES_VOLUME}...")
            subprocess.run(
                ["docker", "volume", "create", NUCLEI_TEMPLATES_VOLUME],
                capture_output=True,
                text=True,
                timeout=30
            )
            needs_download = True  # New volume, definitely needs templates
        else:
            # Volume exists - check if it has templates by counting .yaml files
            check_result = subprocess.run(
                ["docker", "run", "--rm", 
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 "alpine", 
                 "sh", "-c", "find /root/nuclei-templates -name '*.yaml' 2>/dev/null | head -5 | wc -l"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            template_count = int(check_result.stdout.strip()) if check_result.stdout.strip().isdigit() else 0
            needs_download = template_count == 0
        
        # Download templates if needed OR auto-update is enabled
        if needs_download:
            print(f"[*][Docker] Downloading nuclei templates (first run, this may take a minute)...")
        elif auto_update:
            print(f"[*][Docker] Checking for template updates...")
        
        if needs_download or auto_update:
            update_result = subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 docker_image,
                 "-ut"],  # Update templates
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes for initial download
            )
            
            if update_result.returncode != 0:
                print(f"[!][Docker] Warning: Template update may have issues")
                if update_result.stderr:
                    # Filter out info messages
                    errors = [l for l in update_result.stderr.split('\n') if 'FTL' in l or 'ERR' in l]
                    if errors:
                        print(f"[!][Docker] {errors[0][:200]}")
            else:
                # Parse update info from output
                if update_result.stdout:
                    for line in update_result.stdout.split('\n'):
                        if 'Successfully updated' in line or 'already up to date' in line.lower():
                            print(f"[✓][Docker] {line.strip()[:80]}")
                            break
                    else:
                        print(f"[✓][Docker] Templates updated successfully")
                else:
                    print(f"[✓][Docker] Templates ready")
        else:
            print(f"[✓][Docker] Templates volume ready (auto-update disabled)")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"[!][Docker] Timeout while setting up templates")
        return False
    except Exception as e:
        print(f"[!][Docker] Error setting up templates: {e}")
        return False


# =============================================================================
# Katana Docker Management
# =============================================================================

def pull_katana_docker_image(docker_image: str) -> bool:
    """
    Pull the Katana Docker image if not present.
    
    Args:
        docker_image: The Docker image name (e.g., 'projectdiscovery/katana:latest')
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"[*][Docker] Pulling Katana image: {docker_image}...")
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            print(f"[✓][Docker] Pulled Katana image {docker_image}")
        else:
            err = result.stderr.strip().splitlines()[-1] if result.stderr else "unknown error"
            print(f"[!][Docker] Failed to pull Katana image {docker_image}: {err[:200]}")
        return result.returncode == 0
    except Exception as e:
        print(f"[!][Docker] Exception pulling Katana image {docker_image}: {e}")
        return False


# =============================================================================
# Network Utilities
# =============================================================================

def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False

