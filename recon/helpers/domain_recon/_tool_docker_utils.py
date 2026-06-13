"""
Shared utilities for Docker-based recon helpers.
"""
import os
import platform
import shutil
import subprocess
import uuid
from pathlib import Path


def is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


def create_temp_dir(prefix: str) -> Path:
    """Create a temp directory under REDAMON_TEMP_DIR or /tmp/redamon."""
    base = Path(os.environ.get("REDAMON_TEMP_DIR", "/tmp/redamon"))
    temp_dir = base / f".{prefix}_{uuid.uuid4().hex[:8]}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def cleanup_temp_dir(temp_dir: Path):
    """Clean up a temp directory, ignoring errors."""
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    except Exception:
        pass


def pull_docker_image(docker_image: str, timeout: int = 300) -> bool:
    """Pull a Docker image if not already present."""
    try:
        result = subprocess.run(
            ["docker", "images", "-q", docker_image],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            return True
        result = subprocess.run(
            ["docker", "pull", docker_image],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0
    except Exception:
        return False


def build_docker_image(dockerfile_dir: Path, tag: str, timeout: int = 600) -> bool:
    """Build a Docker image from a directory containing a Dockerfile."""
    try:
        result = subprocess.run(
            ["docker", "build", "-t", tag, str(dockerfile_dir)],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0
    except Exception:
        return False


def docker_available() -> bool:
    """Return True if docker is available on the host."""
    return shutil.which("docker") is not None


def write_lines_file(path: Path, lines):
    """Write a list of strings to a file, one per line."""
    path.write_text("\n".join(str(line) for line in lines) + "\n", encoding="utf-8")
