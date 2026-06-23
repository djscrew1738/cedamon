"""
Shared utilities for Docker-based recon helpers.
"""
import logging
import os
import platform
import subprocess
from pathlib import Path

from recon.helpers._file_utils import create_temp_dir, cleanup_temp_dir

logger = logging.getLogger(__name__)


def is_arm64_host() -> bool:
    """Return True when running on an ARM64 host."""
    machine = platform.machine().lower()
    return machine in ("arm64", "aarch64")


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
