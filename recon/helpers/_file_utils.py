"""Shared file and process utility functions."""

import os
import tempfile
from pathlib import Path
from typing import Tuple


def get_real_user_ids() -> Tuple[int, int]:
    """Get real user and group IDs from the environment or SUDO.

    Returns:
        Tuple of (uid, gid). Defaults to (1000, 1000) if undetectable.
    """
    uid = int(os.environ.get("REAL_UID", os.environ.get("SUDO_UID", "1000")))
    gid = int(os.environ.get("REAL_GID", os.environ.get("SUDO_GID", "1000")))
    return uid, gid


def fix_file_ownership(file_path: Path) -> None:
    """Change file ownership to the real user (not root).

    Args:
        file_path: Path to the file or directory to chown.
    """
    uid, gid = get_real_user_ids()
    try:
        os.chown(file_path, uid, gid)
    except (PermissionError, OSError):
        pass  # Best-effort; may fail in containerized environments


def create_temp_dir(prefix: str) -> Path:
    """Create a temporary directory with the given prefix.

    Args:
        prefix: Prefix for the temp directory name.

    Returns:
        Path to the created temporary directory.
    """
    return Path(tempfile.mkdtemp(prefix=prefix))


def cleanup_temp_dir(temp_dir: Path) -> None:
    """Remove a temporary directory and all its contents.

    Args:
        temp_dir: Path to the temporary directory to remove.
    """
    import shutil
    try:
        shutil.rmtree(temp_dir)
    except (PermissionError, OSError):
        pass  # Best-effort cleanup
