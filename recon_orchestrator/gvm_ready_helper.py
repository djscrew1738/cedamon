"""
GVM Readiness Helper
====================
Reusable wrapper around gvm_scan.ready_probe.check_gvm_ready that
returns a uniform {"ready": bool, "message": str} dict and handles
timeouts gracefully (returns not-ready instead of raising).
"""

import logging
import time
from typing import Any, Dict

from gvm_scan.ready_probe import check_gvm_ready

logger = logging.getLogger(__name__)

# Maximum seconds to wait for GVM readiness before giving up.
MAX_READINESS_TIMEOUT_SEC = 60

# Seconds to sleep between probe retries.
PROBE_INTERVAL_SEC = 5


def probe_gvm_readiness(
    timeout: int = MAX_READINESS_TIMEOUT_SEC,
    socket_path: str = "/run/gvmd/gvmd.sock",
    username: str = "admin",
    password: str = "admin",
) -> Dict[str, Any]:
    """
    Check whether GVM is ready to accept scans, with a cap on wall-clock
    wait time.

    Args:
        timeout:  Maximum seconds to keep probing.  The underlying
                   ``check_gvm_ready`` already retries internally; this
                   parameter acts as an outer deadline.  Default 60 s.
        socket_path:  Path to the gvmd Unix socket.
        username:     GVM username.
        password:     GVM password.

    Returns:
        {"ready": bool, "message": str}
    """
    capped = min(timeout, MAX_READINESS_TIMEOUT_SEC)
    deadline = time.monotonic() + capped

    while time.monotonic() < deadline:
        remaining = max(0, int(deadline - time.monotonic()))
        try:
            result = check_gvm_ready(
                socket_path=socket_path,
                username=username,
                password=password,
                max_retries=1,       # we loop externally
                retry_interval=1,
            )
            if result.get("ready"):
                return {"ready": True, "message": result.get("message", "GVM is ready")}
            # Not ready yet — keep polling unless time is up
            error = result.get("error", result.get("message", "GVM not ready"))
            logger.debug("GVM not ready yet (%s); %.0fs remaining", error, remaining)
        except Exception as exc:
            logger.debug("GVM probe raised (%s); %.0fs remaining", exc, remaining)

        if time.monotonic() >= deadline:
            break
        time.sleep(min(PROBE_INTERVAL_SEC, max(1, remaining)))

    return {
        "ready": False,
        "message": (
            f"GVM feed sync did not complete within {capped}s timeout. "
            f"Scans will start once the vulnerability feed has finished syncing."
        ),
    }
