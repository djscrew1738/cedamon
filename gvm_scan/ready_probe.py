"""
GVM Feed-Sync Readiness Probe
=============================
Lightweight probe that connects to GVMD over its Unix socket and reports whether
feed sync has finished and scan configs are available.

Can be run as a module or imported:

    python -m gvm_scan.ready_probe --json

Returns a JSON object with keys:
    ready                  bool
    currently_syncing_count int
    config_count           int
    feeds                  list of feed summary dicts
    message                str
    error                  str (only on connection failure)
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

# GVM imports (handled gracefully if not installed)
try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import GMPv227
    from gvm.transforms import EtreeTransform
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False

GVM_SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
GVM_USERNAME = os.environ.get("GVM_USERNAME", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "admin")


def _parse_feeds(feeds_xml) -> tuple[int, List[Dict[str, Any]]]:
    """Extract currently_syncing count and feed summaries from get_feeds XML."""
    syncing = feeds_xml.findall(".//currently_syncing")
    feed_nodes = feeds_xml.findall(".//feed")
    feed_summaries: List[Dict[str, Any]] = []
    for feed in feed_nodes:
        summary: Dict[str, Any] = {}
        feed_type = feed.find("type")
        name = feed.find("name")
        version = feed.find("version")
        summary["type"] = feed_type.text if feed_type is not None else None
        summary["name"] = name.text if name is not None else None
        summary["version"] = version.text if version is not None else None
        summary["syncing"] = feed.find("currently_syncing") is not None
        feed_summaries.append(summary)
    return len(syncing), feed_summaries


def check_gvm_ready(
    socket_path: str = GVM_SOCKET_PATH,
    username: str = GVM_USERNAME,
    password: str = GVM_PASSWORD,
    max_retries: int = 3,
    retry_interval: int = 2,
) -> Dict[str, Any]:
    """
    Check whether GVM is ready to accept scans.

    Args:
        socket_path: Path to the gvmd Unix socket.
        username: GVM username.
        password: GVM password.
        max_retries: Number of connection attempts before giving up.
        retry_interval: Seconds to sleep between retries.

    Returns:
        Dictionary describing readiness state.
    """
    if not GVM_AVAILABLE:
        return {
            "ready": False,
            "error": "python-gvm library not installed",
            "currently_syncing_count": -1,
            "config_count": 0,
            "feeds": [],
            "message": "python-gvm is not available",
        }

    last_error = ""
    for attempt in range(1, max_retries + 1):
        connection = None
        try:
            connection = UnixSocketConnection(path=socket_path)
            connection.connect()
            transform = EtreeTransform()
            gmp = GMPv227(connection=connection, transform=transform)
            gmp.authenticate(username, password)

            syncing_count, feeds = _parse_feeds(gmp.get_feeds())
            configs = gmp.get_scan_configs()
            config_count_text = configs.findtext(".//config_count", "0")
            try:
                config_count = int(config_count_text or "0")
            except (ValueError, TypeError):
                config_count = 0

            ready = syncing_count == 0 and config_count > 0
            if ready:
                message = (
                    f"GVM is ready ({config_count} scan config(s) loaded, "
                    f"no feeds currently syncing)"
                )
            elif syncing_count > 0:
                message = (
                    f"Feed sync in progress ({syncing_count} feed(s) syncing); "
                    f"{config_count} scan config(s) loaded"
                )
            else:
                message = (
                    "GVM connected but no scan configs loaded yet; "
                    "feed sync may still be initializing"
                )

            return {
                "ready": ready,
                "currently_syncing_count": syncing_count,
                "config_count": config_count,
                "feeds": feeds,
                "message": message,
            }

        except Exception as exc:
            last_error = str(exc)
            if attempt < max_retries:
                time.sleep(retry_interval)
        finally:
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    print(f"[!] check_gvm_ready: connection.disconnect()")
                    pass

    return {
        "ready": False,
        "error": last_error,
        "currently_syncing_count": -1,
        "config_count": 0,
        "feeds": [],
        "message": f"Could not connect to GVM after {max_retries} attempts: {last_error}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="GVM feed-sync readiness probe")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--socket", default=GVM_SOCKET_PATH, help="gvmd socket path")
    parser.add_argument("--username", default=GVM_USERNAME, help="GVM username")
    parser.add_argument("--password", default=GVM_PASSWORD, help="GVM password")
    parser.add_argument(
        "--max-retries", type=int, default=3, help="Connection attempts"
    )
    parser.add_argument(
        "--retry-interval", type=int, default=2, help="Seconds between retries"
    )
    args = parser.parse_args()

    result = check_gvm_ready(
        socket_path=args.socket,
        username=args.username,
        password=args.password,
        max_retries=args.max_retries,
        retry_interval=args.retry_interval,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        # Always return 0 in JSON mode so callers can parse the readiness state
        # without docker-py treating "not ready" as a container failure.
        return 0

    status = "READY" if result["ready"] else "NOT READY"
    print(f"[{status}] {result['message']}")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
