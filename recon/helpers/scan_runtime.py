"""
RedAmon - Scan Runtime Helpers
==============================
Shared utilities for keeping recon scans fast, clean, and reliable:

* Orphan container cleanup (prevents resource/ID collisions from earlier runs)
* Disk-space preflight check
* Monitored subprocess execution with output-file staleness detection
"""

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional


# Container images that are considered ephemeral per-scan tooling.
# Orchestrator/DB/webapp/infrastructure containers are intentionally excluded.
TOOL_IMAGE_PREFIXES = (
    "projectdiscovery/naabu",
    "projectdiscovery/httpx",
    "projectdiscovery/nuclei",
    "projectdiscovery/katana",
    "projectdiscovery/subfinder",
    "projectdiscovery/amass",
    "projectdiscovery/masscan",
)

# Names that should never be removed even if they match an image prefix.
# Active recon scan orchestrators are protected so a cleanup pass does not
# kill the scan container that is calling us.
PROTECTED_NAME_PREFIXES = (
    "redamon-recon-",
    "redamon-recon-orchestrator",
    "redamon-neo4j",
    "redamon-postgres",
    "redamon-webapp",
    "redamon-knowledge-base",
    "redamon-tor",
    "portainer",
)


def _docker(args: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a docker CLI command and return the CompletedProcess."""
    return subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _is_protected_name(name: str) -> bool:
    """Return True if a container name belongs to infrastructure we must keep."""
    name_lower = name.lower()
    return any(name_lower.startswith(p) for p in PROTECTED_NAME_PREFIXES)


def _is_tool_container(image: str) -> bool:
    """Return True if the image is an ephemeral per-scan recon tool."""
    image_lower = image.lower()
    return any(image_lower.startswith(p) for p in TOOL_IMAGE_PREFIXES)


def cleanup_orphan_containers(project_id: Optional[str] = None, dry_run: bool = False,
                               protect_current: bool = True) -> int:
    """
    Remove stale recon-tool containers left behind by previous scans.

    The following are removed:
      * Ephemeral tool containers (naabu, httpx, nuclei, katana, ...) regardless
        of state, because they have random names and cannot be reliably tied to
        a live scan once spawned.
      * Exited ``redamon-recon-`` scan orchestrators that match ``project_id``.

    The following are protected:
      * The container this code is running inside (when ``protect_current``).
      * Running ``redamon-recon-`` orchestrators (active scans).
      * Infrastructure containers (orchestrator, Neo4j, Postgres, webapp, ...).

    Parameters
    ----------
    project_id : str | None
        If provided, exited scan orchestrators whose names contain this id are
        also removed.
    dry_run : bool
        If True, only print what would be removed and return the count.
    protect_current : bool
        If True, never remove the container this code is running inside.

    Returns
    -------
    int
        Number of containers removed (or that would be removed).
    """
    removed = 0
    current_cid = get_project_container_id() if protect_current else None
    try:
        result = _docker(["ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.State}}"], timeout=30)
        if result.returncode != 0:
            print(f"[!][Runtime] Could not list containers: {result.stderr[:200]}")
            return 0

        candidates = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) != 4:
                continue
            cid, image, name, state = parts
            if current_cid and cid.startswith(current_cid):
                continue

            # Remove old scan orchestrators for the same project if they are not running.
            is_exited_project_orchestrator = (
                project_id
                and project_id in name
                and name.lower().startswith("redamon-recon-")
                and state.lower() != "running"
            )
            if is_exited_project_orchestrator:
                candidates.append((cid, image, name, state))
                continue

            if _is_protected_name(name):
                continue

            # Always remove ephemeral tool containers (random names, safe to reap).
            if _is_tool_container(image):
                candidates.append((cid, image, name, state))

        if not candidates:
            return 0

        label = "Would remove" if dry_run else "Removing"
        print(f"[*][Runtime] {label} {len(candidates)} stale recon container(s)...")
        for cid, image, name, state in candidates:
            print(f"    {label}: {name} ({image}) [{state}]")
            if dry_run:
                removed += 1
                continue
            rm = _docker(["rm", "-f", cid], timeout=30)
            if rm.returncode == 0:
                removed += 1
            else:
                print(f"    [!] Failed to remove {name}: {rm.stderr[:200]}")

        if removed and not dry_run:
            print(f"[✓][Runtime] Removed {removed} stale container(s)")
    except Exception as e:
        print(f"[!][Runtime] Orphan cleanup failed: {e}")
    return removed


def check_disk_space(min_gb: float = 5.0, path: str = "/") -> bool:
    """
    Verify that the filesystem has at least ``min_gb`` gigabytes free.

    Returns True if there is enough space, False otherwise. Prints a warning
    when space is low.
    """
    try:
        usage = shutil.disk_usage(path)
        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        pct_used = (usage.used / usage.total) * 100
        if free_gb < min_gb:
            print(f"[!][Runtime] DISK SPACE WARNING: {free_gb:.1f} GB free on {path}")
            print(f"    Total: {total_gb:.1f} GB | Used: {pct_used:.1f}%")
            print(f"    Minimum recommended: {min_gb:.1f} GB")
            return False
        print(f"[✓][Runtime] Disk space OK: {free_gb:.1f} GB free on {path}")
        return True
    except Exception as e:
        print(f"[!][Runtime] Could not check disk space: {e}")
        return False


def _format_duration(seconds: float) -> str:
    """Pretty-print a duration in seconds."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def run_monitored_subprocess(
    cmd: list,
    output_path: Path,
    timeout: int = 600,
    stall_timeout: int = 120,
    label: str = "tool",
) -> tuple[int, str, str, float]:
    """
    Run a subprocess with both a hard timeout and an output-file stall timeout.

    The stall timeout aborts the process if the output file stops growing for
    ``stall_timeout`` seconds. This catches stuck proxy/Tor scans that never
    produce results without waiting for the full hard timeout.

    Parameters
    ----------
    cmd : list
        Command and arguments.
    output_path : Path
        File that the tool is expected to write. If it does not exist, the
        stall timer is ignored.
    timeout : int
        Hard maximum runtime in seconds.
    stall_timeout : int
        If the output file exists and its size has not changed for this many
        seconds, the process is terminated.
    label : str
        Human-readable label for log messages.

    Returns
    -------
    tuple[int, str, str, float]
        (returncode, stdout, stderr, elapsed_seconds)
    """
    start = time.time()
    print(f"[*][Runtime][{label}] Starting monitored run (hard timeout {_format_duration(timeout)}, "
          f"stall timeout {_format_duration(stall_timeout)})")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    last_size = 0
    last_growth_time = start
    stdout_chunks = []
    stderr_chunks = []

    try:
        while proc.poll() is None:
            # Non-blocking read of available output
            if proc.stdout:
                try:
                    chunk = proc.stdout.readline()
                    if chunk:
                        stdout_chunks.append(chunk)
                except Exception:
                    pass
            if proc.stderr:
                try:
                    chunk = proc.stderr.readline()
                    if chunk:
                        stderr_chunks.append(chunk)
                except Exception:
                    pass

            now = time.time()
            elapsed = now - start

            # Hard timeout
            if elapsed >= timeout:
                print(f"[!][Runtime][{label}] Hard timeout reached ({_format_duration(timeout)})")
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                raise subprocess.TimeoutExpired(cmd=" ".join(cmd), timeout=timeout)

            # Stall detection: output file exists but has not grown
            if output_path.exists():
                current_size = output_path.stat().st_size
                if current_size > last_size:
                    last_size = current_size
                    last_growth_time = now
                elif (now - last_growth_time) >= stall_timeout and current_size > 0:
                    print(f"[!][Runtime][{label}] Output stalled for {_format_duration(stall_timeout)} "
                          f"(file size {current_size} bytes)")
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=10)
                    raise subprocess.TimeoutExpired(cmd=" ".join(cmd), timeout=stall_timeout)

            time.sleep(0.5)

        # Drain remaining output
        stdout, stderr = proc.communicate(timeout=10)
        if stdout:
            stdout_chunks.append(stdout)
        if stderr:
            stderr_chunks.append(stderr)

    except subprocess.TimeoutExpired:
        # Re-raise so callers can handle like a normal timeout
        raise
    except Exception:
        # Ensure process is cleaned up on unexpected errors
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
        raise

    elapsed = time.time() - start
    return proc.returncode, "".join(stdout_chunks), "".join(stderr_chunks), elapsed


def get_project_container_id() -> Optional[str]:
    """Return the current container's short ID, if running inside Docker."""
    cgroup = Path("/proc/self/cgroup")
    if cgroup.exists():
        try:
            for line in cgroup.read_text().splitlines():
                if "docker" in line:
                    # Last 64-char hex segment is usually the container ID
                    parts = line.split("/")
                    for part in reversed(parts):
                        candidate = part.strip()
                        if len(candidate) >= 12 and all(c in "0123456789abcdef" for c in candidate[:12]):
                            return candidate[:12]
        except Exception:
            pass
    return os.environ.get("HOSTNAME") if os.environ.get("HOSTNAME") else None
