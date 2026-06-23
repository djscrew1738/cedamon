"""
Docker container lifecycle management for recon processes
"""
import asyncio
import json
import logging
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional, Tuple

import docker
from docker.errors import NotFound, APIError
from docker.models.containers import Container

from models import (
    ReconState, ReconStatus, ReconLogEvent,
    GvmState, GvmStatus, GvmLogEvent,
    GithubHuntState, GithubHuntStatus, GithubHuntLogEvent,
    TrufflehogState, TrufflehogStatus, TrufflehogLogEvent,
    PartialReconState, PartialReconStatus,
    ReconAuditEntry, ScheduledReconEntry, QueuedReconEntry,
)
from state_store import OrchestratorStateStore

logger = logging.getLogger(__name__)

# ANSI escape code pattern for stripping terminal colors from logs
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m|\033\[[0-9;]*m')

# Maximum number of concurrent partial recon runs per project
MAX_PARALLEL_PARTIAL_RECONS = 12

# Maximum number of concurrent recons per user (P3 rate limiting)
USER_MAX_CONCURRENT_RECONS = int(os.environ.get("USER_MAX_CONCURRENT_RECONS", "3"))

# How often to check for scheduled recons (P3 scheduling)
SCHEDULED_RECON_CHECK_INTERVAL = int(os.environ.get("SCHEDULED_RECON_CHECK_INTERVAL", "10"))

# Sub-container images spawned by recon (Docker-in-Docker sibling containers)
SUB_CONTAINER_IMAGES = [
    "projectdiscovery/naabu",
    "projectdiscovery/httpx",
    "projectdiscovery/katana",
    "projectdiscovery/nuclei",
    "projectdiscovery/uncover",
    "sxcurity/gau",
    "frost19k/puredns",
]

# Phase patterns to detect from logs
# Order matters - more specific patterns should come first within each phase
PHASE_PATTERNS = [
    (r"\[Phase 1\]|\[PHASE 1\]|Phase 1:|WHOIS Lookup|domain.*discovery|Domain Reconnaissance", "Domain Discovery", 1),
    (r"\[Phase 2\]|\[PHASE 2\]|Phase 2:|NAABU PORT SCANNER|port.*scan", "Port Scanning", 2),
    (r"\[Phase 3\]|\[PHASE 3\]|Phase 3:|HTTPX HTTP PROBER|http.*prob", "HTTP Probing", 3),
    (r"\[Phase 4\]|\[PHASE 4\]|Phase 4:|Resource Enumeration|Katana.*GAU|resource.*enum", "Resource Enumeration", 4),
    (r"\[Phase 4\.5\]|\[PHASE 4\.5\]|Phase 4\.5:|AI Surface Recon|ai_surface_recon", "AI Surface Recon", 4.5),
    (r"\[Phase 5\]|\[PHASE 5\]|Phase 5:|NUCLEI|Vulnerability Scan|vuln.*scan", "Vulnerability Scanning", 5),
    (r"\[Phase 6\]|\[PHASE 6\]|Phase 6:|CVE LOOKUP|MITRE|CWE|CAPEC", "CVE & MITRE", 6),
]


# GVM phase patterns to detect from logs
GVM_PHASE_PATTERNS = [
    (r"Loading recon data", "Loading Recon Data", 1),
    (r"Connecting to GVM|Waiting for GVM to be ready", "Waiting for GVM", 2),
    (r"Connected to GVM at", "Connected to GVM", 3),
    (r"PHASE 1.*Scanning.*IP|Scanning.*IP addresses", "Scanning IPs", 4),
    (r"PHASE 2.*Scanning.*hostname|Scanning.*hostnames", "Scanning Hostnames", 5),
]


# GitHub Secret Hunt phase patterns to detect from logs
GITHUB_HUNT_PHASE_PATTERNS = [
    (r"GitHub Secret Hunter|Loading.*settings|Initializing", "Loading Settings", 1),
    (r"Scanning repository|Organization found|User found|Scanning organization", "Scanning Repositories", 2),
    (r"SCAN SUMMARY|Final results saved|Scan complete", "Complete", 3),
]

# TruffleHog Secret Scanner phase patterns to detect from logs
TRUFFLEHOG_PHASE_PATTERNS = [
    (r"TruffleHog Secret Scanner|Loading.*settings|Initializing TruffleHog", "Loading Settings", 1),
    (r"Scanning repositor|Scanning organization|Running:.*trufflehog", "Scanning Repositories", 2),
    (r"SCAN SUMMARY|Final results saved|Scan complete", "Complete", 3),
]


class ContainerManager:
    """Manages Docker containers for recon, GVM scan, GitHub hunt, and TruffleHog processes"""

    def __init__(self, recon_image: str = "redamon-recon:latest", gvm_image: str = "redamon-vuln-scanner:latest", github_hunt_image: str = "redamon-github-hunter:latest", trufflehog_image: str = "redamon-trufflehog:latest", state_store: OrchestratorStateStore | None = None):
        self.client = docker.from_env()
        self.recon_image = recon_image
        self.gvm_image = gvm_image
        self.github_hunt_image = github_hunt_image
        self.trufflehog_image = trufflehog_image
        self.running_states: dict[str, ReconState] = {}
        # Nested dict: outer key = project_id, inner key = run_id
        self.partial_recon_states: dict[str, dict[str, PartialReconState]] = {}
        self.gvm_states: dict[str, GvmState] = {}
        self.github_hunt_states: dict[str, GithubHuntState] = {}
        self.trufflehog_states: dict[str, TrufflehogState] = {}
        # Track webapp API URLs per project for mid-run RoE re-validation
        self._project_webapp_urls: dict[str, str] = {}
        # Track last RoE check time per project (throttle to every 5 min)
        self._last_roe_check: dict[str, datetime] = {}
        self._start_locks: dict[str, asyncio.Lock] = {}
        # Track sub-containers per run for selective cleanup.
        # Key: project_id or partial run_id, Value: set of container IDs.
        self._sub_container_ancestry: dict[str, set[str]] = {}
        # Dedicated executor for long-running log streaming threads
        # so they don't starve the default executor used by _exec() and _fetch_project_json
        self._log_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="log-stream"
        )
        # Cache for feed-sync readiness probes so health checks don't hammer GVM
        self._gvm_ready_cache: Tuple[Optional[bool], datetime] = (None, datetime.min.replace(tzinfo=timezone.utc))
        self._gvm_ready_cache_ttl = timedelta(seconds=60)
        self._state_store = state_store or OrchestratorStateStore()
        self._load_state()
        self._recover_containers()

        # P3: Scheduling — dict of project_id -> ScheduledReconEntry
        self._scheduled_recons: dict[str, ScheduledReconEntry] = {}
        self._scheduled_lock = asyncio.Lock()

        # P3: Audit trail — in-memory list of completed recon records
        self._audit_log: list[ReconAuditEntry] = []
        self._max_audit_entries = 200

        # P3: Per-user rate limiting queue
        # user_id -> deque of (pipeline_type, params_dict, future)
        self._user_queues: dict[str, list[dict]] = {}
        # user_id -> count of currently active recons
        self._user_active_counts: dict[str, int] = {}
        self._user_queue_lock = asyncio.Lock()

        # Background task for scheduled recons
        self._scheduler_task: asyncio.Task | None = None
        try:
            self._scheduler_task = asyncio.create_task(self._scheduled_recon_loop())
        except RuntimeError:
            pass

        # Background task that periodically flushes state to disk so that a
        # crash or ungraceful container restart loses at most a few seconds of
        # state (e.g., the last_log_timestamp watermark used for SSE resume).
        self._persist_interval = float(
            os.environ.get("ORCHESTRATOR_PERSIST_INTERVAL_SEC", "5")
        )
        self._persist_task: asyncio.Task | None = None
        try:
            self._persist_task = asyncio.create_task(self._periodic_persist())
        except RuntimeError:
            # No running event loop (e.g., constructed outside async context).
            pass

    async def _exec(self, fn, *args, **kwargs):
        """Run a synchronous Docker call in the default thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(fn, *args, **kwargs))

    async def _ensure_recon_image(self, context: str = "") -> None:
        """Ensure the recon Docker image exists, building it if necessary.

        Implements automatic retry with exponential backoff (1s, 4s, 16s)
        to handle transient failures (network blips, layer cache corruption).
        """
        try:
            await self._exec(self.client.images.get, self.recon_image)
            logger.info(f"Recon image {self.recon_image} found {context}")
            return
        except NotFound:
            pass  # Need to build

        build_path = "/app"
        dockerfile = "recon/Dockerfile"
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(
                    f"Building recon image {self.recon_image} from "
                    f"{build_path}/{dockerfile} {context} "
                    f"(attempt {attempt}/{max_retries})"
                )
                await self._exec(
                    self.client.images.build,
                    path=build_path,
                    dockerfile=dockerfile,
                    tag=self.recon_image,
                    rm=True,
                )
                logger.info(f"Recon image {self.recon_image} built {context}")
                return
            except Exception as e:
                logger.warning(
                    f"Image build attempt {attempt}/{max_retries} failed {context}: {e}"
                )
                if attempt < max_retries:
                    await asyncio.sleep(2 ** (attempt - 1))  # 1s, 4s
                else:
                    raise RuntimeError(
                        f"Failed to build recon image after {max_retries} attempts: {e}"
                    ) from e

    def _save_state(self) -> None:
        """Persist the current orchestrator state to disk."""
        self._state_store.save(
            self.running_states,
            self.gvm_states,
            self.github_hunt_states,
            self.trufflehog_states,
            self.partial_recon_states,
        )

    async def _periodic_persist(self) -> None:
        """Flush the in-memory state snapshot to disk on a fixed cadence."""
        while True:
            try:
                await asyncio.sleep(self._persist_interval)
                self._save_state()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Periodic state persistence failed: {e}")

    async def shutdown(self) -> None:
        """Stop the background persistence task, clean up all containers,
        and perform a final state flush."""
        await self.cleanup()
        if self._scheduler_task is not None:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
            self._scheduler_task = None
        if self._persist_task is not None:
            self._persist_task.cancel()
            try:
                await self._persist_task
            except asyncio.CancelledError:
                pass
            self._persist_task = None
        try:
            self._save_state()
        except Exception as e:
            logger.warning(f"Final state flush during shutdown failed: {e}")
        self._log_executor.shutdown(wait=False)

    def _load_state(self) -> None:
        """Load a previously persisted orchestrator state snapshot."""
        (
            self.running_states,
            self.gvm_states,
            self.github_hunt_states,
            self.trufflehog_states,
            self.partial_recon_states,
        ) = self._state_store.load()

    def _recover_containers(self) -> None:
        """Validate restored states against actual Docker containers.

        Containers that are still running/paused are kept; everything else is
        transitioned to error/idle and removed from the active state map.
        """
        now = datetime.now(timezone.utc)
        terminal_ttl = timedelta(seconds=60)

        def _recover_single(states: dict, status_enum):
            to_remove = []
            for key, state in states.items():
                if state.status in (status_enum.COMPLETED, status_enum.ERROR, status_enum.IDLE):
                    if state.completed_at and (now - state.completed_at) > terminal_ttl:
                        to_remove.append(key)
                    continue
                container_id = state.container_id
                if not container_id:
                    state.status = status_enum.ERROR
                    state.error = "Container ID missing after restart"
                    state.completed_at = now
                    continue
                try:
                    container = self.client.containers.get(container_id)
                    if container.status == "paused":
                        state.status = status_enum.PAUSED
                    elif container.status == "running":
                        state.status = status_enum.RUNNING
                    else:
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = status_enum.COMPLETED
                            state.completed_at = now
                        else:
                            state.status = status_enum.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = now
                        try:
                            container.remove()
                        except Exception:
                            logger.warning("_recover_single: container.remove()", exc_info=True)
                            pass
                except NotFound:
                    if state.status not in (status_enum.COMPLETED, status_enum.ERROR):
                        state.status = status_enum.ERROR
                        state.error = "Container not found after restart"
                        state.completed_at = now
                except Exception as e:
                    logger.warning(f"Recovery check failed for {key}: {e}")
            for key in to_remove:
                del states[key]

        _recover_single(self.running_states, ReconStatus)
        _recover_single(self.gvm_states, GvmStatus)
        _recover_single(self.github_hunt_states, GithubHuntStatus)
        _recover_single(self.trufflehog_states, TrufflehogStatus)

        for project_id, runs in list(self.partial_recon_states.items()):
            _recover_single(runs, PartialReconStatus)
            if not runs:
                del self.partial_recon_states[project_id]

        self._save_state()

    # =========================================================================
    # P3: Recon Scheduling — background loop that starts scheduled recons
    # =========================================================================

    async def _scheduled_recon_loop(self) -> None:
        """Background loop that checks for due scheduled recons every N seconds."""
        while True:
            try:
                await asyncio.sleep(SCHEDULED_RECON_CHECK_INTERVAL)
                await self._check_scheduled_recons()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Scheduled recon check failed: {e}")

    async def _check_scheduled_recons(self) -> None:
        """Start any scheduled recons whose time has arrived."""
        now = datetime.now(timezone.utc)
        async with self._scheduled_lock:
            due = [
                (pid, entry) for pid, entry in self._scheduled_recons.items()
                if entry.scheduled_at <= now
            ]
            for pid, entry in due:
                try:
                    logger.info(
                        f"Starting scheduled recon project_id={pid} "
                        f"type={entry.pipeline_type} scheduled_at={entry.scheduled_at.isoformat()}"
                    )
                    if entry.pipeline_type == "full":
                        await self.start_recon(
                            project_id=pid,
                            user_id=entry.user_id,
                            webapp_api_url=entry.params.get("webapp_api_url", ""),
                            recon_path=entry.params.get("recon_path", ""),
                            custom_templates_path=entry.params.get("custom_templates_path", ""),
                        )
                    elif entry.pipeline_type == "partial":
                        await self.start_partial_recon(
                            project_id=pid,
                            user_id=entry.user_id,
                            webapp_api_url=entry.params.get("webapp_api_url", ""),
                            tool_id=entry.tool_id,
                            graph_inputs=entry.params.get("graph_inputs", {}),
                            user_inputs=entry.params.get("user_inputs", []),
                            user_targets=entry.params.get("user_targets"),
                            include_graph_targets=entry.params.get("include_graph_targets", True),
                            settings_overrides=entry.params.get("settings_overrides", {}),
                        )
                    del self._scheduled_recons[pid]
                except Exception as e:
                    logger.error(f"Failed to start scheduled recon {pid}: {e}")
                    # Remove failed scheduled entries to avoid retry loops
                    self._scheduled_recons.pop(pid, None)

    def schedule_recon(self, pid: str, entry: ScheduledReconEntry) -> None:
        """Register a scheduled recon entry."""
        self._scheduled_recons[pid] = entry
        logger.info(
            f"Scheduled {entry.pipeline_type} recon for project {pid} "
            f"at {entry.scheduled_at.isoformat()}"
        )

    def cancel_scheduled_recon(self, project_id: str) -> bool:
        """Cancel a previously scheduled recon. Returns True if found and removed."""
        entry = self._scheduled_recons.pop(project_id, None)
        if entry:
            logger.info(f"Cancelled scheduled recon for project {project_id}")
            return True
        return False

    def get_scheduled_recons(self) -> list[ScheduledReconEntry]:
        """Return all currently scheduled recons."""
        return list(self._scheduled_recons.values())

    # =========================================================================
    # P3: Audit Trail — record completed recon runs
    # =========================================================================

    def _add_audit_entry(self, entry: ReconAuditEntry) -> None:
        """Add an audit entry, trimming the log if it exceeds max size."""
        self._audit_log.append(entry)
        if len(self._audit_log) > self._max_audit_entries:
            self._audit_log.pop(0)

    def get_audit_log(self, project_id: str | None = None) -> list[ReconAuditEntry]:
        """Return audit entries, optionally filtered by project_id."""
        if project_id is None:
            return list(self._audit_log)
        return [e for e in self._audit_log if e.project_id == project_id]

    # =========================================================================
    # P3: Per-user rate limiting / queue
    # =========================================================================

    async def _try_acquire_user_slot(self, user_id: str) -> bool:
        """Check if a user has capacity for another recon. Non-blocking."""
        async with self._user_queue_lock:
            current = self._user_active_counts.get(user_id, 0)
            if current < USER_MAX_CONCURRENT_RECONS:
                self._user_active_counts[user_id] = current + 1
                return True
            return False

    async def _release_user_slot(self, user_id: str) -> None:
        """Release a user slot and try to start the next queued recon."""
        async with self._user_queue_lock:
            current = self._user_active_counts.get(user_id, 0)
            if current > 0:
                self._user_active_counts[user_id] = current - 1
            # If user has queued items, start the next one
            if user_id in self._user_queues and self._user_queues[user_id]:
                next_entry = self._user_queues[user_id].pop(0)
                # This will re-enter the lock via _try_acquire_user_slot
                asyncio.create_task(self._process_queued_recon(user_id, next_entry))

    async def _process_queued_recon(self, user_id: str, entry: dict) -> None:
        """Process a queued recon entry (called after a slot frees up)."""
        if not await self._try_acquire_user_slot(user_id):
            # Still no slot — put it back at the front
            async with self._user_queue_lock:
                self._user_queues.setdefault(user_id, []).insert(0, entry)
            return
        # Execute the stored start coroutine
        coro = entry.get("coro")
        if coro:
            try:
                await coro
            except Exception as e:
                logger.warning(f"Queued recon failed for user {user_id}: {e}")
        self._release_user_slot(user_id)

    def get_user_queue_status(self, user_id: str) -> tuple[int, int, int]:
        """Return (active_count, queued_count, max_concurrent) for a user."""
        active = self._user_active_counts.get(user_id, 0)
        queued = len(self._user_queues.get(user_id, []))
        return active, queued, USER_MAX_CONCURRENT_RECONS

    async def enqueue_user_recon(self, user_id: str, coro, entry_meta: dict) -> bool:
        """Try to start a recon immediately, or queue it if user is at capacity.
        
        Returns True if started immediately, False if queued.
        """
        if await self._try_acquire_user_slot(user_id):
            # Start immediately
            try:
                await coro
            except Exception as e:
                logger.warning(f"Recon failed for user {user_id}: {e}")
                raise
            finally:
                await self._release_user_slot(user_id)
            return True
        else:
            # Queue it
            async with self._user_queue_lock:
                self._user_queues.setdefault(user_id, []).append({
                    "coro": coro,
                    **entry_meta,
                })
            logger.info(
                f"User {user_id} at capacity ({USER_MAX_CONCURRENT_RECONS}), "
                f"recon queued (position {len(self._user_queues[user_id])})"
            )
            return False

    @staticmethod
    async def _bounded_queue_put(queue: asyncio.Queue, item, timeout: float = 5.0) -> None:
        """Put an item into a bounded queue, dropping oldest entries when full.

        This prevents unbounded memory growth if the consumer is slow.
        """
        async def _put():
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(item)

        await asyncio.wait_for(_put(), timeout=timeout)

    def _update_last_log_timestamp(self, state, docker_ts: datetime | None) -> None:
        """Update the high-water timestamp on a state for SSE replay."""
        if docker_ts is None or state is None:
            return
        cur = state.last_log_timestamp
        if cur is None or docker_ts > cur:
            state.last_log_timestamp = docker_ts

    def _get_container_name(self, project_id: str) -> str:
        """Generate container name for a project"""
        # Sanitize project_id for container name
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-recon-{safe_id}"

    async def get_status(self, project_id: str) -> ReconState:
        """Get current status of a recon process"""
        if project_id in self.running_states:
            state = self.running_states[project_id]

            # Check if container is still running
            if state.container_id:
                try:
                    container = await self._exec(self.client.containers.get, state.container_id)
                    if container.status == "paused":
                        state.status = ReconStatus.PAUSED
                    elif container.status != "running":
                        # Container stopped - check exit code
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        was_completed = False
                        if exit_code == 0:
                            state.status = ReconStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                            was_completed = True
                        else:
                            state.status = ReconStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        # Record audit trail entry
                        started = state.started_at or state.completed_at
                        duration = None
                        if started and state.completed_at:
                            duration = (state.completed_at - started).total_seconds()
                        self._add_audit_entry(ReconAuditEntry(
                            run_id=project_id,
                            project_id=project_id,
                            pipeline_type="full",
                            status="completed" if was_completed else "error",
                            started_at=state.started_at,
                            completed_at=state.completed_at,
                            duration_seconds=duration,
                            phases_completed=state.phase_number or 0,
                            total_phases=state.total_phases,
                            error=state.error,
                        ))

                        # Auto-cleanup: remove finished container
                        try:
                            await self._exec(container.remove)
                            logger.info(f"Auto-removed finished container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove container: {e}")
                except NotFound:
                    # Only set error if not already in a terminal state
                    # (container may have been auto-removed after completion)
                    if state.status not in (ReconStatus.COMPLETED, ReconStatus.ERROR):
                        state.status = ReconStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking recon container for {project_id}: {e}")
                    if state.status not in (ReconStatus.COMPLETED, ReconStatus.ERROR):
                        state.status = ReconStatus.ERROR
                        state.error = f"Docker API error: {e}"

            self._save_state()
            return state

        # Check if there's an orphan container
        container_name = self._get_container_name(project_id)
        try:
            container = await self._exec(self.client.containers.get, container_name)
            if container.status in ("running", "paused"):
                return ReconState(
                    project_id=project_id,
                    status=ReconStatus.PAUSED if container.status == "paused" else ReconStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return ReconState(
            project_id=project_id,
            status=ReconStatus.IDLE,
        )

    async def start_recon(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        recon_path: str,
        custom_templates_path: str = "",
    ) -> ReconState:
        """Start a recon container for a project"""

        logger.info(f"start_recon called project_id={project_id} user_id={user_id}")

        # Serialize start operations per project to prevent race conditions
        # when two concurrent POST /start requests arrive at nearly the same time.
        if project_id not in self._start_locks:
            self._start_locks[project_id] = asyncio.Lock()

        async with self._start_locks[project_id]:
            # Check if already running or paused (inside lock — now accurate)
            current_state = await self.get_status(project_id)
            if current_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
                raise ValueError(f"Recon already active for project {project_id}")

            # Mutual exclusion: block if any partial recon is running
            if self._count_active_partial_recons(project_id) > 0:
                raise ValueError(f"Partial recon(s) running for project {project_id}. Stop them first.")

            # Clean up any existing container
            container_name = self._get_container_name(project_id)
            try:
                old_container = await self._exec(self.client.containers.get, container_name)
                await self._exec(old_container.remove, force=True)
                logger.info(f"Removed old container {container_name} for project {project_id}")
            except NotFound:
                logger.info(f"No existing container to remove for project {project_id}")

            # Create new state
            state = ReconState(
                project_id=project_id,
                status=ReconStatus.STARTING,
                started_at=datetime.now(timezone.utc),
            )
            self.running_states[project_id] = state
            self._save_state()

            try:
                # Store webapp API URL for mid-run RoE re-validation
                self._project_webapp_urls[project_id] = webapp_api_url
                # Ensure recon image exists (with retry)
                await self._ensure_recon_image(context=f"for project {project_id}")

                logger.info(
                    f"Spawning recon container {container_name} for project {project_id} "
                    f"image={self.recon_image} volumes={len(['docker.sock', 'recon', 'graph_db', 'tmp', 'js_uploads', 'js_custom', 'nuclei_templates'])}"
                )

                # Start container with environment variables
                container = await self._exec(
                    self.client.containers.run,
                    self.recon_image,
                    name=container_name,
                    detach=True,
                    network_mode="host",
                    privileged=True,
                    environment={
                        "PROJECT_ID": project_id,
                        "USER_ID": user_id,
                        "WEBAPP_API_URL": webapp_api_url,
                        "UPDATE_GRAPH_DB": "true",
                        # Anonymity — route all scanning traffic through Tor
                        "USE_TOR_FOR_RECON": "true",
                        "HTTP_PROXY": "socks5h://127.0.0.1:9050",
                        "HTTPS_PROXY": "socks5h://127.0.0.1:9050",
                        "ALL_PROXY": "socks5h://127.0.0.1:9050",
                        "NO_PROXY": "localhost,127.0.0.1,::1",
                        # HOST_RECON_OUTPUT_PATH: Required for nested Docker containers (naabu, httpx, etc.)
                        # These run as sibling containers and need host paths for volume mounts
                        "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                        # Custom nuclei templates host path (for sibling nuclei container volume mount)
                        "HOST_CUSTOM_TEMPLATES_PATH": custom_templates_path,
                        # Forward credentials from orchestrator environment
                        "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                        "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                        "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                        "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                        # Agent API for AI hooks (FFuf AI extensions, etc.)
                        "AGENT_API_URL": os.environ.get("AGENT_API_URL", "http://localhost:8090"),
                    },
                    volumes={
                        "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
                        # Mount source code for development (no rebuild needed)
                        # Note: rw needed because output/data are subdirectories
                        f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                        # Mount graph_db module
                        f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                        # Mount /tmp for Docker-in-Docker temp files (avoids spaces in paths)
                        "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                        # JS Recon shared volumes with webapp
                        "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                        "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                        # Official nuclei-templates volume (read-only) for the AI tag
                        # selector to read TEMPLATES-STATS.json. Populated by
                        # ensure_templates_volume() before any nuclei pass.
                        "nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"},
                    },
                    command="python /app/recon/main.py",
                )

                state.container_id = container.id
                state.status = ReconStatus.RUNNING
                logger.info(
                    f"Started recon container {container.id[:12]} for project {project_id} "
                    f"name={container.name} image={self.recon_image}"
                )

            except Exception as e:
                # If the container was spawned but a subsequent step failed,
                # clean it up so we don't leave an orphan running.
                if "container" in dir() and container:
                    try:
                        container.remove(force=True)
                        logger.info(
                            f"Cleaned up orphan container {container.id[:12]} "
                            f"after failure in {project_id}"
                        )
                    except Exception:
                        logger.debug(
                            f"Could not remove container after failure", exc_info=True
                        )
                state.status = ReconStatus.ERROR
                state.error = str(e)
                logger.error(f"Failed to start recon for {project_id}: {e}")

            self._save_state()
            return state

    def _cleanup_sub_containers(self, since: datetime | None = None) -> int:
        """Stop and remove any running sub-containers (naabu, httpx, nuclei, etc.)

        Args:
            since: Only clean containers created at or after this timestamp.
                   When None, cleans ALL matching sub-containers (full recon stop).

        Returns the count of containers cleaned up.
        """
        cleaned = 0
        try:
            # Find all running containers
            containers = self.client.containers.list(all=True)
            for container in containers:
                try:
                    # Apply time-based filter for selective cleanup
                    if since is not None:
                        created_at = container.attrs.get("Created", "0")
                        try:
                            # Docker Created is RFC 3339 or Unix timestamp as string
                            created_ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        except (ValueError, AttributeError):
                            try:
                                created_ts = datetime.fromtimestamp(float(created_at), tz=timezone.utc)
                            except (ValueError, TypeError):
                                created_ts = datetime.now(timezone.utc)
                        if created_ts < since:
                            continue

                    # Check if container image matches any sub-container image
                    image_tags = container.image.tags if container.image.tags else []
                    image_name = container.attrs.get("Config", {}).get("Image", "")

                    for sub_image in SUB_CONTAINER_IMAGES:
                        # Match by image name or tags
                        if (sub_image in image_name or
                            any(sub_image in tag for tag in image_tags)):
                            container_name = container.name
                            container_status = container.status

                            # Stop if running or paused
                            if container_status in ("running", "paused"):
                                if container_status == "paused":
                                    logger.info(f"Unpausing sub-container before stop: {container_name} ({sub_image})")
                                    container.unpause()
                                logger.info(f"Stopping sub-container: {container_name} ({sub_image})")
                                container.stop(timeout=5)

                            # Remove container
                            logger.info(f"Removing sub-container: {container_name} ({sub_image})")
                            container.remove(force=True)
                            cleaned += 1
                            break

                except Exception as e:
                    logger.warning(f"Error cleaning up container {container.name}: {e}")

        except Exception as e:
            logger.error(f"Error listing containers for cleanup: {e}")

        return cleaned

    async def pause_recon(self, project_id: str) -> ReconState:
        """Pause a running recon process using Docker cgroups freeze"""
        state = await self.get_status(project_id)

        if state.status != ReconStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = ReconStatus.PAUSED
                self.running_states[project_id] = state
                logger.info(f"Paused recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to pause: {e}"

        self._save_state()
        return state

    async def resume_recon(self, project_id: str) -> ReconState:
        """Resume a paused recon process"""
        state = await self.get_status(project_id)

        if state.status != ReconStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = ReconStatus.RUNNING
                self.running_states[project_id] = state
                logger.info(f"Resumed recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to resume: {e}"

        self._save_state()
        return state

    async def stop_recon(self, project_id: str, timeout: int = 10) -> ReconState:
        """Stop a running recon process"""
        state = await self.get_status(project_id)

        if state.status not in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            return state

        state.status = ReconStatus.STOPPING

        if state.container_id:
            try:
                container = await self._exec(self.client.containers.get, state.container_id)
                # Unpause before stopping for Docker version compatibility
                if container.status == "paused":
                    await self._exec(container.unpause)
                await self._exec(container.stop, timeout=timeout)
                await self._exec(container.remove)
                state.status = ReconStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped recon container for project {project_id}")
            except NotFound:
                state.status = ReconStatus.IDLE
            except Exception as e:
                state.status = ReconStatus.ERROR
                state.error = f"Failed to stop: {e}"

        # Record audit entry for manual stop
        started = state.started_at or state.completed_at
        duration = None
        if started and state.completed_at:
            duration = (state.completed_at - started).total_seconds()
        self._add_audit_entry(ReconAuditEntry(
            run_id=project_id,
            project_id=project_id,
            pipeline_type="full",
            status="completed",
            started_at=state.started_at,
            completed_at=state.completed_at,
            duration_seconds=duration,
            phases_completed=state.phase_number or 0,
            total_phases=state.total_phases,
            error=state.error if state.status == ReconStatus.ERROR else None,
        ))

        # Clean up sub-containers created after this recon started
        cleaned = await self._exec(self._cleanup_sub_containers, since=state.started_at)
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} sub-container(s) for project {project_id}")

        # Clear any stale partial-recon ancestry entries for this project.
        # Key format: run_id (UUID) — we check by iterating all keys and
        # dropping those whose partial-recon state no longer exists.
        project_run_ids = set(self.partial_recon_states.get(project_id, {}).keys())
        for rid in list(self._sub_container_ancestry.keys()):
            if rid not in project_run_ids:
                stale = self._sub_container_ancestry.pop(rid, set())
                if stale:
                    logger.debug(f"Cleared stale ancestry for {rid} ({len(stale)} container(s))")

        # Clean up state
        if project_id in self.running_states:
            del self.running_states[project_id]

        self._save_state()
        return state

    def _parse_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> ReconLogEvent:
        """Parse a log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes (terminal colors) from log line
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level based on prefix symbols only
        # [!] = error (red), [+]/[✓] = success (green), [*] = action (blue), no symbol = info (gray)
        if "[!]" in line:
            level = "error"  # Red
        elif "[+]" in line or "[✓]" in line:
            level = "success"  # Green
        elif "[*]" in line:
            level = "action"  # Blue

        # Detect phase changes
        for pattern, phase_name, num in PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return ReconLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def _check_roe_mid_run(self, project_id: str) -> bool:
        """Re-validate the RoE time window mid-run.

        Returns True if the recon should continue, False if it should stop
        (i.e., the current time is outside the allowed window).
        """
        webapp_api_url = self._project_webapp_urls.get(project_id)
        if not webapp_api_url:
            return True  # No URL stored — can't check, proceed

        # Throttle checks to at most once every 5 minutes
        now = datetime.now(timezone.utc)
        last_check = self._last_roe_check.get(project_id)
        if last_check and (now - last_check) < timedelta(minutes=5):
            return True
        self._last_roe_check[project_id] = now

        try:
            from api import _fetch_project_json
            project = await _fetch_project_json(webapp_api_url, project_id)
            if not project:
                return True  # Can't fetch — proceed

            if not (project.get('roeEnabled') and project.get('roeTimeWindowEnabled')):
                return True  # RoE not enabled — proceed

            try:
                import zoneinfo
            except ImportError:
                from backports import zoneinfo

            tz_name = project.get('roeTimeWindowTimezone', 'UTC')
            tz = zoneinfo.ZoneInfo(tz_name)
            now_local = datetime.now(tz)
            day_name = now_local.strftime('%A').lower()
            allowed_days = project.get('roeTimeWindowDays', [])
            start_time = project.get('roeTimeWindowStartTime', '09:00')
            end_time = project.get('roeTimeWindowEndTime', '18:00')
            current_time = now_local.strftime('%H:%M')

            if day_name not in allowed_days:
                logger.warning(
                    f"RoE mid-run blocked project_id={project_id}: "
                    f"day={day_name} not in {allowed_days}"
                )
                return False

            if start_time <= end_time:
                outside = current_time < start_time or current_time > end_time
            else:
                outside = current_time < start_time and current_time > end_time
            if outside:
                logger.warning(
                    f"RoE mid-run blocked project_id={project_id}: "
                    f"time={current_time} outside window {start_time}-{end_time} {tz_name}"
                )
                return False

            logger.info(
                f"RoE mid-run passed project_id={project_id} "
                f"day={day_name} time={current_time}"
            )
            return True

        except Exception as e:
            logger.warning(
                f"RoE mid-run check failed for project_id={project_id} "
                f"(proceeding): {e}"
            )
            return True  # Error — proceed to be safe

    async def stream_logs(self, project_id: str) -> AsyncGenerator[ReconLogEvent, None]:
        """Stream logs from a recon container"""
        state = await self.get_status(project_id)

        # The container may still be starting (Docker image build, etc.).
        # Wait for it to become available instead of immediately erroring.
        if not state.container_id:
            for attempt in range(30):  # up to 30 seconds
                await asyncio.sleep(1)
                state = await self.get_status(project_id)
                if state.container_id:
                    break
            else:
                yield ReconLogEvent(
                    log="No container found for this project (timeout after 30s)",
                    timestamp=datetime.now(timezone.utc),
                    level="error",
                )
                return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            # Use a bounded asyncio queue to bridge sync Docker logs to the
            # async generator. Bound prevents unbounded memory if consumer lags.
            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=1000)

            # Capture the event loop before starting the thread (needed for closure)
            loop = asyncio.get_running_loop()

            # On reconnect, resume from the last timestamp we already emitted so
            # the SSE client doesn't receive duplicate history. Docker's `since`
            # is second-granular, so advance by 1us to avoid re-emitting the
            # boundary line (timestamps we tracked are sub-second precise).
            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            # In-memory dedup ring: catches lines Docker re-emits when since= truncates to second granularity
            _dedup_ring: dict[tuple[str, int], None] = {}
            _dedup_ring_max = 200

            def read_logs():
                """Synchronous function to read logs and put them in the queue"""
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, line),
                            loop
                        ).result(timeout=5)
                        # Check if container is still running
                        try:
                            container.reload()
                            if container.status not in ("running", "paused"):
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in log reader thread: {e}")
                finally:
                    # Signal end of logs
                    try:
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        logger.warning("read_logs: asyncio.run_coroutine_threadsafe(", exc_info=True)
                        pass

            # Start log reader in the dedicated streaming executor
            # (separate from default executor to avoid starving short-lived tasks)
            self._log_executor.submit(read_logs)

            # Process logs from queue
            seq = 0
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix (RFC3339Nano format)
                        docker_ts = None
                        log_text = decoded_line
                        # Docker timestamps look like: 2024-01-15T10:30:00.123456789Z <log line>
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    # Truncate nanoseconds to microseconds for stdlib compatibility
                                    # Docker: 2024-01-15T10:30:00.123456789Z -> 2024-01-15T10:30:00.123456+00:00
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]  # max 6 digits
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        seq += 1
                        event.seq = seq

                        # Update current phase tracking
                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            # Update state
                            if project_id in self.running_states:
                                self.running_states[project_id].current_phase = current_phase
                                self.running_states[project_id].phase_number = current_phase_num

                            # Re-validate RoE time window on phase transitions
                            if not await self._check_roe_mid_run(project_id):
                                logger.warning(
                                    f"RoE window closed during phase transition "
                                    f"for project_id={project_id}; stopping recon"
                                )
                                yield ReconLogEvent(
                                    log="[RoE] Time window has closed — stopping recon per Rules of Engagement",
                                    timestamp=datetime.now(timezone.utc),
                                    level="warning",
                                )
                                # Gracefully stop the container
                                try:
                                    await self.stop_recon(project_id)
                                except Exception:
                                    pass
                                return

                        # Track the high-water mark so a reconnecting SSE client
                        # resumes after this line instead of replaying history.
                        if docker_ts is not None:
                            self._update_last_log_timestamp(
                                self.running_states.get(project_id), docker_ts
                            )

                        # Dedup against Docker second-granular since= re-emission
                        if docker_ts is not None:
                            _dedup_key = (log_text, int(docker_ts.timestamp()))
                            if _dedup_key in _dedup_ring:
                                continue
                            _dedup_ring[_dedup_key] = None
                            if len(_dedup_ring) > _dedup_ring_max:
                                _dedup_ring.pop(next(iter(_dedup_ring)))
                        yield event

                except asyncio.TimeoutError:
                    # Check if container is still running or paused
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

                    # Periodic RoE mid-run check (throttled to every 5 min internally)
                    if not await self._check_roe_mid_run(project_id):
                        logger.warning(
                            f"RoE window closed mid-run for project_id={project_id}; "
                            f"stopping recon"
                        )
                        try:
                            await self.stop_recon(project_id)
                        except Exception:
                            pass
                        break

        except (NotFound, APIError):
            yield ReconLogEvent(
                log="Container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield ReconLogEvent(
                log=f"Error streaming logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_running_count(self) -> int:
        """Get count of running recon processes"""
        return sum(1 for s in self.running_states.values() if s.status == ReconStatus.RUNNING)

    async def cleanup(self):
        """Cleanup all running containers on shutdown"""
        for project_id in list(self.running_states.keys()):
            try:
                await self.stop_recon(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up recon {project_id}: {e}")
        for project_id, runs in list(self.partial_recon_states.items()):
            for run_id in list(runs.keys()):
                try:
                    await self.stop_partial_recon(project_id, run_id, timeout=5)
                except Exception as e:
                    logger.error(f"Error cleaning up partial recon {project_id}/{run_id}: {e}")
        for project_id in list(self.gvm_states.keys()):
            try:
                await self.stop_gvm_scan(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up GVM {project_id}: {e}")
        for project_id in list(self.github_hunt_states.keys()):
            try:
                await self.stop_github_hunt(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up GitHub hunt {project_id}: {e}")
        for project_id in list(self.trufflehog_states.keys()):
            try:
                await self.stop_trufflehog(project_id, timeout=5)
            except Exception as e:
                logger.error(f"Error cleaning up TruffleHog {project_id}: {e}")
        self._log_executor.shutdown(wait=False)

    # =========================================================================
    # Partial Recon Container Lifecycle
    # =========================================================================

    def _get_partial_container_name(self, project_id: str, run_id: str) -> str:
        """Generate container name for a partial recon run"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-partial-recon-{safe_id}-{run_id[:8]}"

    def _count_active_partial_recons(self, project_id: str) -> int:
        """Count the number of active (running/starting) partial recons for a project"""
        return sum(
            1 for s in self.partial_recon_states.get(project_id, {}).values()
            if s.status in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING)
        )

    def _refresh_partial_recon_state(self, state: PartialReconState) -> None:
        """Refresh a partial recon state by checking its Docker container"""
        if not state.container_id:
            return
        if state.status in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR, PartialReconStatus.IDLE, PartialReconStatus.PAUSED):
            return

        try:
            container = self.client.containers.get(state.container_id)
            if container.status != "running":
                exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                was_completed = False
                if exit_code == 0:
                    state.status = PartialReconStatus.COMPLETED
                    state.completed_at = datetime.now(timezone.utc)
                    was_completed = True
                else:
                    state.status = PartialReconStatus.ERROR
                    state.error = f"Container exited with code {exit_code}"
                    state.completed_at = datetime.now(timezone.utc)

                # Record audit trail entry for partial recon
                started = state.started_at or state.completed_at
                duration = None
                if started and state.completed_at:
                    duration = (state.completed_at - started).total_seconds()
                self._add_audit_entry(ReconAuditEntry(
                    run_id=state.run_id,
                    project_id=state.project_id,
                    pipeline_type="partial",
                    tool_id=state.tool_id,
                    status="completed" if was_completed else "error",
                    started_at=state.started_at,
                    completed_at=state.completed_at,
                    duration_seconds=duration,
                    error=state.error,
                ))

                try:
                    container.remove()
                    logger.info(f"Auto-removed partial recon container for {state.project_id}/{state.run_id}")
                except Exception as e:
                    logger.warning(f"Failed to auto-remove partial container: {e}")
        except NotFound:
            if state.status not in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR):
                state.status = PartialReconStatus.ERROR
                state.error = "Container not found"
        except APIError as e:
            logger.warning(f"Docker API error checking partial recon {state.project_id}/{state.run_id}: {e}")

    async def get_partial_recon_status(self, project_id: str, run_id: str) -> PartialReconState:
        """Get current status of a specific partial recon run"""
        runs = self.partial_recon_states.get(project_id, {})
        state = runs.get(run_id)
        if state:
            self._refresh_partial_recon_state(state)
            return state

        return PartialReconState(
            project_id=project_id,
            run_id=run_id,
            status=PartialReconStatus.IDLE,
        )

    async def get_all_partial_recon_statuses(self, project_id: str) -> list[PartialReconState]:
        """Get all partial recon states for a project, refreshing container status.
        Auto-cleans completed/errored entries older than 60 seconds.
        """
        runs = self.partial_recon_states.get(project_id, {})
        to_remove = []

        for run_id, state in runs.items():
            self._refresh_partial_recon_state(state)
            # Auto-clean old completed/errored entries
            if state.status in (PartialReconStatus.COMPLETED, PartialReconStatus.ERROR):
                if state.completed_at and (datetime.now(timezone.utc) - state.completed_at).total_seconds() > 60:
                    to_remove.append(run_id)

        for run_id in to_remove:
            del runs[run_id]
        if not runs and project_id in self.partial_recon_states:
            del self.partial_recon_states[project_id]

        return list(runs.values())

    async def start_partial_recon(
        self,
        project_id: str,
        tool_id: str,
        config: dict,
        recon_path: str,
        custom_templates_path: str = "",
    ) -> PartialReconState:
        """Start a partial recon container for a specific tool.

        Args:
            project_id: Project identifier
            tool_id: Tool to run (e.g., "SubdomainDiscovery")
            config: Full config dict to write as JSON for the container
            recon_path: Host path to the recon directory
            custom_templates_path: Host path to mc/nuclei-templates so the
                spawned container can sibling-mount it for nuclei. Without
                this, custom-template selection is silently ignored and
                build_nuclei_command falls back to the full ~8000-template
                pool (the bug Ritesh hit before this fix).
        """
        # Check concurrency limit
        if self._count_active_partial_recons(project_id) >= MAX_PARALLEL_PARTIAL_RECONS:
            raise ValueError(f"Maximum {MAX_PARALLEL_PARTIAL_RECONS} concurrent partial recons reached for project {project_id}")

        # Mutual exclusion with full recon
        recon_state = await self.get_status(project_id)
        if recon_state.status in (ReconStatus.RUNNING, ReconStatus.PAUSED):
            raise ValueError(f"Full recon is running for project {project_id}. Stop it first.")

        run_id = str(uuid.uuid4())
        container_name = self._get_partial_container_name(project_id, run_id)

        state = PartialReconState(
            project_id=project_id,
            run_id=run_id,
            tool_id=tool_id,
            status=PartialReconStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.partial_recon_states.setdefault(project_id, {})[run_id] = state
        self._save_state()
        logger.info(
            f"start_partial_recon project_id={project_id} tool_id={tool_id} run_id={run_id} "
            f"container_name={container_name}"
        )

        try:
            # Ensure recon image exists (with retry)
            await self._ensure_recon_image(context=f"for partial recon {run_id}")

            # Write config JSON to /tmp/redamon/ (shared volume)
            import json
            config_dir = Path("/tmp/redamon")
            config_dir.mkdir(parents=True, exist_ok=True)
            config_path = config_dir / f"partial_{project_id}_{run_id}.json"
            with open(config_path, "w") as f:
                json.dump(config, f)
            logger.info(f"Wrote partial recon config to {config_path} for run {run_id}")

            logger.info(
                f"Spawning partial recon container {container_name} for project {project_id} "
                f"tool_id={tool_id} run_id={run_id}"
            )

            # Start container with the partial_recon.py entry point
            container = await self._exec(
                self.client.containers.run,
                self.recon_image,
                name=container_name,
                detach=True,
                network_mode="host",
                privileged=True,
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": config.get("user_id", ""),
                    "WEBAPP_API_URL": config.get("webapp_api_url", ""),
                    "PARTIAL_RECON_CONFIG": f"/tmp/redamon/partial_{project_id}_{run_id}.json",
                    "PARTIAL_RECON_RUN_ID": run_id,
                    "UPDATE_GRAPH_DB": "true",
                    "HOST_RECON_OUTPUT_PATH": f"{recon_path}/output",
                    # Required for nuclei custom-template support: build_nuclei_command
                    # uses this env var to bind-mount mcp/nuclei-templates into the
                    # sibling nuclei container. Without it, custom-template selection
                    # is silently dropped and the full built-in pool runs instead.
                    "HOST_CUSTOM_TEMPLATES_PATH": custom_templates_path,
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                    # Agent API for AI hooks (FFuf AI extensions, etc.)
                    "AGENT_API_URL": os.environ.get("AGENT_API_URL", "http://localhost:8090"),
                },
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
                    f"{recon_path}": {"bind": "/app/recon", "mode": "rw"},
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                    "/tmp/redamon": {"bind": "/tmp/redamon", "mode": "rw"},
                    # JS Recon shared volumes with webapp (uploaded files + custom patterns)
                    "redamon_js_recon_uploads": {"bind": "/data/js-recon-uploads", "mode": "ro"},
                    "redamon_js_recon_custom": {"bind": "/data/js-recon-custom", "mode": "ro"},
                    # Official nuclei-templates volume (read-only) for the AI tag
                    # selector to read TEMPLATES-STATS.json.
                    "nuclei-templates": {"bind": "/opt/nuclei-templates-official", "mode": "ro"},
                },
                command="python /app/recon/partial_recon.py",
            )

            state.container_id = container.id
            state.status = PartialReconStatus.RUNNING
            # Track this container in ancestry for precise sub-container cleanup
            self._sub_container_ancestry.setdefault(run_id, set()).add(container.id)
            logger.info(
                f"Started partial recon container {container.id[:12]} for project {project_id}, "
                f"tool {tool_id}, run {run_id}"
            )

        except Exception as e:
            # If the container was spawned but a subsequent step failed,
            # clean it up so we don't leave an orphan running.
            if "container" in dir() and container:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Could not remove orphan container", exc_info=True)
            state.status = PartialReconStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start partial recon for {project_id}/{run_id}: {e}")

        self._save_state()
        return state

    async def stop_partial_recon(self, project_id: str, run_id: str, timeout: int = 10) -> PartialReconState:
        """Stop a specific partial recon run"""
        state = await self.get_partial_recon_status(project_id, run_id)

        if state.status not in (PartialReconStatus.RUNNING, PartialReconStatus.STARTING, PartialReconStatus.PAUSED):
            return state

        state.status = PartialReconStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = PartialReconStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped partial recon container for project {project_id}, run {run_id}")
            except NotFound:
                state.status = PartialReconStatus.IDLE
            except Exception as e:
                state.status = PartialReconStatus.ERROR
                state.error = f"Failed to stop: {e}"

        # Container-level ancestry cleanup: kill only sub-containers known to
        # belong to this run, avoiding the imprecise since=timestamp filter
        # that could orphan or over-kill sibling containers from parallel runs.
        container_ids = self._sub_container_ancestry.pop(run_id, set())
        # Exclude the main container (already stopped above) to avoid redundant
        # stop/remove calls that would hit NotFound.
        if state.container_id in container_ids:
            container_ids.discard(state.container_id)
        cleaned = 0
        for cid in container_ids:
            try:
                container = self.client.containers.get(cid)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=5)
                container.remove(force=True)
                cleaned += 1
            except NotFound:
                pass  # already gone
            except Exception as e:
                logger.warning(f"Error cleaning up sub-container {cid}: {e}")
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} sub-container(s) for partial recon {run_id}")

        # Remove from state dict
        runs = self.partial_recon_states.get(project_id, {})
        if run_id in runs:
            del runs[run_id]
        if not runs and project_id in self.partial_recon_states:
            del self.partial_recon_states[project_id]

        # Best-effort cleanup of config file
        try:
            config_path = Path(f"/tmp/redamon/partial_{project_id}_{run_id}.json")
            if config_path.exists():
                config_path.unlink()
        except Exception:
            logger.warning("_refresh_partial_recon_state: config_path = Path(f'/tmp/redamon/partial_{project_id}_{run_id}.json')", exc_info=True)
            pass

        self._save_state()
        return state

    async def pause_partial_recon(self, project_id: str, run_id: str) -> PartialReconState:
        """Pause a specific partial recon using Docker cgroups freeze"""
        state = await self.get_partial_recon_status(project_id, run_id)

        if state.status != PartialReconStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = PartialReconStatus.PAUSED
                logger.info(f"Paused partial recon container for project {project_id}, run {run_id}")
            except NotFound:
                state.status = PartialReconStatus.ERROR
                state.error = "Container not found"
            except Exception as e:
                state.status = PartialReconStatus.ERROR
                state.error = f"Failed to pause: {e}"

        # Persist back to partial recon states
        runs = self.partial_recon_states.get(project_id, {})
        if run_id in runs:
            runs[run_id] = state
        self._save_state()
        return state

    async def resume_partial_recon(self, project_id: str, run_id: str) -> PartialReconState:
        """Resume a paused partial recon"""
        state = await self.get_partial_recon_status(project_id, run_id)

        if state.status != PartialReconStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = PartialReconStatus.RUNNING
                logger.info(f"Resumed partial recon container for project {project_id}, run {run_id}")
            except NotFound:
                state.status = PartialReconStatus.ERROR
                state.error = "Container not found"
            except Exception as e:
                state.status = PartialReconStatus.ERROR
                state.error = f"Failed to resume: {e}"

        runs = self.partial_recon_states.get(project_id, {})
        if run_id in runs:
            runs[run_id] = state
        self._save_state()
        return state

    async def stream_partial_logs(self, project_id: str, run_id: str) -> AsyncGenerator[ReconLogEvent, None]:
        """Stream logs from a specific partial recon container.
        Reuses the same log parsing logic as full recon.
        """
        state = await self.get_partial_recon_status(project_id, run_id)

        # The container may still be starting — wait for it.
        if not state.container_id:
            for attempt in range(30):
                await asyncio.sleep(1)
                state = await self.get_partial_recon_status(project_id, run_id)
                if state.container_id:
                    break
            else:
                yield ReconLogEvent(
                    log="No partial recon container found for this project (timeout after 30s)",
                    timestamp=datetime.now(timezone.utc),
                    level="error",
                )
                return

        current_phase: Optional[str] = "Partial Recon"
        current_phase_num: Optional[int] = 1

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=1000)
            loop = asyncio.get_running_loop()

            # On reconnect, resume from the last timestamp we already emitted so
            # the SSE client doesn't receive duplicate history. Docker's `since`
            # is second-granular, so advance by 1us to avoid re-emitting the
            # boundary line (timestamps we tracked are sub-second precise).
            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            # In-memory dedup ring: catches lines Docker re-emits when since= truncates to second granularity
            _dedup_ring: dict[tuple[str, int], None] = {}
            _dedup_ring_max = 200

            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, line), loop
                        ).result(timeout=5)
                        try:
                            container.reload()
                            if container.status not in ("running", "paused"):
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in partial recon log reader: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, None), loop
                        ).result(timeout=5)
                    except Exception:
                        logger.warning("read_logs: asyncio.run_coroutine_threadsafe(", exc_info=True)
                        pass

            self._log_executor.submit(read_logs)

            seq = 0
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        seq += 1
                        event.seq = seq
                        # Partial recon always runs a single tool/phase, so pin
                        # phase_number to 1 regardless of which full-pipeline
                        # pattern the line happens to match (e.g. NUCLEI => 5).
                        event.phase_number = 1
                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = 1
                        # Track the high-water mark so a reconnecting SSE client
                        # resumes after this line instead of replaying history.
                        if docker_ts is not None:
                            if project_id in self.partial_recon_states and run_id in self.partial_recon_states[project_id]:
                                cur = self.partial_recon_states[project_id][run_id].last_log_timestamp
                                if cur is None or docker_ts > cur:
                                    self.partial_recon_states[project_id][run_id].last_log_timestamp = docker_ts
                        # Dedup against Docker second-granular since= re-emission
                        if docker_ts is not None:
                            _dedup_key = (log_text, int(docker_ts.timestamp()))
                            if _dedup_key in _dedup_ring:
                                continue
                            _dedup_ring[_dedup_key] = None
                            if len(_dedup_ring) > _dedup_ring_max:
                                _dedup_ring.pop(next(iter(_dedup_ring)))
                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield ReconLogEvent(
                log="Partial recon container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield ReconLogEvent(
                log=f"Error streaming partial recon logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    # =========================================================================
    # GVM Vulnerability Scan Container Lifecycle
    # =========================================================================

    def _get_gvm_container_name(self, project_id: str) -> str:
        """Generate container name for a GVM scan"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-gvm-{safe_id}"

    async def get_gvm_status(self, project_id: str) -> GvmState:
        """Get current status of a GVM scan process"""
        if project_id in self.gvm_states:
            state = self.gvm_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = GvmStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = GvmStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = GvmStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished GVM container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove GVM container: {e}")
                except NotFound:
                    if state.status not in (GvmStatus.COMPLETED, GvmStatus.ERROR):
                        state.status = GvmStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking GVM container for {project_id}: {e}")
                    if state.status not in (GvmStatus.COMPLETED, GvmStatus.ERROR):
                        state.status = GvmStatus.ERROR
                        state.error = f"Docker API error: {e}"

            self._save_state()
            return state

        # Check if there's an orphan container
        container_name = self._get_gvm_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return GvmState(
                    project_id=project_id,
                    status=GvmStatus.PAUSED if container.status == "paused" else GvmStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return GvmState(
            project_id=project_id,
            status=GvmStatus.IDLE,
        )

    async def start_gvm_scan(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        recon_path: str,
        gvm_scan_path: str,
    ) -> GvmState:
        """Start a GVM vulnerability scanner container for a project"""

        # Check if already running or paused
        current_state = await self.get_gvm_status(project_id)
        if current_state.status in (GvmStatus.RUNNING, GvmStatus.PAUSED):
            raise ValueError(f"GVM scan already active for project {project_id}")

        # Clean up any existing container
        container_name = self._get_gvm_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old GVM container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = GvmState(
            project_id=project_id,
            status=GvmStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.gvm_states[project_id] = state
        self._save_state()

        try:
            # Wait for GVM feed sync before spawning the scanner. This avoids
            # scanner crashes when gvmd is not yet ready to accept connections.
            from gvm_ready_helper import probe_gvm_readiness

            readiness = probe_gvm_readiness(timeout=60)
            if not readiness["ready"]:
                raise RuntimeError(readiness["message"])

            # Ensure GVM scanner image exists (pre-build on startup if missing)
            if not self.ensure_gvm_scanner_image():
                raise RuntimeError(
                    f"GVM scanner image {self.gvm_image} is missing and could not be built"
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.gvm_image,
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                    # GVM connection settings
                    "GVM_SOCKET_PATH": os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"),
                    "GVM_USERNAME": os.environ.get("GVM_USERNAME", "admin"),
                    "GVM_PASSWORD": os.environ.get("GVM_PASSWORD", "admin"),
                },
                volumes={
                    # GVM socket for communicating with gvmd
                    "redamon_gvmd_socket": {"bind": "/run/gvmd", "mode": "ro"},
                    # Recon output (read-only, for extracting targets)
                    f"{recon_path}/output": {"bind": "/app/recon/output", "mode": "ro"},
                    # GVM scan output (read-write, for saving results)
                    f"{gvm_scan_path}/output": {"bind": "/app/gvm_scan/output", "mode": "rw"},
                    # Mount graph_db module for Neo4j updates
                    f"{Path(recon_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                    # Mount gvm_scan source for development (no rebuild needed)
                    f"{gvm_scan_path}": {"bind": "/app/gvm_scan", "mode": "rw"},
                },
                command="python gvm_scan/main.py",
            )

            state.container_id = container.id
            state.status = GvmStatus.RUNNING
            logger.info(f"Started GVM scanner container {container.id} for project {project_id}")

        except Exception as e:
            if "container" in dir() and container:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Could not remove orphan container", exc_info=True)
            state.status = GvmStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start GVM scan for {project_id}: {e}")

        self._save_state()
        return state

    async def pause_gvm_scan(self, project_id: str) -> GvmState:
        """Pause a running GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status != GvmStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = GvmStatus.PAUSED
                self.gvm_states[project_id] = state
                logger.info(f"Paused GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to pause: {e}"

        self._save_state()
        return state

    async def resume_gvm_scan(self, project_id: str) -> GvmState:
        """Resume a paused GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status != GvmStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = GvmStatus.RUNNING
                self.gvm_states[project_id] = state
                logger.info(f"Resumed GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to resume: {e}"

        self._save_state()
        return state

    async def stop_gvm_scan(self, project_id: str, timeout: int = 10) -> GvmState:
        """Stop a running GVM scan process"""
        state = await self.get_gvm_status(project_id)

        if state.status not in (GvmStatus.RUNNING, GvmStatus.PAUSED):
            return state

        state.status = GvmStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = GvmStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped GVM container for project {project_id}")
            except NotFound:
                state.status = GvmStatus.IDLE
            except Exception as e:
                state.status = GvmStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.gvm_states:
            del self.gvm_states[project_id]

        self._save_state()
        return state

    def _parse_gvm_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> GvmLogEvent:
        """Parse a GVM log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"

        # Detect phase changes
        for pattern, phase_name, num in GVM_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return GvmLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_gvm_logs(self, project_id: str) -> AsyncGenerator[GvmLogEvent, None]:
        """Stream logs from a GVM scanner container"""
        state = await self.get_gvm_status(project_id)

        if not state.container_id:
            for attempt in range(30):
                await asyncio.sleep(1)
                state = await self.get_gvm_status(project_id)
                if state.container_id:
                    break
            else:
                yield GvmLogEvent(
                    log="No GVM container found for this project (timeout after 30s)",
                    timestamp=datetime.now(timezone.utc),
                    level="error",
                )
                return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=1000)
            loop = asyncio.get_running_loop()

            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            # In-memory dedup ring: catches lines Docker re-emits when since= truncates to second granularity
            _dedup_ring: dict[tuple[str, int], None] = {}
            _dedup_ring_max = 200

            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, line),
                            loop
                        ).result(timeout=5)
                        try:
                            container.reload()
                            if container.status not in ("running", "paused"):
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in GVM log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        logger.warning("read_logs: asyncio.run_coroutine_threadsafe(", exc_info=True)
                        pass

            self._log_executor.submit(read_logs)

            seq = 0
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_gvm_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        seq += 1
                        event.seq = seq

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.gvm_states:
                                self.gvm_states[project_id].current_phase = current_phase
                                self.gvm_states[project_id].phase_number = current_phase_num

                        if docker_ts is not None:
                            self._update_last_log_timestamp(
                                self.gvm_states.get(project_id), docker_ts
                            )

                        # Dedup against Docker second-granular since= re-emission
                        if docker_ts is not None:
                            _dedup_key = (log_text, int(docker_ts.timestamp()))
                            if _dedup_key in _dedup_ring:
                                continue
                            _dedup_ring[_dedup_key] = None
                            if len(_dedup_ring) > _dedup_ring_max:
                                _dedup_ring.pop(next(iter(_dedup_ring)))
                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield GvmLogEvent(
                log="GVM container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield GvmLogEvent(
                log=f"Error streaming GVM logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_gvm_running_count(self) -> int:
        """Get count of running GVM scan processes"""
        return sum(1 for s in self.gvm_states.values() if s.status == GvmStatus.RUNNING)

    def is_gvm_available(self) -> bool:
        """Check if GVM stack is installed by looking for the gvmd container"""
        try:
            container = self.client.containers.get("redamon-gvm-gvmd")
            return container.status == "running"
        except Exception:
            return False

    def build_gvm_scanner_image(
        self,
        build_path: str = "/app",
        dockerfile: str = "gvm_scan/Dockerfile",
    ) -> bool:
        """Build the GVM scanner image ahead of first scan."""
        try:
            logger.info(
                f"Pre-building GVM scanner image from {build_path}/{dockerfile}"
            )
            self.client.images.build(
                path=build_path,
                dockerfile=dockerfile,
                tag=self.gvm_image,
                rm=True,
            )
            logger.info(f"GVM scanner image built: {self.gvm_image}")
            return True
        except Exception as e:
            logger.error(f"Failed to build GVM scanner image: {e}")
            return False

    def ensure_gvm_scanner_image(self) -> bool:
        """Ensure the GVM scanner image exists; build it if missing (with retry)."""
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                self.client.images.get(self.gvm_image)
                return True
            except NotFound:
                if attempt < max_retries:
                    logger.info(
                        f"GVM scanner image {self.gvm_image} not found; building "
                        f"(attempt {attempt}/{max_retries})"
                    )
                    if self.build_gvm_scanner_image():
                        return True
                    time.sleep(2 ** (attempt - 1))
                else:
                    logger.info(
                        f"GVM scanner image {self.gvm_image} not found; "
                        f"final build attempt"
                    )
                    return self.build_gvm_scanner_image()
            except Exception as e:
                logger.error(f"Failed to check GVM scanner image: {e}")
                if attempt >= max_retries:
                    return False
                time.sleep(2 ** (attempt - 1))

    def _probe_gvm_feed_sync(self) -> Tuple[bool, dict]:
        """Run a one-off readiness probe against the gvmd socket."""
        gvm_scan_path = os.environ.get("GVM_SCAN_PATH", "/app/gvm_scan")
        try:
            output = self.client.containers.run(
                self.gvm_image,
                remove=True,
                network_mode="host",
                volumes={
                    "redamon_gvmd_socket": {"bind": "/run/gvmd", "mode": "ro"},
                    # Mount live source so the probe picks up the current code
                    # without requiring an image rebuild.
                    gvm_scan_path: {"bind": "/app/gvm_scan", "mode": "ro"},
                },
                environment={
                    "GVM_SOCKET_PATH": os.environ.get(
                        "GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock"
                    ),
                    "GVM_USERNAME": os.environ.get("GVM_USERNAME", "admin"),
                    "GVM_PASSWORD": os.environ.get("GVM_PASSWORD", "admin"),
                    "PYTHONPATH": "/app",
                },
                command=[
                    "python",
                    "-m",
                    "gvm_scan.ready_probe",
                    "--json",
                    "--max-retries",
                    "3",
                ],
                stdout=True,
                stderr=True,
            )
            result = json.loads(output.decode("utf-8"))
            return bool(result.get("ready", False)), result
        except Exception as e:
            logger.warning(f"GVM readiness probe failed: {e}")
            return False, {"error": str(e)}

    def is_gvm_ready(self, timeout: int = 0, max_age: int = 60) -> bool:
        """
        Check if GVM has finished feed sync and is ready to run scans.

        Args:
            timeout: If > 0, block up to this many seconds waiting for readiness.
            max_age: Cache validity in seconds for probe results.

        Returns:
            True if GVM is available and feed sync is complete.
        """
        if not self.is_gvm_available():
            self._gvm_ready_cache = (False, datetime.now(timezone.utc))
            return False

        def _cached_or_probe() -> bool:
            now = datetime.now(timezone.utc)
            cached_ready, cached_at = self._gvm_ready_cache
            if cached_ready is not None and now - cached_at < timedelta(seconds=max_age):
                return bool(cached_ready)
            ready, _ = self._probe_gvm_feed_sync()
            self._gvm_ready_cache = (ready, datetime.now(timezone.utc))
            return ready

        if timeout <= 0:
            return _cached_or_probe()

        deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
        while datetime.now(timezone.utc) < deadline:
            if _cached_or_probe():
                return True
            time.sleep(5)
        return False

    # =========================================================================
    # GitHub Secret Hunt Container Lifecycle
    # =========================================================================

    def _get_github_hunt_container_name(self, project_id: str) -> str:
        """Generate container name for a GitHub hunt"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-github-hunt-{safe_id}"

    async def get_github_hunt_status(self, project_id: str) -> GithubHuntState:
        """Get current status of a GitHub hunt process"""
        if project_id in self.github_hunt_states:
            state = self.github_hunt_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = GithubHuntStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = GithubHuntStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = GithubHuntStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished GitHub hunt container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove GitHub hunt container: {e}")
                except NotFound:
                    if state.status not in (GithubHuntStatus.COMPLETED, GithubHuntStatus.ERROR):
                        state.status = GithubHuntStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking GitHub hunt container for {project_id}: {e}")
                    if state.status not in (GithubHuntStatus.COMPLETED, GithubHuntStatus.ERROR):
                        state.status = GithubHuntStatus.ERROR
                        state.error = f"Docker API error: {e}"

            self._save_state()
            return state

        # Check if there's an orphan container
        container_name = self._get_github_hunt_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return GithubHuntState(
                    project_id=project_id,
                    status=GithubHuntStatus.PAUSED if container.status == "paused" else GithubHuntStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return GithubHuntState(
            project_id=project_id,
            status=GithubHuntStatus.IDLE,
        )

    async def start_github_hunt(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        github_hunt_path: str,
    ) -> GithubHuntState:
        """Start a GitHub secret hunt container for a project"""

        # Check if already running
        current_state = await self.get_github_hunt_status(project_id)
        if current_state.status in (GithubHuntStatus.RUNNING, GithubHuntStatus.PAUSED):
            raise ValueError(f"GitHub hunt already active for project {project_id}")

        # Clean up any existing container
        container_name = self._get_github_hunt_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old GitHub hunt container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = GithubHuntState(
            project_id=project_id,
            status=GithubHuntStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.github_hunt_states[project_id] = state
        self._save_state()

        try:
            # Ensure GitHub hunt image exists
            try:
                self.client.images.get(self.github_hunt_image)
            except NotFound:
                build_path = "/app"
                dockerfile = f"{Path(github_hunt_path).name}/Dockerfile"
                logger.info(f"Building GitHub hunt image from {build_path}/{dockerfile}")
                self.client.images.build(
                    path=build_path,
                    dockerfile=dockerfile,
                    tag=self.github_hunt_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.github_hunt_image,
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    # GitHub hunt output (read-write, for saving results)
                    f"{github_hunt_path}/output": {"bind": "/app/github_secret_hunt/output", "mode": "rw"},
                    # Mount github_secret_hunt source for development (no rebuild needed)
                    f"{github_hunt_path}": {"bind": "/app/github_secret_hunt", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    f"{Path(github_hunt_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                },
                command="python github_secret_hunt/main.py",
            )

            state.container_id = container.id
            state.status = GithubHuntStatus.RUNNING
            logger.info(f"Started GitHub hunt container {container.id} for project {project_id}")

        except Exception as e:
            if "container" in dir() and container:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Could not remove orphan container", exc_info=True)
            state.status = GithubHuntStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start GitHub hunt for {project_id}: {e}")

        self._save_state()
        return state

    async def pause_github_hunt(self, project_id: str) -> GithubHuntState:
        """Pause a running GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status != GithubHuntStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = GithubHuntStatus.PAUSED
                self.github_hunt_states[project_id] = state
                logger.info(f"Paused GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to pause: {e}"

        self._save_state()
        return state

    async def resume_github_hunt(self, project_id: str) -> GithubHuntState:
        """Resume a paused GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status != GithubHuntStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = GithubHuntStatus.RUNNING
                self.github_hunt_states[project_id] = state
                logger.info(f"Resumed GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to resume: {e}"

        self._save_state()
        return state

    async def stop_github_hunt(self, project_id: str, timeout: int = 10) -> GithubHuntState:
        """Stop a running GitHub hunt process"""
        state = await self.get_github_hunt_status(project_id)

        if state.status not in (GithubHuntStatus.RUNNING, GithubHuntStatus.PAUSED):
            return state

        state.status = GithubHuntStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = GithubHuntStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped GitHub hunt container for project {project_id}")
            except NotFound:
                state.status = GithubHuntStatus.IDLE
            except Exception as e:
                state.status = GithubHuntStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.github_hunt_states:
            del self.github_hunt_states[project_id]

        self._save_state()
        return state

    def _parse_github_hunt_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> GithubHuntLogEvent:
        """Parse a GitHub hunt log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line or "[!!!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"
        elif "[~]" in line:
            level = "warning"

        # Detect phase changes
        for pattern, phase_name, num in GITHUB_HUNT_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return GithubHuntLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_github_hunt_logs(self, project_id: str) -> AsyncGenerator[GithubHuntLogEvent, None]:
        """Stream logs from a GitHub hunt container"""
        state = await self.get_github_hunt_status(project_id)

        if not state.container_id:
            for attempt in range(30):
                await asyncio.sleep(1)
                state = await self.get_github_hunt_status(project_id)
                if state.container_id:
                    break
            else:
                yield GithubHuntLogEvent(
                    log="No GitHub hunt container found for this project (timeout after 30s)",
                    timestamp=datetime.now(timezone.utc),
                    level="error",
                )
                return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=1000)
            loop = asyncio.get_running_loop()

            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            # In-memory dedup ring: catches lines Docker re-emits when since= truncates to second granularity
            _dedup_ring: dict[tuple[str, int], None] = {}
            _dedup_ring_max = 200

            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, line),
                            loop
                        ).result(timeout=5)
                        try:
                            container.reload()
                            if container.status not in ("running", "paused"):
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in GitHub hunt log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        logger.warning("read_logs: asyncio.run_coroutine_threadsafe(", exc_info=True)
                        pass

            self._log_executor.submit(read_logs)

            seq = 0
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_github_hunt_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        seq += 1
                        event.seq = seq

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.github_hunt_states:
                                self.github_hunt_states[project_id].current_phase = current_phase
                                self.github_hunt_states[project_id].phase_number = current_phase_num

                        if docker_ts is not None:
                            self._update_last_log_timestamp(
                                self.github_hunt_states.get(project_id), docker_ts
                            )

                        # Dedup against Docker second-granular since= re-emission
                        if docker_ts is not None:
                            _dedup_key = (log_text, int(docker_ts.timestamp()))
                            if _dedup_key in _dedup_ring:
                                continue
                            _dedup_ring[_dedup_key] = None
                            if len(_dedup_ring) > _dedup_ring_max:
                                _dedup_ring.pop(next(iter(_dedup_ring)))
                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield GithubHuntLogEvent(
                log="GitHub hunt container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield GithubHuntLogEvent(
                log=f"Error streaming GitHub hunt logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_github_hunt_running_count(self) -> int:
        """Get count of running GitHub hunt processes"""
        return sum(1 for s in self.github_hunt_states.values() if s.status == GithubHuntStatus.RUNNING)

    # =========================================================================
    # TruffleHog Secret Scanner Container Lifecycle
    # =========================================================================

    def _get_trufflehog_container_name(self, project_id: str) -> str:
        """Generate container name for a TruffleHog scan"""
        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', project_id)
        return f"redamon-trufflehog-{safe_id}"

    async def get_trufflehog_status(self, project_id: str) -> TrufflehogState:
        """Get current status of a TruffleHog scan process"""
        if project_id in self.trufflehog_states:
            state = self.trufflehog_states[project_id]

            if state.container_id:
                try:
                    container = self.client.containers.get(state.container_id)
                    if container.status == "paused":
                        state.status = TrufflehogStatus.PAUSED
                    elif container.status != "running":
                        exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                        if exit_code == 0:
                            state.status = TrufflehogStatus.COMPLETED
                            state.completed_at = datetime.now(timezone.utc)
                        else:
                            state.status = TrufflehogStatus.ERROR
                            state.error = f"Container exited with code {exit_code}"
                            state.completed_at = datetime.now(timezone.utc)

                        try:
                            container.remove()
                            logger.info(f"Auto-removed finished TruffleHog container for project {project_id}")
                        except Exception as e:
                            logger.warning(f"Failed to auto-remove TruffleHog container: {e}")
                except NotFound:
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = "Container not found"
                except APIError as e:
                    logger.warning(f"Docker API error checking TruffleHog container for {project_id}: {e}")
                    if state.status not in (TrufflehogStatus.COMPLETED, TrufflehogStatus.ERROR):
                        state.status = TrufflehogStatus.ERROR
                        state.error = f"Docker API error: {e}"

            self._save_state()
            return state

        # Check if there's an orphan container
        container_name = self._get_trufflehog_container_name(project_id)
        try:
            container = self.client.containers.get(container_name)
            if container.status in ("running", "paused"):
                return TrufflehogState(
                    project_id=project_id,
                    status=TrufflehogStatus.PAUSED if container.status == "paused" else TrufflehogStatus.RUNNING,
                    container_id=container.id,
                )
        except NotFound:
            pass

        return TrufflehogState(
            project_id=project_id,
            status=TrufflehogStatus.IDLE,
        )

    async def start_trufflehog(
        self,
        project_id: str,
        user_id: str,
        webapp_api_url: str,
        trufflehog_path: str,
    ) -> TrufflehogState:
        """Start a TruffleHog scan container for a project"""

        # Check if already running
        current_state = await self.get_trufflehog_status(project_id)
        if current_state.status in (TrufflehogStatus.RUNNING, TrufflehogStatus.PAUSED):
            raise ValueError(f"TruffleHog scan already active for project {project_id}")

        # Clean up any existing container
        container_name = self._get_trufflehog_container_name(project_id)
        try:
            old_container = self.client.containers.get(container_name)
            old_container.remove(force=True)
            logger.info(f"Removed old TruffleHog container {container_name}")
        except NotFound:
            pass

        # Create new state
        state = TrufflehogState(
            project_id=project_id,
            status=TrufflehogStatus.STARTING,
            started_at=datetime.now(timezone.utc),
        )
        self.trufflehog_states[project_id] = state
        self._save_state()

        try:
            # Ensure TruffleHog image exists
            try:
                self.client.images.get(self.trufflehog_image)
            except NotFound:
                build_path = "/app"
                dockerfile = f"{Path(trufflehog_path).name}/Dockerfile"
                logger.info(f"Building TruffleHog image from {build_path}/{dockerfile}")
                self.client.images.build(
                    path=build_path,
                    dockerfile=dockerfile,
                    tag=self.trufflehog_image,
                    rm=True,
                )

            # Start container with environment variables
            container = self.client.containers.run(
                self.trufflehog_image,
                name=container_name,
                detach=True,
                network_mode="host",
                environment={
                    "PROJECT_ID": project_id,
                    "USER_ID": user_id,
                    "WEBAPP_API_URL": webapp_api_url,
                    "PYTHONUNBUFFERED": "1",
                    # Forward Neo4j credentials from orchestrator environment
                    "NEO4J_URI": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                    "NEO4J_USER": os.environ.get("NEO4J_USER", "neo4j"),
                    "NEO4J_PASSWORD": os.environ.get("NEO4J_PASSWORD", ""),
                    "INTERNAL_API_KEY": os.environ.get("INTERNAL_API_KEY", ""),
                },
                volumes={
                    # TruffleHog output (read-write, for saving results)
                    f"{trufflehog_path}/output": {"bind": "/app/trufflehog_scan/output", "mode": "rw"},
                    # Mount trufflehog_scan source for development (no rebuild needed)
                    f"{trufflehog_path}": {"bind": "/app/trufflehog_scan", "mode": "rw"},
                    # Mount graph_db module for Neo4j integration
                    f"{Path(trufflehog_path).parent}/graph_db": {"bind": "/app/graph_db", "mode": "ro"},
                },
                command="python trufflehog_scan/main.py",
            )

            state.container_id = container.id
            state.status = TrufflehogStatus.RUNNING
            logger.info(f"Started TruffleHog container {container.id} for project {project_id}")

        except Exception as e:
            if "container" in dir() and container:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Could not remove orphan container", exc_info=True)
            state.status = TrufflehogStatus.ERROR
            state.error = str(e)
            logger.error(f"Failed to start TruffleHog scan for {project_id}: {e}")

        self._save_state()
        return state

    async def pause_trufflehog(self, project_id: str) -> TrufflehogState:
        """Pause a running TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status != TrufflehogStatus.RUNNING:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.pause()
                state.status = TrufflehogStatus.PAUSED
                self.trufflehog_states[project_id] = state
                logger.info(f"Paused TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to pause: {e}"

        self._save_state()
        return state

    async def resume_trufflehog(self, project_id: str) -> TrufflehogState:
        """Resume a paused TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status != TrufflehogStatus.PAUSED:
            return state

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                container.unpause()
                state.status = TrufflehogStatus.RUNNING
                self.trufflehog_states[project_id] = state
                logger.info(f"Resumed TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.ERROR
                state.error = "Container not found"
            except APIError as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to resume: {e}"

        self._save_state()
        return state

    async def stop_trufflehog(self, project_id: str, timeout: int = 10) -> TrufflehogState:
        """Stop a running TruffleHog scan process"""
        state = await self.get_trufflehog_status(project_id)

        if state.status not in (TrufflehogStatus.RUNNING, TrufflehogStatus.PAUSED):
            return state

        state.status = TrufflehogStatus.STOPPING

        if state.container_id:
            try:
                container = self.client.containers.get(state.container_id)
                if container.status == "paused":
                    container.unpause()
                container.stop(timeout=timeout)
                container.remove()
                state.status = TrufflehogStatus.IDLE
                state.completed_at = datetime.now(timezone.utc)
                logger.info(f"Stopped TruffleHog container for project {project_id}")
            except NotFound:
                state.status = TrufflehogStatus.IDLE
            except Exception as e:
                state.status = TrufflehogStatus.ERROR
                state.error = f"Failed to stop: {e}"

        if project_id in self.trufflehog_states:
            del self.trufflehog_states[project_id]

        self._save_state()
        return state

    def _parse_trufflehog_log_line(self, line: str, current_phase: Optional[str], current_phase_num: Optional[int], timestamp: Optional[datetime] = None) -> TrufflehogLogEvent:
        """Parse a TruffleHog log line and detect phase changes"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        phase = current_phase
        phase_num = current_phase_num
        is_phase_start = False
        level = "info"

        # Strip ANSI escape codes
        line = ANSI_ESCAPE.sub('', line)

        # Detect log level
        if "[!]" in line or "[!!!]" in line:
            level = "error"
        elif "[+]" in line or "[✓]" in line:
            level = "success"
        elif "[*]" in line:
            level = "action"
        elif "[~]" in line:
            level = "warning"

        # Detect phase changes
        for pattern, phase_name, num in TRUFFLEHOG_PHASE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                if phase_name != current_phase:
                    phase = phase_name
                    phase_num = num
                    is_phase_start = True
                break

        return TrufflehogLogEvent(
            log=line.rstrip(),
            timestamp=timestamp,
            phase=phase,
            phase_number=phase_num,
            is_phase_start=is_phase_start,
            level=level,
        )

    async def stream_trufflehog_logs(self, project_id: str) -> AsyncGenerator[TrufflehogLogEvent, None]:
        """Stream logs from a TruffleHog scan container"""
        state = await self.get_trufflehog_status(project_id)

        if not state.container_id:
            for attempt in range(30):
                await asyncio.sleep(1)
                state = await self.get_trufflehog_status(project_id)
                if state.container_id:
                    break
            else:
                yield TrufflehogLogEvent(
                    log="No TruffleHog container found for this project (timeout after 30s)",
                    timestamp=datetime.now(timezone.utc),
                    level="error",
                )
                return

        current_phase: Optional[str] = None
        current_phase_num: Optional[int] = None

        try:
            container = self.client.containers.get(state.container_id)

            log_queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=1000)
            loop = asyncio.get_running_loop()

            since_ts = None
            if state.last_log_timestamp is not None:
                since_ts = state.last_log_timestamp + timedelta(microseconds=1)

            # In-memory dedup ring: catches lines Docker re-emits when since= truncates to second granularity
            _dedup_ring: dict[tuple[str, int], None] = {}
            _dedup_ring_max = 200

            def read_logs():
                try:
                    log_stream_kwargs = {"stream": True, "follow": True, "timestamps": True}
                    if since_ts is not None:
                        log_stream_kwargs["since"] = since_ts
                    for line in container.logs(**log_stream_kwargs):
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, line),
                            loop
                        ).result(timeout=5)
                        try:
                            container.reload()
                            if container.status not in ("running", "paused"):
                                break
                        except Exception:
                            break
                except Exception as e:
                    logger.error(f"Error in TruffleHog log reader thread: {e}")
                finally:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            ContainerManager._bounded_queue_put(log_queue, None),
                            loop
                        ).result(timeout=5)
                    except Exception:
                        logger.warning("read_logs: asyncio.run_coroutine_threadsafe(", exc_info=True)
                        pass

            self._log_executor.submit(read_logs)

            seq = 0
            while True:
                try:
                    line = await asyncio.wait_for(log_queue.get(), timeout=1.0)
                    if line is None:
                        break

                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        # Parse Docker timestamp prefix
                        docker_ts = None
                        log_text = decoded_line
                        if len(decoded_line) > 30 and decoded_line[4] == '-' and decoded_line[10] == 'T':
                            space_idx = decoded_line.find(' ')
                            if space_idx > 0:
                                ts_str = decoded_line[:space_idx]
                                try:
                                    ts_clean = ts_str.replace('Z', '+00:00')
                                    dot_idx = ts_clean.find('.')
                                    plus_idx = ts_clean.find('+', dot_idx) if dot_idx > 0 else -1
                                    if dot_idx > 0 and plus_idx > 0:
                                        frac = ts_clean[dot_idx + 1:plus_idx][:6]
                                        ts_clean = ts_clean[:dot_idx + 1] + frac + ts_clean[plus_idx:]
                                    docker_ts = datetime.fromisoformat(ts_clean)
                                    log_text = decoded_line[space_idx + 1:]
                                except (ValueError, OverflowError):
                                    pass

                        event = self._parse_trufflehog_log_line(log_text, current_phase, current_phase_num, timestamp=docker_ts)
                        seq += 1
                        event.seq = seq

                        if event.is_phase_start:
                            current_phase = event.phase
                            current_phase_num = event.phase_number

                            if project_id in self.trufflehog_states:
                                self.trufflehog_states[project_id].current_phase = current_phase
                                self.trufflehog_states[project_id].phase_number = current_phase_num

                        if docker_ts is not None:
                            self._update_last_log_timestamp(
                                self.trufflehog_states.get(project_id), docker_ts
                            )

                        # Dedup against Docker second-granular since= re-emission
                        if docker_ts is not None:
                            _dedup_key = (log_text, int(docker_ts.timestamp()))
                            if _dedup_key in _dedup_ring:
                                continue
                            _dedup_ring[_dedup_key] = None
                            if len(_dedup_ring) > _dedup_ring_max:
                                _dedup_ring.pop(next(iter(_dedup_ring)))
                        yield event

                except asyncio.TimeoutError:
                    try:
                        container.reload()
                        if container.status not in ("running", "paused"):
                            break
                    except Exception:
                        break

        except (NotFound, APIError):
            yield TrufflehogLogEvent(
                log="TruffleHog container stopped",
                timestamp=datetime.now(timezone.utc),
                level="info",
            )
        except Exception as e:
            yield TrufflehogLogEvent(
                log=f"Error streaming TruffleHog logs: {e}",
                timestamp=datetime.now(timezone.utc),
                level="error",
            )

    def get_trufflehog_running_count(self) -> int:
        """Get count of running TruffleHog scan processes"""
        return sum(1 for s in self.trufflehog_states.values() if s.status == TrufflehogStatus.RUNNING)
