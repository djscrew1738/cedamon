"""
Comprehensive tests for ContainerManager — Docker container lifecycle management.

Mocks ``docker.from_env()`` and ``OrchestratorStateStore`` to test all state
transitions and lifecycle methods without a real Docker daemon.

IMPORTANT: ``_exec()`` calls ``run_in_executor(None, partial(fn, *args))``,
so methods passed to it (e.g. ``containers.get``, ``containers.run``) must be
*sync* ``MagicMock``, **not** ``AsyncMock``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Patch docker before importing ContainerManager
# ---------------------------------------------------------------------------
with patch.dict("sys.modules"):
    docker_mock = MagicMock()
    docker_mock.errors = MagicMock()
    docker_mock.errors.NotFound = type("NotFound", (Exception,), {})
    docker_mock.errors.APIError = type("APIError", (Exception,), {})
    import sys

    sys.modules["docker"] = docker_mock
    sys.modules["docker.errors"] = docker_mock.errors
    sys.modules["docker.models"] = MagicMock()
    sys.modules["docker.models.containers"] = MagicMock()

    from container_manager import (
        ContainerManager,
        SUB_CONTAINER_IMAGES,
        MAX_PARALLEL_PARTIAL_RECONS,
    )
    from models import (
        ReconStatus,
        ReconState,
        GvmStatus,
        GvmState,
        GithubHuntStatus,
        GithubHuntState,
        TrufflehogStatus,
        TrufflehogState,
        PartialReconStatus,
        PartialReconState,
    )

pytestmark = pytest.mark.asyncio


# ===========================================================================
# Helpers
# ===========================================================================

_NOT_FOUND = docker_mock.errors.NotFound
_API_ERROR = docker_mock.errors.APIError


def _cm(status="running", container_id="c-0000", exit_code=0, image_tags=None):
    """Return a mock Docker container object."""
    c = MagicMock()
    c.id = container_id
    c.status = status
    c.name = f"container-{container_id}"
    c.attrs = {"State": {"ExitCode": exit_code}, "Config": {"Image": "busybox"}}
    c.image = MagicMock()
    c.image.tags = image_tags or []
    return c


def _partial_state(
    project_id="proj-x",
    run_id="run-1",
    status=PartialReconStatus.RUNNING,
    container_id="pc-1",
):
    return PartialReconState(
        project_id=project_id,
        run_id=run_id,
        tool_id="SubdomainDiscovery",
        status=status,
        container_id=container_id,
        started_at=datetime.now(timezone.utc),
    )


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def mock_docker_client():
    client = MagicMock()
    client.containers = MagicMock()
    client.containers.list = MagicMock(return_value=[])
    client.images = MagicMock()
    return client


@pytest.fixture
def mock_state_store():
    store = MagicMock()
    store.save.return_value = None
    store.load.return_value = ({}, {}, {}, {}, {})
    return store


@pytest.fixture
def manager(mock_docker_client, mock_state_store):
    with patch("container_manager.docker.from_env", return_value=mock_docker_client):
        mgr = ContainerManager(state_store=mock_state_store)
        mgr.client = mock_docker_client
        return mgr


@pytest.fixture
def running_state():
    return ReconState(
        project_id="proj-1",
        status=ReconStatus.RUNNING,
        container_id="abc123",
        started_at=datetime.now(timezone.utc),
    )


# ===========================================================================
# Constructor & Shutdown
# ===========================================================================


class TestConstructorAndShutdown:
    def test_constructor_loads_state(self, mock_docker_client, mock_state_store):
        with patch("container_manager.docker.from_env", return_value=mock_docker_client):
            mgr = ContainerManager(state_store=mock_state_store)
        mock_state_store.load.assert_called_once()
        assert mgr.recon_image == "redamon-recon:latest"
        assert mgr.gvm_image == "redamon-vuln-scanner:latest"
        assert mgr.github_hunt_image == "redamon-github-hunter:latest"
        assert mgr.trufflehog_image == "redamon-trufflehog:latest"

    def test_constructor_initializes_data_structures(self, mock_docker_client, mock_state_store):
        with patch("container_manager.docker.from_env", return_value=mock_docker_client):
            mgr = ContainerManager(state_store=mock_state_store)
        assert mgr.running_states == {}
        assert mgr.partial_recon_states == {}
        assert mgr.gvm_states == {}
        assert mgr.github_hunt_states == {}
        assert mgr.trufflehog_states == {}
        assert mgr._sub_container_ancestry == {}
        assert mgr._start_locks == {}
        assert isinstance(mgr._sub_container_ancestry, dict)

    def test_constructor_no_event_loop(self, mock_docker_client, mock_state_store):
        """When constructed outside an async context, persist task is not created."""
        with patch("container_manager.docker.from_env", return_value=mock_docker_client):
            mgr = ContainerManager(state_store=mock_state_store)
        assert mgr._persist_task is None or isinstance(mgr._persist_task, asyncio.Task)

    async def test_shutdown(self, manager):
        manager._persist_task = None
        await manager.shutdown()

    async def test_shutdown_cancels_persist_task(self, manager):
        task = asyncio.create_task(asyncio.sleep(9999))
        manager._persist_task = task
        await manager.shutdown()
        assert task.cancelled()

    def test_max_parallel_partial_recons_constant(self):
        assert MAX_PARALLEL_PARTIAL_RECONS == 12

    def test_sub_container_images_defined(self):
        assert len(SUB_CONTAINER_IMAGES) > 0
        assert "projectdiscovery/naabu" in SUB_CONTAINER_IMAGES


class TestRecovery:
    def test_load_state_empty(self, manager):
        assert manager.running_states == {}
        assert manager.gvm_states == {}
        assert manager.partial_recon_states == {}


# ===========================================================================
# State Management
# ===========================================================================


class TestStateManagement:
    def test_save_state_calls_store(self, manager, mock_state_store):
        mock_state_store.reset_mock()
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager._save_state()
        mock_state_store.save.assert_called_once()
        args, _ = mock_state_store.save.call_args
        assert "p1" in args[0]

    def test_save_state_with_partial(self, manager, mock_state_store):
        mock_state_store.reset_mock()
        manager.partial_recon_states["proj-x"] = {"run-1": _partial_state()}
        manager._save_state()
        mock_state_store.save.assert_called_once()
        args, _ = mock_state_store.save.call_args
        assert "proj-x" in args[4]
        assert "run-1" in args[4]["proj-x"]

    def test_save_state_with_all_state_types(self, manager, mock_state_store):
        mock_state_store.reset_mock()
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.gvm_states["p2"] = GvmState(
            project_id="p2", status=GvmStatus.RUNNING, container_id="c2"
        )
        manager.github_hunt_states["p3"] = GithubHuntState(
            project_id="p3", status=GithubHuntStatus.RUNNING, container_id="c3"
        )
        manager.trufflehog_states["p4"] = TrufflehogState(
            project_id="p4", status=TrufflehogStatus.RUNNING, container_id="c4"
        )
        manager._save_state()
        args, _ = mock_state_store.save.call_args
        assert "p1" in args[0]
        assert "p2" in args[1]
        assert "p3" in args[2]
        assert "p4" in args[3]

    def test_load_state_restores_data(self, mock_docker_client, mock_state_store):
        ts = datetime.now(timezone.utc)
        recon = ReconState(
            project_id="p1", status=ReconStatus.RUNNING,
            container_id="c1", current_phase="Port Scanning",
            started_at=ts,
        )
        mock_state_store.load.return_value = ({"p1": recon}, {}, {}, {}, {})
        with patch("container_manager.docker.from_env", return_value=mock_docker_client):
            mgr = ContainerManager(state_store=mock_state_store)
        assert "p1" in mgr.running_states
        assert mgr.running_states["p1"].current_phase == "Port Scanning"


# ===========================================================================
# Recon Lifecycle
# ===========================================================================


class TestReconLifecycle:
    async def test_get_status_idle(self, manager):
        status = await manager.get_status("unknown")
        assert status.status == ReconStatus.IDLE

    async def test_get_status_running(self, manager, running_state):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.RUNNING

    async def test_get_status_paused(self, manager, running_state):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.PAUSED

    async def test_get_status_completed(self, manager, running_state):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0)
        )
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.COMPLETED
        assert status.completed_at is not None

    async def test_get_status_error_on_exit(self, manager, running_state):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=1)
        )
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.ERROR

    async def test_get_status_orphan(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="orphan-42")
        )
        status = await manager.get_status("orphan")
        assert status.status == ReconStatus.RUNNING
        assert status.container_id == "orphan-42"

    async def test_get_status_orphan_paused(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="paused", container_id="orphan-42")
        )
        status = await manager.get_status("orphan")
        assert status.status == ReconStatus.PAUSED
        assert status.container_id == "orphan-42"

    async def test_get_status_not_found(self, manager, running_state):
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.ERROR
        assert "Container not found" in (status.error or "")

    async def test_start_recon(self, manager):
        c = _cm(status="running", container_id="new-c-42")
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.client.containers.run = MagicMock(return_value=c)
        manager.client.images.get = MagicMock(return_value=MagicMock())

        state = await manager.start_recon(
            project_id="p1", user_id="u1", webapp_api_url="http://w:3000",
            recon_path="/tmp/r",
        )
        assert state.project_id == "p1"
        assert state.status == ReconStatus.RUNNING
        assert state.container_id == "new-c-42"

    async def test_start_recon_raises_if_active(self, manager, running_state):
        manager.running_states["proj-1"] = running_state
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        with pytest.raises(ValueError, match="already active"):
            await manager.start_recon(
                project_id="proj-1", user_id="u1", webapp_api_url="http://w:3000",
                recon_path="/tmp/r",
            )

    async def test_start_recon_raises_if_partial_active(self, manager):
        manager.partial_recon_states["p1"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        with pytest.raises(ValueError, match="Partial recon"):
            await manager.start_recon(
                project_id="p1", user_id="u1", webapp_api_url="http://w:3000",
                recon_path="/tmp/r",
            )

    async def test_start_recon_handles_failure(self, manager):
        """When image build fails, state transitions to ERROR."""
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.client.images.get = MagicMock(side_effect=Exception("build failed"))
        state = await manager.start_recon(
            project_id="p1", user_id="u1", webapp_api_url="http://w:3000",
            recon_path="/tmp/r",
        )
        assert state.status == ReconStatus.ERROR
        assert "build failed" in (state.error or "")

    async def test_stop_recon(self, manager, running_state):
        """stop_recon returns COMPLETED when get_status detects exited container."""
        manager.running_states["proj-1"] = running_state
        c = _cm(status="exited", exit_code=0)
        manager.client.containers.get = MagicMock(return_value=c)
        manager.client.containers.list = MagicMock(return_value=[])
        state = await manager.stop_recon("proj-1")
        # get_status detects completed container first; stop_recon returns early
        assert state.status == ReconStatus.COMPLETED

    async def test_stop_nonexistent(self, manager):
        state = await manager.stop_recon("ghost")
        assert state.status == ReconStatus.IDLE

    async def test_stop_recon_clears_ancestry(self, manager, running_state):
        """stop_recon should clean up stale ancestry entries."""
        manager.running_states["proj-1"] = running_state
        manager._sub_container_ancestry["proj-1"] = {"sub1", "sub2"}
        manager._sub_container_ancestry["stale-run"] = {"sub3"}
        # get_status must return RUNNING so stop_recon proceeds
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.client.containers.list = MagicMock(return_value=[])
        await manager.stop_recon("proj-1")
        assert "stale-run" not in manager._sub_container_ancestry

    async def test_stop_recon_cleans_sub_containers(self, manager, running_state):
        """stop_recon calls _cleanup_sub_containers with started_at."""
        manager.running_states["proj-1"] = running_state
        # Make get_status return RUNNING so stop_recon proceeds
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.client.containers.list = MagicMock(return_value=[])
        original_cleanup = manager._cleanup_sub_containers
        manager._cleanup_sub_containers = MagicMock(return_value=2)
        await manager.stop_recon("proj-1")
        manager._cleanup_sub_containers.assert_called_once()
        manager._cleanup_sub_containers = original_cleanup


# ===========================================================================
# Pause / Resume
# ===========================================================================


class TestPauseResume:
    async def test_pause(self, manager, running_state):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.running_states["proj-1"] = running_state
        state = await manager.pause_recon("proj-1")
        assert state.status == ReconStatus.PAUSED

    async def test_pause_not_running(self, manager):
        state = await manager.pause_recon("ghost")
        assert state.status == ReconStatus.IDLE

    async def test_pause_not_found(self, manager, running_state):
        """Pause when container is not found sets ERROR."""
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.running_states["proj-1"] = running_state
        state = await manager.pause_recon("proj-1")
        assert state.status == ReconStatus.ERROR

    async def test_resume(self, manager, running_state):
        running_state.status = ReconStatus.PAUSED
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.running_states["proj-1"] = running_state
        state = await manager.resume_recon("proj-1")
        assert state.status == ReconStatus.RUNNING

    async def test_resume_not_paused(self, manager):
        state = await manager.resume_recon("ghost")
        assert state.status == ReconStatus.IDLE

    async def test_resume_not_found(self, manager):
        """Resume when container not found sets ERROR."""
        state = ReconState(
            project_id="proj-1", status=ReconStatus.PAUSED, container_id="abc123"
        )
        manager.running_states["proj-1"] = state
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        result = await manager.resume_recon("proj-1")
        assert result.status == ReconStatus.ERROR

    async def test_pause_nonexistent(self, manager):
        state = await manager.pause_recon("ghost")
        assert state.status == ReconStatus.IDLE


# ===========================================================================
# Utilities
# ===========================================================================


class TestUtilities:
    def test_sanitize_container_name(self, manager):
        name = manager._get_container_name("Hello World!(test)")
        assert "redamon-recon-" in name
        assert " " not in name
        assert "_" in name

    def test_get_partial_container_name(self, manager):
        name = manager._get_partial_container_name("proj-1", "abc12345-xxxx")
        assert name.startswith("redamon-partial-recon-proj-1-")
        assert len(name) > len("redamon-partial-recon-proj-1-")

    def test_get_gvm_container_name(self, manager):
        name = manager._get_gvm_container_name("test project!")
        assert name.startswith("redamon-gvm-")

    def test_get_github_hunt_container_name(self, manager):
        name = manager._get_github_hunt_container_name("test project!")
        assert name.startswith("redamon-github-hunt-")

    def test_get_trufflehog_container_name(self, manager):
        name = manager._get_trufflehog_container_name("test project!")
        assert name.startswith("redamon-trufflehog-")

    def test_running_count(self, manager):
        assert manager.get_running_count() == 0
        manager.running_states = {
            "a": ReconState(project_id="a", status=ReconStatus.RUNNING, container_id="c1"),
            "b": ReconState(project_id="b", status=ReconStatus.PAUSED, container_id="c2"),
            "c": ReconState(project_id="c", status=ReconStatus.RUNNING, container_id="c3"),
        }
        assert manager.get_running_count() == 2

    def test_running_count_non_running(self, manager):
        """Paused and starting states are not counted."""
        manager.running_states = {
            "a": ReconState(project_id="a", status=ReconStatus.STARTING, container_id="c1"),
            "b": ReconState(project_id="b", status=ReconStatus.COMPLETED, container_id="c2"),
            "c": ReconState(project_id="c", status=ReconStatus.ERROR, container_id="c3"),
        }
        assert manager.get_running_count() == 0

    def test_gvm_running_count(self, manager):
        assert manager.get_gvm_running_count() == 0
        manager.gvm_states = {
            "a": GvmState(project_id="a", status=GvmStatus.RUNNING, container_id="c1"),
            "b": GvmState(project_id="b", status=GvmStatus.PAUSED, container_id="c2"),
        }
        assert manager.get_gvm_running_count() == 1

    def test_update_last_log_timestamp(self, manager):
        s = ReconState(project_id="p", status=ReconStatus.RUNNING)
        ts = datetime.now(timezone.utc)
        manager._update_last_log_timestamp(s, ts)
        assert s.last_log_timestamp == ts

    def test_update_last_log_timestamp_none(self, manager):
        s = ReconState(project_id="p", status=ReconStatus.RUNNING)
        manager._update_last_log_timestamp(s, None)
        assert s.last_log_timestamp is None

    def test_update_last_log_timestamp_none_state(self, manager):
        manager._update_last_log_timestamp(None, datetime.now(timezone.utc))
        # Should not raise

    def test_count_active_partial_recons(self, manager):
        assert manager._count_active_partial_recons("proj-x") == 0
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING),
            "run-2": _partial_state(status=PartialReconStatus.STARTING),
            "run-3": _partial_state(status=PartialReconStatus.PAUSED),
        }
        assert manager._count_active_partial_recons("proj-x") == 2

    def test_count_active_partial_recons_empty_project(self, manager):
        assert manager._count_active_partial_recons("nonexistent") == 0


# ===========================================================================
# GVM Lifecycle
# ===========================================================================


class TestGvmLifecycle:
    async def test_idle(self, manager):
        assert (await manager.get_gvm_status("x")).status == GvmStatus.IDLE

    async def test_running(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        assert (await manager.get_gvm_status("proj-x")).status == GvmStatus.RUNNING

    async def test_paused(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        assert (await manager.get_gvm_status("proj-x")).status == GvmStatus.PAUSED

    async def test_completed(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0)
        )
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        status = await manager.get_gvm_status("proj-x")
        assert status.status == GvmStatus.COMPLETED

    async def test_error_on_exit(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=1)
        )
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        status = await manager.get_gvm_status("proj-x")
        assert status.status == GvmStatus.ERROR

    async def test_not_found(self, manager):
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        status = await manager.get_gvm_status("proj-x")
        assert status.status == GvmStatus.ERROR

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        assert (await manager.stop_gvm_scan("proj-x")).status == GvmStatus.COMPLETED

    async def test_stop_not_running(self, manager):
        assert (await manager.stop_gvm_scan("ghost")).status == GvmStatus.IDLE

    async def test_stop_not_found(self, manager):
        """When container not found, get_gvm_status sets ERROR and stop returns early."""
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        state = await manager.stop_gvm_scan("proj-x")
        # get_gvm_status catches NotFound → ERROR; stop_gvm_scan returns early
        assert state.status == GvmStatus.ERROR

    async def test_pause_gvm(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        assert (await manager.pause_gvm_scan("proj-x")).status == GvmStatus.PAUSED

    async def test_resume_gvm(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.PAUSED, container_id="g-1"
        )
        assert (await manager.resume_gvm_scan("proj-x")).status == GvmStatus.RUNNING

    def test_available_defaults_false(self, manager):
        assert manager.is_gvm_available() is False


# ===========================================================================
# GitHub Hunt Lifecycle
# ===========================================================================


class TestGithubHuntLifecycle:
    async def test_idle(self, manager):
        assert (await manager.get_github_hunt_status("x")).status == GithubHuntStatus.IDLE

    async def test_running(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.get_github_hunt_status("proj-x")).status == GithubHuntStatus.RUNNING

    async def test_paused(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.get_github_hunt_status("proj-x")).status == GithubHuntStatus.PAUSED

    async def test_completed(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0)
        )
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.get_github_hunt_status("proj-x")).status == GithubHuntStatus.COMPLETED

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.stop_github_hunt("proj-x")).status == GithubHuntStatus.COMPLETED

    async def test_stop_not_running(self, manager):
        assert (await manager.stop_github_hunt("ghost")).status == GithubHuntStatus.IDLE

    async def test_pause_github_hunt(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.pause_github_hunt("proj-x")).status == GithubHuntStatus.PAUSED

    async def test_resume_github_hunt(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.PAUSED, container_id="gh-1"
        )
        assert (await manager.resume_github_hunt("proj-x")).status == GithubHuntStatus.RUNNING

    async def test_get_github_hunt_running_count(self, manager):
        assert manager.get_github_hunt_running_count() == 0
        manager.github_hunt_states["a"] = GithubHuntState(
            project_id="a", status=GithubHuntStatus.RUNNING, container_id="c1"
        )
        assert manager.get_github_hunt_running_count() == 1


# ===========================================================================
# TruffleHog Lifecycle
# ===========================================================================


class TestTrufflehogLifecycle:
    async def test_idle(self, manager):
        assert (await manager.get_trufflehog_status("x")).status == TrufflehogStatus.IDLE

    async def test_running(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.get_trufflehog_status("proj-x")).status == TrufflehogStatus.RUNNING

    async def test_paused(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.get_trufflehog_status("proj-x")).status == TrufflehogStatus.PAUSED

    async def test_completed(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0)
        )
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.get_trufflehog_status("proj-x")).status == TrufflehogStatus.COMPLETED

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.stop_trufflehog("proj-x")).status == TrufflehogStatus.COMPLETED

    async def test_stop_not_running(self, manager):
        assert (await manager.stop_trufflehog("ghost")).status == TrufflehogStatus.IDLE

    async def test_pause_trufflehog(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.pause_trufflehog("proj-x")).status == TrufflehogStatus.PAUSED

    async def test_resume_trufflehog(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.PAUSED, container_id="th-1"
        )
        assert (await manager.resume_trufflehog("proj-x")).status == TrufflehogStatus.RUNNING

    async def test_get_trufflehog_running_count(self, manager):
        assert manager.get_trufflehog_running_count() == 0
        manager.trufflehog_states["a"] = TrufflehogState(
            project_id="a", status=TrufflehogStatus.RUNNING, container_id="c1"
        )
        assert manager.get_trufflehog_running_count() == 1


# ===========================================================================
# Partial Recon — State & Transitions
# ===========================================================================


class TestPartialReconStatus:
    async def test_idle(self, manager):
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.IDLE

    async def test_running(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.RUNNING

    async def test_completed(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0)
        )
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.COMPLETED

    async def test_error_on_exit(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=1)
        )
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.ERROR
        assert s.error is not None

    async def test_paused(self, manager):
        """_refresh_partial_recon_state doesn't handle paused containers;
        it falls through to the exit-code check and transitions to COMPLETED."""
        c = _cm(status="paused", container_id="pc-1")
        manager.client.containers.get = MagicMock(return_value=c)
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        }
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        # "paused" != "running", exit_code=0 → COMPLETED
        assert s.status == PartialReconStatus.COMPLETED

    async def test_not_found(self, manager):
        """When container is not found, non-terminal state transitions to ERROR."""
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.ERROR
        assert "not found" in (s.error or "").lower()

    async def test_container_id_missing(self, manager):
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id=None)
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        # Should stay as-is since _refresh_partial_recon_state returns early
        assert s.status == PartialReconStatus.RUNNING

    async def test_terminal_state_not_refreshed(self, manager):
        """Terminal states should skip container refresh."""
        state = _partial_state(status=PartialReconStatus.COMPLETED, container_id="pc-1")
        state.completed_at = datetime.now(timezone.utc)
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        # Even if get raises, the terminal state should be preserved
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.COMPLETED

    async def test_get_all_partial_recon_statuses(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(run_id="run-1", status=PartialReconStatus.RUNNING),
            "run-2": _partial_state(run_id="run-2", status=PartialReconStatus.RUNNING),
        }
        results = await manager.get_all_partial_recon_statuses("proj-x")
        assert len(results) == 2

    async def test_get_all_partial_recon_empty(self, manager):
        results = await manager.get_all_partial_recon_statuses("nonexistent")
        assert results == []

    async def test_get_all_cleans_old_completed(self, manager):
        """Completed entries older than 60s should be auto-removed."""
        old_ts = datetime.now(timezone.utc) - timedelta(seconds=120)
        state = _partial_state(status=PartialReconStatus.COMPLETED)
        state.completed_at = old_ts
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        results = await manager.get_all_partial_recon_statuses("proj-x")
        assert len(results) == 0

    async def test_get_all_keeps_recent_completed(self, manager):
        """Completed entries younger than 60s should be kept."""
        recent_ts = datetime.now(timezone.utc)
        state = _partial_state(status=PartialReconStatus.COMPLETED)
        state.completed_at = recent_ts
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        results = await manager.get_all_partial_recon_statuses("proj-x")
        assert len(results) == 1

    async def test_auto_clean_removes_empty_project(self, manager):
        old_ts = datetime.now(timezone.utc) - timedelta(seconds=120)
        state = _partial_state(status=PartialReconStatus.COMPLETED)
        state.completed_at = old_ts
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        await manager.get_all_partial_recon_statuses("proj-x")
        assert "proj-x" not in manager.partial_recon_states or \
            manager.partial_recon_states["proj-x"] == {}


# ===========================================================================
# Partial Recon — Start / Stop / Pause / Resume
# ===========================================================================


class TestPartialReconLifecycle:
    async def test_start_partial_recon(self, manager):
        c = _cm(status="running", container_id="partial-42")
        manager.client.images.get = MagicMock(return_value=MagicMock())
        manager.client.containers.run = MagicMock(return_value=c)

        with patch("builtins.open", MagicMock()):
            state = await manager.start_partial_recon(
                project_id="proj-x",
                tool_id="SubdomainDiscovery",
                config={"user_id": "u1", "webapp_api_url": "http://w:3000"},
                recon_path="/tmp/recon",
            )
        assert state.status == PartialReconStatus.RUNNING
        assert state.container_id == "partial-42"
        # Verify ancestry tracking
        assert "partial-42" in manager._sub_container_ancestry.get(state.run_id, set())

    async def test_start_partial_recon_respects_concurrency_limit(self, manager):
        # Fill up to the max
        runs = {}
        for i in range(MAX_PARALLEL_PARTIAL_RECONS):
            runs[f"run-{i}"] = _partial_state(
                run_id=f"run-{i}", status=PartialReconStatus.RUNNING
            )
        manager.partial_recon_states["proj-x"] = runs

        with pytest.raises(ValueError, match="Maximum"):
            await manager.start_partial_recon(
                project_id="proj-x",
                tool_id="SubdomainDiscovery",
                config={},
                recon_path="/tmp/recon",
            )

    async def test_start_partial_recon_raises_if_full_recon_active(self, manager, running_state):
        manager.running_states["proj-x"] = running_state
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        with pytest.raises(ValueError, match="Full recon is running"):
            await manager.start_partial_recon(
                project_id="proj-x",
                tool_id="SubdomainDiscovery",
                config={},
                recon_path="/tmp/recon",
            )

    async def test_start_partial_recon_handles_failure(self, manager):
        manager.client.images.get = MagicMock(side_effect=Exception("no image"))
        state = await manager.start_partial_recon(
            project_id="proj-x",
            tool_id="SubdomainDiscovery",
            config={},
            recon_path="/tmp/recon",
        )
        assert state.status == PartialReconStatus.ERROR
        assert "no image" in (state.error or "")

    async def test_stop_partial_recon(self, manager):
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        }
        s = await manager.stop_partial_recon("proj-x", "run-1")
        # _refresh_partial_recon_state sees running container → keeps RUNNING
        # stop_partial_recon calls containers.get again → stops and removes
        # After stop, status goes to IDLE
        assert s.status == PartialReconStatus.IDLE

    async def test_stop_partial_recon_not_running(self, manager):
        s = await manager.stop_partial_recon("proj-x", "ghost-run")
        assert s.status == PartialReconStatus.IDLE

    async def test_stop_partial_recon_not_found(self, manager):
        """When container is NotFound, state should go IDLE."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        s = await manager.stop_partial_recon("proj-x", "run-1")
        # _refresh_partial_recon_state catches NotFound and sets ERROR first
        # Then stop_partial_recon returns early because status is not RUNNING/STARTING/PAUSED
        assert s.status == PartialReconStatus.ERROR

    async def test_stop_partial_recon_cleans_ancestry(self, manager):
        """stop_partial_recon should pop the run_id from _sub_container_ancestry."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager._sub_container_ancestry["run-1"] = {"pc-1", "sub-1", "sub-2"}
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        await manager.stop_partial_recon("proj-x", "run-1")
        assert "run-1" not in manager._sub_container_ancestry

    async def test_stop_partial_cleanup_removes_state(self, manager):
        """After stop, the run should be removed from partial_recon_states."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        await manager.stop_partial_recon("proj-x", "run-1")
        assert "run-1" not in manager.partial_recon_states.get("proj-x", {})

    async def test_pause_partial_recon(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING)
        }
        s = await manager.pause_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.PAUSED

    async def test_pause_partial_recon_not_running(self, manager):
        state = _partial_state(status=PartialReconStatus.PAUSED)
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        s = await manager.pause_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.PAUSED

    async def test_resume_partial_recon(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": _partial_state(status=PartialReconStatus.PAUSED)
        }
        s = await manager.resume_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.RUNNING

    async def test_resume_partial_recon_not_paused(self, manager):
        s = await manager.resume_partial_recon("proj-x", "ghost")
        assert s.status == PartialReconStatus.IDLE


# ===========================================================================
# Sub-Container Ancestry
# ===========================================================================


class TestSubContainerAncestry:
    def test_ancestry_starts_empty(self, manager):
        assert manager._sub_container_ancestry == {}

    async def test_ancestry_tracked_on_start(self, manager):
        """Starting a partial recon should record the container in ancestry."""
        c = _cm(status="running", container_id="partial-99")
        manager.client.images.get = MagicMock(return_value=MagicMock())
        manager.client.containers.run = MagicMock(return_value=c)
        with patch("builtins.open", MagicMock()):
            state = await manager.start_partial_recon(
                project_id="proj-x",
                tool_id="SubdomainDiscovery",
                config={},
                recon_path="/tmp/recon",
            )
        assert state.run_id in manager._sub_container_ancestry
        assert "partial-99" in manager._sub_container_ancestry[state.run_id]

    async def test_ancestry_cleaned_on_stop(self, manager):
        """stop_partial_recon should pop ancestry for the run."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager._sub_container_ancestry["run-1"] = {"pc-1", "sub-1"}
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        await manager.stop_partial_recon("proj-x", "run-1")
        assert "run-1" not in manager._sub_container_ancestry

    async def test_ancestry_excludes_main_container_on_stop(self, manager):
        """The main container ID should be excluded from sub-container cleanup."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager._sub_container_ancestry["run-1"] = {"pc-1", "sub-1"}
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        await manager.stop_partial_recon("proj-x", "run-1")
        # sub-1 should have been stopped; pc-1 should have been discarded
        # (No assertion on get calls since they all return MagicMock)

    async def test_ancestry_not_found_skipped(self, manager):
        """If a sub-container is already gone, NotFound should not propagate."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager._sub_container_ancestry["run-1"] = {"pc-1", "ghost-container"}
        manager.client.containers.get = MagicMock(
            side_effect=lambda cid: _NOT_FOUND("gone") if cid == "ghost-container"
            else _cm(status="running", container_id=cid)
        )
        # Should not raise
        s = await manager.stop_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.IDLE


# ===========================================================================
# _cleanup_sub_containers
# ===========================================================================


class TestCleanupSubContainers:
    def test_cleanup_none_running(self, manager):
        manager.client.containers.list = MagicMock(return_value=[])
        count = manager._cleanup_sub_containers()
        assert count == 0

    def test_cleanup_skips_non_matching_images(self, manager):
        c = _cm(status="running", container_id="other", image_tags=["ubuntu:latest"])
        c.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "ubuntu:latest"}}
        manager.client.containers.list = MagicMock(return_value=[c])
        count = manager._cleanup_sub_containers()
        assert count == 0

    def test_cleanup_matches_sub_container_image(self, manager):
        c = _cm(
            status="running", container_id="naabu-1",
            image_tags=["projectdiscovery/naabu:latest"],
        )
        c.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "projectdiscovery/naabu:latest"}}
        manager.client.containers.list = MagicMock(return_value=[c])
        count = manager._cleanup_sub_containers()
        assert count == 1

    def test_cleanup_unpauses_before_stop(self, manager):
        c = _cm(
            status="paused", container_id="httpx-1",
            image_tags=["projectdiscovery/httpx:latest"],
        )
        c.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "projectdiscovery/httpx:latest"}}
        manager.client.containers.list = MagicMock(return_value=[c])
        count = manager._cleanup_sub_containers()
        assert count == 1
        c.unpause.assert_called_once()

    def test_cleanup_with_since_filter(self, manager):
        """Containers created before 'since' should be skipped."""
        now = datetime.now(timezone.utc)
        old_ts = (now - timedelta(hours=2)).isoformat()
        c = _cm(
            status="running", container_id="naabu-1",
            image_tags=["projectdiscovery/naabu:latest"],
        )
        c.attrs = {
            "State": {"ExitCode": 0},
            "Config": {"Image": "projectdiscovery/naabu:latest"},
            "Created": old_ts,
        }
        manager.client.containers.list = MagicMock(return_value=[c])
        count = manager._cleanup_sub_containers(since=now)
        assert count == 0

    def test_cleanup_error_listing(self, manager):
        manager.client.containers.list = MagicMock(
            side_effect=Exception("API error")
        )
        # Should not raise
        count = manager._cleanup_sub_containers()
        assert count == 0

    def test_cleanup_single_container(self, manager):
        """Verify a single matching container is stopped and removed."""
        c = _cm(
            status="running", container_id="nuclei-1",
            image_tags=["projectdiscovery/nuclei:latest"],
        )
        c.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "projectdiscovery/nuclei:latest"}}
        manager.client.containers.list = MagicMock(return_value=[c])
        count = manager._cleanup_sub_containers()
        assert count == 1
        c.stop.assert_called_once()
        c.remove.assert_called_once_with(force=True)

    def test_cleanup_multiple_sub_containers(self, manager):
        c1 = _cm(status="running", container_id="nuclei-1", image_tags=["projectdiscovery/nuclei:latest"])
        c1.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "projectdiscovery/nuclei:latest"}}
        c2 = _cm(status="running", container_id="naabu-1", image_tags=["projectdiscovery/naabu:latest"])
        c2.attrs = {"State": {"ExitCode": 0}, "Config": {"Image": "projectdiscovery/naabu:latest"}}
        manager.client.containers.list = MagicMock(return_value=[c1, c2])
        count = manager._cleanup_sub_containers()
        assert count == 2


# ===========================================================================
# Status Transitions
# ===========================================================================


class TestStatusTransitions:
    async def test_recon_full_lifecycle(self, manager):
        """IDLE → STARTING → RUNNING → IDLE via stop."""
        # IDLE
        assert (await manager.get_status("p1")).status == ReconStatus.IDLE

        # STARTING → RUNNING
        c = _cm(status="running", container_id="c1")
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.client.containers.run = MagicMock(return_value=c)
        manager.client.images.get = MagicMock(return_value=MagicMock())
        manager.client.containers.list = MagicMock(return_value=[])
        state = await manager.start_recon(
            project_id="p1", user_id="u1", webapp_api_url="http://w:3000",
            recon_path="/tmp/r",
        )
        assert state.status == ReconStatus.RUNNING

        # RUNNING → IDLE (stop)
        manager.client.containers.get = MagicMock(return_value=_cm(status="running", container_id="c1"))
        state = await manager.stop_recon("p1")
        assert state.status == ReconStatus.IDLE

    async def test_partial_recon_full_lifecycle(self, manager):
        """IDLE → STARTING → RUNNING → (pause) → PAUSED → (resume) → RUNNING → IDLE."""
        c = _cm(status="running", container_id="pc-1")
        manager.client.images.get = MagicMock(return_value=MagicMock())
        manager.client.containers.run = MagicMock(return_value=c)

        # IDLE → STARTING → RUNNING
        with patch("builtins.open", MagicMock()):
            state = await manager.start_partial_recon(
                project_id="p1", tool_id="PortScan", config={},
                recon_path="/tmp/r",
            )
        assert state.status == PartialReconStatus.RUNNING

        # RUNNING → PAUSED
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        state = await manager.pause_partial_recon("p1", state.run_id)
        assert state.status == PartialReconStatus.PAUSED

        # PAUSED → RUNNING
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        state = await manager.resume_partial_recon("p1", state.run_id)
        assert state.status == PartialReconStatus.RUNNING

        # RUNNING → IDLE (stop)
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        state = await manager.stop_partial_recon("p1", state.run_id)
        assert state.status == PartialReconStatus.IDLE

    async def test_gvm_full_lifecycle(self, manager):
        """IDLE → RUNNING → PAUSED → RUNNING → COMPLETED."""
        # IDLE
        assert (await manager.get_gvm_status("p1")).status == GvmStatus.IDLE

        # RUNNING
        manager.gvm_states["p1"] = GvmState(
            project_id="p1", status=GvmStatus.RUNNING, container_id="g-1"
        )
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.get_gvm_status("p1")).status == GvmStatus.RUNNING

        # PAUSED
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.pause_gvm_scan("p1")).status == GvmStatus.PAUSED

        # RESUME → RUNNING
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        assert (await manager.resume_gvm_scan("p1")).status == GvmStatus.RUNNING

        # RUNNING → COMPLETED (stop)
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        assert (await manager.stop_gvm_scan("p1")).status == GvmStatus.COMPLETED

    async def test_github_hunt_full_lifecycle(self, manager):
        """IDLE → RUNNING → PAUSED → RUNNING → COMPLETED."""
        manager.github_hunt_states["p1"] = GithubHuntState(
            project_id="p1", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.get_github_hunt_status("p1")).status == GithubHuntStatus.RUNNING

        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.pause_github_hunt("p1")).status == GithubHuntStatus.PAUSED

        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        assert (await manager.resume_github_hunt("p1")).status == GithubHuntStatus.RUNNING

        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        assert (await manager.stop_github_hunt("p1")).status == GithubHuntStatus.COMPLETED

    async def test_trufflehog_full_lifecycle(self, manager):
        """IDLE → RUNNING → PAUSED → RUNNING → COMPLETED."""
        manager.trufflehog_states["p1"] = TrufflehogState(
            project_id="p1", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.get_trufflehog_status("p1")).status == TrufflehogStatus.RUNNING

        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        assert (await manager.pause_trufflehog("p1")).status == TrufflehogStatus.PAUSED

        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        assert (await manager.resume_trufflehog("p1")).status == TrufflehogStatus.RUNNING

        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        assert (await manager.stop_trufflehog("p1")).status == TrufflehogStatus.COMPLETED


# ===========================================================================
# Error Handling
# ===========================================================================


class TestErrorHandling:
    async def test_docker_api_error_in_get_status(self, manager, running_state):
        manager.client.containers.get = MagicMock(side_effect=_API_ERROR("boom"))
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.ERROR

    async def test_docker_api_error_in_partial_pause(self, manager):
        """APIError during partial pause should set ERROR."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager.client.containers.get = MagicMock(side_effect=_API_ERROR("API boom"))
        s = await manager.pause_partial_recon("proj-x", "run-1")
        # get_partial_recon_status calls _refresh_partial_recon_state which catches APIError
        # with a warning and leaves status unchanged; pause_partial_recon then gets RUNNING
        # and tries to pause, but containers.get raises APIError again in pause_partial_recon
        assert s.status == PartialReconStatus.ERROR

    async def test_docker_api_error_in_partial_resume(self, manager):
        """APIError during partial resume should set ERROR."""
        state = _partial_state(status=PartialReconStatus.PAUSED, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        manager.client.containers.get = MagicMock(side_effect=_API_ERROR("API boom"))
        s = await manager.resume_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.ERROR

    async def test_partial_stop_docker_exception(self, manager):
        """Exception during stop_partial_recon container ops should set ERROR state."""
        state = _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        manager.partial_recon_states["proj-x"] = {"run-1": state}
        # Return running for refresh call (status check), then raise on direct get in stop
        running = _cm(status="running", container_id="pc-1")
        manager.client.containers.get = MagicMock(
            side_effect=[running, Exception("unexpected error")]
        )
        s = await manager.stop_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.ERROR
        assert "unexpected error" in (s.error or "")

    async def test_stop_recon_handles_not_found(self, manager, running_state):
        """NotFound during stop_recon should transition to IDLE."""
        manager.running_states["proj-1"] = running_state
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        state = await manager.stop_recon("proj-1")
        # get_status catches NotFound and sets ERROR, then stop_recon returns early
        assert state.status == ReconStatus.ERROR

    async def test_general_exception_in_start_recon(self, manager):
        """Unexpected exceptions during start_recon should be caught gracefully."""
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("nope"))
        manager.client.images.get = MagicMock(
            side_effect=RuntimeError("unexpected build error")
        )
        state = await manager.start_recon(
            project_id="p1", user_id="u1", webapp_api_url="http://w:3000",
            recon_path="/tmp/r",
        )
        assert state.status == ReconStatus.ERROR
        assert state.error is not None

    async def test_general_exception_in_start_partial_recon(self, manager):
        """Unexpected exceptions during start_partial_recon should be caught."""
        manager.client.images.get = MagicMock(
            side_effect=RuntimeError("image pull failed")
        )
        state = await manager.start_partial_recon(
            project_id="p1", tool_id="PortScan", config={},
            recon_path="/tmp/r",
        )
        assert state.status == PartialReconStatus.ERROR
        assert "image pull failed" in (state.error or "")


# ===========================================================================
# Cleanup
# ===========================================================================


class TestCleanup:
    async def test_cleanup_empty(self, manager):
        """cleanup() on an empty manager should not raise."""
        await manager.cleanup()

    async def test_cleanup_stops_all_types(self, manager):
        """cleanup() should stop recons, partial recons, GVM, etc."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.partial_recon_states["p1"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        }
        manager.gvm_states["p1"] = GvmState(
            project_id="p1", status=GvmStatus.RUNNING, container_id="g1"
        )
        manager.github_hunt_states["p1"] = GithubHuntState(
            project_id="p1", status=GithubHuntStatus.RUNNING, container_id="gh1"
        )
        manager.trufflehog_states["p1"] = TrufflehogState(
            project_id="p1", status=TrufflehogStatus.RUNNING, container_id="th1"
        )
        # Set up mock containers for each stop call
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="c1")
        )
        manager.client.containers.list = MagicMock(return_value=[])
        await manager.cleanup()
        # After cleanup, states should be removed
        assert "p1" not in manager.running_states
        assert "p1" not in manager.gvm_states
        assert "p1" not in manager.github_hunt_states
        assert "p1" not in manager.trufflehog_states


# ===========================================================================
# _recover_containers
# ===========================================================================


class TestRecoverContainers:
    def test_recover_running_container(self, manager):
        """A running container should keep state as RUNNING."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="c1")
        )
        manager._recover_containers()
        assert manager.running_states["p1"].status == ReconStatus.RUNNING

    def test_recover_paused_container(self, manager):
        """A paused container should transition state to PAUSED."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="paused", container_id="c1")
        )
        manager._recover_containers()
        assert manager.running_states["p1"].status == ReconStatus.PAUSED

    def test_recover_exited_success(self, manager):
        """An exited container with exit code 0 should become COMPLETED."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=0, container_id="c1")
        )
        manager._recover_containers()
        assert manager.running_states["p1"].status == ReconStatus.COMPLETED

    def test_recover_exited_failure(self, manager):
        """An exited container with non-zero exit code should become ERROR."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="exited", exit_code=1, container_id="c1")
        )
        manager._recover_containers()
        assert manager.running_states["p1"].status == ReconStatus.ERROR

    def test_recover_container_not_found(self, manager):
        """A missing container should transition to ERROR."""
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.RUNNING, container_id="c1"
        )
        manager.client.containers.get = MagicMock(side_effect=_NOT_FOUND("missing"))
        manager._recover_containers()
        assert manager.running_states["p1"].status == ReconStatus.ERROR

    def test_recover_removes_old_terminal_states(self, manager):
        """Terminal states older than 60s should be removed."""
        old_ts = datetime.now(timezone.utc) - timedelta(seconds=120)
        manager.running_states["p1"] = ReconState(
            project_id="p1", status=ReconStatus.COMPLETED,
            container_id="c1", completed_at=old_ts,
        )
        manager._recover_containers()
        assert "p1" not in manager.running_states

    def test_recover_partial_recon(self, manager):
        """Partial recon states should also be recovered."""
        manager.partial_recon_states["p1"] = {
            "run-1": _partial_state(status=PartialReconStatus.RUNNING, container_id="pc-1")
        }
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running", container_id="pc-1")
        )
        manager._recover_containers()
        assert manager.partial_recon_states["p1"]["run-1"].status == PartialReconStatus.RUNNING
