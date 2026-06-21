"""
Tests for ContainerManager — Docker container lifecycle management.

Mocks ``docker.from_env()`` and ``OrchestratorStateStore`` to test all state
transitions and lifecycle methods without a real Docker daemon.

IMPORTANT: ``_exec()`` calls ``run_in_executor(None, partial(fn, *args))``,
so methods passed to it (e.g. ``containers.get``, ``containers.run``) must be
*sync* ``MagicMock``, **not** ``AsyncMock``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
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

    from container_manager import ContainerManager
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


def _cm(status="running", container_id="c-0000", exit_code=0):
    """Return a mock Docker container object."""
    c = MagicMock()
    c.id = container_id
    c.status = status
    c.attrs = {"State": {"ExitCode": exit_code}}
    return c


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def mock_docker_client():
    client = MagicMock()
    client.containers = MagicMock()
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

    async def test_shutdown(self, manager):
        manager._persist_task = None
        await manager.shutdown()


class TestRecovery:
    def test_load_state_empty(self, manager):
        assert manager.running_states == {}
        assert manager.gvm_states == {}


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

    async def test_get_status_not_found(self, manager, running_state):
        original_exec = manager._exec

        async def _exec_side_effect(fn, *args, **kwargs):
            from container_manager import docker
            if fn is manager.client.containers.get:
                raise docker.errors.NotFound("nope")
            return await original_exec(fn, *args, **kwargs)

        manager._exec = _exec_side_effect  # type: ignore[assignment]
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.ERROR

    async def test_start_recon(self, manager):
        c = _cm(status="running", container_id="new-c-42")
        # step 1/2: get_status orphan + cleanup → NotFound (both use container name)
        # step 3: _ensure_recon_image checks images.get → succeed
        # step 4: containers.run → return container
        call_count = 0

        def _get_side_effect(name):
            nonlocal call_count
            call_count += 1
            from container_manager import docker
            if call_count <= 2:  # orphan check + cleanup
                raise docker.errors.NotFound(f"no such container {name}")
            return c

        manager.client.containers.get = MagicMock(side_effect=_get_side_effect)
        manager.client.containers.run = MagicMock(return_value=c)
        manager.client.images.get = MagicMock(return_value=MagicMock())

        state = await manager.start_recon(
            project_id="p1",
            user_id="u1",
            webapp_api_url="http://w:3000",
            recon_path="/tmp/r",
        )
        assert state.project_id == "p1"
        assert state.status in (ReconStatus.STARTING, ReconStatus.RUNNING)

    async def test_start_recon_raises_if_active(self, manager, running_state):
        manager.running_states["proj-1"] = running_state
        # get_status will find running_state in dict → no orphan check needed
        manager.client.containers.get = MagicMock(
            return_value=_cm(status="running")
        )
        with pytest.raises(ValueError, match="already active"):
            await manager.start_recon(
                project_id="proj-1",
                user_id="u1",
                webapp_api_url="http://w:3000",
                recon_path="/tmp/r",
            )

    async def test_stop_recon(self, manager, running_state):
        manager.running_states["proj-1"] = running_state
        c = _cm(status="exited")
        manager.client.containers.get = MagicMock(return_value=c)
        state = await manager.stop_recon("proj-1")
        assert state.status == ReconStatus.IDLE

    async def test_stop_nonexistent(self, manager):
        """stop_recon on an unknown project returns IDLE state (no error)."""
        state = await manager.stop_recon("ghost")
        assert state.status == ReconStatus.IDLE


# ===========================================================================
# Pause / Resume
# ===========================================================================


class TestPauseResume:
    async def test_pause(self, manager, running_state):
        manager.client.containers.get = MagicMock(return_value=_cm(status="running"))
        manager.running_states["proj-1"] = running_state
        state = await manager.pause_recon("proj-1")
        assert state.status == ReconStatus.PAUSED

    async def test_resume(self, manager, running_state):
        running_state.status = ReconStatus.PAUSED
        manager.client.containers.get = MagicMock(return_value=_cm(status="paused"))
        manager.running_states["proj-1"] = running_state
        state = await manager.resume_recon("proj-1")
        assert state.status == ReconStatus.RUNNING

    async def test_pause_nonexistent(self, manager):
        """pause_recon on unknown project returns IDLE state (no error)."""
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

    def test_running_count(self, manager):
        assert manager.get_running_count() == 0
        manager.running_states = {
            "a": ReconState(project_id="a", status=ReconStatus.RUNNING, container_id="c1"),
            "b": ReconState(project_id="b", status=ReconStatus.PAUSED, container_id="c2"),
            "c": ReconState(project_id="c", status=ReconStatus.RUNNING, container_id="c3"),
        }
        assert manager.get_running_count() == 2

    def test_update_last_log_timestamp(self, manager):
        s = ReconState(project_id="p", status=ReconStatus.RUNNING)
        ts = datetime.now(timezone.utc)
        manager._update_last_log_timestamp(s, ts)
        assert s.last_log_timestamp == ts

    def test_update_last_log_timestamp_none(self, manager):
        s = ReconState(project_id="p", status=ReconStatus.RUNNING)
        manager._update_last_log_timestamp(s, None)
        assert s.last_log_timestamp is None


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

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.gvm_states["proj-x"] = GvmState(
            project_id="proj-x", status=GvmStatus.RUNNING, container_id="g-1"
        )
        assert (await manager.stop_gvm_scan("proj-x")).status == GvmStatus.COMPLETED

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

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.github_hunt_states["proj-x"] = GithubHuntState(
            project_id="proj-x", status=GithubHuntStatus.RUNNING, container_id="gh-1"
        )
        assert (await manager.stop_github_hunt("proj-x")).status == GithubHuntStatus.COMPLETED


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

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.trufflehog_states["proj-x"] = TrufflehogState(
            project_id="proj-x", status=TrufflehogStatus.RUNNING, container_id="th-1"
        )
        assert (await manager.stop_trufflehog("proj-x")).status == TrufflehogStatus.COMPLETED


# ===========================================================================
# Partial Recon
# ===========================================================================


class TestPartialReconLifecycle:
    async def test_idle(self, manager):
        s = await manager.get_partial_recon_status("proj-x", "run-1")
        assert s.status == PartialReconStatus.IDLE

    async def test_stop(self, manager):
        manager.client.containers.get = MagicMock(return_value=_cm(status="exited"))
        manager.partial_recon_states["proj-x"] = {
            "run-1": PartialReconState(
                project_id="proj-x",
                run_id="run-1",
                status=PartialReconStatus.RUNNING,
                container_id="pc-1",
            )
        }
        s = await manager.stop_partial_recon("proj-x", "run-1")
        assert s.status == PartialReconStatus.COMPLETED


# ===========================================================================
# Error Handling
# ===========================================================================


class TestErrorHandling:
    async def test_docker_api_error_in_get_status(self, manager, running_state):
        original_exec = manager._exec

        async def _exec_side_effect(fn, *args, **kwargs):
            from container_manager import docker
            if fn is manager.client.containers.get:
                raise docker.errors.APIError("boom")
            return await original_exec(fn, *args, **kwargs)

        manager._exec = _exec_side_effect  # type: ignore[assignment]
        manager.running_states["proj-1"] = running_state
        status = await manager.get_status("proj-1")
        assert status.status == ReconStatus.ERROR
