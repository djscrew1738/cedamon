"""Tests for the persistent orchestrator state store."""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from state_store import OrchestratorStateStore
from models import (
    ReconState,
    ReconStatus,
    GvmState,
    GvmStatus,
    GithubHuntState,
    GithubHuntStatus,
    TrufflehogState,
    TrufflehogStatus,
    PartialReconState,
    PartialReconStatus,
)


def _make_recon(project_id: str = "proj-1") -> ReconState:
    return ReconState(
        project_id=project_id,
        status=ReconStatus.RUNNING,
        current_phase="Port Scanning",
        phase_number=2,
        container_id="abc123",
        started_at=datetime.now(timezone.utc),
        last_log_timestamp=datetime.now(timezone.utc),
    )


def _make_gvm(project_id: str = "proj-1") -> GvmState:
    return GvmState(
        project_id=project_id,
        status=GvmStatus.RUNNING,
        container_id="gvm123",
        started_at=datetime.now(timezone.utc),
        last_log_timestamp=datetime.now(timezone.utc),
    )


def test_save_and_load_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        store = OrchestratorStateStore(path=f"{tmp}/state.json")
        recon = _make_recon()
        gvm = _make_gvm()
        github = GithubHuntState(
            project_id="proj-1",
            status=GithubHuntStatus.RUNNING,
            container_id="gh123",
        )
        trufflehog = TrufflehogState(
            project_id="proj-1",
            status=TrufflehogStatus.RUNNING,
            container_id="th123",
        )
        partial = PartialReconState(
            project_id="proj-1",
            run_id="run-1",
            tool_id="SubdomainDiscovery",
            status=PartialReconStatus.RUNNING,
            container_id="partial123",
            last_log_timestamp=datetime.now(timezone.utc),
        )

        store.save(
            running_states={"proj-1": recon},
            gvm_states={"proj-1": gvm},
            github_hunt_states={"proj-1": github},
            trufflehog_states={"proj-1": trufflehog},
            partial_recon_states={"proj-1": {"run-1": partial}},
        )

        loaded = store.load()
        loaded_recon = loaded[0]["proj-1"]
        loaded_gvm = loaded[1]["proj-1"]
        loaded_gh = loaded[2]["proj-1"]
        loaded_th = loaded[3]["proj-1"]
        loaded_partial = loaded[4]["proj-1"]["run-1"]

        assert loaded_recon.status == ReconStatus.RUNNING
        assert loaded_recon.current_phase == "Port Scanning"
        assert loaded_recon.last_log_timestamp is not None
        assert loaded_gvm.status == GvmStatus.RUNNING
        assert loaded_gh.status == GithubHuntStatus.RUNNING
        assert loaded_th.status == TrufflehogStatus.RUNNING
        assert loaded_partial.tool_id == "SubdomainDiscovery"
        assert loaded_partial.last_log_timestamp is not None


def test_load_missing_file_returns_empty():
    with tempfile.TemporaryDirectory() as tmp:
        store = OrchestratorStateStore(path=f"{tmp}/not_here.json")
        assert store.load() == ({}, {}, {}, {}, {})


def test_save_is_atomic():
    with tempfile.TemporaryDirectory() as tmp:
        store = OrchestratorStateStore(path=f"{tmp}/state.json")
        recon = _make_recon()
        store.save(
            running_states={"proj-1": recon},
            gvm_states={},
            github_hunt_states={},
            trufflehog_states={},
            partial_recon_states={},
        )

        data = json.loads(Path(store.path).read_text())
        assert data["version"] == 1
        assert "saved_at" in data
        assert data["running_states"]["proj-1"]["status"] == "running"


def test_load_ignores_corrupt_entries():
    with tempfile.TemporaryDirectory() as tmp:
        store = OrchestratorStateStore(path=f"{tmp}/state.json")
        store.path.write_text(
            json.dumps({
                "version": 1,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "running_states": {
                    "good": _make_recon("good").model_dump(mode="json"),
                    "bad": {"not_a_valid_state": True},
                },
                "gvm_states": {},
                "github_hunt_states": {},
                "trufflehog_states": {},
                "partial_recon_states": {},
            })
        )

        loaded = store.load()
        assert "good" in loaded[0]
        assert "bad" not in loaded[0]
