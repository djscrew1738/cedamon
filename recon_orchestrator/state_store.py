"""
Persistent snapshot store for the orchestrator's in-memory state.

The store writes a JSON snapshot on every state mutation so that a restarted
orchestrator can recover running containers instead of forgetting them.  Only
non-terminal containers are restored; finished/error states are kept only
briefly to avoid stale snapshots.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import (
    GithubHuntState,
    GvmState,
    PartialReconState,
    ReconState,
    TrufflehogState,
)

logger = logging.getLogger(__name__)

DEFAULT_STATE_PATH = "/app/state/orchestrator_state.json"


class OrchestratorStateStore:
    """Simple JSON-backed store for orchestrator runtime state."""

    def __init__(self, path: str | None = None):
        self.path = Path(path or os.environ.get("ORCHESTRATOR_STATE_PATH") or DEFAULT_STATE_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _serialize_dt(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        # Ensure UTC-aware ISO strings for round-trip safety.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    def _serialize_state(self, state: Any) -> dict:
        """Serialize a Pydantic state model to a plain dict."""
        data = state.model_dump() if hasattr(state, "model_dump") else state.dict()
        for key in ("started_at", "completed_at", "last_log_timestamp"):
            if key in data and isinstance(data[key], datetime):
                data[key] = self._serialize_dt(data[key])
        # Enums are serialized by Pydantic to their values, but nested status
        # enums inside partial recon may still be enum objects.
        if "status" in data and hasattr(data["status"], "value"):
            data["status"] = data["status"].value
        return data

    def save(
        self,
        running_states: dict[str, ReconState],
        gvm_states: dict[str, GvmState],
        github_hunt_states: dict[str, GithubHuntState],
        trufflehog_states: dict[str, TrufflehogState],
        partial_recon_states: dict[str, dict[str, PartialReconState]],
    ) -> None:
        """Persist the current orchestrator state to disk."""
        snapshot = {
            "version": 1,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "running_states": {
                pid: self._serialize_state(s) for pid, s in running_states.items()
            },
            "gvm_states": {
                pid: self._serialize_state(s) for pid, s in gvm_states.items()
            },
            "github_hunt_states": {
                pid: self._serialize_state(s) for pid, s in github_hunt_states.items()
            },
            "trufflehog_states": {
                pid: self._serialize_state(s) for pid, s in trufflehog_states.items()
            },
            "partial_recon_states": {
                pid: {
                    run_id: self._serialize_state(s)
                    for run_id, s in runs.items()
                }
                for pid, runs in partial_recon_states.items()
            },
        }
        tmp_path = self.path.with_suffix(".json.tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, default=str)
            tmp_path.replace(self.path)
        except Exception as e:
            logger.warning(f"Failed to persist orchestrator state: {e}")

    def load(
        self,
    ) -> tuple[
        dict[str, ReconState],
        dict[str, GvmState],
        dict[str, GithubHuntState],
        dict[str, TrufflehogState],
        dict[str, dict[str, PartialReconState]],
    ]:
        """Load the most recent persisted state snapshot."""
        if not self.path.exists():
            return {}, {}, {}, {}, {}

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load orchestrator state: {e}")
            return {}, {}, {}, {}, {}

        running_states: dict[str, ReconState] = {}
        gvm_states: dict[str, GvmState] = {}
        github_hunt_states: dict[str, GithubHuntState] = {}
        trufflehog_states: dict[str, TrufflehogState] = {}
        partial_recon_states: dict[str, dict[str, PartialReconState]] = {}

        for pid, data in snapshot.get("running_states", {}).items():
            try:
                running_states[pid] = ReconState.model_validate(data)
            except Exception as e:
                logger.warning(f"Skipping corrupt recon state for {pid}: {e}")

        for pid, data in snapshot.get("gvm_states", {}).items():
            try:
                gvm_states[pid] = GvmState.model_validate(data)
            except Exception as e:
                logger.warning(f"Skipping corrupt GVM state for {pid}: {e}")

        for pid, data in snapshot.get("github_hunt_states", {}).items():
            try:
                github_hunt_states[pid] = GithubHuntState.model_validate(data)
            except Exception as e:
                logger.warning(f"Skipping corrupt GitHub hunt state for {pid}: {e}")

        for pid, data in snapshot.get("trufflehog_states", {}).items():
            try:
                trufflehog_states[pid] = TrufflehogState.model_validate(data)
            except Exception as e:
                logger.warning(f"Skipping corrupt TruffleHog state for {pid}: {e}")

        for pid, runs in snapshot.get("partial_recon_states", {}).items():
            partial_recon_states[pid] = {}
            for run_id, data in runs.items():
                try:
                    partial_recon_states[pid][run_id] = PartialReconState.model_validate(data)
                except Exception as e:
                    logger.warning(f"Skipping corrupt partial recon state {pid}/{run_id}: {e}")

        return (
            running_states,
            gvm_states,
            github_hunt_states,
            trufflehog_states,
            partial_recon_states,
        )
