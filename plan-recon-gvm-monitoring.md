# Plan: Recon/GVM Scan Monitoring & Resilience

## 1. Goal & Scope

**Objective:** Make reconnaissance and GVM scans more observable, recoverable, and user-friendly by adding persistent orchestrator state, resumable log streaming, bounded log buffers, pre-flight readiness checks, and richer frontend monitoring.

**IN scope:**
- Backend (recon_orchestrator):
  - Persist recon/GVM run state to disk and recover it on orchestrator restart.
  - Support log replay on SSE reconnect for full recon and GVM (like partial recon already does).
  - Bound the log queue to avoid unbounded memory growth on long scans.
  - Pre-flight GVM readiness check before spawning a GVM scanner.
- Frontend (webapp):
  - Toast notifications when recon/GVM completes or errors.
  - Live SSE connection status badge in the Recon/GVM logs drawer.
  - Compact scan progress monitor in the graph toolbar (elapsed time, current phase, severity counts when available).
  - GVM readiness banner when GVM feed sync is still in progress.
- Tests:
  - Unit tests for the modified hooks (`useReconStatus`, `useGvmStatus`).
  - API route tests for the start/status/available endpoints that touch the new behavior.

**OUT of scope (future work):**
- Full scan history / run list UI.
- Per-target progress tracking.
- Scan settings preview in confirm modals.
- Server-push status (WebSocket) — we keep polling + SSE.
- Automatic reverse-shell exploitation.

## 2. Files to Create / Modify

### Backend

- `(MODIFY) recon_orchestrator/container_manager.py`
  - Add load/save of per-project state JSON.
  - Recover state on startup from disk + Docker inspection.
  - Add `last_log_timestamp` handling to `stream_logs` / `stream_gvm_logs`.
  - Bound `asyncio.Queue` used for log streaming.
  - Add GVM readiness pre-flight before `start_gvm_scan`.

- `(MODIFY) recon_orchestrator/models.py`
  - Add `last_log_timestamp` to `ReconState` and `GvmState`.
  - Add a small `RunStateSnapshot` model for disk persistence.

- `(MODIFY) recon_orchestrator/api.py`
  - Expose `GET /health` GVM readiness details if not already present.
  - Return richer conflict messages when a scan is already running.

- `(MODIFY) gvm_scan/main.py` / `gvm_scan/gvm_scanner.py`
  - Emit structured progress logs (phase, batch, severity counts) that the frontend can parse.

### Frontend

- `(MODIFY) webapp/src/hooks/useReconStatus.ts`
  - Detect completion/error transitions and invoke callbacks.

- `(MODIFY) webapp/src/hooks/useGvmStatus.ts`
  - Same as above for GVM.

- `(MODIFY) webapp/src/hooks/useReconSSE.ts` / `useGvmSSE.ts`
  - Export `isConnected` and reconnect state already present; ensure consumers can read them.

- `(MODIFY) webapp/src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.tsx`
  - Add a connection-status badge (connected / reconnecting / disconnected).

- `(MODIFY) webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx`
  - Add a compact scan monitor showing recon/GVM progress and elapsed time.

- `(MODIFY) webapp/src/app/graph/page.tsx`
  - Wire completion/error toasts.
  - Wire GVM readiness banner.
  - Pass SSE connection state into `ReconLogsDrawer`.

- `(MODIFY) webapp/src/app/api/gvm/available/route.ts`
  - Return `gvm_ready` boolean from orchestrator health.

- `(MODIFY) webapp/src/app/api/recon/[projectId]/status/route.ts`
  - Small retry wrapper for transient orchestrator fetch failures.

### Tests

- `(NEW) webapp/src/hooks/useReconStatus.test.ts`
- `(NEW) webapp/src/hooks/useGvmStatus.test.ts`
- `(NEW) webapp/src/app/api/recon/[projectId]/status/route.test.ts`
- `(NEW) webapp/src/app/api/gvm/available/route.test.ts`
- `(NEW) recon_orchestrator/test_container_manager_state.py` (backend unit tests for state persistence/recovery)

## 3. Architecture / Key Decisions

### Persistent state store: per-project JSON in shared output volume
- **Why:** The orchestrator is currently purely in-memory. A restart loses `started_at`, phase, and user context. Using a simple JSON file on the already-mounted output volume is the smallest change that survives restarts without adding a database dependency.
- **Trade-off:** Not as robust as a real DB, but sufficient for scan state and consistent with the existing file-based output model.

### Log replay via `last_log_timestamp`
- **Why:** Partial recon already does this; full recon/GVM currently replay the entire log buffer on reconnect, which is noisy and slow. Storing the latest seen timestamp and passing Docker `since=` solves it.
- **Trade-off:** Docker `since=` is second-granular, so a line at the reconnect boundary may still duplicate; existing partial-recon dedup pattern will be reused.

### Bounded log queue
- **Why:** Long scans can produce thousands of log lines; an unbounded queue risks OOM. A capped queue with coalescing/dropping of old lines protects memory.
- **Trade-off:** Very old log lines may be dropped if the consumer is slow, but logs are also written to file/Docker, so they are not lost permanently.

### GVM readiness pre-flight
- **Why:** Users currently start GVM and see silence while the container waits for gvmd feed sync. Checking readiness before spawn lets us show "GVM feed sync in progress" immediately.
- **Trade-off:** Adds a blocking call before spawn; we cap it at ~60s and fall back to spawning anyway so scans are not blocked indefinitely.

### Frontend monitoring: toolbar + toasts
- **Why:** The existing UI only shows status in the logs drawer and toolbar buttons. A small progress monitor and completion toasts close the biggest observability gaps without redesigning the page.
- **Trade-off:** Still poll-based; future work can move to server-push.

## 4. Step-by-Step Implementation

1. **Backend state model**
   - Add `last_log_timestamp` to `ReconState`/`GvmState` in `models.py`.
   - Add `RunStateSnapshot` Pydantic model for disk persistence.

2. **Backend state persistence**
   - In `container_manager.py`, implement `_load_project_state(project_id)` and `_save_project_state(project_id)`.
   - Call `_save_project_state` after every meaningful state transition (start, phase change, pause, complete, error).
   - On `ContainerManager` initialization, scan the output directory and rebuild in-memory states.

3. **Backend log replay**
   - Update `stream_logs` and `stream_gvm_logs` to accept a `since` parameter.
   - Read `last_log_timestamp` from state when starting/reconnecting a stream.
   - Update `last_log_timestamp` whenever a log line is emitted.

4. **Backend bounded queue**
   - Cap the `asyncio.Queue` in log streaming (e.g., 1000 lines).
   - When full, drop the oldest line and optionally emit a single "... N lines omitted ..." marker.

5. **Backend GVM readiness pre-flight**
   - Extract the existing `ready_probe.py` / `is_gvm_ready` logic into a reusable helper.
   - Call it in `start_gvm_scan` before container creation; surface `gvm_ready` in status/health.
   - On timeout, spawn anyway and let the scanner handle retries.

6. **Frontend hook completion toasts**
   - Add `onComplete` / `onError` optional callbacks to `useReconStatus` and `useGvmStatus`.
   - Invoke them when a transition into `completed`/`error` is detected.

7. **Frontend SSE connection status**
   - Ensure `useReconSSE` / `useGvmSSE` expose `isConnected`.
   - Add a small badge in `ReconLogsDrawer` showing connected/reconnecting/disconnected.

8. **Frontend scan monitor**
   - Extend `GraphToolbar` to render a compact progress card when recon or GVM is active.
   - Show elapsed time, current phase, and severity counts from status stats/logs.

9. **Frontend GVM readiness banner**
   - Poll `/api/gvm/available` and show a non-blocking banner when `gvm_ready === false`.

10. **Frontend API resilience**
    - Add a small retry wrapper (`fetchWithRetry`) to the orchestrator-facing API routes.

11. **Tests**
    - Write unit tests for hooks using mocked `fetch` and `EventSource`.
    - Write API route tests using mocked `fetch` responses.
    - Write backend tests for state save/load/recovery.

12. **Verification**
    - Run `npx tsc --noEmit` and `npx vitest run` in `webapp/`.
    - Run backend unit tests in `recon_orchestrator/`.
    - Sanity-check a full recon and GVM start/stop flow manually if possible.

## 5. Testing Strategy

### Unit tests
- **State persistence:** save/load round-trip, recovery with missing file, recovery when container is gone.
- **Log replay:** `since=` is passed, timestamp is updated, duplicate boundary handled.
- **Bounded queue:** queue drops old lines when cap is reached.
- **GVM readiness:** ready path spawns immediately; not-ready path sets status and spawns after timeout.
- **Hooks:** status transitions call `onComplete`/`onError`; polling intervals switch correctly; start/stop/pause/resume call correct endpoints.
- **SSE hooks:** connection state toggles on open/error/close; reconnect attempts capped.

### Integration / route tests
- **Recon status route:** returns orchestrator state, falls back to idle on network error, retries transient errors.
- **GVM available route:** returns `gvm_ready` from orchestrator health.
- **Start routes:** forward correct payloads, handle 409 conflict.

### Edge cases
- Orchestrator restarts mid-scan and user reconnects — state should recover.
- SSE reconnect during high log volume — no duplicate flood.
- User starts GVM while feed sync is running — banner shown and scan still usable.
- Container exits with error code — status becomes `error` and error message preserved.

## 6. Risks & Rollback

| Risk | Mitigation |
|---|---|
| State file corruption | Write to temp file then atomic rename; fallback to Docker inspection if read fails. |
| New state format breaks existing orchestrator on next deploy | Default missing fields safely; keep backward-compatible Pydantic models. |
| Bounded queue drops important lines | Logs remain in Docker/file; UI badge warns if lines were omitted. |
| GVM readiness check delays scan start | Cap timeout; always fall back to spawn. |
| Frontend polling more expensive | Use existing intervals; monitor only adds a small render. |

**Rollback:** Remove the new state-file writes and revert to in-memory-only state; frontend changes are additive and can be disabled by reverting component edits.
