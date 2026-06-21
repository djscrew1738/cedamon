# Container Manager Architecture

**File:** `recon_orchestrator/container_manager.py`  
**Lines:** ~2,600  
**Pattern:** Orchestrator — manages Docker container lifecycles for four scan types

---

## Overview

`ContainerManager` is the single entry point for all containerized scan workloads.
It wraps the Docker SDK and provides async lifecycle methods (start/stop/pause/
resume/stream) for four scan types — each with a parallel but independent set of
methods:

| Scan Type | State Dict | Status Enum | Container Prefix | Key Methods |
|-----------|-----------|-------------|------------------|-------------|
| Full Recon | `running_states` | `ReconStatus` | `recon-{project_id}` | `start_recon`, `stream_logs` |
| GVM Vuln Scan | `gvm_states` | `GvmStatus` | `gvm-scan-{project_id}` | `start_gvm_scan`, `stream_gvm_logs` |
| GitHub Secret Hunt | `github_hunt_states` | `GithubHuntStatus` | `gh-hunt-{project_id}` | `start_github_hunt`, `stream_github_hunt_logs` |
| TruffleHog Scan | `trufflehog_states` | `TrufflehogStatus` | `trufflehog-{project_id}` | `start_trufflehog`, `stream_trufflehog_logs` |
| Partial Recon | `partial_recon_states` | `PartialReconStatus` | `partial-recon-{project_id}-{run_id}` | `start_partial_recon`, `stream_partial_logs` |

---

## Sub-Container Model

Each scan runs inside its own Docker container. The manager:

1. **Builds** the Docker image on first use (`_ensure_recon_image`)
2. **Runs** the container with environment variables (project ID, user ID, API URL)
3. **Streams** stdout/stderr via `docker logs --follow --timestamps` in a background thread
4. **Persists** state to disk via `OrchestratorStateStore` every `PERSIST_INTERVAL` seconds

### Container Naming Convention

```
recon-{project_id}                  # Full pipeline recon
gvm-scan-{project_id}               # GVM vulnerability scan
gh-hunt-{project_id}                # GitHub secret hunt
trufflehog-{project_id}             # TruffleHog scan
partial-recon-{project_id}-{run_id} # Single-tool partial recon
```

---

## State Persistence & Recovery

### In-Memory + Disk Hybrid

State is held in-memory for fast access and periodically flushed to disk so the
orchestrator can survive restarts.

```
┌─────────────────┐     periodic flush      ┌──────────────────┐
│  In-Memory Dict │ ◄──────────────────────► │ OrchestratorState│
│  running_states │   (every N seconds)      │   Store (disk)   │
│  gvm_states     │                          └──────────────────┘
│  ...            │
└─────────────────┘
```

- **`_save_state()`** (line 179): Serializes all five state dicts to disk.
- **`_load_state()`** (line 217): Loads from disk on startup.
- **`_periodic_persist()`** (line 189): Background asyncio task calling `_save_state()` on a timer.
- **`_recover_containers()`** (line 227): After loading state, validates each container against the live Docker daemon. Running/paused containers are kept; exited/missing containers are transitioned to `ERROR`.

### SSE Log Replay on Reconnect

Each state model carries a `last_log_timestamp` field. When a client reconnects
to a log stream, the manager passes this as `since=` to `docker logs` so only
new lines are emitted — preventing full history replay on reconnect.

### SSE Dedup (200-entry LRU Ring)

Log streams that reconnect may receive duplicate lines from Docker (due to
`since=` second granularity). Each stream closure maintains a 200-entry LRU
ring buffer that drops events whose `(seq, log)` tuple was already emitted.

---

## Orphan Container Cleanup

### Detection

Orphan sub-containers are containers launched by the pipeline (e.g., via
`docker run` inside the recon container) that survive after the parent
container stops.

### Cleanup Paths

| Trigger | Method | Description |
|---------|--------|-------------|
| On stop | `_cleanup_sub_containers()` (line 516) | Kills all sub-containers created since the recon started |
| On cleanup | `cleanup_all_containers()` | Stops every managed container and all sub-containers |
| On shutdown | `shutdown()` (line 200) | Calls `cleanup()` then persists final state |

### Partial Recon Lifecycle

Partial recons are single-tool runs that share the same parent project. Each
run has its own container, state, and log stream. The manager tracks them in
a nested dict keyed by `project_id → {run_id: state}` and enforces a
`MAX_PARALLEL_PARTIAL_RECONS=12` cap.

---

## Log Streaming Architecture

```
Client (SSE)          Manager                 Executor Thread          Docker
    │                    │                          │                    │
    │  stream_logs()     │                          │                    │
    │──────────────────► │                          │                    │
    │                    │  _exec(read_logs)         │                    │
    │                    │ ────────────────────────► │                    │
    │                    │                          │  docker logs -f    │
    │                    │                          │ ─────────────────► │
    │                    │                          │  ◄── stream ──────│
    │                    │     asyncio.Queue         │                    │
    │                    │ ◄── bounded queue ─────── │                    │
    │  ◄── SSE event ─── │                          │                    │
    │      (yield)       │                          │                    │
```

Each log stream:
1. Launches a `ThreadPoolExecutor` task that reads from `docker logs --follow`
2. Parses each line into a typed event model (`ReconLogEvent`, `GvmLogEvent`, etc.)
3. Pushes events through a bounded `asyncio.Queue` (capacity 500) so the Docker reader never blocks
4. The async generator yields from the queue to the SSE response

---

## Shutdown Sequence

```
shutdown()
  └─ cleanup()
      ├─ Stop all recon containers
      ├─ Stop all GVM containers
      ├─ Stop all GitHub hunt containers
      ├─ Stop all TruffleHog containers
      └─ Stop all partial recon containers
  └─ Cancel persist task
  └─ _save_state() (final flush)
  └─ Shut down ThreadPoolExecutor
```

---

## Key Design Decisions

1. **No async Docker SDK** — The Docker SDK for Python is synchronous.
   All Docker calls are wrapped in `run_in_executor()` (`_exec()` at line 131)
   to avoid blocking the asyncio event loop.

2. **Bounded queues prevent OOM** — Log queues are capped at 500 entries.
   The `_bounded_queue_put` helper drops oldest entries when full instead of
   blocking the producer.

3. **State recovery validates against Docker** — On restart, the manager
   checks actual container status rather than trusting persisted state, so
   killed containers don't remain as "running" ghosts.

4. **Thread-per-stream** — Each SSE log stream spawns one thread reading
   Docker logs. The `ThreadPoolExecutor` is sized to the number of streams,
   not the number of containers.
