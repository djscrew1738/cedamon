# Recon Pipeline — Improvement Plan

This document catalogs all known issues, limitations, and improvement opportunities
in the RedAmon reconnaissance pipeline, organized by priority.

**Legend**: `[P0]` = Critical · `[P1]` = High · `[P2]` = Medium · `[P3]` = Low

---

## [P0] Orphan Sub-Containers on Partial Recon Stop

### Problem
`ContainerManager.stop_partial_recon()` explicitly skips `_cleanup_sub_containers()`
(line ~1088) to avoid killing sibling containers from other parallel partial runs.
This means stopped partial recons leave orphan containers behind, which accumulate
over time and waste resources.

### Options
1. **Tag-based selective cleanup** — Tag each sub-container with the run_id at
   spawn time. On stop, kill only containers matching that run_id's tag. This is
   the cleanest fix but requires changing the Docker spawn calls in `_run_tool()`.
2. **Container-level ancestry tracking** — Maintain a `dict[run_id, set[container_id]]`
   on the ContainerManager. On stop, iterate that set and kill only those containers.
3. **Orphan sweep on next start** — Before starting a new partial recon, sweep
   and kill any orphan containers. Cheaper but doesn't prevent accumulation.

### Effort
- **Option 1**: ~2 days (backend changes only)
- **Option 2**: ~1.5 days (simpler, preferred)
- **Option 3**: ~0.5 day (band-aid)

---

## [P0] Missing `PAUSED` State for Partial Recon

### Problem
`PartialReconStatus` enum has no `PAUSED` value. Partial runs can only be stopped,
not paused/resumed. This is asymmetric with full recon, GVM, GitHub Hunt, and
TruffleHog pipelines, all of which support pause/resume via Docker cgroups freeze.

### Options
1. **Add `PAUSED` state + Docker cgroups freeze** — Mirror the full recon pause
   implementation (`_pause_container` + `_resume_container`). Requires adding pause
   and resume API endpoints for partial runs.
2. **Leave partial recons as stop-only but document the asymmetry** — Simplest
   but leaves the inconsistency.

### Effort
- **Option 1**: ~1 day (backend + frontend + types)
- **Option 2**: ~0.25 day (documentation only)

---

## [P1] Single Log Drawer — Cannot View Multiple Pipelines Simultaneously

### Problem
`activeLogsDrawer` in `graph/page.tsx` (line 83) is a single `useState` value.
Only one pipeline's log drawer can be open at a time. If a user wants to monitor
a full recon and a partial recon simultaneously, they can't.

### Options
1. **Allow multiple simultaneous drawers** — Change `activeLogsDrawer` to a
   `Set<'recon' | 'gvm' | ...>` and render each open drawer side-by-side or as
   stackable overlays.
2. **Tabbed multi-drawer** — Render one drawer with tabs at the top for each
   active pipeline. Simpler than full multi-drawer but still allows quick switching.
3. **Mini-log badges** — Instead of full drawers, show a small floating badge per
   active pipeline that expands on hover to show the last N log lines.

### Effort
- **Option 1**: ~3 days (significant UI refactor)
- **Option 2**: ~2 days (new TabbedLogsDrawer component)
- **Option 3**: ~1 day (lightweight, UX-tradeoff)

---

## [P1] ScanProgressMonitor Shows Only One Scan

### Problem
`ScanProgressMonitor` only renders the first active scan. If multiple scans are
running concurrently (e.g., full recon + GVM + partial), only one progress bar
is visible with a `+N` badge. The user has no visibility into what else is
running or its progress.

### Options
1. **Stack multiple progress bars** — When space permits, show up to 3 progress
   bars stacked vertically in the toolbar. Collapse to `+N` badge at smaller widths.
2. **Dropdown expansion** — Keep the single compact bar but make the `+N` badge
   clickable to expand a dropdown with all active scans and their progress.
3. **Mini-badge per scan** — Show a small colored dot per scan in a horizontal
   row; the user can hover to see details. Most compact option.

### Effort
- **Option 1**: ~1 day (CSS + logic changes to ScanProgressMonitor)
- **Option 2**: ~1.5 days (new dropdown component)
- **Option 3**: ~0.5 day (lightest)

---

## [P1] Emergency Pause Asymmetry

### Problem
`handleEmergencyPauseAll()` pauses full recon, GVM, GitHub Hunt, and TruffleHog
via Docker cgroups freeze, but calls `stopPartialRecon()` for partial runs, which
fully terminates them. Partial runs are unrecoverable after emergency pause.

### Options
1. **Implement pause/resume for partial recons** (see P0) then change emergency
   pause to pause partial runs instead of stopping them.
2. **Accept the asymmetry** — Partial runs are typically short-lived (< 5 min),
   so restarting them is less painful than full pipelines.

### Effort
- **Option 1**: ~1 day (depends on P0 partial recon pause)
- **Option 2**: 0 (no change)

---

## [P1] SSE Dedup Reliability

### Problem
- Docker `since=` timestamps are truncated to second granularity, which means
  the same boundary line can be replayed on reconnect.
- The frontend dedup Set (`timestamp|log` keys) is bounded at 1000 entries per
  run. Under high log rates this can overflow.
- Nanosecond timestamps from Docker are truncated to 6-digit microseconds in
  `_format_log_line()`, potentially causing duplicate lines on reconnect.

### Options
1. **Server-side line IDs** — Add a monotonically increasing sequence number to
   each log line on the backend. Use `since_seq=<last_seq>` for resume instead of
   Docker timestamps. Replace the frontend Set with a simple `lastSeq` check.
2. **Increase dedup Set bound** — Raise from 1000 to 5000 and add LRU eviction
   instead of simple overflow drop. Quicker but doesn't solve the root cause.

### Effort
- **Option 1**: ~2 days (backend + frontend coordination)
- **Option 2**: ~0.5 day (frontend only)

---

## [P2] Redundant Status Polling

### Problem
Five independent polling hooks each run on their own 5s timer when active:
`useReconStatus`, `useMultiPartialReconStatus`, `useGvmStatus`,
`useGithubHuntStatus`, `useTrufflehogStatus`. This generates 5 parallel
HTTP requests every 5 seconds when all pipelines are running.

### Options
1. **Unified status endpoint** — Add a single `GET /recon/{id}/all-status`
   endpoint that returns all five states in one response. Replace the five hooks
   with one `useAllStatus` hook.
2. **Server-sent events for status** — Replace all polling with a single SSE
   endpoint that pushes status updates on state transitions.
3. **Staggered polling** — Keep separate hooks but jitter their intervals to
   spread requests evenly. Cheapest option.

### Effort
- **Option 1**: ~2 days (backend + frontend)
- **Option 2**: ~3 days (more complex)
- **Option 3**: ~0.5 day (config-only, simple)

---

## [P2] Image Build Cold Start

### Problem
On first run (or after image prune), both full and partial recon trigger a
Docker image build of `redamon-recon:latest`. This takes 30–60 seconds and
blocks the pipeline start. There is no progress feedback to the user during
this time — the button just appears stuck.

### Options
1. **Pre-build in Docker Compose** — Build the image in `docker-compose.yml`
   with `build: .` so it's ready before the orchestrator starts.
2. **Build progress SSE** — Stream build output back to the frontend so the
   user sees what's happening.
3. **Async build with queue** — Return immediately from the start endpoint,
   build in background, and start the container when the build finishes.

### Effort
- **Option 1**: ~1 hour (trivial config change)
- **Option 2**: ~1 day (backend SSE + frontend display)
- **Option 3**: ~2 days (state machine changes)

---

## [P2] No Retry on Image Build Failure

### Problem
If `docker build` fails (network issue, disk full, corrupted layer cache), the
error is terminal for that run. The user must manually retry.

### Options
1. **Automatic retry (3 attempts)** — Wrap the build call with exponential
   backoff (1s, 4s, 16s). Clear state back to IDLE if all retries exhausted.
2. **Separate build + run phases** — Split the STARTING phase into BUILD and RUN
   sub-phases. If BUILD fails, the button changes to "Retry Build" with clear
   error feedback.

### Effort
- **Option 1**: ~3 hours (backend only)
- **Option 2**: ~1 day (backend + frontend phase display)

---

## [P2] GraphToolbar Prop Explosion

### Problem
`GraphToolbar` receives 50+ individual props from `graph/page.tsx`. This makes
the component hard to reason about, test, and extend. Every new pipeline type
adds 5-10 more props.

### Options
1. **Consolidate into typed context objects** — Group props into logical
   bundles: `reconControl`, `gvmControl`, `viewControl`, `agentStatus`, etc.
   Each bundle is a single typed interface.
2. **Full context provider** — Extract all pipeline state into a
   `ReconPipelineContext` provider, and let any child component consume what it
   needs. Biggest refactor but cleanest.

### Effort
- **Option 1**: ~1.5 days (moderate refactor)
- **Option 2**: ~3 days (full context extraction)

---

## [P2] RoE Enforcement Only at Start

### Problem
Rules of Engagement (time window, scope) are checked only at pipeline start.
A pipeline started within the RoE window could run past the end of the window
with no enforcement. Similarly, scope additions mid-run are not validated.

### Options
1. **Mid-run RoE check** — Add a periodic check in the running loop that
   compares current time against the RoE window. If outside, pause or terminate
   the pipeline gracefully.
2. **RoE check at phase boundaries** — More granular: check before each new
   tool phase in the pipeline. If the RoE window has closed, skip the remaining
   phases.

### Effort
- **Option 1**: ~1 day (backend only)
- **Option 2**: ~1.5 days (backend only)

---

## [P2] Global Header Notifications for Recon Events

### Problem
Recon completions, errors, and other async events are only visible within the
graph page. If the user navigates to another page (Insights, Settings, Reports),
they miss important status updates.

### Options
1. **Global toast notifications** — Fire a toast from the SSE onComplete/onError
   callbacks regardless of current page. Use the existing Toast system.
2. **Global header badge** — Show a small badge on the recon status icon in the
   GlobalHeader, with a count of completed/errored runs.
3. **Persistent notification center** — Save notifications to the DB and show
   them in a notification drawer accessible from the GlobalHeader.

### Effort
- **Option 1**: ~0.5 day (frontend only, leverages existing Toast)
- **Option 2**: ~1 day (frontend + minimal context)
- **Option 3**: ~2 days (backend + frontend)

---

## [P3] Graph-Inputs Endpoint Data Freshness

### Problem
`GET /recon/{id}/graph-inputs/{tool_id}` falls back from the Neo4j driver
(not installed in orchestrator image) to querying the webapp API. On fallback,
it may return stale data if the webapp's cache hasn't caught up with recent
recon results.

### Options
1. **Install Neo4j driver in orchestrator** — Add `neo4j` to
   `recon_orchestrator/requirements.txt`. Remove the fallback.
2. **Add cache-busting query param** — Pass a timestamp via the webapp API
   endpoint to bypass its cache when the query originates from the orchestrator.

### Effort
- **Option 1**: ~0.5 day (add dependency + adjust import path)
- **Option 2**: ~0.5 day (backend API change)

---

## [P3] No Recon Scheduling

### Problem
Users cannot schedule a recon to start at a future time (e.g., during approved
maintenance windows). All recons must be started manually.

### Options
1. **Simple cron-based scheduling** — Add a `scheduledAt` field to the start
   payload. The orchestrator delays container spawn until the scheduled time.
   Frontend adds a date/time picker to the confirm modal.
2. **Full recurring schedule** — More complex: support recurring schedules with
   RRULE-style patterns. Requires DB persistence and a scheduler daemon.

### Effort
- **Option 1**: ~1.5 days (backend + frontend)
- **Option 2**: ~4 days (significant)

---

## [P3] Missing Recon History / Audit Trail

### Problem
Completed recon runs have no persistent history beyond the JSON state store
(which is pruned after 60s TTL). Users cannot review past runs, compare results
across runs, or audit when specific tools were executed.

### Options
1. **Persist run records to Postgres** — When a recon completes or errors,
   save a run record (run_id, project_id, tool, status, duration, node counts)
   to the webapp's Postgres DB via API callback.
2. **Log archive to disk** — Save completed log files to a persistent volume
   with a retention policy.

### Effort
- **Option 1**: ~2 days (backend + DB migration + frontend history page)
- **Option 2**: ~1 day (backend only)

---

## [P3] No Rate Limiting / Queue

### Problem
The only concurrency control is `MAX_PARALLEL_PARTIAL_RECONS=12`. There is no
per-user throttling or queue mechanism. Multiple users can start resource-heavy
recons simultaneously.

### Options
1. **Simple global semaphore** — Limit total concurrent recons (full + partial)
   to a configurable maximum. Queue excess requests with a FIFO queue.
2. **Per-user rate limits** — Track starts per user per time window using the
   JWT subject from the auth header.

### Effort
- **Option 1**: ~1 day (backend only)
- **Option 2**: ~1.5 days (backend + auth integration)

---

## Quick-Win Summary

| Change | Priority | Effort | Area |
|--------|----------|--------|------|
| Pre-build Docker image in Compose | P2 | ~1h | DevOps |
| Auto-retry image build (3 attempts) | P2 | ~3h | Backend |
| Stagger polling intervals | P2 | ~0.5d | Frontend |
| Global toast on recon complete/error | P2 | ~0.5d | Frontend |
| Selective sub-container cleanup | P0 | ~1.5d | Backend |

## Medium-Term

| Change | Priority | Effort | Area |
|--------|----------|--------|------|
| Partial recon pause/resume | P0 | ~1d | Backend + Frontend |
| Multi-scan progress display | P1 | ~1d | Frontend |
| SSE line IDs for reliable dedup | P1 | ~2d | Backend + Frontend |
| Tabbed multi-log drawer | P1 | ~2d | Frontend |
| Mid-run RoE check | P2 | ~1d | Backend |
| GraphToolbar prop consolidation | P2 | ~1.5d | Frontend |
