# RedAmon Recon Pipeline — Phase 4 Optimizations Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Eliminate remaining sequential bottlenecks in the recon pipeline, Docker lifecycle, and infrastructure layers to further reduce end-to-end wall-clock time.

**Architecture:** Three-layer optimization — pipeline-phase parallelism (resource enum phase-2, CVE+MITRE), Docker lifecycle (recovery parallelization, state dirty-flag), and infrastructure (regex pre-compilation, Neo4j pooling).

**Tech Stack:** Python 3.14, Docker SDK, ThreadPoolExecutor, asyncio, Neo4j, FastAPI

---

## Layer 1: Pipeline-Phase Parallelism

### Task 1: Parallelize Resource Enum Phase 2 tools

**Objective:** FFuf, Jsluice, Arjun, Kiterunner, and ZAP Ajax Spider currently run sequentially after Katana/Hakrawler/GAU/ParamSpider complete. All five consume the same endpoint list but produce independent output. Run them in parallel via ThreadPoolExecutor.

**Files:**
- Modify: `recon/main_recon_modules/resource_enum.py` — the section after Phase 1 fan-in (~line 900+)

**Current state (simplified):**
```python
# Phase 1: Katana || Hakrawler || GAU || ParamSpider (already parallel)
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = {katana, hakrawler, gau, paramspider}
    # wait all, merge

# Phase 2: sequential
if FFUF_ENABLED: combined = _run_ffuf(combined, ...)
if JSLUICE_ENABLED: combined = _run_jsluice(combined, ...)
if ARJUN_ENABLED: combined = _run_arjun(combined, ...)
if KITERUNNER_ENABLED: combined = _run_kiterunner(combined, ...)
if ZAP_AJAX_SPIDER_ENABLED: combined = _run_zap_ajax_spider(combined, ...)
```

**Target state:**
```python
# Phase 2: FFuf || Jsluice || Arjun || Kiterunner || ZAP Ajax Spider (parallel)
phase2_tools = {}
if FFUF_ENABLED: phase2_tools['ffuf'] = _run_ffuf
if JSLUICE_ENABLED: phase2_tools['jsluice'] = _run_jsluice
if ARJUN_ENABLED: phase2_tools['arjun'] = _run_arjun
if KITERUNNER_ENABLED: phase2_tools['kiterunner'] = _run_kiterunner
if ZAP_AJAX_SPIDER_ENABLED: phase2_tools['zap_ajax'] = _run_zap_ajax_spider

if phase2_tools:
    with ThreadPoolExecutor(max_workers=min(len(phase2_tools), 5)) as p2_exec:
        p2_futures = {name: p2_exec.submit(fn, combined, settings) for name, fn in phase2_tools.items()}
        for name, future in p2_futures.items():
            try:
                result = future.result()
                if result:
                    combined = result  # or merge by key
            except Exception as e:
                print(f"[!][ResourceEnum] {name} failed: {e}")
```

**Key risk:** Each tool writes to different keys in `combined` (ffuf → `combined['ffuf']`, jsluice → `combined['jsluice']`, etc.). Verify no shared-key conflicts exist before parallelizing. Each tool wrapper must return a dict of keys to merge rather than mutating `combined` directly (follow the `_run_dns_prevalidation` pattern from recon/main.py).

**Verification:**
- Existing resource_enum tests pass
- Manual run: `python recon/main.py` with all resource enum tools enabled — verify output contains all tool results

---

### Task 2: Parallelize CVE Lookup + MITRE Enrichment

**Objective:** In the vuln_scan phase (recon/main.py Group 6), CVE lookup and MITRE ATT&CK enrichment run sequentially. Both consume vulnerability findings but produce independent graph nodes. Run in parallel.

**Files:**
- Modify: `recon/main.py` — the vuln_scan post-processing section (~line 1780-1940)

**Current state:**
```python
# After vuln_scan + graphql_scan complete:
if CVE_LOOKUP_ENABLED:
    combined_result = run_cve_lookup(combined_result, ...)
    save_recon_file(combined_result, output_file)

if MITRE_ENRICHMENT_ENABLED:
    combined_result = run_mitre_enrichment(combined_result, ...)
    save_recon_file(combined_result, output_file)
```

**Target state:**
```python
# CVE Lookup || MITRE Enrichment (parallel fan-out)
cve_mitre_futures = {}
cve_mitre_executor = None
if CVE_LOOKUP_ENABLED or MITRE_ENRICHMENT_ENABLED:
    workers = (1 if CVE_LOOKUP_ENABLED else 0) + (1 if MITRE_ENRICHMENT_ENABLED else 0)
    cve_mitre_executor = ThreadPoolExecutor(max_workers=workers)
    if CVE_LOOKUP_ENABLED:
        cve_mitre_futures['cve'] = cve_mitre_executor.submit(run_cve_lookup, combined_result, ...)
    if MITRE_ENRICHMENT_ENABLED:
        cve_mitre_futures['mitre'] = cve_mitre_executor.submit(run_mitre_enrichment, combined_result, ...)

    cve_mitre_executor.shutdown(wait=True)
    for name, future in cve_mitre_futures.items():
        try:
            combined_result = future.result()
        except Exception as e:
            print(f"[!][{name}] Failed: {e}")

    save_recon_file(combined_result, output_file)
```

**Verification:**
- Integration smoke tests pass
- Both CVE and MITRE data appear in final output when enabled

---

## Layer 2: Docker Lifecycle

### Task 3: Parallelize _recover_containers Docker API calls

**Objective:** `_recover_containers` calls `_recover_single` 5 times for different state types. Each `_recover_single` iterates containers and calls `self.client.containers.get()` serially. Batch Docker API calls using ThreadPoolExecutor.

**Files:**
- Modify: `recon_orchestrator/container_manager.py:_recover_containers` (~line 347)

**Current state:**
```python
def _recover_containers(self) -> None:
    def _recover_single(states, status_enum):
        for key, state in states.items():
            container_id = state.container_id
            if container_id:
                container = self.client.containers.get(container_id)  # serial API call
                # ... check status ...
```

**Target state:** Collect all container IDs across all state types, resolve them in a single ThreadPoolExecutor batch, then map results back.

```python
def _recover_containers(self) -> None:
    # Phase 1: collect all container IDs
    recovery_tasks = []
    for states, status_enum in [(self.running_states, ReconStatus), ...]:
        for key, state in states.items():
            if state.container_id and state.status not in TERMINAL:
                recovery_tasks.append((key, state, state.container_id, status_enum))

    if not recovery_tasks:
        return

    # Phase 2: resolve all containers in parallel
    def _check_one(container_id):
        try:
            return container_id, self.client.containers.get(container_id)
        except NotFound:
            return container_id, None

    with ThreadPoolExecutor(max_workers=min(len(recovery_tasks), 20)) as exec:
        results = dict(exec.map(_check_one, [t[2] for t in recovery_tasks]))

    # Phase 3: map results back to states
    for key, state, container_id, status_enum in recovery_tasks:
        container = results.get(container_id)
        if container is None:
            state.status = status_enum.ERROR
            state.error = "Container not found after restart"
        elif container.status == "running":
            state.status = status_enum.RUNNING
        # ... etc
```

**Verification:**
- Container manager unit tests: mock Docker client, verify parallel calls
- Orchestrator restart: verify state recovery correct after restart

---

### Task 4: Add dirty-flag to state persistence

**Objective:** `_save_state()` is called ~20 times during a typical recon lifecycle (start, each phase transition, pause, resume, stop). Each call serializes all 5 state dicts to disk. A dirty flag with the existing 5-second periodic persist means we write once per burst instead of per event.

**Files:**
- Modify: `recon_orchestrator/container_manager.py` — add `_state_dirty` flag, modify `_save_state` and `_periodic_persist`

**Implementation:**
```python
# In __init__:
self._state_dirty = False

def _mark_dirty(self) -> None:
    """Mark state as needing persistence. Called after every mutation."""
    self._state_dirty = True

def _save_state(self, force: bool = False) -> None:
    """Persist if dirty (or forced). Called by periodic persist loop."""
    if not force and not self._state_dirty:
        return
    self._state_store.save(...)
    self._state_dirty = False

# In every state mutation (start, pause, resume, stop, complete):
self._mark_dirty()
self._save_state(force=False)  # -> no-op unless periodic persist hasn't flushed yet
# Instead of: self._save_state()
```

**Change pattern:** Replace all `self._save_state()` calls with `self._mark_dirty()` (the periodic persist writes to disk). Keep `self._save_state(force=True)` at shutdown for final flush.

**Verification:**
- State persists correctly across pause/resume/stop
- Periodic persist test: modify state, verify written within 5s

---

## Layer 3: Infrastructure

### Task 5: Pre-compile phase-pattern regexes

**Objective:** `PHASE_PATTERNS`, `GVM_PHASE_PATTERNS`, etc. are lists of `(pattern_string, label, phase_number)` tuples. Every log line triggers `re.search(pattern, line)` which compiles the regex fresh each time. Pre-compile to `re.compile` objects.

**Files:**
- Modify: `recon_orchestrator/container_manager.py` — the pattern lists at module level (~lines 58-91)

**Current state:**
```python
PHASE_PATTERNS = [
    (r"\[Phase 1\]|...", "Domain Discovery", 1),
    ...
]
```

**Target state:**
```python
PHASE_PATTERNS = [
    (re.compile(r"\[Phase 1\]|..."), "Domain Discovery", 1),
    ...
]
```

Then update the matching code:
```python
# Before: if re.search(pattern, line):
# After:  if pattern.search(line):
```

This requires updating all log-streaming methods: `stream_logs`, `stream_partial_logs`, `stream_gvm_logs`, `stream_github_hunt_logs`, `stream_trufflehog_logs`.

**Verification:**
- All existing SSE log streaming tests pass
- Phase detection still works correctly

---

### Task 6: Neo4j connection pooling (low-risk, high-impact)

**Objective:** Every graph update in `_graph_update_bg` creates a new `Neo4jClient()`, calls `verify_connection()`, runs the update, then closes. For pipelines with 10+ phases, that's 10+ new connections. A module-level connection pool reduces overhead.

**Files:**
- Modify: `recon/main.py:_graph_update_bg` and `graph_db/neo4j_client.py`
- Create: (optional) `recon/neo4j_pool.py`

**Approach A (simpler):** Add a `Neo4jClient` singleton or context-manager reuse in `_graph_update_bg`.

```python
_graph_client = None

def _graph_update_bg(update_method_name, combined_result, user_id, project_id):
    global _graph_client
    if _graph_client is None or not _graph_client._driver:
        _graph_client = Neo4jClient()

    def _do_update():
        snapshot = copy.deepcopy(combined_result)
        if _graph_client.verify_connection():
            method = getattr(_graph_client, update_method_name)
            method(snapshot, user_id, project_id)
```

**Approach B (better, but larger change):** Use Neo4j's built-in connection pool via `neo4j.driver` with `max_connection_lifetime`.

Either approach is fine for the scale RedAmon operates at (single-user, single-pipeline). Approach A is sufficient and minimal.

**Verification:**
- Write 2 tests: (1) graph updates still work, (2) driver is reused across updates
- Integration smoke tests pass

---

## Execution Order

1. **Task 1** (Resource enum Phase 2) — biggest wall-clock win, 30-180s saved
2. **Task 2** (CVE + MITRE parallel) — 10-60s saved
3. **Task 5** (Regex pre-compile) — simplest, lowest risk
4. **Task 3** (Recovery parallelization) — improves restart experience
5. **Task 4** (Dirty flag) — reduces disk I/O
6. **Task 6** (Neo4j pooling) — infrastructure improvement

## Risk Assessment

| Task | Risk | Mitigation |
|---|---|---|
| 1. Resource enum Phase 2 | **Medium** — tools write to shared dict | Each tool returns mergeable dict; verify key independence |
| 2. CVE + MITRE parallel | **Low** — separate output keys | Same pattern as OSINT parallelization already shipped |
| 3. Recovery parallelization | **Medium** — state mutation in threads | Collect all IDs first, resolve, then mutate in main thread |
| 4. Dirty flag | **Low** — pure optimization | Keep force-save at shutdown; 5s persist still catches everything |
| 5. Regex pre-compile | **Very low** — behavioral no-op | Run existing SSE tests |
| 6. Neo4j pooling | **Low** — existing connection pattern | Keep `verify_connection()` check; add driver close at shutdown |
