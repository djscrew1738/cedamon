# RedAmon Codebase Improvement Plan

> **For Hermes:** Implement phases sequentially. Each phase is self-contained and can be executed independently. Use TDD (test-driven development) for all new test suites — write the test first, verify it fails, then implement/correct the code.

**Goal:** Improve RedAmon's codebase health by eliminating the highest-impact technical debt: bare-except error swallowing, untested legacy code, missing test coverage in critical paths, and dangerously large monolithic files.

**Architecture:** Five phases ordered by risk-to-effort ratio. Phase 1 (bare excepts) is 5 lines of changes with massive reliability impact. Phase 2 removes 6,835 lines of dead code. Phase 3-4 add test coverage to the most exposed zero-coverage modules. Phase 5 splits the largest monolithic files.

**Tech Stack:** Python 3.14, pytest, neo4j, docker SDK, Next.js/TypeScript (frontend not in scope for Phases 1-5)

---

## Phase 1: Fix 4 Remaining Bare `except:` Catches

**Risk:** Low | **Effort:** ~10 min | **Impact:** Eliminates silent error swallowing in socket I/O, JSON parsing, and WebSocket communication paths.

### Background

Previous cleanups (Tier 1.1, 1.2) fixed 37+ files but 4 bare `except:` catches remain. These swallow ALL exception types (KeyboardInterrupt, SystemExit, MemoryError, etc.) and make failures invisible.

### Task 1.1: Fix bare `except:` in `http_probe.py` (3 sites)

**Objective:** Replace 3 bare `except:` blocks with specific exception handling that logs the failure.

**Files:**
- Modify: `recon/main_recon_modules/http_probe.py` (lines 364, 396, 1329)

**Step 1: Fix line ~364 — banner grab socket error**

Current:
```python
            try:
                sock.send(probe)
                sock.settimeout(timeout)
                banner = sock.recv(1024)
            except:
                print(f"[!] grab_banner: sock.send(probe)")
                pass
```

Replace with:
```python
            try:
                sock.send(probe)
                sock.settimeout(timeout)
                banner = sock.recv(1024)
            except (OSError, socket.timeout) as e:
                print(f"[!] grab_banner: socket error for port {port}: {e}")
                pass
```

**Step 2: Fix line ~396 — Wappalyzer cache JSON decode**

Current:
```python
        try:
            with open(WAPPALYZER_CACHE_FILE, 'r') as f:
                cached_data = json.load(f)
            ...
        except:
            print(f"[*][httpx] Using cached Wappalyzer DB ...")
```

Replace with:
```python
        try:
            with open(WAPPALYZER_CACHE_FILE, 'r') as f:
                cached_data = json.load(f)
            ...
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            print(f"[*][httpx] Could not read cached Wappalyzer DB: {e}")
```

**Step 3: Fix line ~1329 — another JSON/IO exception**

Current:
```python
            except:
                print(f"[*][httpx] Using cached Wappalyzer DB ...")
```

Replace with:
```python
            except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
                print(f"[*][httpx] Could not read cached Wappalyzer DB: {e}")
```

**Step 4: Verify — syntax check**

```bash
python3 -c "import ast; ast.parse(open('recon/main_recon_modules/http_probe.py').read()); print('OK')"
```

**Step 5: Commit**

```bash
git add recon/main_recon_modules/http_probe.py
git commit -m "fix: replace bare excepts with typed exceptions in http_probe.py"
```

### Task 1.2: Fix bare `except:` in `websocket_api.py` (1 site)

**Objective:** Replace bare `except:` pass in WebSocket error handler with `except Exception:` that at minimum logs the failure.

**Files:**
- Modify: `agentic/websocket_api.py` (line ~1636)

**Step 1: Fix the handler**

Current:
```python
        except:
            pass
```

Replace with:
```python
        except Exception:
            logger.debug("Could not send error message to disconnected client")
```

**Step 2: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('agentic/websocket_api.py').read()); print('OK')"
```

**Step 3: Commit**

```bash
git add agentic/websocket_api.py
git commit -m "fix: replace bare except with Exception in websocket_api.py error handler"
```

**Verification for Phase 1:**
```bash
# Confirm zero bare excepts remain
grep -rn 'except\s*:' --include='*.py' recon/main_recon_modules/http_probe.py agentic/websocket_api.py | grep -v '#.*except:'
# Expected: no output
```

---

## Phase 2: Remove `neo4j_client_legacy.py` — 6,835 Lines of Dead Code

**Risk:** Low | **Effort:** ~5 min | **Impact:** Removes the single largest file in the codebase. It's not imported by any live code.

### Background

`graph_db/neo4j_client_legacy.py` (6,835 lines) is the original monolithic Neo4j client that was refactored into mixins (`graph_db/mixins/`). The active client is `graph_db/neo4j_client.py` (32 lines) which uses the mixin architecture. The legacy file is only referenced by:

1. `_fix_except_pass.py` — a tooling script that lists it as a target
2. `tests/test_graph_db_refactor.py` — tests that validate the refactoring was correct

Neither reference imports or executes it at runtime.

### Task 2.1: Verify no runtime imports

```bash
grep -rn 'neo4j_client_legacy' --include='*.py' --exclude='test_*.py' --exclude='_fix_except_pass.py' --exclude-dir=.venv --exclude-dir=__pycache__ .
# Expected: no output (only test files and tooling reference it)
```

### Task 2.2: Remove references from tooling

**Files:**
- Modify: `_fix_except_pass.py` — remove line 74: `"graph_db/neo4j_client_legacy.py",`
- Modify: `tests/test_graph_db_refactor.py` — remove or update tests that reference legacy file

**Step 1: Update `_fix_except_pass.py`**

Find and remove the line containing `"graph_db/neo4j_client_legacy.py"` from the TARGETS list.

```bash
# Verify the line exists
grep -n 'neo4j_client_legacy' _fix_except_pass.py
```

Then patch to remove it.

**Step 2: Update `tests/test_graph_db_refactor.py`**

This test file validates that the refactored mixin modules match the legacy client. Since the refactoring is complete and validated, the legacy comparison tests are no longer needed. Review and remove the specific tests that reference the legacy file (around lines 155 and 360).

**Step 3: Delete the legacy file**

```bash
git rm graph_db/neo4j_client_legacy.py
```

**Step 4: Verify nothing breaks**

```bash
# Import the active client
python3 -c "from graph_db import Neo4jClient; print('OK: imports cleanly')"
# Verify tests still pass (excluding the removed legacy refs)
python3 -m pytest tests/test_graph_db_refactor.py -v --tb=short 2>&1 | tail -20
```

**Step 5: Commit**

```bash
git add _fix_except_pass.py tests/test_graph_db_refactor.py
git commit -m "refactor: remove neo4j_client_legacy.py (6835 lines of dead code)"
```

**Verification for Phase 2:**
```bash
ls graph_db/neo4j_client_legacy.py 2>&1
# Expected: No such file or directory
```

---

## Phase 3: Add Test Coverage to `graph_db/` (22 source files, ZERO tests)

**Risk:** Low-Medium | **Effort:** ~2-3 hours | **Impact:** The graph database layer is the single source of truth for all recon data. Zero test coverage means schema drift, broken Cypher queries, and data corruption go undetected until production.

### Background

The `graph_db/` package has:
- 22 source files
- 0 test files
- 1 integration test (`tests/test_graph_db_refactor.py`) — tests refactoring correctness, not functionality

The package architecture:
```
graph_db/
├── __init__.py           # Exports Neo4jClient
├── neo4j_client.py       # Public client class (32 lines, composed of mixins)
├── schema.py             # Schema constants and constraints
├── cpe_resolver.py       # CPE-to-CVE resolution
├── tenant_filter.py      # Tenant isolation utilities
├── mixins/
│   ├── base_mixin.py     # Connection lifecycle, schema init, base queries
│   ├── recon_mixin.py    # Core recon data ingestion
│   ├── gvm_mixin.py      # GVM vulnerability results
│   ├── secret_mixin.py   # GitHub secret hunt / TruffleHog results
│   ├── osint_mixin.py    # OSINT enrichment (Shodan, Censys, etc.) — 2,262 lines
│   ├── graphql_mixin.py  # GraphQL scan results
│   ├── fireteam_mixin.py # Fireteam agent coordination
│   └── recon/            # Per-phase recon mixins
│       ├── domain_mixin.py
│       ├── port_mixin.py
│       ├── http_mixin.py
│       ├── resource_mixin.py
│       ├── vuln_mixin.py
│       ├── takeover_mixin.py
│       ├── vhost_sni_mixin.py
│       ├── js_recon_mixin.py
│       ├── ai_surface_recon_mixin.py
│       └── user_input_mixin.py
```

### Approach

Tests use the same mocking pattern as `tests/test_graph_db_refactor.py` — stub the `neo4j` package at module level so no live Neo4j connection is needed. Focus on:

1. **Schema integrity** — constants are correct, constraints don't conflict
2. **Query generation** — Cypher strings are syntactically valid and use parameterized inputs
3. **Mixin composition** — MRO is correct, no method collisions
4. **Data transformation** — JSON parse helpers handle edge cases (empty, null, malformed)

### Task 3.1: Create `graph_db/tests/` directory and conftest

**Files:**
- Create: `graph_db/tests/__init__.py`
- Create: `graph_db/tests/conftest.py`

**Step 1: Create `conftest.py` with neo4j stub**

```python
"""Shared fixtures for graph_db unit tests."""
import sys
import pytest
from unittest.mock import MagicMock

_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())


@pytest.fixture
def mock_driver():
    """Return a fresh mock driver for each test."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value = session
    return driver


@pytest.fixture
def mock_session(mock_driver):
    """Return a mock session."""
    return mock_driver.session.return_value


@pytest.fixture
def client(mock_driver):
    """Create a Neo4jClient with a mocked driver."""
    from graph_db import Neo4jClient
    # Patch the driver creation
    import graph_db.mixins.base_mixin
    original = graph_db.mixins.base_mixin.GraphDatabase.driver
    graph_db.mixins.base_mixin.GraphDatabase.driver = MagicMock(return_value=mock_driver)
    c = Neo4jClient()
    graph_db.mixins.base_mixin.GraphDatabase.driver = original
    return c
```

**Step 2: Verify conftest loads**

```bash
python3 -c "import graph_db.tests.conftest; print('OK')"
```

### Task 3.2: Test schema constants (`schema.py`)

**Files:**
- Create: `graph_db/tests/test_schema.py`

**Tests to write:**

1. `test_node_labels_are_valid` — all `NODE_LABELS` match `^[A-Za-z][A-Za-z0-9_]*$`
2. `test_relationship_types_are_valid` — all relationship types match valid pattern
3. `test_constraints_have_unique_names` — no duplicate constraint names
4. `test_no_duplicate_node_labels` — all labels are unique
5. `test_no_orphan_relationship_types` — every relationship type references known node labels

```python
"""Schema constant tests."""
import re
import pytest
from graph_db import schema


class TestNodeLabels:
    def test_all_labels_match_pattern(self):
        for label in schema.NODE_LABELS:
            assert re.match(r'^[A-Za-z][A-Za-z0-9_]*$', label), \
                f"Invalid label: {label}"

    def test_no_duplicates(self):
        assert len(schema.NODE_LABELS) == len(set(schema.NODE_LABELS))


class TestConstraints:
    def test_unique_constraint_names(self):
        names = [c['name'] for c in schema.CONSTRAINTS]
        assert len(names) == len(set(names)), f"Duplicate constraints: {names}"


class TestRelationships:
    def test_all_types_match_pattern(self):
        for rel in schema.RELATIONSHIP_TYPES:
            assert re.match(r'^[A-Z_]+$', rel), f"Invalid relationship: {rel}"
```

### Task 3.3: Test base mixin (connection lifecycle)

**Files:**
- Create: `graph_db/tests/test_base_mixin.py`

**Tests to write:**

1. `test_client_connects_on_context_manager` — `with Neo4jClient() as c:` calls driver
2. `test_client_closes_on_exit` — context manager exit calls driver.close()
3. `test_merge_operation_uses_parameters` — verify Cypher uses `$param` not string interpolation
4. `test_tenant_filter_applied_to_read_queries` — tenant ID injected into WHERE clauses

```python
"""Base mixin tests."""
import pytest


class TestConnectionLifecycle:
    def test_client_connects_on_init(self, client, mock_driver):
        """Client should construct a driver on instantiation."""
        assert client._driver is not None

    def test_client_runs_schema_init(self, client, mock_session):
        """Schema constraints should be created on init."""
        # First session.run() call should be a constraint creation
        calls = mock_session.run.call_args_list
        assert len(calls) > 0, "Expected at least one schema init call"


class TestCypherSafety:
    def test_merge_uses_parameters(self, client, mock_session):
        """All merge operations must use $param, never string interpolation."""
        client.update_graph_from_domain_discovery({}, "user1", "proj1")
        for call in mock_session.run.call_args_list:
            query = call[0][0]
            # Verify the query uses $ parameters, not raw string insertion
            if "user1" in query:
                # user_id should appear as $user_id, not raw
                assert "$user_id" in query or "$" + "user_id" in query, \
                    f"Query uses raw user_id instead of parameter: {query[:100]}"
```

### Task 3.4: Test tenant filter (`tenant_filter.py`)

**Files:**
- Create: `graph_db/tests/test_tenant_filter.py`

**Tests to write:**

1. `test_inject_tenant_clause_adds_where` — Cypher gets `WHERE n.tenant_id = $tid`
2. `test_inject_tenant_clause_preserves_existing_where` — existing WHERE gets AND
3. `test_inject_tenant_clause_with_clause` — WITH clause handled correctly
4. `test_inject_tenant_clause_no_where_no_with` — bare MATCH gets correct injection

```python
"""Tenant filter tests."""
from graph_db.tenant_filter import inject_tenant_clause


class TestTenantFilterInjection:
    def test_adds_where_when_no_existing(self):
        query = "MATCH (n:Host) RETURN n"
        result = inject_tenant_clause(query, param_name="tenant_id")
        assert "WHERE" in result
        assert "$tenant_id" in result
        assert "MATCH (n:Host)" in result  # preserves original

    def test_appends_and_to_existing_where(self):
        query = "MATCH (n:Host) WHERE n.active = true RETURN n"
        result = inject_tenant_clause(query, param_name="tenant_id")
        assert "AND" in result
        assert "n.active = true" in result  # preserves original condition

    def test_idempotent(self):
        query = "MATCH (n:Host) RETURN n"
        once = inject_tenant_clause(query, param_name="tenant_id")
        twice = inject_tenant_clause(once, param_name="tenant_id")
        assert once == twice  # should not double-inject
```

### Task 3.5: Test CPE resolver (`cpe_resolver.py`)

**Files:**
- Create: `graph_db/tests/test_cpe_resolver.py`

**Tests to write:**

1. `test_parse_cpe_standard_format` — `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*` → correct dict
2. `test_parse_cpe_minimal` — vendor and product only
3. `test_parse_cpe_empty_string` — returns None
4. `test_parse_cpe_invalid_prefix` — non-CPE string returns None
5. `test_resolve_to_cve_mocked` — API call path returns CVE list (mocked HTTP)

### Task 3.6: Test one mixin end-to-end (domain_mixin)

**Files:**
- Create: `graph_db/tests/test_domain_mixin.py`

**Tests to write:**

1. `test_ingest_domain_creates_node` — domain discovery data creates Domain nodes
2. `test_ingest_domain_creates_relationships` — Domain → IP relationships created
3. `test_ingest_empty_data_no_error` — empty dict doesn't crash
4. `test_ingest_malformed_data_handled` — missing required fields handled gracefully
5. `test_idempotent_ingestion` — same data twice = MERGE not CREATE duplicate

```python
"""Domain mixin tests."""
import pytest


class TestDomainIngestion:
    SAMPLE_DATA = {
        "subdomains": ["api.example.com", "www.example.com"],
        "ips": {"api.example.com": ["1.2.3.4"], "www.example.com": ["5.6.7.8"]},
        "wildcard": False,
        "wildcard_domains": [],
    }

    def test_ingest_creates_nodes(self, client, mock_session):
        client.update_graph_from_domain_discovery(
            self.SAMPLE_DATA, "user1", "proj1"
        )
        # Verify session.run was called with MERGE queries
        calls = mock_session.run.call_args_list
        merge_calls = [c for c in calls if "MERGE" in c[0][0]]
        assert len(merge_calls) > 0, "Expected at least one MERGE call"

    def test_ingest_empty_data_no_crash(self, client, mock_session):
        client.update_graph_from_domain_discovery({}, "user1", "proj1")
        # Should not raise, even with no subdomains

    def test_ingest_malformed_data_no_crash(self, client, mock_session):
        client.update_graph_from_domain_discovery(
            {"subdomains": None, "ips": "not_a_dict"}, "user1", "proj1"
        )
        # Should not raise — graceful degradation

    def test_user_id_in_parameters(self, client, mock_session):
        client.update_graph_from_domain_discovery(
            self.SAMPLE_DATA, "user1", "proj1"
        )
        for call in mock_session.run.call_args_list:
            params = call[0][1] if len(call[0]) > 1 else {}
            # user_id should be passed as a parameter, not embedded in query string
            if "user1" == params.get("user_id"):
                return  # found it passed as parameter
        pytest.fail("user_id not found as a Cypher parameter")
```

### Task 3.7: Commit Phase 3

```bash
git add graph_db/tests/
git commit -m "test: add graph_db test suite (schema, base mixin, tenant filter, CPE resolver, domain mixin)"
```

**Verification for Phase 3:**
```bash
python3 -m pytest graph_db/tests/ -v --tb=short
# Expected: all tests pass (15-20 tests)
```

---

## Phase 4: Add Test Coverage to `container_manager.py` (3,195 lines, no test suite)

**Risk:** Medium | **Effort:** ~2-3 hours | **Impact:** The container manager handles Docker lifecycle for ALL recon scans. A regression in cleanup logic leaks containers and eats RAM. Currently zero test coverage.

### Background

`container_manager.py` is the largest file in `recon_orchestrator/`. It manages:
- Full recon pipeline execution (spawns `redamon-recon` container)
- Partial recon execution (spawns per-tool containers)
- GVM scanner (spawns `redamon-vuln-scanner` container)
- GitHub secret hunt + TruffleHog scans
- Log streaming via SSE
- Container cleanup and orphan detection
- Concurrent run limits (max 12 partial recons per project)
- Scheduled recon queue

The existing test files (`recon_orchestrator/tests/test_container_manager.py` at 1,649 lines) exist but are likely integration tests or focused on specific APIs. Need to verify coverage.

### Approach

Tests use `unittest.mock` to stub `docker.from_env()` — no Docker daemon required. Focus on:
1. State machine transitions (pending → running → completed/failed)
2. Log streaming and ANSI escape stripping
3. Container cleanup and orphan detection
4. Concurrent run limiting
5. Error handling and recovery

### Task 4.1: Create helper factories for mock containers

**Files:**
- Create: `recon_orchestrator/tests/factories.py`

```python
"""Test factories for container_manager mocks."""
from unittest.mock import MagicMock
from datetime import datetime, timezone


def mock_container(status="running", logs=b"", name="redamon-recon-abc123"):
    """Create a mock Docker container with standard logging behavior."""
    c = MagicMock()
    c.status = status
    c.name = name
    c.id = "abc123def456"
    c.short_id = "abc123"

    # Simulate streaming logs
    def _logs(**kwargs):
        if kwargs.get("stream"):
            yield logs if isinstance(logs, bytes) else logs.encode()
        else:
            return logs
    c.logs = MagicMock(side_effect=_logs)
    c.attrs = {
        "Created": datetime.now(timezone.utc).isoformat(),
        "State": {"Status": status, "Running": status == "running"},
        "Name": name,
    }
    return c


def mock_docker_client(containers=None):
    """Create a mock Docker client with configurable container list."""
    client = MagicMock()
    client.containers = MagicMock()
    client.containers.list.return_value = containers or []
    client.containers.run = MagicMock()
    client.containers.get = MagicMock()
    return client
```

### Task 4.2: Test State Store operations

**Files:**
- Create: `recon_orchestrator/tests/test_state_store.py`

**Tests to write:**

1. `test_create_recon_state` — new ReconState has correct defaults
2. `test_transition_recon_state` — pending → running → completed works
3. `test_transition_invalid` — running → pending raises or is no-op
4. `test_partial_recon_parallel_limit` — enforcing MAX_PARALLEL_PARTIAL_RECONS
5. `test_concurrent_user_limit` — USER_MAX_CONCURRENT_RECONS enforced

### Task 4.3: Test log streaming and ANSI stripping

**Files:**
- Create: `recon_orchestrator/tests/test_log_streaming.py`

**Tests to write:**

1. `test_ansi_escape_stripped` — `\x1b[32mGREEN\x1b[0m` → `GREEN`
2. `test_multiline_logs_yielded_line_by_line` — `b"line1\nline2\n"` → 2 events
3. `test_empty_logs_no_event` — empty bytes → no log event
4. `test_container_not_found_graceful` — Container disappears mid-stream → stops cleanly
5. `test_log_stream_resumes_after_restart` — post-restart logs stream from last offset

### Task 4.4: Test container cleanup

**Files:**
- Modify/Add to: `recon_orchestrator/tests/test_container_manager.py`

**Tests to write:**

1. `test_orphaned_container_detected_and_removed` — container with no state entry gets cleaned
2. `test_completed_container_cleaned_after_stream` — after log stream ends, container removed
3. `test_cleanup_handles_not_found` — container already gone → no error
4. `test_cleanup_handles_api_error` — Docker API error 500 → logged, not fatal
5. `test_concurrent_cleanup_safe` — two cleanup calls on same container don't collide

### Task 4.5: Test retry wrapper (`_exec_with_retry`)

**Files:**
- Modify/Add to: `recon_orchestrator/tests/test_container_manager.py`

**Tests to write:**

1. `test_retry_on_transient_error` — APIError with 500 → retries then succeeds on attempt 3
2. `test_no_retry_on_permanent_error` — ImageNotFound → fails immediately, no retry
3. `test_backoff_increases` — delay between retries grows exponentially
4. `test_retry_count_respected` — `max_retries=2` → exactly 2 attempts on persistent failure

### Task 4.6: Commit Phase 4

```bash
git add recon_orchestrator/tests/
git commit -m "test: add container_manager test suite (state store, log streaming, cleanup, retry)"
```

**Verification for Phase 4:**
```bash
python3 -m pytest recon_orchestrator/tests/ -v --tb=short
# Expected: all tests pass (~25-30 tests total)
```

---

## Phase 5: Split Monolithic Files

**Risk:** Medium | **Effort:** ~3-4 hours | **Impact:** Large files create merge conflicts, make code reviews painful, and hide bugs. Targeted splits of the worst offenders.

### Priority targets

| File | Lines | Strategy |
|---|---|---|
| `agentic/prompts/base.py` | 2,709 | Extract per-attack-skill prompts into submodules |
| `recon/main.py` | 2,598 | Extract phase runners into `recon/pipeline_phases/` |
| `agentic/tools.py` | 2,111 | Extract per-tool handlers into `agentic/tool_handlers/` |
| `recon/helpers/security_checks.py` | 2,661 | Extract check functions into `recon/helpers/security_checks/` |

### Task 5.1: Split `recon/main.py` — extract phase runners

**Files:**
- Create: `recon/pipeline_phases/__init__.py`
- Create: `recon/pipeline_phases/domain_discovery.py`
- Create: `recon/pipeline_phases/port_scan.py`
- Create: `recon/pipeline_phases/http_probe.py`
- Create: `recon/pipeline_phases/resource_enum.py`
- Create: `recon/pipeline_phases/vuln_scan.py`
- Create: `recon/pipeline_phases/mitre_enrich.py`
- Modify: `recon/main.py`

**Approach:**

Each phase runner module exports a single function `run_<phase>(settings: dict) -> dict` that takes project settings and returns phase results. `main.py` becomes a thin orchestrator:

```python
# recon/main.py (after refactor — ~200 lines)
from recon.pipeline_phases import (
    run_domain_discovery,
    run_port_scan,
    run_http_probe,
    run_resource_enum,
    run_vuln_scan,
    run_mitre_enrich,
)

PHASES = [
    ("domain_discovery", run_domain_discovery),
    ("port_scan", run_port_scan),
    ("http_probe", run_http_probe),
    ("resource_enum", run_resource_enum),
    ("vuln_scan", run_vuln_scan),
    ("mitre_enrich", run_mitre_enrich),
]

def run_pipeline(settings: dict) -> dict:
    results = {}
    for phase_name, phase_fn in PHASES:
        if phase_name in settings.get("disabled_phases", []):
            continue
        phase_results = phase_fn(settings)
        results[phase_name] = phase_results
        # SSE streaming, checkpointing, graph updates handled here
    return results
```

**Verification:**
```bash
python3 -c "from recon.pipeline_phases import *; print('OK')"
python3 -m pytest recon/tests/ -v --tb=short -x -q 2>&1 | tail -5
```

### Task 5.2: Split `agentic/prompts/base.py` — extract attack skill prompts

**Files:**
- Create: `agentic/prompts/attack_skills/__init__.py`
- Modify: `agentic/prompts/base.py` (reduce to core system prompt only)

**Approach:**

Each attack skill's prompt block gets its own file:
- `agentic/prompts/attack_skills/sql_injection.py`
- `agentic/prompts/attack_skills/xss.py`
- `agentic/prompts/attack_skills/container_k8s.py`
- etc.

The `base.py` module keeps the core system prompt and imports attack skill prompts dynamically. Each extracted module exports a single `PROMPT: str` constant.

**Verification:**
```bash
python3 -c "from agentic.prompts.attack_skills import *; print('OK')"
```

### Task 5.3: Commit Phase 5

```bash
git add recon/pipeline_phases/ agentic/prompts/attack_skills/
git add recon/main.py agentic/prompts/base.py
git commit -m "refactor: split recon/main.py and agentic/prompts/base.py into submodules"
```

---

## Phase 6: Coverage Gap — `agentic/orchestrator_helpers/` (35 files, ZERO tests)

**Risk:** High | **Effort:** ~3-4 hours | **Impact:** The LangGraph agent's orchestration logic — nodes, chain writers, member streaming, tool dispatch — is completely untested. This is the core AI agent decision-making layer.

### Task 6.1: Test orchestration state transitions

**Files:**
- Create: `agentic/tests/test_orchestrator_state.py`

**Tests to write:**

1. `test_initial_state_has_required_fields`
2. `test_state_transition_info_to_exploit` — informational phase → exploitation
3. `test_phase_triggers_correct_node`
4. `test_empty_graph_produces_info_phase` — no findings → informational, not exploit

### Task 6.2: Test tool dispatch routing

**Files:**
- Create: `agentic/tests/test_tool_dispatch.py`

**Tests to write:**

1. `test_parse_tool_output_nmap` — real nmap XML → parsed findings
2. `test_parse_tool_output_nuclei` — real nuclei JSONL → parsed vulns
3. `test_parse_tool_output_empty` — empty output → empty findings
4. `test_parse_tool_output_garbage` — non-JSON output → handled gracefully
5. `test_dispatch_route_maps_correct_tool` — tool name → correct parser function

### Task 6.3: Test Fireteam coordination

**Files:**
- Create: `agentic/tests/test_fireteam_coordination.py`

**Tests to write:**

1. `test_specialist_creation` — Fireteam member created with correct role
2. `test_wave_completion_updates_todos`
3. `test_concurrent_members_dont_collide`
4. `test_deduped_findings_across_members`

### Task 6.4: Commit Phase 6

```bash
git add agentic/tests/
git commit -m "test: add orchestrator_helpers test suite (state, dispatch, fireteam)"
```

---

## Summary: Execution Order

| Phase | What | Time | Risk | Impact |
|---|---|---|---|---|
| **1** | Fix 4 bare excepts | 10 min | Low | Eliminates silent failures |
| **2** | Remove legacy Neo4j client | 5 min | Low | -6,835 lines dead code |
| **3** | graph_db test suite (~20 tests) | 2-3 hr | Low-Med | Zero → covered critical data layer |
| **4** | container_manager test suite (~25 tests) | 2-3 hr | Med | Zero → covered Docker lifecycle |
| **5** | Split monolithic files (2 of 4) | 3-4 hr | Med | 5,300 lines split into submodules |
| **6** | orchestrator_helpers test suite (~20 tests) | 3-4 hr | High | Zero → covered AI agent core |

**Total: ~12-16 hours of focused work across 6 phases. Each phase is independently committable and verifiable.**

---

## Risks & Tradeoffs

1. **Testing with mocked neo4j/docker** — mocks can drift from real behavior. Mitigation: integration smoke tests (run against real Neo4j/Docker) should be added after unit test suites are stable.
2. **File splits risk import breakage** — other modules may import from sub-modules being split. Need a `grep -rn "from recon import\|from recon.main\|from agentic.prompts.base"` audit before any split.
3. **Existing tests may break** — 50 recon test files and 84 agentic test files may have imports that need updating after splits. Run full test suite after each phase.
4. **Legacy Neo4j client removal** — test_graph_db_refactor.py tests the legacy file. Must verify those tests are non-essential before modifying or removing them.

## Open Questions

1. Should `agentic/tools.py` (2,111 lines) also be split in Phase 5, or deferred due to risk?
2. Should `recon/helpers/security_checks.py` (2,661 lines) be split into per-check modules, or left as-is since security checks are stable?
3. Should `graph_db/mixins/osint_mixin.py` (2,262 lines) be split into per-provider sub-mixins?
