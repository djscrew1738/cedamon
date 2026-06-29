# RedAmon — Phase 5 Deep Optimization Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Deepen optimization into the webapp, API layer, and infrastructure — beyond the pipeline parallelization already achieved in Phases 1-4.

**Architecture:** Three domains — webapp frontend performance, API response caching, and infrastructure hardening. Each domain has independent tasks that can execute in parallel.

**Tech Stack:** Next.js 16, FastAPI, Docker, PostgreSQL, Neo4j, SSE

---

## Domain 1: Webapp Frontend Performance

### Task W1: Add route-level code splitting with dynamic imports

**Objective:** Heavy pages (graph, insights, cypherfix) load all their chart libraries at page load time. Use Next.js `dynamic()` to lazy-load chart components, reducing initial bundle size.

**Files:**
- Modify: `webapp/src/app/graph/page.tsx`
- Modify: `webapp/src/app/insights/page.tsx`
- Modify: `webapp/src/app/cypherfix/page.tsx`

**Approach:**
```tsx
// Before: import { SeverityDonut } from './components/SeverityDonut'
// After:
const SeverityDonut = dynamic(() => import('./components/SeverityDonut'), {
  loading: () => <div className={styles.chartSkeleton} />,
  ssr: false,
})
```

**Priority components to lazy-load:**
- All Recharts chart components in insights/page.tsx (30+ imports)
- react-force-graph-2d/3d in graph/page.tsx
- @xterm/xterm in graph page (terminal component)
- react-syntax-highlighter in cypherfix page

**Verification:**
- `npm run build` passes without errors
- `ls -lh .next/static/chunks/` — verify chunk count increased (code split working)
- All pages load correctly (manual browser test)

---

### Task W2: Add image optimization for graph page icons

**Objective:** The graph page renders node type icons. Where possible, use Next.js `<Image>` component with proper sizing and lazy loading to reduce layout shift.

**Files:**
- Modify: `webapp/src/app/graph/components/` — node rendering components

**Verification:**
- Lighthouse score > 90 on graph page
- No layout shift warnings in browser console

---

## Domain 2: API Layer Caching

### Task A1: Add in-memory response cache for frequently-hit endpoints

**Objective:** Endpoints like `/api/projects/[id]/status`, `/api/graph/overview`, `/api/insights/summary` are polled frequently (every 2-5s by the frontend). Add a simple TTL cache to avoid redundant DB queries.

**Files:**
- Create: `recon_orchestrator/cache.py`
- Modify: `recon_orchestrator/api.py` — wrap relevant endpoints

**Implementation:**
```python
# recon_orchestrator/cache.py
import time
from functools import wraps
from typing import Any, Callable

class TTLCache:
    """Simple in-memory TTL cache for API responses."""
    def __init__(self, ttl_seconds: float = 2.0):
        self._cache: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time.monotonic() - ts > self._ttl:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._cache[key] = (time.monotonic(), value)

    def invalidate(self, key_prefix: str = "") -> None:
        if key_prefix:
            self._cache = {k: v for k, v in self._cache.items() if not k.startswith(key_prefix)}
        else:
            self._cache.clear()

# Global caches with different TTLs
status_cache = TTLCache(ttl_seconds=1.0)    # Status polls — very short TTL
insights_cache = TTLCache(ttl_seconds=5.0)   # Insights — medium TTL
overview_cache = TTLCache(ttl_seconds=3.0)   # Graph overview — medium TTL
```

**Endpoints to cache:**
- `GET /api/projects/{id}/status` — TTL 1s (polled every 2s by frontend)
- `GET /api/graph/overview` — TTL 3s
- `GET /api/insights/summary` — TTL 5s
- `GET /api/projects/{id}/recon/status` — TTL 1s (already has in-memory state)

**Cache invalidation:** Invalidate on POST/PUT/DELETE to related resources. The TTL handles staleness if invalidation is missed.

**Verification:**
- Unit tests: cache hit/miss/expiry/invalidation
- Manual: start recon, observe status endpoint response times drop after first poll

---

### Task A2: Add ETag support to static API responses

**Objective:** Endpoints that return large static data (project settings, tool catalogs) can use ETag headers so the frontend can cache them via `If-None-Match`.

**Files:**
- Modify: `recon_orchestrator/api.py` — add ETag middleware or per-endpoint headers

**Approach:** Compute a hash (SHA256 or simple `hash(str(data))`) for large response bodies. Return `ETag` header. On subsequent requests with `If-None-Match`, return `304 Not Modified`.

**Verification:**
- `curl -v` shows ETag header on first request
- `curl -H "If-None-Match: <etag>"` returns 304

---

## Domain 3: Infrastructure Hardening

### Task I1: Add subprocess timeout to remaining calls

**Objective:** Some subprocess calls in the recon pipeline lack timeouts. A stuck subprocess can hang the entire pipeline. Add `timeout=` to all `subprocess.run/call/Popen` calls.

**Files to audit:**
- `recon/main_recon_modules/` — all .py files
- `recon/helpers/` — all .py files
- `recon/partial_recon_modules/` — all .py files

**Pattern:**
```python
# Before: subprocess.run(cmd, ...)
# After:  subprocess.run(cmd, timeout=300, ...)
```

**Search command:**
```bash
grep -rn "subprocess\.\(run\|call\|Popen\|check_output\)" recon/ --include="*.py" | grep -v "timeout=" | grep -v test_
```

**Verification:**
- For each file modified: verify the timeout value is reasonable for the tool
- Run integration smoke tests

---

### Task I2: Add Docker image layer caching for recon image build

**Objective:** `_ensure_recon_image` builds from source every time the image is missing. The build copies the entire recon/ directory. Add a `.dockerignore` and order COPY statements to maximize layer caching.

**Files:**
- Create/Modify: `recon/Dockerfile` — reorder COPY for caching
- Create: `recon/.dockerignore` — exclude __pycache__, tests, .git, etc.

**Dockerfile optimization:**
```dockerfile
# Layer 1: dependencies (rarely changes)
COPY requirements.txt .
RUN pip install -r requirements.txt

# Layer 2: source code (changes frequently, but only invalidates this layer)
COPY recon/ /app/recon/
```

**Verification:**
- `docker build -t redamon-recon:latest -f recon/Dockerfile .` — first build takes full time
- Second build (no code changes) — completes in < 5s via cache
- Third build (code change) — only last layer rebuilds

---

### Task I3: Compress recon output JSON files

**Objective:** The `combined_result` JSON can be 10-50MB for large scans. Each `save_recon_file` writes the full uncompressed JSON. Add optional gzip compression to reduce I/O and disk usage.

**Files:**
- Modify: `recon/main.py:save_recon_file` — add `compress` parameter

**Implementation:**
```python
def save_recon_file(data: dict, output_file: Path, pretty: bool = False, compress: bool = False):
    if compress:
        import gzip, json as _json
        compressed_path = output_file.with_suffix(output_file.suffix + '.gz')
        with gzip.open(compressed_path, 'wt', encoding='utf-8') as f:
            _json.dump(data, f, default=str)
        return
    
    # existing logic
```

**Verification:**
- Compressed file is 5-10x smaller
- Test: write compressed, read back, verify identical data
- Integration tests still pass

---

## Execution Order

**Parallel tracks (independent):**
- Track A: W1 → W2 (webapp frontend)
- Track B: A1 → A2 (API caching)
- Track C: I1 → I2 → I3 (infrastructure)
- Track D: Task 3 + Task 6 from Phase 4 plan (container recovery + Neo4j pooling, deferred)

**Recommended execution:**
1. I1 (subprocess timeouts) — quick audit, high safety impact
2. A1 (API cache) — biggest frontend responsiveness win
3. W1 (code splitting) — biggest bundle size win
4. I2 (Docker layer cache) — developer experience
5. W2, A2, I3 — polish

## Risk Assessment

| Task | Risk | Notes |
|---|---|---|
| W1: Code splitting | Low | Next.js dynamic() is well-tested; graceful degradation if import fails |
| W2: Image optimization | Low | Cosmetic only |
| A1: API cache | **Medium** | Stale data risk; short TTLs + invalidation on mutation mitigate this |
| A2: ETag | Low | Purely additive header |
| I1: Subprocess timeouts | Low | Adds safety; appropriate timeout values per tool |
| I2: Docker cache | Low | Build-only change; no runtime impact |
| I3: JSON compression | Low | Optional; non-breaking addition |
