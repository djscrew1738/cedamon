# Custom Scans — Pipeline Composition for RedAmon Recon

## 1. Problem Statement

The current recon pipeline is a **fixed 6-phase sequence** hardcoded in
`recon/main.py`:

```
domain_discovery → port_scan → http_probe → resource_enum → vuln_scan → mitre_enrich
```

Users cannot:
- Compose their own tool sequences (e.g. skip port scan, run only takeover checks)
- Run attack-oriented workflows (e.g. vhost discovery → parameter fuzzing → SQLi)
- Mix partial/full scans in a single coordinated run
- Define reusable scan profiles per project type (bug-bounty, pentest, red-team)
- Inject custom tooling between existing phases

The 25+ individual tools already exist in `recon/partial_recon_modules/` but are
only accessible one-at-a-time.  No orchestration layer ties them together.

---

## 2. Vision

### Pipeline as a DAG of Typed Tools

Users define scanning pipelines as a **directed acyclic graph** where each node
is a tool and edges represent data dependencies.  The execution engine resolves
the DAG, runs independent phases in parallel, and streams results live.

### Attack-Oriented by Default

Pipelines are organised around **offensive security objectives**, not tool
categories:

| Objective | Typical phases | Why it matters |
|---|---|---|
| **Surface Mapping** | Subdomain Discovery → DNS Resolve → HTTP Probe → Tech Detect → JS Recon | Classic recon — fastest path to attack surface |
| **Takeover Hunt** | Subdomain Discovery → DNS Resolve → HTTP Probe → Subdomain Takeover Check | Cloud asset takeover — high-severity findings per hour |
| **API Security** | Subdomain Discovery → HTTP Probe → Endpoint Crawl → Param Discovery → Arjun → GraphQL Scan | API-first testing |
| **Deep Pentest** | Full pipeline + Nuclei + Nmap + Custom Templates | Compliance-grade coverage |
| **Red Team Blitz** | Passive Discovery → Uncover/Censys → Shodan → Port Scan → VHost Discovery | No domain required — start from IP/CIDR |
| **Supply Chain** | Domain Discovery → Cloud Enum → Cloudlist → Secret Scanning | Cloud exposure assessment |

### Reusable Templates

Each objective becomes a **pipeline template** that users instantiate per
project.  Templates are versioned, shareable, and can include:
- Conditional phases ("skip port scan if no HTTP targets found")
- Tool-specific settings (rate limits, concurrency, timeouts)
- RoE boundary rules (exclude CIDRs, restrict active checks)
- Notification triggers (Slack/Discord on critical finding)

---

## 3. Data Model

### 3.1 Pipeline Template (persisted, versioned)

```
PipelineTemplate {
  id:            UUID
  name:          string          // "Surface Mapping", "API Security", …
  description:   string
  version:       semver
  category:      enum            // recon, attack, audit, custom
  phases:        PhaseDef[]      // ordered list of DAG nodes
  tags:          string[]        // "fast", "loud", "stealth", "active", …
  author:        string
  created_at:    datetime
  updated_at:    datetime
}

PhaseDef {
  id:            UUID
  tool_id:       string          // "SubdomainDiscovery", "Nuclei", …
  label:         string          // user-visible name
  depends_on:    UUID[]          // phase IDs that must complete first
  config:        ToolConfig      // tool-specific overrides
  condition:     string | null   // expression like "prev.results.count > 0"
  parallel_with: UUID[] | null   // hint: run concurrently with these phases
  timeout:       int | null      // per-phase timeout (seconds)
}
```

### 3.2 Pipeline Run (runtime instance)

```
PipelineRun {
  id:              UUID
  project_id:      UUID
  template_id:     UUID
  status:          enum          // queued, starting, running, paused, completed, error
  phases:          PhaseRun[]    // instantiated phases
  artifact_id:     UUID          // link to output artifact
  started_at:      datetime
  completed_at:    datetime
  error:           string | null
  triggered_by:    string        // "user", "webhook", "schedule"
}

PhaseRun {
  id:              UUID
  phase_def_id:    UUID
  status:          enum          // pending, running, completed, skipped, error
  tool_id:         string
  input_snapshot:  dict          // frozen inputs at execution time
  output_summary:  dict          // counts, stats, first-N findings
  started_at:      datetime
  completed_at:    datetime
  error:           string | null
}
```

### 3.3 Run Artifact (combined output)

```
RunArtifact {
  id:              UUID
  run_id:          UUID
  project_id:      UUID
  format:          enum          // json, ndjson
  size_bytes:      int
  phase_results:   map<phase_id → PhaseOutput>
  graph_snapshot:  dict          // relevant Neo4j subgraph at run start
  storage_path:    string        // /app/recon/output/custom_{run_id}.json
}
```

---

## 4. Architecture & Components

### 4.1 Pipeline Engine (new module: `recon/pipeline_engine/`)

```
recon/pipeline_engine/
├── __init__.py
├── resolver.py         # Resolves DAG, topsorts, detects cycles
├── executor.py         # Executes phases respecting dependencies
├── context.py          # Shared context: results bus, artifact store
├── conditions.py       # Evaluates skip/continue expressions
├── tool_proxy.py       # Proxies to partial_recon_modules/* runners
└── templates/          # Built-in pipeline template definitions
    ├── surface_map.json
    ├── api_security.json
    ├── takeover_hunt.json
    ├── deep_pentest.json
    └── red_team_blitz.json
```

**`resolver.py`** — Takes a list of `PhaseDef`, builds a graph, runs
Kahn topological sort.  Detects cycles, missing dependencies, and orphan
phases.  Produces an execution plan: a list of "waves" where all phases in a
wave can run in parallel.

```
Input:  [A, B(depends=A), C(depends=A), D(depends=B, C)]
Output: Wave 0: [A]
        Wave 1: [B, C]    ← parallel
        Wave 2: [D]
```

**`executor.py`** — Iterates waves in order.  For each wave, spawns a
ThreadPoolExecutor (one thread per phase in the wave).  Each thread:
1. Evaluates the phase's condition expression against current context
2. Calls `tool_proxy.run(tool_id, input_data, config)`
3. Stores output in shared context
4. Streams progress events to the orchestrator via Redis pub/sub

**`tool_proxy.py`** — Thin wrapper around each
`recon.partial_recon_modules.*` runner.  Normalises inputs/outputs so the
engine has a uniform interface:

```python
# Every tool runner follows:
def run(config: ToolConfig, context: PipelineContext) -> PhaseOutput:
    ...

class ToolConfig(TypedDict):
    targets: list[str]         # domains, IPs, URLs from previous phases
    settings: dict             # tool-specific overrides
    project_id: str
    user_id: str

class PhaseOutput(TypedDict):
    status: str                # "completed", "skipped", "error"
    results: dict              # tool-specific results structure
    summary: dict              # counts, stats
    artifacts: list[str]       # file paths
    errors: list[str]
```

### 4.2 Orchestrator Changes (`recon_orchestrator/`)

**New endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/pipeline/{project_id}/start` | Start a pipeline run |
| `GET` | `/pipeline/{project_id}/status` | Get run status |
| `POST` | `/pipeline/{project_id}/pause` | Pause running pipeline |
| `POST` | `/pipeline/{project_id}/resume` | Resume paused pipeline |
| `POST` | `/pipeline/{project_id}/stop` | Abort running pipeline |
| `GET` | `/pipeline/{project_id}/logs` | SSE stream of phase transitions |
| `GET` | `/pipeline/{project_id}/result` | Download final artifact |
| `GET` | `/pipeline/templates` | List available pipeline templates |
| `POST` | `/pipeline/templates` | Save a custom pipeline template |
| `GET` | `/pipeline/templates/{id}` | Get template detail |
| `PUT` | `/pipeline/templates/{id}` | Update custom template |
| `DELETE` | `/pipeline/templates/{id}` | Delete custom template |

**Container lifecycle:**

Instead of launching one monolithic container per project, the orchestrator
manages a **pipeline worker** container that:
- Runs the pipeline engine as its entrypoint
- Receives the execution plan via environment / mounted config
- Streams phase-progress events back to the orchestrator
- Keeps running across phases (no container restart between phases)
- Cleans up only on completion/error/abort

The worker container is **reusable per project** — subsequent pipeline runs
reuse the same image with a new config.

### 4.3 Recon Container Changes

**New entrypoint** `recon/pipeline_run.py`:

```python
# Invoked by orchestrator instead of main.py or partial_recon.py
def main():
    config = load_pipeline_config()     # JSON from env/mount
    engine = PipelineEngine(config)
    engine.run()                         # resolves DAG, executes waves
    engine.export_artifact()             # writes combined output JSON
    engine.emit_completion()             # signals orchestrator via Redis
```

The existing `recon/main.py` and `recon/partial_recon.py` remain untouched —
the pipeline engine **calls the same `recon.partial_recon_modules.*` runners**
that partial recon uses.  No duplicate tool code.

### 4.4 Graph DB Integration

Each phase output is **automatically streamed to Neo4j** by the engine
(context-aware graph builders):

| Phase output | Graph update method |
|---|---|
| Subdomains | `update_graph_from_domain_recon()` |
| Ports | `update_graph_from_port_scan()` |
| HTTP endpoints | `update_graph_from_http_probe()` |
| Vulns | `update_graph_from_vuln_scan()` |
| Secrets | `update_graph_from_secret_scan()` |

The engine wraps these calls in a background thread (same pattern as
`_graph_update_bg()` in `main.py`) so the pipeline never blocks on Neo4j.

---

## 5. Attack-Oriented Pipeline Templates

### 5.1 Surface Mapping (fast recon — <10 min)

```
SubdomainDiscovery ─→ DNS Resolve ─→ HTTP Probe ─→ Tech Detect ─→ JS Recon
       │                                                           │
       └→ Cloud Enum ──────────────────────────────────────────────┘
                                                              │
                                                              └→ Endpoint AI Classifier
```

**Best for:** Bug bounty target triage, initial client assessment
**Tools:** Subfinder, Amass, Chaos, DNSx, Httpx, Jsluice, Katana
**Attack angle:** Maximise surface area per minute. Skip port scan, skip vuln scan.

### 5.2 Takeover Hunt (high-severity per hour)

```
SubdomainDiscovery → DNS Resolve → HTTP Probe → SubdomainTakeover Check
                                            │
                                            └→ Cloud Enum → Cloudlist
```

**Best for:** Cloud asset takeover discovery
**Tools:** Subfinder, DNSx, Httpx, subdomain-takeover detector, cloud_enum
**Attack angle:** Each takeover is P1/critical. Optimise for speed over breadth.

### 5.3 API Security Assessment

```
SubdomainDiscovery → HTTP Probe → Katana Crawl → Arjun Param Discovery
                                        │                  │
                                        ├→ Jsluice JS Parse┤
                                        │                  │
                                        └→ GraphQL Scan ───┘
                                                            │
                                                            └→ Nuclei (http/exposures)
```

**Best for:** API-first web applications
**Tools:** Katana, Arjun, Jsluice, graphqlscan, Nuclei
**Attack angle:** Modern apps expose 10× more API endpoints than HTML pages.

### 5.4 Deep Pentest (compliance-grade)

```
SubdomainDiscovery → DNS Resolve → HTTP Probe → Resource Enum → Nuclei → MITRE Enrich
       │                │                           │
       └→ ASN Map ──────┘                           ├→ Param Discovery
              │                                     ├→ FFUF Fuzzing
              │                                     └→ Custom Templates
              │
              └→ Port Scan (Masscan → Nmap)
                          │
                          └→ Nmap Script Scan
```

**Best for:** Compliance, PCI-DSS, full-scope pentests
**Tools:** All available
**Attack angle:** Depth over speed. Every vector checked.

### 5.5 Red Team Blitz (no domain — start from IP/CIDR)

```
Uncover → Censys → Shodan → HTTP Probe → Tech Detect → VHost Discovery
                                            │                  │
                                            ├→ Nuclei ─────────┘
                                            │
                                            └→ Port Scan (targeted, top-100)
```

**Best for:** Red team ops, external assessments with minimal scope
**Tools:** Uncover, Censys, Shodan, Httpx, Nuclei, naabu, vhost discovery
**Attack angle:** No domain provided — discover everything from IP space.

### 5.6 Supply Chain / Cloud Exposure

```
SubdomainDiscovery → Cloud Enum → Cloudlist → TruffleHog → Github Secret Hunt
       │                │
       └→ ASN Map ──────┘
              │
              └→ Port Scan (cloud IP ranges)
```

**Best for:** M&A due diligence, cloud migration validation
**Tools:** cloud_enum, cloudlist, TruffleHog, GitHub secret hunt
**Attack angle:** Cloud misconfigurations and leaked credentials are the
highest-ROI findings in modern infrastructure.

---

## 6. UI Components (Webapp)

### 6.1 Pipeline Builder

A drag-and-drop phase composer in the webapp:
- **Tool palette** — searchable list of all 25+ tools with descriptions
- **Canvas** — visual DAG with dependency arrows
- **Phase config panel** — tool-specific settings (rate limit, concurrency,
  custom headers, auth tokens, template selection)
- **Condition editor** — simple expression builder ("skip if no live hosts")
- **Template gallery** — pre-built templates with one-click instantiate
- **Version diff** — compare pipeline versions side-by-side

### 6.2 Pipeline Run Monitor

A real-time execution view:
- **Wave visualisation** — coloured blocks showing current/running/done phases
- **Live log stream** — per-phase SSE output piped to the browser
- **Summary panel** — running counts of hosts, endpoints, findings
- **Abort/Pause/Resume** controls
- **Phase timeline** — Gantt-style chart showing when each phase ran

### 6.3 Result Explorer

Post-run analysis:
- **Dependency graph** — visual trace of what data fed what
- **Phase replay** — expand any phase to see full tool output
- **Comparison mode** — diff two pipeline runs on the same project
- **Export** — JSON, PDF report, or raw tool output archive

---

## 7. Implementation Phases

### Phase 1 — Engine & Data Model (2-3 weeks)

| Step | What | Files |
|---|---|---|
| 1.1 | Pipeline template schema + Prisma migration | `webapp/prisma/schema.prisma` |
| 1.2 | Pipeline run + phase run + artifact models | `webapp/prisma/schema.prisma` |
| 1.3 | `resolver.py` — topological sort, cycle detection, wave generation | `recon/pipeline_engine/resolver.py` |
| 1.4 | `executor.py` — wave iteration, thread-pool, condition eval | `recon/pipeline_engine/executor.py` |
| 1.5 | `tool_proxy.py` — uniform wrapper around all partial_recon runners | `recon/pipeline_engine/tool_proxy.py` |
| 1.6 | `pipeline_run.py` — new container entrypoint | `recon/pipeline_run.py` |

### Phase 2 — Orchestrator Integration (1-2 weeks)

| Step | What | Files |
|---|---|---|
| 2.1 | Pipeline CRUD endpoints + container lifecycle | `recon_orchestrator/api.py` |
| 2.2 | Pipeline run + SSE streaming | `recon_orchestrator/container_manager.py` |
| 2.3 | Pipeline template CRUD endpoints | `recon_orchestrator/api.py` |
| 2.4 | Worker container management (start, stop, logs) | `recon_orchestrator/container_manager.py` |
| 2.5 | Redis pub/sub for phase events | `recon_orchestrator/` (new module) |

### Phase 3 — UI (2-3 weeks)

| Step | What | Files |
|---|---|---|
| 3.1 | Pipeline builder — drag-and-drop canvas | `webapp/src/app/pipelines/builder/` |
| 3.2 | Template gallery with one-click instantiate | `webapp/src/app/pipelines/templates/` |
| 3.3 | Run monitor — wave visualisation + SSE logs | `webapp/src/app/pipelines/monitor/` |
| 3.4 | Result explorer — phase replay + export | `webapp/src/app/pipelines/results/` |
| 3.5 | Pipeline management (list, edit, delete, version) | `webapp/src/app/pipelines/` |

### Phase 4 — Attack Templates & Polish (1 week)

| Step | What |
|---|---|
| 4.1 | Define 6 built-in attack-oriented templates (as JSON in `templates/`) |
| 4.2 | Template import/export (JSON files) |
| 4.3 | Pipeline scheduling (cron triggers via OpenHands automations) |
| 4.4 | Notification hooks (Slack, Discord on phase completion / critical finding) |
| 4.5 | Pipeline cost/impact estimation (predicted runtime, tool count, network egress) |

---

## 8. Key Design Decisions

### 8.1 Why DAG instead of linear pipeline?

A linear pipeline is simpler but forces serial execution.  The DAG model lets
independent phases run in parallel:
```
Subdomain Discovery ←──→ Cloud Enum    ←──→ ASN Map
         │                                   │
         └──────────→ Port Scan ←────────────┘
```
In the linear model, Cloud Enum and ASN Map would run after Port Scan (or not
at all).  In the DAG model they run concurrently with subdomain discovery.

### 8.2 Why new container entrypoint instead of modifying main.py?

- `main.py` is the **full pipeline** — changing it risks breaking existing runs
- `partial_recon.py` runs **one tool at a time** — different paradigm
- The pipeline engine calls the **same module functions** — no code duplication
- Keeps backward compat: existing `/recon/{project_id}/start` still works

### 8.3 Why conditions on phases?

Attack pipelines often have natural dependencies:
- "Run Nuclei only if HTTP probe found live hosts"
- "Run subdomain takeover only if target is a known cloud provider"
- "Skip Nmap script scan if no open ports found"

Hardcoded `if` checks are brittle.  A simple expression language
(`prev.results.live_hosts > 0`) lets users define their own branching logic.

### 8.4 How does this relate to partial recon?

| Feature | Partial Recon | Custom Scans |
|---|---|---|
| Scope | One tool, one run | N tools, sequenced pipeline |
| Data flow | Manual (user re-runs) | Automatic (DAG context passing) |
| Parallelism | None | DAG wave parallelism |
| Reusability | None | Versioned templates |
| Attack patterns | Single tool | Full attack workflow |

Both coexist.  Partial recon is for ad-hoc single-tool runs.  Custom scans
are for repeatable, multi-phase attack workflows.

---

## 9. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| DAG cycles cause infinite loops | Low | Kahn topsort + `max_depth=20` guard |
| Phase timeout starves dependents | Medium | Per-phase timeout kills only that phase; dependents see `null` input |
| Container memory for parallel waves | Medium | Configurable `max_parallel_phases` (default 4) |
| Tool output schema incompatibility | Low | `tool_proxy.py` enforces normalised output; integration tests per tool |
| User creates overly aggressive pipelines | Medium | RoE boundary check injected before every active phase; hard guardrail |
| Pipeline state lost on orchestrator restart | High | PipelineRun persisted in Postgres; running phases marked for re-queuing |

---

## 10. Success Metrics

| Metric | Target | How to measure |
|---|---|---|
| Time to run a targeted attack workflow | <5 min for Surface Mapping | Pipeline run duration |
| Time to add a new pipeline template | <10 min | Developer workflow test |
| Pipeline adoption | >50% of scans use custom pipelines | Webapp analytics |
| Findings per pipeline run | 2× vs full pipeline (attack-focused) | Compare template types |
| Parallel efficiency | >2× speedup for DAG vs linear | Wave timing data |
