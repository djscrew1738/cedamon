# Recon Pipeline — 6‑Tier Improvement Plan

**Status:** Active · **Updated:** 2026-06-16  
**Tiers completed:** 1.2 (silent excepts), 1.3 (searchsploit parser)  
**Tiers remaining:** 1.1, 2, 3, 4, 5, 6

---

## Tier 1: Error Handling & Reliability

> **Goal:** Eliminate silent failures and add observability to all recon code paths.

### ✅ Tier 1.2 — Silent `except: pass` Remediation (COMPLETE)
- Automated `_fix_except_pass.py` script patched 37 files across `recon/`, `recon_orchestrator/`
- Bare `except:` and `except Exception: pass` patterns replaced with logged/printed warnings
- All 37 modified files pass `ast.parse()` syntax validation
- Added `logging.getLogger(__name__)` to `_tool_docker_utils.py` (was missing any logging mechanism)
- `recon/main.py` added to target list (was missed)

### ✅ Tier 1.3 — `parse_searchsploit` (COMPLETE)
- Parser added to `agentic/output_parsers.py`
- Registered in `PARSER_REGISTRY`

### 🔲 Tier 1.1 — Remaining Non-Recon Silent Excepts
**Files outside `recon/` still needing attention:**

| File | Line | Pattern |
|------|------|---------|
| `github_secret_hunt/github_secret_hunt.py` | 579 | `except: pass` |
| `graph_db/mixins/recon/js_recon_mixin.py` | 53 | `except Exception: pass` |
| `graph_db/neo4j_client_legacy.py` | 289 | `except Exception: pass` |
| `graph_db/schema.py` | 171 | `except Exception: pass` |
| `guinea_pigs/ai_surface_target/...py` | 136 | `except Exception: pass` |
| `gvm_scan/gvm_scanner.py` | 176, 246 | `except Exception: pass` |
| `gvm_scan/ready_probe.py` | 140 | `except Exception: pass` |
| `knowledge_base/curation/data_ingestion.py` | 291, 386 | `except Exception: pass` |
| `mcp/servers/metasploit_server.py` | 304 | `except: pass` |
| `mcp/servers/network_recon_server.py` | 683 | `except Exception: pass` |
| `mcp/servers/nuclei_server.py` | 58 | `except Exception: pass` |
| `mcp/servers/terminal_server.py` | 173 | `except Exception: pass` |

**Action:** Run `_fix_except_pass.py` with extended TARGETS list covering these modules.  
**Effort:** Low (script already handles the patterns)  
**Risk:** Low — same pattern as proven recon/ fix

### 🔲 Tier 1.4 — Retry & Resilience Audit
- Audit all subprocess calls for proper timeout handling
- Add retry logic with backoff to flaky external API calls
- Verify orphan container cleanup in `container_manager.py` (8+ orphan code paths, zero tests)
- Add disk-space checks before write operations (preempt full-disk failures)

---

## Tier 2: Test Coverage

> **Goal:** Close critical test gaps, especially for the container manager and parsers.

### 🔲 Tier 2.1 — Parser Tests
- Add `TestParseSearchsploit` test class (Tier 1.3 delivered parser, no tests yet)
- Add `TestParseMasscan` test class (currently reuses `parse_naabu` via alias)
- Verify `test_tool_registry_consistency.py` _KNOWN_MISSING list is up to date
  - `cve_intel` and `tradecraft_lookup` are stale entries (both now in TOOL_PHASE_MAP)

### 🔲 Tier 2.2 — Container Manager Tests ⚠️ **HIGH PRIORITY**
`recon_orchestrator/container_manager.py` is **2569 lines with zero tests**. Critical coverage needed:
- Orphan container detection and cleanup (8+ code paths at lines 315, 462, 1041, 1278, 1389, 1806, 1908, 2212, 2314)
- `shutdown()` graceful teardown (line 153)
- `_cleanup_sub_containers()` (line 481)
- Parallel partial recon lifecycle management
- `_scan_cleanup()` full flow

**Effort:** High (complex module with Docker subprocess interactions)  
**Risk:** High untested — failures visible in production only

### 🔲 Tier 2.3 — Cross-Registry Consistency Tests
- Already partially exists at `agentic/tests/test_tool_registry_consistency.py`
- Add automated check that every tool in canonical list (or PARSER_REGISTRY) exists in:
  - TOOL_PHASE_MAP
  - TOOL_COST_MODEL
  - TOOL_CLUSTERS
  - DANGEROUS_TOOLS
  - _FALLBACK_TOOLS
- Document known gaps as explicit exceptions with tracking issues

### 🔲 Tier 2.4 — Integration Smoke Tests
- End-to-end pipeline smoke test: load config → run subset → verify output merged into TargetInfo
- Verify phase gating (don't run phase 2 until phase 1 completes)
- Test with empty/garbage/malformed tool output in each parser

---

## Tier 3: Tool Registry Consistency

> **Goal:** Every tool is properly registered in all registries with no drift.

### 🔲 Tier 3.1 — Fix `execute_masscan` Missing from `TOOL_PHASE_MAP`
- **File:** `agentic/project_settings.py` around line 223
- **Problem:** `execute_masscan` is in `PARSER_REGISTRY` and `TOOL_COST_MODEL` but NOT in `TOOL_PHASE_MAP`
- **Action:** Add `execute_masscan` to `TOOL_PHASE_MAP` with appropriate phase assignment

### 🔲 Tier 3.2 — Fix `execute_searchsploit` Missing from `TOOL_COST_MODEL`
- **File:** `agentic/tool_cost_model.py` around line 23
- **Problem:** `execute_searchsploit` is in `PARSER_REGISTRY` (Tier 1.3) but not in `TOOL_COST_MODEL`
- **Action:** Add cost entry for searchsploit

### 🔲 Tier 3.3 — Fix `execute_playwright` Missing from `TOOL_CLUSTERS`
- **File:** `agentic/heuristics/engine.py` around line 64
- **Problem:** `execute_playwright` is in `PARSER_REGISTRY` and `TOOL_PHASE_MAP` but not in `TOOL_CLUSTERS`
- **Action:** Add to appropriate tool cluster

### 🔲 Tier 3.4 — `execute_masscan` Parser Independence
- Currently aliased to `parse_naabu` in PARSER_REGISTRY (line 165)
- If masscan output format diverges from naabu, it breaks silently
- **Action:** Create independent entry point with its own test coverage (low effort, high safety)

### 🔲 Tier 3.5 — Stale Test Exception Cleanup
- `agentic/tests/test_tool_registry_consistency.py` lines 80-87
- `cve_intel` and `tradecraft_lookup` are listed as missing from TOOL_PHASE_MAP but ARE present
- Update `_KNOWN_MISSING` dict to match current code

---

## Tier 4: Documentation

> **Goal:** Make the pipeline comprehensible and maintainable for new contributors.

### 🔲 Tier 4.1 — "Adding a New Tool/Parser" Guide
Adding a tool currently requires touching at least 5 places with no single reference document:
1. Parser function in `agentic/output_parsers.py`
2. `PARSER_REGISTRY` entry
3. `TOOL_PHASE_MAP` phase assignment
4. `TOOL_COST_MODEL` cost/time entry
5. `TOOL_CLUSTERS` / `_FALLBACK_TOOLS` in heuristics
6. Tests
7. Canonical tool list

**Action:** Create `readmes/GUIDE_ADDING_TOOL.md` with step-by-step checklist and examples.

### 🔲 Tier 4.2 — Pipeline Data-Flow Documentation
**What's missing:** How output flows from `parse_tool_output()` → merge into `TargetInfo` → persist to Neo4j → surface in UI is undocumented end-to-end.

**Action:** Add data-flow diagram and narrative to `readmes/README.RECON.md`.

### 🔲 Tier 4.3 — Container Lifecycle Architecture Doc
`container_manager.py` is 2569 lines with no architectural overview. Document:
- Sub-container model
- Orphan detection strategy
- Cleanup phases and triggers
- Shutdown sequence

**Action:** Create `readmes/CONTAINER_MANAGER_ARCH.md`.

### 🔲 Tier 4.4 — `tool_cost_model.py` Module Docstring
Currently has no module-level docstring. Add explanation of:
- Purpose of the cost model
- How costs are assigned (integer scale meaning)
- How time estimates are determined
- Category classification scheme

---

## Tier 5: Code Quality & Maintainability

> **Goal:** Reduce technical debt and improve code organization.

### 🔲 Tier 5.1 — Split Monolithic `output_parsers.py`
**Current state:** 609-line single file with 16+ parser functions + dispatch logic  
**Action:** Split into `agentic/output_parsers/` directory:
```
output_parsers/
├── __init__.py          # exports + PARSER_REGISTRY + parse_tool_output
├── _base.py             # shared helpers, result types
├── nmap.py              # parse_nmap
├── httpx.py             # parse_httpx
├── nuclei.py            # parse_nuclei
├── searchsploit.py      # parse_searchsploit (Tier 1.3)
├── ...
```
**Risk:** Medium — impacts imports across codebase; careful refactoring needed

### 🔲 Tier 5.2 — AttackPanel Component Splitting
**Current state:** `AttackPanel.tsx` is 780 lines
- Split `SuggestionCard` into its own component
- Extract filter/search bar
- Extract attack stats summary
- Extract run/stop handlers into custom hook

### 🔲 Tier 5.3 — Deprecated Field Cleanup
- Remove `BEARER_TOKEN` legacy field from `agentic/project_settings.py:342`
- Remove `original_objective` deprecated field from `agentic/state.py:792`
- Remove dated snapshot references (e.g., `claude-sonnet-4-20250514`)

### 🔲 Tier 5.4 — Unified Utility Functions
- Deduplicate `cleanup_temp_dir` / `create_temp_dir` across recon modules
- Consolidate file ownership helpers (`fix_file_ownership`, `get_real_user_ids`)
- Create shared subprocess runner with consistent timeout/error handling

---

## Tier 6: Features & Enhancements

> **Goal:** Add capability and polish.

### 🔲 Tier 6.1 — Heuristic Engine Coverage Expansion
(See `plan-heuristic-engine-next-slice.md` for full detail)
- Add TECH_RULES for Tomcat, Jenkins, GitLab, Elasticsearch, Memcached, Docker, Kubernetes, SAP, API Gateways, OAuth/OIDC
- Add PORT_RULES for DNS (53), Kerberos (88), RPC (111), NFS (2049), WinRM (5985/5986), WebLogic (7001), Elasticsearch (9200), Memcached (11211), SNMP (161)
- Add COMBO_RULES for multi-signal playbooks

### 🔲 Tier 6.2 — Mobile Responsive Improvements
(See `plan-mobile-ui-improvements.md` for full detail)
- AttackPanel responsive breakpoints (768px, 480px): summary grid 4→2→1 columns
- PageBottomBar compact layout on mobile
- Touch gesture support for graph interactions
- `useIsMobile` / `useIsSmallPhone` hooks already created

### 🔲 Tier 6.3 — GVM Scan Monitoring & Resilience
(See `plan-recon-gvm-monitoring.md` for full detail)
- Persistent orchestrator state
- Resumable log streaming
- Bounded log buffers
- Pre-flight readiness checks
- Frontend monitoring dashboard

### 🔲 Tier 6.4 — LLM-Driven AI Pipeline Expansion
(See `plan-add-5-ai-pipelines.md` for full detail)
- 5 new AI-driven recon pipelines following the established pattern
- Integrate with existing `/llm/` endpoint infrastructure

---

## Appendix: Priority Matrix

| Tier | Item | Effort | Impact | Risk | Priority |
|------|------|--------|--------|------|----------|
| 1.1 | Non-recon silent excepts | Low | Medium | Low | **P1** |
| 2.2 | Container manager tests | High | High | High | **P1** |
| 3.1 | masscan→TOOL_PHASE_MAP | Low | Medium | Low | **P1** |
| 3.2 | searchsploit→TOOL_COST_MODEL | Low | Medium | Low | **P1** |
| 3.3 | playwright→TOOL_CLUSTERS | Low | Medium | Low | **P1** |
| 2.1 | searchsploit/masscan parser tests | Low | Medium | Low | **P2** |
| 3.4 | masscan parser independence | Low | Low | Low | **P2** |
| 3.5 | Stale test data fix | Low | Low | Low | **P2** |
| 4.1 | "Adding a tool" guide | Medium | High | None | **P2** |
| 5.1 | Split output_parsers.py | Medium | Medium | Medium | **P3** |
| 4.2 | Pipeline data-flow docs | Medium | Medium | None | **P3** |
| 4.3 | Container lifecycle docs | Medium | Medium | None | **P3** |
| 5.2 | AttackPanel split | Medium | Low | Medium | **P3** |
| 5.3 | Deprecated field cleanup | Low | Low | Low | **P3** |
| 1.4 | Retry/resilience audit | Medium | Medium | Low | **P3** |
| 6.1 | Heuristic engine expansion | Medium | High | Low | **P3** |
| 5.4 | Utility deduplication | Medium | Low | Low | **P4** |
| 4.4 | tool_cost_model.py docstring | Low | Low | None | **P4** |
| 2.3 | Cross-registry consistency tests | Low | Medium | Low | **P4** |
| 2.4 | Integration smoke tests | Medium | Medium | Low | **P4** |
| 6.2-6.4 | Feature work (separate plans) | Varies | Varies | Varies | Per-plan |

## Appendix: Completed Work

| Item | Date | Details |
|------|------|---------|
| Tier 1.2 — Silent except fix | 2026-06-16 | 37 files patched, all syntax-validated |
| Tier 1.3 — parse_searchsploit | 2026-06-15 | Parser added and registered |
| Tier 5.2 — Mobile responsive | 2026-06-15 | AttackPanel 768px/480px breakpoints merged |
