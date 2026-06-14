# Plan: Heuristic Engine — Coverage Expansion (Next Slice)

## 1. Goal

Expand the structured expert heuristic engine (`agentic/heuristics/`) so it covers more high-value technologies, network services, CI/CD/container stacks, and attack-path biases. The engine should surface better default tool recommendations without changing any caller code.

## 2. Scope

A focused, quick next slice. We add declarative rules only — no engine architecture changes.

### 2.1 New Technology Rules (`TECH_RULES`)

Add rules for technologies commonly seen in red-team engagements:

| Tech | Tool | Rationale |
|------|------|-----------|
| `tomcat` | `execute_nuclei` | Tomcat manager and known CVE templates |
| `jenkins` | `execute_nuclei` | Jenkins plugin/CVE enumeration |
| `gitlab` | `execute_nuclei` | GitLab CE/EE known vulns |
| `elasticsearch` | `execute_nuclei` | ES exposure / CVE templates |
| `memcached` | `execute_nmap` | Check stats exposure on 11211 |
| `docker` | `execute_nuclei` | Docker daemon / registry exposure |
| `kubernetes` | `execute_nuclei` | K8s API / etcd / dashboard exposure |
| `sap` | `execute_nuclei` | SAP Web Dispatcher / Portal templates |
| `api gateway` / `kong` / `zuul` | `execute_arjun` | Discover hidden API params |
| `oauth` / `openid` | `execute_curl` | Probe well-known OIDC endpoints |

Update `TECH_KEYWORDS` for multi-word techs (`api gateway`, `kong`, `zuul`, `openid`).

### 2.2 New Port Rules (`PORT_RULES`)

Add high-signal ports beyond the current set:

| Port | Tool | Suggested Args | Rationale |
|------|------|----------------|-----------|
| 53 | `execute_nmap` | `script: dns-recursion,dns-service-discovery` | DNS enumeration / recursion tests |
| 88 | `execute_nmap` | `script: krb5-enum-users` | Kerberos user enumeration |
| 111 | `execute_nmap` | `script: rpcinfo` | RPC services |
| 2049 | `execute_nmap` | `script: nfs-showmount,nfs-statfs` | NFS shares |
| 5985 / 5986 | `execute_nmap` | `script: http-winrm` | WinRM exposure |
| 7001 | `execute_nuclei` | `templates: ["weblogic/"]` | WebLogic known CVEs |
| 9200 | `execute_nuclei` | `templates: ["elasticsearch/"]` | Elasticsearch exposure |
| 11211 | `execute_nmap` | `script: memcached-info` | Memcached exposure |
| 161 | `execute_nmap` | `script: snmp-info,snmp-sysdescr` | SNMP info |

### 2.3 New Combination Rules (`COMBO_RULES`)

Add multi-signal expert playbooks:

| Signals | Tools | Rationale |
|---------|-------|-----------|
| `jenkins` + `gitlab` | `execute_nuclei` (CI/CD templates), `execute_katana` | CI/CD pipeline attack surface |
| `tomcat` + `java` | `execute_ffuf` | Brute-force Tomcat manager / .war paths |
| `docker` + `kubernetes` | `execute_nuclei` (K8s templates), `execute_curl` | Container orchestration exposure |
| `wordpress` + `jenkins` | `execute_wpscan`, `execute_nuclei` | WordPress as CI artifact + Jenkins |

### 2.4 New Coverage-Gap Rules (`COVERAGE_RULES`)

Derive recommendations from richer `target_info` fields:

| Condition | Tool | Rationale |
|-----------|------|-----------|
| `target_info["credentials"]` non-empty and `execute_hydra` not run | `execute_hydra` | Use discovered creds for brute-force / spray |
| `target_info["endpoints"]` non-empty and no `execute_ffuf` / `execute_arjun` | `execute_arjun` | Hidden parameter discovery on known endpoints |
| `target_info["js_files"]` non-empty and `execute_jsluice` not run | `execute_jsluice` | Extract secrets/endpoints from JS |
| `target_info["live_hosts"]` non-empty and `execute_nuclei` not run | `execute_nuclei` | Vuln-scan confirmed live hosts |
| `target_info["subdomains"]` non-empty and `execute_httpx` not run | `execute_httpx` | Probe newly discovered subdomains |

> **Note:** Some of these fields may not yet be populated by parsers. The rules are defensive (check existence) and safe to add now; they activate automatically as parsers emit richer `target_info`.

### 2.5 Attack-Path-Aware Biases

Introduce a lightweight `PATH_BIAS_RULES` registry in `rules.py`. The engine already receives `phase` and `target_info`; we will also accept an optional `attack_path_type` in `RuleContext` and `build_context()`.

Biases are **additive nudges** (lower-priority rules that only appear when the path type matches). They do not override CVE or port signals.

| Attack Path | Nudge Tool | Rationale |
|-------------|------------|-----------|
| `sql_injection` | `execute_arjun` | Parameter discovery before SQLi testing |
| `xss` | `execute_katana` | Crawl for input vectors |
| `rce` | `execute_searchsploit`, `metasploit_console` (exploitation phase) | Map CVEs to RCE exploits |
| `container_k8s` | `execute_nuclei` (K8s templates) | Container-specific vuln scans |
| `brute_force_credential_guess` | `execute_hydra` | Credential brute-force |
| `ssrf` | `execute_curl` | Manual SSRF probes |
| `cicd_pipeline` | `execute_nuclei` (CI/CD templates) | Jenkins/GitLab/GitHub Actions exposure |

The `think_node.py` wiring will pass `state.get("attack_path_type", "")` into `recommend_tools()` / `build_context()`.

## 3. Implementation Steps

1. **Extend `agentic/heuristics/rules.py`**
   - Add `attack_path_type: str = ""` to `RuleContext`.
   - Add helper `RuleContext.has_attack_path(*names)`.
   - Add new `TECH_RULES`, `PORT_RULES`, `COMBO_RULES`.
   - Add `PATH_BIAS_RULES` list.
   - Add new coverage-gap evaluators that inspect `target_info`.
   - Export `PATH_BIAS_RULES`.

2. **Extend `agentic/heuristics/engine.py`**
   - Import `PATH_BIAS_RULES`.
   - In `recommend()`, after coverage rules, evaluate path-bias rules.
   - Ensure path-bias rules respect phase and `already_run` like other rules.

3. **Update `agentic/heuristics/engine.py` `build_context()`**
   - Accept optional `attack_path_type` argument and pass it to `RuleContext`.

4. **Update `agentic/tool_recommender.py`**
   - Forward `attack_path_type` from `recommend_tools()` kwargs into `build_context()`.

5. **Update `agentic/orchestrator_helpers/nodes/think_node.py`**
   - Pass `attack_path_type=state.get("attack_path_type", "")` to `recommend_tools()`.

6. **Update `agentic/prompts/base.py`**
   - Add a short note that heuristic recommendations are biased by the classified attack path when available.

7. **Add tests in `agentic/tests/test_heuristics.py`**
   - New tech rules: tomcat, jenkins, kubernetes, memcached.
   - New port rules: 53, 2049, 9200, 11211.
   - New combo rules: jenkins+gitlab.
   - Coverage-gap rules: credentials → hydra, endpoints → arjun, js_files → jsluice.
   - Attack-path biases: `container_k8s`, `brute_force_credential_guess`, `rce`.
   - Ensure no regression for existing tests.

8. **Run validation**
   - `cd agentic && pytest tests/test_heuristics.py -v`
   - `cd webapp && npm run type-check` (lint is currently broken in this environment)
   - `cd webapp && npm run build`

## 4. Files to Modify

| File | Change |
|------|--------|
| `agentic/heuristics/rules.py` | New rules + `RuleContext` extension + `PATH_BIAS_RULES` |
| `agentic/heuristics/engine.py` | Evaluate path biases; extend `build_context()` |
| `agentic/tool_recommender.py` | Forward `attack_path_type` |
| `agentic/orchestrator_helpers/nodes/think_node.py` | Pass `attack_path_type` from state |
| `agentic/prompts/base.py` | Mention attack-path-aware heuristics |
| `agentic/tests/test_heuristics.py` | New coverage tests |

## 5. Testing Strategy

- Unit tests for each new rule category.
- Regression: ensure the 11 existing heuristic tests still pass.
- Edge cases:
  - Empty `attack_path_type` does not trigger path biases.
  - Missing `target_info` keys do not crash coverage-gap evaluators.
  - `already_run` correctly excludes path-bias tools.
  - Phase restrictions still apply to path-bias rules.

## 6. Rollback / Safety

- All changes are additive; no existing rules are removed.
- Engine architecture is unchanged. If a rule causes bad recommendations, it can be disabled by removing it from the registry list.
- Path biases default to off when `attack_path_type` is empty.
- Coverage-gap rules use safe `.get()` access to `target_info`.

## 7. Success Criteria

- `pytest tests/test_heuristics.py` passes with ≥ 20 tests.
- `HeuristicEngine.recommend()` returns relevant tools for tomcat, jenkins, kubernetes, elasticsearch, and memcached signals.
- Passing `attack_path_type="container_k8s"` adds K8s-biased recommendations.
- No type-check or build regressions in `webapp`.
