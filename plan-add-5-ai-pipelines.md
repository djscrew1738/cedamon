# Implementation Plan: 5 New LLM-Driven Recon Pipelines

This plan adds five new recon pipelines that follow the established **AI in Pipeline** pattern already used by:

- `FFUF_AI_EXTENSIONS` → `/llm/ffuf-extensions`
- `NUCLEI_AI_TAGS` → `/llm/nuclei-tags`
- `WAF_AI_CLASSIFIER` → `/llm/waf-classify`
- `NUCLEI_AI_RESPONSE_FILTER` → `/llm/nuclei-fp-filter`
- `TAKEOVER_AI_CLASSIFIER` → `/llm/takeover-classify`

Each new pipeline is a **per-tool boolean flag**, cascade-gated by the master `AI_IN_PIPELINE` switch, with the LLM call delegated to a new `/llm/*` endpoint in `agentic/api.py` and a thin planner module under `recon/helpers/ai_planner/`.

---

## 1. Design Principles

1. **Master/cascade contract** — every new per-tool AI flag is forced ON when `AI_IN_PIPELINE=true` and forced OFF when `AI_IN_PIPELINE=false` inside `apply_ai_pipeline_overrides()`. No UI drift.
2. **Recon container stays LLM-agnostic** — the recon modules call a local planner helper, which POSTs to the agentic container. API keys and provider resolution stay in one place.
3. **Failure-soft** — if the agentic endpoint is unreachable, returns non-JSON, or times out, the planner falls back to the pre-AI behavior (keep data, keep scanning, no hard failures).
4. **Cost-bounded** — each pipeline uses batching, caching, strict caps on items sent to the LLM, and only fires when there is ambiguous/fuzzy data to classify.
5. **Observability** — all planner logs use the existing `[symbol][Module-AI]` prefix so they appear in the recon drawer SSE stream.
6. **No new runtime dependencies** in the recon image; reuse `requests`, `pydantic` is only in the agentic image.

---

## 2. Cross-Cutting Changes Required For Every Pipeline

For each new flag `XXX_AI_YYY` and its camelCase webapp field `xxxAiYyy`:

| Layer | File | Change |
|-------|------|--------|
| Agentic API | `agentic/api.py` | Add Pydantic request model, system prompt, and `POST /llm/xxx-yyy` FastAPI route. Reuse `_build_llm_with_model_for_user`, `normalize_content`, fence stripping. |
| Planner | `recon/helpers/ai_planner/<pipeline>.py` | Add helper that builds the request, POSTs to `AGENT_API_URL/llm/xxx-yyy`, validates JSON, and returns structured data. Never raise on failure. |
| Settings defaults | `recon/project_settings.py` `DEFAULT_SETTINGS` | Add `XXX_AI_YYY: False`. |
| Settings mapping | `recon/project_settings.py` `build_project_settings()` | Add `settings['XXX_AI_YYY'] = project.get('xxxAiYyy', DEFAULT_SETTINGS[...])`. |
| AI cascade | `recon/project_settings.py` `apply_ai_pipeline_overrides()` | Add flag to both ON and OFF branches. Update the log line. |
| DB schema | `webapp/prisma/schema.prisma` | Add `xxxAiYyy Boolean @default(false) @map("xxx_ai_yyy")` to the `Project` model. |
| Preset schema | `webapp/src/lib/recon-preset-schema.ts` | Add `xxxAiYyy: bool` and a catalog description in `RECON_PARAMETER_CATALOG`. |
| UI cascade | `webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx` | Add to the master toggle cascade list and to `aiPipelineHooks` summary. |
| UI module toggle | relevant section `.tsx` | Add a disabled-when-master-off toggle (e.g. `JsReconSection`, `VhostSniSection`, `NucleiSection`, `ParameterDiscoverySection`, `SubdomainDiscoverySection`). |
| Tests | `agentic/tests/test_llm_endpoints_provider_compat.py` | Add OpenAI-string + Bedrock-block cases for the new endpoint. |
| Tests | `recon/tests/test_ai_pipeline_integration.py` | Update mocks to include the new flag and assert cascade behavior. |
| Tests | `recon/tests/test_ai_<pipeline>.py` | Add unit tests for the planner helper and module integration (mock agent endpoint). |

After schema changes run:

```bash
cd webapp && npx prisma migrate dev --name add_ai_pipeline_flags_v2
```

---

## 3. The Five Pipelines

### 3.1 JS Recon AI Filter

**Flag:** `JS_RECON_AI_FILTER` (webapp `jsReconAiFilter`)
**Endpoint:** `POST /llm/js-finding-filter`
**Planner:** `recon/helpers/ai_planner/js_filter.py`
**Integration:** `recon/main_recon_modules/js_recon.py`

#### Problem
The JS recon module extracts secrets, endpoints, GraphQL operations, and developer comments via regex. The regexes produce false positives: minified variable names, base64 blobs, CDN paths, and non-sensitive tokens. Manual triage is tedious.

#### What the AI does
After the regex extractors run, batch the findings and ask the LLM to score each one as `keep`, `demote`, or `drop` based on surrounding code context. Real secrets and interesting endpoints are kept; obvious false positives are dropped before graph ingestion.

#### Request schema
```json
{
  "findings": [
    {
      "type": "secret|endpoint|dev_comment|graphql|websocket",
      "name": "AWS Access Key",
      "matched_text": "AKIA...",
      "context": "<150 chars around match>",
      "source_url": "https://target.example.com/app.js"
    }
  ],
  "model": "claude-opus-4-6",
  "user_id": "...",
  "project_id": "..."
}
```

#### Response schema
```json
{
  "results": [
    {
      "index": 0,
      "keep": true,
      "confidence": 92,
      "reason": "AWS key literal in API client code",
      "severity_delta": 0
    }
  ]
}
```

#### Integration point
In `js_recon.py`, after `scan_js_content()`, `extract_endpoints()`, `scan_dev_comments()`, and source-map/dependency results are collected, call:

```python
if settings.get('JS_RECON_AI_FILTER') and ai_pipeline_model:
    from recon.helpers.ai_planner.js_filter import filter_js_findings
    findings = filter_js_findings(all_findings, ai_pipeline_model, ...)
```

#### Fallback
On any failure return the original list unchanged.

#### Cost bounding
- Batch size: **20–30 findings per LLM call**.
- Skip findings with `confidence == 'high'` and a passing `validate_secret()` where one exists — they are already strong.
- Cap total AI-filtered findings per scan to **500** (process the rest raw).

---

### 3.2 VHost & SNI AI Candidate Ranker

**Flag:** `VHOST_SNI_AI_RANK` (webapp `vhostSniAiRank`)
**Endpoint:** `POST /llm/vhost-rank`
**Planner:** `recon/helpers/ai_planner/vhost_rank.py`
**Integration:** `recon/main_recon_modules/vhost_sni_enum.py`

#### Problem
`_build_candidate_set()` can generate thousands of `{prefix}.{apex}` hostnames per IP. Most will never resolve to a real vhost. Probing all of them is slow and noisy.

#### What the AI does
Rank candidate hostnames by likelihood of being a real virtual host on the target IP, using the apex domain, existing graph candidates (SANs, subdomains, PTRs), and keyword semantics (admin, staging, api, etc.). The highest-ranked candidates are probed first and the deterministic cap keeps the most promising ones.

#### Request schema
```json
{
  "apex_domain": "example.com",
  "target_ip": "203.0.113.10",
  "candidates": ["admin.example.com", "api.example.com", "..."],
  "graph_context": ["www.example.com", "staging.example.com"],
  "model": "claude-opus-4-6",
  "user_id": "...",
  "project_id": "..."
}
```

#### Response schema
```json
{
  "ranked": ["admin.example.com", "api.example.com"],
  "scores": {"admin.example.com": 95, "api.example.com": 78},
  "reason": "admin prefix is a high-signal internal app; api prefix matches common routing"
}
```

#### Integration point
In `vhost_sni_enum.py`, after `_build_candidate_set()` and before applying `max_candidates`:

```python
if settings.get('VHOST_SNI_AI_RANK') and ai_pipeline_model:
    from recon.helpers.ai_planner.vhost_rank import rank_vhost_candidates
    candidate_set = rank_vhost_candidates(
        apex, ip, candidate_set, graph_candidates, ai_pipeline_model, max_candidates
    )
```

#### Fallback
If ranking fails, fall back to the existing deterministic sort + cap.

#### Cost bounding
- Send at most **200 candidates** to the LLM per IP. If there are more, pre-rank with the existing static `INTERNAL_KEYWORDS` bonus and send the top 200.
- One LLM call per IP, not per candidate.

---

### 3.3 Port Banner AI Classifier

**Flag:** `PORT_SCAN_AI_BANNER_CLASSIFY` (webapp `portScanAiBannerClassify`)
**Endpoint:** `POST /llm/port-banner-classify`
**Planner:** `recon/helpers/ai_planner/port_banner_classify.py`
**Integration:** `recon/main_recon_modules/port_scan.py`, `recon/main_recon_modules/nmap_scan.py`, banner grabbing

#### Problem
Naabu/Masscan report open ports but often no service. Nmap `-sV` may return generic banners like `unknown` or `Apache httpd`. The existing AI port catalog is regex-based and misses custom/non-standard AI runtimes or multi-purpose ports such as 8000/8080.

#### What the AI does
Classify ambiguous banners into service families and flag AI/LLM-related services (Ollama, vLLM, TGI, LiteLLM, Open WebUI, vector DBs, etc.) when static lookups are inconclusive.

#### Request schema
```json
{
  "ip": "203.0.113.10",
  "port": 8080,
  "banner": "HTTP/1.1 200 OK\r\nServer: uvicorn\r\n...",
  "static_guess": "",
  "model": "claude-opus-4-6",
  "user_id": "...",
  "project_id": "..."
}
```

#### Response schema
```json
{
  "service_family": "ai-runtime|web|database|cache|unknown",
  "product_guess": "Open WebUI / uvicorn",
  "is_ai_related": true,
  "confidence": 84,
  "reason": "uvicorn header plus Open WebUI favicon path in body"
}
```

#### Integration point
- In `port_scan.py` after `_annotate_ai_port_catalog()` for entries where the port is in the `disambiguate=True` catalog or no IANA name exists.
- In `nmap_scan.py` after parsing XML for ports whose `product`/`version` is generic or where `match_ai_nmap_version()` returned nothing.
- In banner grabbing for non-HTTP banners (SSH, FTP, etc.).

#### Fallback
On failure keep the existing static annotation (or none).

#### Cost bounding
- Only classify ports that are **ambiguous** after static lookups.
- Batch by host: up to **25 ports per LLM call**.

---

### 3.4 Parameter AI Prioritizer

**Flag:** `PARAMETER_AI_PRIORITY` (webapp `parameterAiPriority`)
**Endpoint:** `POST /llm/param-priority`
**Planner:** `recon/helpers/ai_planner/param_priority.py`
**Integration:** `recon/main_recon_modules/resource_enum.py`

#### Problem
ParamSpider, Arjun, and crawling can discover hundreds of URL parameters. Most are UI/state parameters with low security value. Manual prioritization for focused DAST/Nuclei is slow.

#### What the AI does
Score each discovered parameter for injection/testing priority based on its name, the endpoint path, HTTP method, and the source of discovery. Mark high-priority parameters so downstream tools can focus on them.

#### Request schema
```json
{
  "base_url": "https://api.example.com",
  "path": "/v1/users",
  "method": "GET",
  "parameters": [
    {"name": "id", "position": "query", "source": "katana"},
    {"name": "redirect", "position": "query", "source": "paramspider"}
  ],
  "model": "claude-opus-4-6",
  "user_id": "...",
  "project_id": "..."
}
```

#### Response schema
```json
{
  "priorities": [
    {"name": "redirect", "score": 88, "likely_injectable": true, "reason": "open-redirect / SSRF candidate"},
    {"name": "id", "score": 42, "likely_injectable": false, "reason": "common identifier, low priority"}
  ]
}
```

#### Integration point
In `resource_enum.py`, after all URL discovery tools have merged into `by_base_url` and before graph writing, add a new `_annotate_parameter_priority()` pass (similar to `_annotate_ai_endpoint_classifier()`). It stamps each parameter dict with `ai_priority_score` and `ai_likely_injectable`.

#### Fallback
On failure leave parameters unchanged; downstream tools continue using static `category`.

#### Cost bounding
- Only endpoints with **≤20 parameters** are sent; larger endpoints are split.
- Batch up to **50 endpoints per LLM call** by base URL.
- Skip parameters already classified as `is_ai_prompt_injectable` — they are already high value.

---

### 3.5 Subdomain Relevance AI Filter

**Flag:** `SUBDOMAIN_AI_RELEVANCE` (webapp `subdomainAiRelevance`)
**Endpoint:** `POST /llm/subdomain-relevance`
**Planner:** `recon/helpers/ai_planner/subdomain_relevance.py`
**Integration:** `recon/main_recon_modules/http_probe.py`

#### Problem
Subdomain discovery tools can emit wildcard answers, parked pages, CDN dead-ends, or unrelated shared-hosting responses. These pollute the target list and waste resources in later phases.

#### What the AI does
After HTTP probing, classify each subdomain as relevant or irrelevant based on its response (status code, title, server, body sample, detected technologies). Demote or drop irrelevant subdomains so resource enum and vuln scanning focus on real targets.

#### Request schema
```json
{
  "subdomain": "staging.example.com",
  "target_domain": "example.com",
  "http_status": 200,
  "title": "Staging Environment",
  "server": "nginx",
  "body_sample": "<html>...",
  "technologies": ["nginx", "React"],
  "model": "claude-opus-4-6",
  "user_id": "...",
  "project_id": "..."
}
```

#### Response schema
```json
{
  "relevant": true,
  "confidence": 91,
  "reason": " staging app with matching apex domain and real tech stack",
  "suggested_action": "keep"
}
```

#### Integration point
In `http_probe.py` after `parse_httpx_output()` has built `by_url`/`by_host` and AI header/title annotations are done. Call the planner with one entry per unique host and add `ai_relevance`/`ai_relevance_confidence` to each `by_host` entry. Add a new summary key `ai_relevance_dropped`.

If needed downstream, also expose `combined_result['http_probe']['relevant_hosts']` so `resource_enum` and `vuln_scan` can skip demoted hosts.

#### Fallback
On failure mark every host as relevant and continue.

#### Cost bounding
- Batch **up to 50 subdomains per LLM call**.
- Only classify hosts with a non-error status (<500); exclude root domain.
- Cap at **500 subdomains** per scan; remaining hosts are kept by default.

---

## 4. Implementation Order

Recommended order so each pipeline can be tested independently before wiring the next:

1. **Subdomain Relevance Filter** — smallest blast radius, only touches `http_probe.py` and adds a summary key.
2. **VHost Candidate Ranker** — isolated to `vhost_sni_enum.py` and easy to verify via candidate counts.
3. **Port Banner Classifier** — adds value to existing port scan output without changing pipeline flow.
4. **Parameter Prioritizer** — builds on the existing resource-enum annotation pattern.
5. **JS Recon Filter** — most data-heavy; save for last so the batching/caching pattern is solid.

Within each pipeline, implement vertically:

1. Agentic endpoint + unit tests.
2. Planner helper + planner unit tests.
3. Recon module integration + integration tests.
4. Settings/DB/UI wiring.
5. End-to-end smoke test.

---

## 5. Testing Plan

### Agentic endpoint tests
Extend `agentic/tests/test_llm_endpoints_provider_compat.py` with OpenAI-string and Bedrock-block cases for each of the five new endpoints. Assert HTTP 200 and correct field extraction.

### Settings cascade tests
Update `recon/tests/test_ai_pipeline_integration.py`:
- Add the five new flags to `_mock_project()`.
- Add assertions that `get_settings()` forces each flag ON when `aiInPipeline=True` and OFF when `aiInPipeline=False`.
- Add a CLI-mode assertion.

### Planner tests
For each planner create `recon/tests/test_ai_<pipeline>.py`:
- Mock the agentic endpoint with `responses`/`requests_mock`.
- Test happy path, malformed JSON, HTTP 5xx, timeout, empty input.
- Assert fallback behavior (no data loss).

### Module integration tests
- For JS filter: pass a synthetic list of findings with known false positives and assert they are dropped.
- For VHost ranker: assert candidates are reordered/demoted and cap is respected.
- For Port banner classifier: assert ambiguous banners get `ai_service_guess`.
- For Parameter prioritizer: assert `ai_priority_score` is stamped.
- For Subdomain relevance: assert low-relevance hosts are marked `relevant=false`.

### UI tests
- Open the Project form, toggle AI in Pipeline, and verify each new toggle enables/disables and cascades correctly.
- Verify presets with `aiInPipeline: true` serialize/deserialize the new flags.

### Cost guard tests
- Verify that when the master toggle is OFF, no planner module is imported and no HTTP calls are made.
- Verify batch caps are respected.

---

## 6. Rollout & Backward Compatibility

- All new flags default to `False` in `DEFAULT_SETTINGS` and the Prisma schema, so existing projects are unaffected.
- Existing `AI_IN_PIPELINE=false` projects keep every new flag OFF via the cascade.
- New agentic endpoints are additive; old recon containers that do not know about them will simply not call them.
- Preset files in `webapp/src/recon-presets/presets/` should be updated only if a preset is intended to opt into a specific new pipeline (e.g. an AI-heavy preset); otherwise leave defaults.
- Update `readmes/AI_IN_PIPELINE.md` (or create it) with a table of all 10 AI hooks and their toggles.

---

## 7. Open Decisions

1. **Batch serialization limits** — some agentic providers have input token caps. Decide final batch sizes after a token-count smoke test on representative data.
2. **Caching strategy** — should VHost ranker and Port banner classifier cache results by fingerprint across scans/projects? If yes, add a small in-memory `lru_cache` or Redis-backed cache in the planner.
3. **Graph schema updates** — do we want to persist `ai_priority_score`, `ai_relevance`, etc. as node properties? If yes, update `graph_db/schema.py` and the corresponding mixins.
4. **Pricing/alerting** — consider adding a per-scan LLM call counter in `combined_result['metadata']['ai_calls']` so operators can audit cost.
