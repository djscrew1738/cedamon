# Guide: Adding a New Tool / Parser

**Purpose:** Adding a new MCP tool to RedAmon requires touching **six** registry
locations so the agent, cost model, parser, heuristics, phase gating, and danger
policy all stay in sync. Use this checklist to avoid silent gaps.

---

## Step-by-Step Checklist

### 1. Parser function (`agentic/output_parsers.py`)
Add a `def parse_<toolname>(raw: str | None) -> dict[str, Any] | None`
function that translates the tool's stdout into the canonical result shape:

```python
def parse_my_tool(raw: str | None) -> dict[str, Any] | None:
    if not raw or not raw.strip():
        return None
    return {
        "ports": [...],
        "services": [...],
        "technologies": [...],
        "vulnerabilities": [...],
        "subdomains": [...],
        "endpoints": [...],
        "credentials": [...],
        "findings": [...],
        "parameters": [...],
    }
```

Only include keys the tool actually produces.

### 2. `PARSER_REGISTRY` (`agentic/output_parsers.py`)
Register the function so the dispatch in `parse_tool_output()` can find it:

```python
PARSER_REGISTRY: dict[str, Callable] = {
    ...
    "execute_my_tool": parse_my_tool,
}
```

### 3. Canonical tool list (`tests/test_tool_registry_consistency.py`)
All consistency checks derive from `CANONICAL_MCP_TOOLS`. Add your tool name:

```python
CANONICAL_MCP_TOOLS: set[str] = {
    ...
    "execute_my_tool",
}
```

### 4. `TOOL_PHASE_MAP` (`agentic/project_settings.py`)
Assign the tool to one or more pipeline phases so the agent respects phase
gating:

```python
DEFAULT_AGENT_SETTINGS = {
    "TOOL_PHASE_MAP": {
        ...
        "execute_my_tool": ["informational", "enum"],
    },
}
```

Valid phases: `informational`, `enum`, `fuzz`, `vuln_scan`, `exploitation`,
`post_exploitation`, `privilege_escalation`, `lateral_movement`,
`exfiltration`, `persistence`, `cleanup`.

### 5. `TOOL_COST_MODEL` (`agentic/tool_cost_model.py`)
Annotate resource intensity and estimated runtime so the LLM can weigh
trade-offs:

```python
TOOL_COST_MODEL: dict[str, dict[str, Any]] = {
    ...
    "execute_my_tool": {
        "cost": 3,              # 1-10 scale (1 = cheap, 10 = expensive)
        "time_estimate": "30s",
        "parallel_safe": True,
        "category": "recon",
    },
}
```

### 6. Heuristic registries (`agentic/heuristics/engine.py`)
If the tool should appear in clusters or as a fallback:

```python
TOOL_CLUSTERS: dict[str, dict[str, Any]] = {
    ...
    "my_tool_cluster": {
        "tools": ["execute_my_tool"],
        ...
    },
}

_FALLBACK_TOOLS: list[str] = [
    ...
    "execute_my_tool",
]
```

### 7. Heuristic rules (`agentic/heuristics/rules.py`)
Add rules that recommend the tool when relevant conditions are met. These are
organized by category:

- **`PORT_RULES`** — fire when specific ports are detected (e.g., port 80 → httpx)
- **`TECH_RULES`** — fire when technologies are detected (e.g., WordPress → wpscan)
- **`COMBO_RULES`** — fire when multiple signals coincide (e.g., Jenkins + GitLab → CI/CD playbook)
- **`PATH_BIAS_RULES`** — fire when the attack path type matches
- **`COVERAGE_RULES`** — fire when coverage gaps are detected (e.g., have subdomains but no httpx probe)

### 8. Dangerous tools (`agentic/project_settings.py`)
If the tool is destructive or inherently risky, add it to `DANGEROUS_TOOLS`:

```python
DANGEROUS_TOOLS: set[str] = {
    ...
    "execute_my_tool",
}
```

### 9. Tests
- **Parser tests:** Add a `TestParseMyTool` class to `agentic/tests/test_output_parsers.py` covering normal output, empty output, garbage input, and edge cases.
- **Consistency tests:** Run `uv run python3 -m pytest tests/test_tool_registry_consistency.py -v` to verify every registry entry is present.

---

## Verification

Run the full consistency check suite:

```bash
cd agentic
uv run python3 -m pytest tests/test_tool_registry_consistency.py -v
```

All 7 tests should pass. If you intentionally omit a tool from a specific
registry, add it to `_KNOWN_MISSING` in the test file with a documented
rationale.
