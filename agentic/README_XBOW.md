# RedaMon XBOW — Autonomous Offensive Security Agent

RedaMon XBOW extends the RedaMon penetration testing framework with XBOW-level
autonomous capabilities: dynamic exploit synthesis, self-correcting OODA loop,
general security reasoning, intelligent context management, and cross-engagement
learning.

## Quick Start

```bash
# Validate setup (no target needed)
python3 agentic/benchmark_runner.py --dry-run

# Run against OWASP Juice Shop
python3 agentic/benchmark_runner.py \
    --target-image juice-shop \
    --objective "Find admin credentials and any flags" \
    --timeout-minutes 30 \
    --attempts 3

# Run against a custom Docker image
python3 agentic/benchmark_runner.py \
    --target-image my-target:latest \
    --objective "Enumerate services and find vulnerabilities" \
    --flag-format "SECRET\\{[^}]+\\}" \
    --port 8080

# Run from a task file (JSON)
python3 -m agentic.benchmark_main --task /path/to/task.json --ooda

# Run integration tests
python3 agentic/tests/test_xbow_integration.py
```

## Task File Format

```json
{
    "task_id": "mission-001",
    "objective": "Find the flag on machine 10.10.10.5",
    "target": "10.10.10.5",
    "flag_format": "FLAG\\{[^}]+\\}",
    "category": "puzzle",
    "timeout_minutes": 60,
    "hints": ["Look at port 80"]
}
```

## Architecture

```
Orchestrator.invoke_with_ooda()
  └── OODALoop.run()
        ├── OBSERVE   → SandboxExecutor + ContextManager
        ├── ORIENT    → World model snapshots + stuck detection
        ├── DECIDE    → GeneralPlanner (7 task categories)
        └── ACT       → ExploitSynthAgent + ToolLoader
             └── SandboxExecutor (Docker or subprocess fallback)
        └── CrossEngagementMemory.record_tactic()
```

## Modules

| Module | Purpose |
|---|---|
| `sandbox_executor.py` | Isolated code execution (Docker + subprocess/seccomp fallback) |
| `context_manager.py` | SQLite action log, TF-IDF retrieval, assets/vulns tables |
| `tool_loader.py` | Dynamic tool discovery (GitHub → LLM), pip/git/apt install, caching |
| `general_planner.py` | Task classification, hierarchical plans, sub-task expansion |
| `exploit_synth_agent.py` | Custom exploit generation, 3-retry debug, payload transformation |
| `ooda_loop.py` | Observe-Orient-Decide-Act loop, stuck detection, 4-level recovery |
| `cross_engagement.py` | Persistent tactical memory across engagements |
| `benchmark_runner.py` | Docker target launcher, health check, flag verification |

## Task Categories

| Category | Example Objectives | Example Tools |
|---|---|---|
| `offensive` | "Pentest example.com" | nmap, nuclei, metasploit, hydra |
| `forensic` | "Analyze this memory dump for malware" | volatility, strings, bulk_extractor |
| `puzzle` | "Find the flag on 10.10.10.5" | nmap, gobuster, john, sqlmap |
| `audit` | "Audit this AWS IAM policy" | prowler, scoutsuite, checkov |
| `log_analysis` | "Find the attacker IP in these Apache logs" | jq, awk, grep, zeek |
| `crypto` | "Decrypt this XOR ciphertext" | python, openssl, z3, cyberchef |
| `reverse_engineering` | "Analyze this binary for backdoors" | ghidra, radare2, gdb, strings |

## Stuck-State Recovery

OODA loop detects stuck states and escalates through 4 recovery levels:

1. **Backtrack** — Revert world model to last successful state, retry
2. **Switch Strategy** — Ask planner for a completely different approach
3. **Acquire Tools** — Search GitHub + install missing tools
4. **Human Escalation** — Produce full-context guidance request

## Settings

All XBOW features are opt-in. Enable in project settings:

| Setting | Default | Description |
|---|---|---|
| `XBOW_ENABLED` | `False` | Master switch for XBOW modules |
| `XBOW_PREFER_OODA` | `False` | Use OODA loop for invoke() |
| `XBOW_MAX_CYCLES` | `200` | Max OODA cycles per mission |
| `XBOW_EXPLOIT_MAX_RETRIES` | `3` | Max exploit synthesis retries |
| `XBOW_SANDBOX_TIMEOUT` | `60` | Sandbox execution timeout (seconds) |
| `XBOW_STUCK_THRESHOLD` | `5` | Cycles without progress before recovery |

## Requirements

- Python 3.12+
- Docker (optional, for sandbox isolation and benchmark targets)
- The agent container must have langchain + LLM API keys configured
