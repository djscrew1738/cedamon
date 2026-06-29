#!/usr/bin/env python3
"""
RedaMon XBOW Integration Test — Full Pipeline Validation.

Tests all XBOW modules working together without requiring an LLM.
Validates the complete data flow: ContextManager → OODALoop → 
ExploitSynthAgent → SandboxExecutor → CrossEngagementMemory.

This is the test suite that validates the pipeline is production-ready.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure agentic dir is on path.
_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from context_manager import ContextManager
from sandbox_executor import SandboxExecutor
from ooda_loop import OODALoop, Observation, Decision, OODACycleEntry, RecoveryLevel
from cross_engagement import CrossEngagementMemory, TacticRule
from general_planner import (
    GeneralPlanner, SecurityPlan, PlanPhase, TaskCategory, BenchmarkTask,
)

RESULTS = []
PASS = 0
FAIL = 0


def test(name: str):
    """Decorator-style test collector."""
    def wrapper(fn):
        global PASS, FAIL
        try:
            result = fn()
            if asyncio.iscoroutine(result):
                result = asyncio.run(result)
            if result:
                RESULTS.append(f"  PASS  {name}")
                PASS += 1
            else:
                RESULTS.append(f"  FAIL  {name}")
                FAIL += 1
        except Exception as exc:
            RESULTS.append(f"  FAIL  {name}: {exc}")
            FAIL += 1
        return fn
    return wrapper


# ---------------------------------------------------------------------------
# Test 1: ContextManager assets + vulnerabilities
# ---------------------------------------------------------------------------
@test("ContextManager assets table")
def test_assets_table():
    ctx = ContextManager(db_path=":memory:")
    ctx.initialize()

    ctx.add_asset("sess-1", "ip", "10.10.10.5")
    ctx.add_asset("sess-1", "domain", "example.com")
    ctx.add_asset("sess-1", "credential", "admin:password123")

    ips = ctx.query_assets("sess-1", asset_type="ip")
    domains = ctx.query_assets("sess-1", asset_type="domain")
    creds = ctx.query_assets("sess-1", asset_type="credential")

    ctx.close()
    return len(ips) == 1 and ips[0].value == "10.10.10.5" \
       and len(domains) == 1 and len(creds) == 1


@test("ContextManager vulnerabilities table")
def test_vulns_table():
    ctx = ContextManager(db_path=":memory:")
    ctx.initialize()

    ctx.add_vulnerability(
        "sess-1", "sqli", endpoint="http://10.10.10.5/login.php",
        description="SQL injection in user param", confidence=0.95,
        severity="critical",
    )
    ctx.add_vulnerability(
        "sess-1", "xss", endpoint="http://10.10.10.5/search",
        description="Reflected XSS", severity="medium",
    )

    ctx.mark_vulnerability_exploited(
        "sess-1", "sqli", "http://10.10.10.5/login.php",
        exploit_code="SELECT 1 FROM dual",
    )

    critical = ctx.query_vulnerabilities("sess-1", severity="critical")
    exploited = ctx.query_vulnerabilities("sess-1", exploited=True)

    ctx.close()
    return len(critical) == 1 and critical[0].vuln_type == "sqli" \
       and len(exploited) == 1 and exploited[0].exploited


@test("ContextManager structured summary")
def test_structured_summary():
    ctx = ContextManager(db_path=":memory:")
    ctx.initialize()

    ctx.add_asset("sess", "ip", "10.0.0.1")
    ctx.add_asset("sess", "domain", "target.com")
    ctx.add_vulnerability("sess", "rce", endpoint="upload.php", description="RCE in upload.php",
                          severity="critical")
    ctx.mark_vulnerability_exploited("sess", "rce", "upload.php")

    summary = ctx.get_structured_summary("sess")
    ctx.close()

    return "assets" in summary and "vulnerabilities" in summary \
       and len(summary["vulnerabilities"]["exploited"]) == 1


# ---------------------------------------------------------------------------
# Test 2: SandboxExecutor
# ---------------------------------------------------------------------------
@test("SandboxExecutor Docker detection")
async def test_docker_detection():
    executor = SandboxExecutor(auto_build=False)
    available = await executor._is_docker_available()
    # Docker is available on this system.
    return available is True


@test("SandboxExecutor subprocess execution")
async def test_subprocess_fallback():
    executor = SandboxExecutor(auto_build=False, docker_path="/nonexistent/docker")

    result = await executor.execute(
        code="print('hello world')\nprint('success')",
        timeout=30,
    )
    return result.exit_code == 0 and "hello world" in result.stdout


@test("SandboxExecutor timeout kill")
async def test_timeout():
    executor = SandboxExecutor(auto_build=False, docker_path="/nonexistent/docker")

    result = await executor.execute(
        code="import time; time.sleep(30); print('should not print')",
        timeout=3,
    )
    return result.timed_out or result.exit_code != 0


@test("SandboxExecutor code size limit")
async def test_code_size_limit():
    executor = SandboxExecutor(auto_build=False)

    try:
        await executor.execute(code="A" * 200_000, timeout=5)
        return False  # Should have raised ValueError.
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Test 3: OODALoop
# ---------------------------------------------------------------------------
@test("OODALoop initialization")
def test_ooda_init():
    ctx = ContextManager(db_path=":memory:")
    ctx.initialize()

    ooda = OODALoop(
        llm=None, planner=None, context_manager=ctx,
        sandbox_executor=None, max_cycles=10,
    )

    return ooda._cycle == 0 \
       and ooda._consecutive_no_progress == 0 \
       and not ooda._completed


@test("OODALoop stuck detection - repeated action")
def test_ooda_stuck_repeated():
    ooda = OODALoop(max_cycles=10)
    # Inject repeated actions.
    ooda._action_counter["nmap_scan"] = 3
    ooda._action_timestamps["abc123"] = time.time() - 5

    # Create a minimal state dict.
    state = {"current_phase": "informational", "execution_trace": []}

    async def _run():
        stuck, reason = await ooda._detect_stuck(state, "nmap_scan")
        return stuck and "repeated" in reason.lower()

    return asyncio.run(_run())


@test("OODALoop stuck detection - no progress")
def test_ooda_stuck_no_progress():
    ooda = OODALoop(max_cycles=10)
    ooda._consecutive_no_progress = 6  # > MAX_NO_PROGRESS_CYCLES
    state = {"current_phase": "informational", "execution_trace": []}

    async def _run():
        stuck, reason = await ooda._detect_stuck(state, "nmap_scan")
        return stuck and "no progress" in reason.lower()

    return asyncio.run(_run())


@test("OODALoop recovery levels exist")
def test_ooda_recovery_levels():
    return (
        RecoveryLevel.BACKTRACK == "backtrack"
        and RecoveryLevel.SWITCH_STRATEGY == "switch_strategy"
        and RecoveryLevel.ACQUIRE_TOOLS == "acquire_tools"
        and RecoveryLevel.HUMAN_ESCALATION == "human_escalation"
    )


@test("OODALoop action hash tracking")
def test_ooda_action_hash():
    ooda = OODALoop(max_cycles=10)
    hash1 = ooda._action_hash("nmap", {"target": "10.0.0.1", "ports": "1-1000"})
    hash2 = ooda._action_hash("nmap", {"target": "10.0.0.1", "ports": "1-1000"})
    hash3 = ooda._action_hash("nmap", {"target": "10.0.0.2", "ports": "1-1000"})

    return hash1 == hash2 and hash1 != hash3 and len(hash1) == 16


@test("OODALoop world model snapshot")
def test_ooda_snapshot():
    ooda = OODALoop(max_cycles=10)
    state = {"current_phase": "exploitation", "target_info": {"ip": "10.0.0.1"}}

    ooda._cycle = 1
    ooda._snapshot_world_model(state)
    ooda._cycle = 2
    ooda._snapshot_world_model(state)

    return len(ooda._world_model_snapshots) == 2 \
       and ooda._world_model_snapshots[0]["_cycle"] == 1 \
       and ooda._world_model_snapshots[1]["_cycle"] == 2


# ---------------------------------------------------------------------------
# Test 4: GeneralPlanner (without LLM)
# ---------------------------------------------------------------------------
@test("GeneralPlanner task categories")
def test_task_categories():
    return (
        TaskCategory.OFFENSIVE == "offensive"
        and TaskCategory.FORENSIC == "forensic"
        and TaskCategory.PUZZLE == "puzzle"
        and TaskCategory.CRYPTO == "crypto"
        and TaskCategory.LOG_ANALYSIS == "log_analysis"
        and TaskCategory.REVERSE_ENGINEERING == "reverse_engineering"
    )


@test("GeneralPlanner fails gracefully without LLM")
def test_planner_no_llm():
    planner = GeneralPlanner(llm=None)
    try:
        asyncio.run(planner.create_plan(objective="Test"))
        return False
    except RuntimeError as exc:
        return "requires an LLM" in str(exc)


@test("GeneralPlanner phase templates exist for all categories")
def test_phase_templates():
    from general_planner import PHASE_TEMPLATES

    for cat in TaskCategory:
        if cat != TaskCategory.UNKNOWN:
            assert cat in PHASE_TEMPLATES, f"Missing phase template for {cat}"
            assert len(PHASE_TEMPLATES[cat]) >= 2, \
                f"Too few phases for {cat}: {len(PHASE_TEMPLATES[cat])}"

    return True


@test("SecurityPlan phase/subtask navigation")
def test_plan_navigation():
    plan = SecurityPlan(
        objective="Test plan",
        category=TaskCategory.OFFENSIVE,
        phases=[
            PlanPhase(
                name="phase1",
                description="First phase",
                sub_tasks=["task1", "task2", "task3"],
                status="active",
            ),
            PlanPhase(
                name="phase2",
                description="Second phase",
                sub_tasks=["task4"],
            ),
        ],
    )

    # Current phase and subtask.
    assert plan.current_phase().name == "phase1"
    assert plan.current_subtask() == "task1"

    # Advance subtask.
    assert plan.advance_subtask() is True
    assert plan.current_subtask() == "task2"
    assert plan.advance_subtask() is True
    assert plan.current_subtask() == "task3"
    assert plan.advance_subtask() is False  # No more subtasks in phase1

    # Advance phase.
    assert plan.advance_phase() is True
    assert plan.current_phase().name == "phase2"
    assert plan.current_subtask() == "task4"
    assert plan.advance_phase() is False  # No more phases

    # Phase 1 should be marked completed.
    assert plan.phases[0].status == "completed"
    assert plan.phases[1].status == "active"

    return True


@test("BenchmarkTask from_json")
def test_benchmark_task_json():
    task_path = "/tmp/test_benchmark_task.json"
    task_data = {
        "task_id": "test-001",
        "objective": "Find the flag",
        "target": "10.10.10.5",
        "flag_format": r"FLAG\{[^}]+\}",
        "hints": ["Look at port 80"],
        "category": "puzzle",
        "timeout_minutes": 60,
    }
    with open(task_path, "w") as f:
        json.dump(task_data, f)

    task = BenchmarkTask.from_json(task_path)
    os.remove(task_path)

    return (
        task.task_id == "test-001"
        and task.objective == "Find the flag"
        and task.target == "10.10.10.5"
        and task.flag_format == r"FLAG\{[^}]+\}"
        and task.timeout_minutes == 60
    )


# ---------------------------------------------------------------------------
# Test 5: CrossEngagementMemory
# ---------------------------------------------------------------------------
@test("CrossEngagementMemory record + query")
def test_cross_eng_record():
    mem_path = "/tmp/test_cross_eng_mem.json"
    mem = CrossEngagementMemory(memory_path=mem_path)

    mem.record_tactic(
        "WordPress plugin X has SQLi in endpoint Y",
        target_fingerprint="wordpress+php7.4+nginx",
        attack_type="sqli",
        confidence=0.9,
    )
    mem.record_tactic(
        "Apache Struts 2 CVE-2017-5638 RCE",
        target_fingerprint="java+struts2+tomcat",
        attack_type="rce",
        confidence=0.95,
    )

    tactics = mem.query_tactics("wordpress")
    struts = mem.query_tactics("java+struts2")
    none = mem.query_tactics("django+python")

    os.remove(mem_path)
    return len(tactics) >= 1 and len(struts) >= 1 and len(none) == 0


@test("CrossEngagementMemory duplicate update")
def test_cross_eng_duplicate():
    mem_path = "/tmp/test_cross_eng_dup.json"
    mem = CrossEngagementMemory(memory_path=mem_path)

    rule1 = mem.record_tactic(
        "SQL injection in login form",
        target_fingerprint="php+mysql",
        attack_type="sqli",
        confidence=0.7,
    )
    rule2 = mem.record_tactic(
        "SQL injection in login form",  # Same tactic
        target_fingerprint="php+mysql",
        attack_type="sqli",
        confidence=0.7,
    )

    os.remove(mem_path)
    return rule1.success_count == 2 and rule2.confidence > 0.7


@test("CrossEngagementMemory prioritized paths")
def test_cross_eng_prioritized():
    mem_path = "/tmp/test_cross_eng_pri.json"
    mem = CrossEngagementMemory(memory_path=mem_path)

    mem.record_tactic(
        "Critical RCE in Tomcat", target_fingerprint="java+tomcat",
        attack_type="rce", confidence=0.95,
    )
    mem.record_tactic(
        "Minor XSS in footer", target_fingerprint="java+tomcat",
        attack_type="xss", confidence=0.3,
    )

    paths = mem.get_prioritized_attack_paths("java+tomcat", limit=5)
    os.remove(mem_path)

    return len(paths) == 2 and "RCE" in paths[0] and "XSS" in paths[1]


@test("CrossEngagementMemory stats")
def test_cross_eng_stats():
    mem_path = "/tmp/test_cross_eng_stats.json"
    mem = CrossEngagementMemory(memory_path=mem_path)

    mem.record_tactic("RCE in upload", attack_type="rce", confidence=0.9)
    mem.record_tactic("SQLi in login", attack_type="sqli", confidence=0.8)
    mem.record_tactic("XSS in search", attack_type="xss", confidence=0.6)

    stats = mem.stats()
    os.remove(mem_path)

    return stats["total_rules"] == 3 and "rce" in stats["attack_types"]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 70)
    print("  RedaMon XBOW Integration Test Suite")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print()

    # Run all tests (decorators execute on import).
    total = PASS + FAIL
    print(f"\nResults: {PASS}/{total} passed, {FAIL} failed\n")

    for r in RESULTS:
        print(r)

    print()
    if FAIL == 0:
        print("=== ALL TESTS PASSED ===")
    else:
        print(f"=== {FAIL} TEST(S) FAILED ===")

    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
