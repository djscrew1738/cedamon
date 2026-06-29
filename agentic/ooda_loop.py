"""
OODA (Observe-Orient-Decide-Act) Executive Loop for RedaMon XBOW Integration.

Replaces linear "execute next action -> get result" with a continuous,
self-correcting OODA cycle. This is the heart of the XBOW integration.

Phase 1 hardening improvements:
    - Action hash + timestamp tracking for stuck detection
    - World model snapshots before each action for backtracking
    - Proper 4-level escalating recovery with state restoration

Usage:
    ooda = OODALoop(llm=..., planner=..., ...)
    result = await ooda.run(state, config, objective="Scan example.com")
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_NO_PROGRESS_CYCLES = 5
MAX_REPEATED_ACTIONS = 2
HISTORY_WINDOW = 20
DEFAULT_MAX_CYCLES = 200

FLAG_PATTERNS = [
    r"FLAG\{[^}]+\}", r"flag\{[^}]+\}",
    r"HTB\{[^}]+\}", r"CTF\{[^}]+\}",
]


class RecoveryLevel(str, Enum):
    NONE = "none"
    BACKTRACK = "backtrack"
    SWITCH_STRATEGY = "switch_strategy"
    ACQUIRE_TOOLS = "acquire_tools"
    HUMAN_ESCALATION = "human_escalation"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Observation:
    cycle: int
    timestamp: str
    phase: str
    last_action: str
    last_output: str
    last_error: str = ""
    new_findings: list[str] = field(default_factory=list)
    opened_ports: list[int] = field(default_factory=list)
    credentials_found: list[str] = field(default_factory=list)
    world_model_changes: list[str] = field(default_factory=list)
    progress_made: bool = False
    stuck_detected: bool = False
    stuck_reason: str = ""
    flag_found: Optional[str] = None


@dataclass
class Decision:
    cycle: int
    action_type: str
    tool_name: str = ""
    tool_args: dict = field(default_factory=dict)
    reasoning: str = ""
    expected_outcome: str = ""
    recovery_level: RecoveryLevel = RecoveryLevel.NONE
    recovery_description: str = ""
    sub_task: str = ""


@dataclass
class OODACycleEntry:
    cycle: int
    timestamp: str
    observation: Optional[Observation] = None
    orientation: Optional[dict] = None
    decision: Optional[Decision] = None
    action_result: Optional[dict] = None


# ---------------------------------------------------------------------------
# OODA Loop
# ---------------------------------------------------------------------------

class OODALoop:
    """OODA executive loop with stuck-state detection and recovery."""

    def __init__(
        self,
        *,
        llm=None,
        planner=None,
        context_manager=None,
        sandbox_executor=None,
        tool_loader=None,
        exploit_synth=None,
        max_cycles: int = DEFAULT_MAX_CYCLES,
        execute_tool_fn: Optional[Callable] = None,
        think_fn: Optional[Callable] = None,
    ):
        self.llm = llm
        self.planner = planner
        self.context_manager = context_manager
        self.sandbox = sandbox_executor
        self.tool_loader = tool_loader
        self.exploit_synth = exploit_synth
        self.max_cycles = max_cycles
        self.execute_tool_fn = execute_tool_fn
        self.think_fn = think_fn

        # Internal state.
        self._cycle: int = 0
        self._history: list[OODACycleEntry] = []
        self._action_counter: dict[str, int] = defaultdict(int)
        self._action_hash_set: set[tuple[str, str]] = set()
        self._action_timestamps: dict[str, float] = {}
        self._world_model_snapshots: list[dict] = []
        self._last_good_state: Optional[dict] = None
        self._consecutive_no_progress: int = 0
        self._world_model: dict[str, Any] = {}
        self._completed: bool = False
        self._found_flag: Optional[str] = None

        self._session_id: str = ""
        self._user_id: str = ""
        self._project_id: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self, state: dict, config: Optional[dict] = None,
        objective: str = "", plan: Optional[Any] = None,
    ) -> dict:
        self._cycle = 0
        self._history.clear()
        self._action_counter.clear()
        self._action_hash_set.clear()
        self._action_timestamps.clear()
        self._world_model_snapshots.clear()
        self._consecutive_no_progress = 0
        self._completed = False
        self._found_flag = None

        if config:
            cfg = config.get("configurable", {})
            self._session_id = cfg.get("thread_id", "default")
            self._user_id = cfg.get("user_id", "")
            self._project_id = cfg.get("project_id", "")

        if plan is None and self.planner is not None and objective:
            try:
                plan = await self.planner.create_plan(objective=objective)
            except Exception as exc:
                logger.error("Plan creation failed: %s", exc)
                return {"completion_reason": f"Plan creation failed: {exc}"}

        logger.info(
            "=== OODA LOOP START === session=%s, max_cycles=%d",
            self._session_id, self.max_cycles,
        )
        start_time = time.time()

        while self._cycle < self.max_cycles and not self._completed:
            self._cycle += 1
            logger.info("--- OODA Cycle %d ---", self._cycle)

            # Snapshot world model BEFORE action (for backtracking).
            self._snapshot_world_model(state)

            # OBSERVE
            observation = await self._observe(state, plan)
            self._log_cycle("observe", observation)

            if observation.flag_found:
                self._found_flag = observation.flag_found
                self._completed = True
                logger.info("FLAG FOUND in cycle %d: %s", self._cycle, self._found_flag)
                break

            # ORIENT
            orientation = await self._orient(observation, state, plan)
            self._log_cycle("orient", orientation)
            self._world_model.update(orientation.get("world_model_updates", {}))

            if self.context_manager:
                try:
                    self.context_manager.save_world_model(
                        "current", json.dumps(self._world_model, default=str)
                    )
                except Exception as exc:
                    logger.debug("World model save failed: %s", exc)

            if orientation.get("mission_complete"):
                self._completed = True
                logger.info("Mission complete")
                break

            # DECIDE
            decision = await self._decide(observation, orientation, state, plan)
            self._log_cycle("decide", decision)

            if decision.action_type == "completion":
                self._completed = True
                break

            if decision.action_type == "human_escalation":
                logger.warning("Human escalation: %s", decision.recovery_description)
                self._completed = True
                state["request_human_guidance"] = decision.recovery_description
                break

            # ACT
            action_result = await self._act(decision, state, plan)
            self._log_cycle("act", action_result)

            if action_result:
                state = self._update_state(state, action_result)

            # Track action for stuck detection (hash + timestamp).
            self._track_action(decision, action_result)

            # Record in context manager.
            if self.context_manager:
                try:
                    self.context_manager.record_action(
                        session_id=self._session_id,
                        action_name=decision.tool_name or decision.action_type,
                        phase=state.get("current_phase", "informational"),
                        raw_output=action_result.get("output", "") if action_result else "",
                        summary=decision.reasoning[:500],
                        key_findings=action_result.get("findings", []) if action_result else [],
                        credentials_found=action_result.get("credentials", []) if action_result else [],
                        error_summary=action_result.get("error", "") if action_result else "",
                        opened_ports=action_result.get("ports", []) if action_result else [],
                        success=action_result.get("success", True) if action_result else True,
                    )
                except Exception as exc:
                    logger.warning("Failed to record action: %s", exc)

        elapsed = time.time() - start_time
        logger.info(
            "=== OODA LOOP END === cycles=%d, elapsed=%.1fs, flag=%s",
            self._cycle, elapsed, self._found_flag,
        )
        await self._write_audit_log()
        return {
            "completion_reason": (
                f"Mission completed in {self._cycle} cycles"
                if self._completed
                else f"Max cycles ({self.max_cycles}) reached"
            ),
            "flag_found": self._found_flag,
            "cycles": self._cycle,
            "elapsed_seconds": elapsed,
        }

    async def run_until_flag(
        self, plan: Any, flag_pattern: str = r"FLAG\{[^}]+\}",
        timeout: float = 3600,
    ) -> dict:
        import re as _re
        self._cycle = 0
        self._history.clear()
        self._completed = False
        self._found_flag = None
        start = time.time()
        flag_re = _re.compile(flag_pattern)
        while self._cycle < self.max_cycles and time.time() - start < timeout:
            self._cycle += 1
            state = {"current_phase": "exploitation", "execution_trace": []}
            observation = await self._observe(state, plan)
            for pattern in FLAG_PATTERNS + [flag_pattern]:
                m = _re.search(pattern, observation.last_output or "")
                if m:
                    self._found_flag = m.group(0)
                    return {"found_flag": self._found_flag, "steps": self._cycle,
                            "elapsed_seconds": time.time() - start}
            if observation.stuck_detected:
                logger.warning("Stuck: %s", observation.stuck_reason)
            orientation = await self._orient(observation, state, plan)
            if orientation.get("mission_complete"):
                break
            decision = await self._decide(observation, orientation, state, plan)
            action_result = await self._act(decision, state, plan)
            if action_result:
                state = self._update_state(state, action_result)
                output = action_result.get("output", "")
                if flag_re.search(output):
                    m = flag_re.search(output)
                    if m:
                        self._found_flag = m.group(0)
                        logger.info("FLAG FOUND: %s", self._found_flag)
                        return {"found_flag": self._found_flag, "steps": self._cycle,
                                "elapsed_seconds": time.time() - start}
        return {"found_flag": self._found_flag, "steps": self._cycle,
                "elapsed_seconds": time.time() - start}

    def get_audit_log(self) -> list[dict]:
        return [
            {
                "cycle": e.cycle, "timestamp": e.timestamp,
                "observation": e.observation.__dict__ if e.observation else None,
                "orientation": e.orientation,
                "decision": e.decision.__dict__ if e.decision else None,
                "action_result": e.action_result,
            }
            for e in self._history
        ]

    # ------------------------------------------------------------------
    # Action tracking & stuck detection
    # ------------------------------------------------------------------

    def _action_hash(self, action_name: str, args: dict) -> str:
        """Compute a stable hash for an action+args combination."""
        raw = f"{action_name}:{json.dumps(args, sort_keys=True, default=str)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _track_action(self, decision: Decision, result: Optional[dict]) -> None:
        """Track action hash + timestamp for stuck detection."""
        action_hash = self._action_hash(decision.tool_name or decision.action_type,
                                         decision.tool_args)
        now = time.time()

        # Increment action counter.
        self._action_counter[decision.tool_name or decision.action_type] += 1

        # Record hash+timestamp.
        self._action_hash_set.add((action_hash, decision.tool_name or ""))
        self._action_timestamps[action_hash] = now

        # Update last good state on success.
        if result and result.get("success"):
            self._last_good_state = {
                "_cycle": self._cycle,
                "_world_model": dict(self._world_model),
                "_timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _snapshot_world_model(self, state: dict) -> None:
        """Store a lightweight snapshot of the current world model."""
        snapshot = {
            "_cycle": self._cycle,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_phase": state.get("current_phase", "informational"),
            "_target_info": json.dumps(
                state.get("target_info", {}), default=str
            )[:2000],
            "_world_model": dict(self._world_model),
        }
        self._world_model_snapshots.append(snapshot)
        if len(self._world_model_snapshots) > HISTORY_WINDOW:
            self._world_model_snapshots = self._world_model_snapshots[-HISTORY_WINDOW:]

    # ------------------------------------------------------------------
    # OODA Phases
    # ------------------------------------------------------------------

    async def _observe(self, state: dict, plan: Optional[Any]) -> Observation:
        exec_trace = state.get("execution_trace", [])
        last_step = exec_trace[-1] if exec_trace else {}

        last_action = last_step.get("tool_name", "none")
        last_output = (last_step.get("tool_output") or "")[:5000]
        last_error = last_step.get("error_message", "")

        flag_found = None
        for pattern in FLAG_PATTERNS:
            m = re.search(pattern, last_output)
            if m:
                flag_found = m.group(0)
                break

        new_findings = []
        ports = re.findall(r"(\d+)/tcp\s+open", last_output)
        new_findings.extend(f"port {p}/tcp open" for p in ports)
        if "credential" in last_output.lower() or "password" in last_output.lower():
            new_findings.append("Credentials found")

        stuck_detected, stuck_reason = await self._detect_stuck(state, last_action)
        progress_made = bool(new_findings) or last_step.get("success", False)

        if progress_made:
            self._consecutive_no_progress = 0
        else:
            self._consecutive_no_progress += 1

        return Observation(
            cycle=self._cycle,
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=state.get("current_phase", "informational"),
            last_action=last_action, last_output=last_output,
            last_error=last_error, new_findings=new_findings,
            progress_made=progress_made,
            stuck_detected=stuck_detected, stuck_reason=stuck_reason,
            flag_found=flag_found,
        )

    async def _orient(self, observation: Observation, state: dict,
                      plan: Optional[Any]) -> dict:
        updates = {}
        if observation.flag_found:
            return {"flag_found": observation.flag_found, "mission_complete": True}

        for finding in observation.new_findings:
            if "port" in finding:
                updates.setdefault("discovered_ports", []).append(finding)
            if "technology" in finding.lower():
                updates.setdefault("discovered_tech", []).append(finding)
            if "credential" in finding.lower() or "password" in finding.lower():
                updates.setdefault("discovered_credentials", []).append(finding)

        if plan and observation.progress_made:
            phase = plan.current_phase()
            if phase and any(
                kw in observation.last_output.lower()
                for kw in ["success", "completed", "found", "extracted"]
            ):
                if not plan.advance_subtask():
                    if not plan.advance_phase():
                        updates["mission_complete"] = True
                    else:
                        updates["phase_advanced"] = plan.current_phase().name
                else:
                    updates["subtask_advanced"] = True

        return {"world_model_updates": updates,
                "mission_complete": updates.get("mission_complete", False),
                "stuck_detected": observation.stuck_detected}

    async def _decide(self, observation: Observation, orientation: dict,
                      state: dict, plan: Optional[Any]) -> Decision:
        recovery_level = RecoveryLevel.NONE
        recovery_description = ""

        if observation.stuck_detected:
            recovery_level, recovery_description = await self._apply_recovery(
                observation, state, plan
            )
            if recovery_level == RecoveryLevel.HUMAN_ESCALATION:
                return Decision(cycle=self._cycle, action_type="human_escalation",
                                reasoning=recovery_description,
                                recovery_level=recovery_level,
                                recovery_description=recovery_description)

        if plan and self.planner:
            phase = plan.current_phase()
            sub_task = plan.current_subtask()
            if phase and sub_task:
                try:
                    action = await self.planner.expand_subtask(
                        phase_name=phase.name, phase_goal=phase.goal,
                        sub_task=sub_task,
                        world_model=json.dumps(self._world_model, default=str),
                        previous_actions=observation.last_action,
                    )
                    return Decision(
                        cycle=self._cycle,
                        action_type=action.get("action_type", "tool_call"),
                        tool_name=action.get("tool_name", ""),
                        tool_args=action.get("tool_args", {}),
                        reasoning=action.get("reasoning", ""),
                        expected_outcome=action.get("expected_outcome", ""),
                        recovery_level=recovery_level,
                        recovery_description=recovery_description,
                        sub_task=sub_task,
                    )
                except Exception as exc:
                    logger.warning("Sub-task expansion failed: %s", exc)
            elif not phase:
                return Decision(cycle=self._cycle, action_type="completion",
                                reasoning="All plan phases completed")

        # Fallback: use ReAct think if available.
        if self.think_fn:
            try:
                think_result = await self.think_fn(state)
                return Decision(
                    cycle=self._cycle, action_type="tool_call",
                    tool_name=think_result.get("tool_name", ""),
                    tool_args=think_result.get("tool_args", {}),
                    reasoning=think_result.get("reasoning", ""),
                    expected_outcome="ReAct think output",
                    recovery_level=recovery_level,
                )
            except Exception as exc:
                logger.error("ReAct think failed: %s", exc)

        return Decision(cycle=self._cycle, action_type="completion",
                        reasoning="No actionable decision path available")

    async def _act(self, decision: Decision, state: dict,
                   plan: Optional[Any]) -> Optional[dict]:
        logger.info("ACT: %s -> %s", decision.action_type, decision.tool_name or "")

        if decision.action_type == "reasoning":
            return {"output": decision.reasoning, "success": True}

        if decision.action_type == "phase_advance":
            if plan:
                plan.advance_phase()
            return {"output": "Phase advanced", "success": True}

        if decision.action_type == "backtrack":
            if self._last_good_state:
                state.update(self._last_good_state.get("_world_model", {}))
                return {"output": "State reverted to last good checkpoint",
                        "success": True}
            return {"output": "No checkpoint to revert to", "success": False}

        if decision.action_type == "request_tool":
            if self.tool_loader:
                try:
                    tool = await self.tool_loader.acquire_tool(
                        requirement=decision.recovery_description or decision.reasoning,
                    )
                    if tool:
                        return {"output": f"Tool acquired: {tool.name}", "success": True}
                    return {"output": "No suitable tool found", "success": False}
                except Exception as exc:
                    return {"output": str(exc), "error": str(exc), "success": False}
            return {"output": "Tool loader not available", "success": False}

        if decision.action_type == "tool_call":
            if (decision.tool_name == "exploit_synth"
                    or "exploit" in decision.tool_name.lower()
                    and self.exploit_synth):
                try:
                    result = await self.exploit_synth.synthesize_and_exploit(
                        vuln_description=decision.tool_args.get(
                            "vuln_description", decision.reasoning),
                        target=decision.tool_args.get("target", ""),
                        target_details=decision.tool_args.get("target_details"),
                    )
                    return {
                        "output": result.output, "error": result.error_output,
                        "success": result.success, "findings": result.evidence,
                        "exploit_code": result.exploit_code,
                    }
                except Exception as exc:
                    return {"output": f"Exploit synth error: {exc}", "success": False}

            if self.tool_loader and self.tool_loader.has_tool(decision.tool_name):
                try:
                    result = await self.tool_loader.execute_tool(
                        tool_name=decision.tool_name, kwargs=decision.tool_args,
                    )
                    return {
                        "output": result.get("stdout", ""),
                        "error": result.get("stderr", ""),
                        "success": result.get("success", False),
                    }
                except Exception as exc:
                    return {"output": str(exc), "success": False}

            if self.execute_tool_fn:
                try:
                    result = await self.execute_tool_fn(
                        tool_name=decision.tool_name, tool_args=decision.tool_args,
                    )
                    return result
                except Exception as exc:
                    return {"output": str(exc), "error": str(exc), "success": False}

            return {"output": f"No executor for {decision.tool_name}",
                    "success": False}

        return {"output": f"Unknown action type: {decision.action_type}",
                "success": False}

    # ------------------------------------------------------------------
    # Stuck Detection & Recovery
    # ------------------------------------------------------------------

    async def _detect_stuck(self, state: dict,
                            last_action: str) -> tuple[bool, str]:
        reasons = []

        # Check 1: same action hash repeated (action + same args).
        if last_action and last_action != "none":
            action_hash = self._action_hash(last_action, {})
            last_time = self._action_timestamps.get(action_hash, 0)
            if time.time() - last_time < 30:  # within 30 seconds
                self._action_counter[last_action] += 1
            if self._action_counter[last_action] > MAX_REPEATED_ACTIONS:
                reasons.append(
                    f"Same action '{last_action}' repeated "
                    f"{self._action_counter[last_action]} times"
                )

        # Check 2: no progress for N cycles.
        if self._consecutive_no_progress >= MAX_NO_PROGRESS_CYCLES:
            reasons.append(
                f"No progress for {self._consecutive_no_progress} cycles"
            )

        # Check 3: same error repeated 3+ times.
        exec_trace = state.get("execution_trace", [])
        errors = [s.get("error_message", "") for s in exec_trace[-10:]
                  if s.get("error_message")]
        if len(errors) >= 3 and len(set(errors)) == 1:
            reasons.append(
                f"Same error repeated {len(errors)} times: {errors[0][:100]}"
            )

        if reasons:
            return True, "; ".join(reasons)
        return False, ""

    async def _apply_recovery(
        self, observation: Observation, state: dict, plan: Optional[Any],
    ) -> tuple[RecoveryLevel, str]:
        # Level 1: Backtrack.
        if self._last_good_state and self._consecutive_no_progress < 10:
            return RecoveryLevel.BACKTRACK, (
                f"Reverting to last good state (cycle "
                f"{self._last_good_state.get('_cycle', 'unknown')}) "
                f"and retrying with different parameters."
            )

        # Level 2: Switch strategy.
        if plan and self.planner:
            try:
                plan = await self.planner.revise_plan(
                    plan=plan, stuck_reason=observation.stuck_reason,
                    world_model=json.dumps(self._world_model, default=str),
                )
                phase = plan.current_phase()
                return RecoveryLevel.SWITCH_STRATEGY, (
                    f"Strategy switched. Current phase: "
                    f"{phase.name if phase else 'none'}"
                )
            except Exception as exc:
                logger.warning("Plan revision failed: %s", exc)

        # Level 3: Acquire new tools.
        if self.tool_loader:
            return RecoveryLevel.ACQUIRE_TOOLS, (
                f"Requesting dynamic tool acquisition. "
                f"Reason: {observation.stuck_reason}"
            )

        # Level 4: Human escalation.
        return RecoveryLevel.HUMAN_ESCALATION, (
            f"All automated recovery attempts exhausted.\n"
            f"Mission: {plan.objective if plan else 'unknown'}\n"
            f"Stuck reason: {observation.stuck_reason}\n"
            f"Cycles without progress: {self._consecutive_no_progress}\n"
            f"Last action: {observation.last_action}\n"
            f"Last error: {observation.last_error}\n"
            f"World model: {json.dumps(self._world_model, default=str, indent=2)}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _log_cycle(self, phase: str, data: Any) -> None:
        entry = OODACycleEntry(
            cycle=self._cycle,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        if phase == "observe":
            entry.observation = data
        elif phase == "orient":
            entry.orientation = data
        elif phase == "decide":
            entry.decision = data
        elif phase == "act":
            existing = None
            for e in reversed(self._history):
                if e.cycle == self._cycle:
                    existing = e; break
            if existing:
                existing.action_result = data
            else:
                entry.action_result = data
                self._history.append(entry)
            return
        self._history.append(entry)

    def _update_state(self, state: dict, action_result: dict) -> dict:
        state = dict(state)
        trace = list(state.get("execution_trace", []))
        trace.append({
            "step_id": f"ooda-{self._cycle}",
            "iteration": self._cycle,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "phase": state.get("current_phase", "informational"),
            "tool_name": action_result.get("tool_name", ""),
            "tool_output": action_result.get("output", ""),
            "success": action_result.get("success", True),
            "error_message": action_result.get("error", ""),
        })
        state["execution_trace"] = trace[-HISTORY_WINDOW:]
        state["current_iteration"] = self._cycle
        findings = action_result.get("findings", [])
        if findings:
            target_info = dict(state.get("target_info", {}))
            for f in findings:
                if "port" in str(f).lower():
                    target_info.setdefault("open_ports", []).append(f)
            state["target_info"] = target_info
        return state

    async def _write_audit_log(self) -> None:
        log_dir = os.environ.get("REDAMON_OODA_LOG_DIR", "/tmp/redamon_ooda_logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(
            log_dir,
            f"ooda_{self._session_id}_"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
        )
        try:
            with open(log_path, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": self._session_id,
                    "total_cycles": self._cycle,
                    "found_flag": self._found_flag,
                    "cycles": self.get_audit_log(),
                }, f, indent=2, default=str)
            logger.info("Audit log written to %s", log_path)
        except Exception as exc:
            logger.warning("Failed to write audit log: %s", exc)
