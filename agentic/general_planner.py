"""
General Security Reasoning Planner for RedaMon XBOW Integration.

Extends RedaMon's pentest-focused planning to handle arbitrary natural
language security objectives, including:
    - Offensive operations ("pentest the domain X")
    - Forensic analysis ("analyze these Apache logs and find the attacker's IP")
    - CTF puzzle solving ("find the flag on 10.10.10.5")
    - Security audits ("audit this AWS IAM policy for privilege escalation")
    - Log analysis ("find anomalies in these firewall logs")

Key Features:
    - Task classification (offensive / forensic / puzzle / audit / log_analysis)
    - Hierarchical plan generation: top-level phases with dynamic sub-tasks
    - Tool requirement detection and dynamic tool acquisition integration
    - Integration with the OODA loop for continuous plan revision
    - Benchmark mode support for autonomous CTF solving

Architecture:
    The GeneralPlanner wraps the existing agentic planning with:
    1. A classifier that identifies the task type from natural language.
    2. Phase generation appropriate to the task type.
    3. Sub-task expansion within each phase, driven by the OODA loop.
    4. Dynamic tool loading when requirements exceed known tools.

Usage:
    planner = GeneralPlanner(llm=llm_client, tool_loader=loader)
    plan = await planner.create_plan(
        objective="Analyze these Apache logs and find the attacker's IP",
        context={"log_file": "/tmp/access.log"},
    )
    # plan.phases = ["forensic_analysis", "reporting"]
    # phase 1 has sub-tasks: parse_logs, identify_patterns, correlate_ips, ...
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Task types
# ---------------------------------------------------------------------------

class TaskCategory(str, Enum):
    """Classification of security objectives for planning."""
    OFFENSIVE = "offensive"             # Pentesting, exploitation, red team
    FORENSIC = "forensic"               # Memory/disk forensics, log analysis
    PUZZLE = "puzzle"                   # CTF challenges, flag hunting
    AUDIT = "audit"                     # Configuration review, policy audit
    LOG_ANALYSIS = "log_analysis"       # APT hunting, anomaly detection
    CRYPTO = "crypto"                   # Cryptographic challenges
    REVERSE_ENGINEERING = "reverse_engineering"  # Binary analysis
    UNKNOWN = "unknown"


# Known tool categories by task type.
TASK_TOOL_MAP: dict[TaskCategory, list[str]] = {
    TaskCategory.OFFENSIVE: [
        "nmap", "nuclei", "metasploit", "hydra", "ffuf", "sqlmap",
        "subfinder", "httpx", "katana", "naabu", "amass", "gau",
    ],
    TaskCategory.FORENSIC: [
        "volatility", "bulk_extractor", "strings", "binwalk",
        "foremost", "sleuthkit", "plaso", "log2timeline",
    ],
    TaskCategory.PUZZLE: [
        "nmap", "gobuster", "john", "hashcat", "sqlmap",
        "burp", "curl", "nc", "python", "gdb",
    ],
    TaskCategory.AUDIT: [
        "prowler", "scoutsuite", "cloudsploit", "kube-bench",
        "lynis", "trivy", "checkov",
    ],
    TaskCategory.LOG_ANALYSIS: [
        "jq", "awk", "grep", "zeek", "suricata",
        "chainsaw", "hayabusa", "sigma",
    ],
    TaskCategory.CRYPTO: [
        "openssl", "python", "sage", "z3", "hashcat",
        "john", "cyberchef",
    ],
    TaskCategory.REVERSE_ENGINEERING: [
        "ghidra", "radare2", "gdb", "objdump", "strings",
        "ltrace", "strace", "x64dbg",
    ],
}

# Phase templates by task category.
PHASE_TEMPLATES: dict[TaskCategory, list[dict]] = {
    TaskCategory.OFFENSIVE: [
        {"name": "reconnaissance", "description": "Discover assets, ports, services, endpoints"},
        {"name": "vulnerability_analysis", "description": "Identify vulnerabilities and misconfigurations"},
        {"name": "exploitation", "description": "Exploit vulnerabilities to gain access"},
        {"name": "post_exploitation", "description": "Maintain access, lateral movement, data exfiltration"},
        {"name": "reporting", "description": "Document findings and remediation steps"},
    ],
    TaskCategory.FORENSIC: [
        {"name": "evidence_acquisition", "description": "Secure and verify the evidence"},
        {"name": "data_extraction", "description": "Extract relevant artifacts from evidence"},
        {"name": "analysis", "description": "Analyze artifacts for indicators"},
        {"name": "correlation", "description": "Correlate findings across artifacts"},
        {"name": "reporting", "description": "Document timeline and conclusions"},
    ],
    TaskCategory.PUZZLE: [
        {"name": "reconnaissance", "description": "Enumerate target and discover the puzzle surface"},
        {"name": "exploitation", "description": "Solve stages and capture flags"},
        {"name": "flag_submission", "description": "Validate and submit the flag"},
    ],
    TaskCategory.AUDIT: [
        {"name": "scope_definition", "description": "Define audit scope and compliance framework"},
        {"name": "data_collection", "description": "Gather configuration data and policies"},
        {"name": "analysis", "description": "Analyze against benchmarks and best practices"},
        {"name": "findings", "description": "Document gaps and prioritize by severity"},
        {"name": "reporting", "description": "Generate audit report with recommendations"},
    ],
    TaskCategory.LOG_ANALYSIS: [
        {"name": "ingestion", "description": "Parse and normalize log data"},
        {"name": "filtering", "description": "Filter noise and identify relevant events"},
        {"name": "pattern_detection", "description": "Detect known TTPs and anomalies"},
        {"name": "attribution", "description": "Identify the threat actor and attack chain"},
        {"name": "reporting", "description": "Document IOC timeline and attack narrative"},
    ],
    TaskCategory.CRYPTO: [
        {"name": "analysis", "description": "Identify cipher type and key characteristics"},
        {"name": "attack", "description": "Apply cryptographic attack technique"},
        {"name": "verification", "description": "Verify decryption and extract solution"},
    ],
    TaskCategory.REVERSE_ENGINEERING: [
        {"name": "static_analysis", "description": "Disassemble and analyze binary structure"},
        {"name": "dynamic_analysis", "description": "Debug and trace execution"},
        {"name": "solution", "description": "Extract flag or bypass protection"},
    ],
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class PlanPhase:
    """A top-level phase in a RedaMon plan."""
    name: str
    description: str
    goal: str = ""                          # What this phase should accomplish
    sub_tasks: list[str] = field(default_factory=list)  # Sub-task descriptions
    required_tools: list[str] = field(default_factory=list)
    success_criteria: str = ""              # How to know this phase is complete
    status: str = "pending"                 # pending, active, completed, skipped


@dataclass
class SecurityPlan:
    """A complete hierarchical security plan generated by GeneralPlanner."""
    objective: str
    category: TaskCategory
    phases: list[PlanPhase] = field(default_factory=list)
    target_description: str = ""
    expected_tools: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)  # Tools to acquire
    flag_pattern: Optional[str] = None       # Regex for CTF flag detection
    created_at: float = 0.0
    current_phase_idx: int = 0
    current_subtask_idx: int = 0

    def current_phase(self) -> Optional[PlanPhase]:
        """Get the currently active phase."""
        if 0 <= self.current_phase_idx < len(self.phases):
            return self.phases[self.current_phase_idx]
        return None

    def current_subtask(self) -> Optional[str]:
        """Get the current sub-task description."""
        phase = self.current_phase()
        if phase and 0 <= self.current_subtask_idx < len(phase.sub_tasks):
            return phase.sub_tasks[self.current_subtask_idx]
        return None

    def advance_subtask(self) -> bool:
        """Move to the next sub-task. Returns False if no more sub-tasks."""
        phase = self.current_phase()
        if not phase:
            return False
        if self.current_subtask_idx + 1 < len(phase.sub_tasks):
            self.current_subtask_idx += 1
            return True
        return False

    def advance_phase(self) -> bool:
        """Move to the next phase. Returns False if no more phases."""
        if self.current_phase_idx + 1 < len(self.phases):
            phase = self.current_phase()
            if phase:
                phase.status = "completed"
            self.current_phase_idx += 1
            self.current_subtask_idx = 0
            next_phase = self.current_phase()
            if next_phase:
                next_phase.status = "active"
            return True
        return False


# ---------------------------------------------------------------------------
# Classification prompt
# ---------------------------------------------------------------------------

CLASSIFICATION_PROMPT = """\
Classify the following security objective into one task category and extract
key details for planning.

Objective: {objective}

Available categories:
- offensive: Penetration testing, red teaming, exploitation, hacking a target
- forensic: Memory/disk forensics, incident response, artifact analysis
- puzzle: CTF challenges, capture-the-flag, wargames
- audit: Configuration review, compliance audit, policy assessment
- log_analysis: Log review, APT hunting, SIEM analysis, anomaly detection
- crypto: Cryptographic challenges, cipher breaking, key recovery
- reverse_engineering: Binary analysis, malware analysis, crackme

Respond with a JSON object:
{{
    "category": "one of the above",
    "confidence": 0.0-1.0,
    "target_description": "what is being analyzed or attacked",
    "flag_pattern": "regex for expected flag format, or null",
    "key_artifacts": ["list of files/hosts/services mentioned"],
    "reasoning": "brief explanation of classification"
}}
"""

PLAN_GENERATION_PROMPT = """\
You are a senior security operator and planner. Generate a hierarchical
operation plan for the following objective.

Objective: {objective}
Task Category: {category}
Target: {target_description}
Available Tools: {available_tools}

The plan should have these phases (matching the task category):
{phase_template}

For each phase, generate:
1. A concrete goal (what success looks like for this phase)
2. 3-8 specific sub-tasks (actionable steps)
3. Required tools for this phase
4. Success criteria (measurable outcome)

Format your response as a JSON object:
{{
    "phases": [
        {{
            "name": "phase_name",
            "goal": "concrete goal",
            "sub_tasks": ["task 1", "task 2", ...],
            "required_tools": ["tool1", "tool2"],
            "success_criteria": "how to verify completion"
        }}
    ],
    "expected_tools": ["all tools needed across all phases"],
    "flag_pattern": "regex or null"
}}
"""

SUB_TASK_EXPANSION_PROMPT = """\
Expand the following sub-task into a concrete action plan.

Phase: {phase_name}
Phase Goal: {phase_goal}
Sub-task: {sub_task}
Current World Model: {world_model}
Previous Actions: {previous_actions}

Generate exactly ONE action as a JSON object:
{{
    "action_type": "tool_call | reasoning | completion | request_tool",
    "tool_name": "name of tool to call (if action_type=tool_call)",
    "tool_args": {{"arg1": "value1"}},
    "reasoning": "why this action advances the sub-task",
    "expected_outcome": "what we expect the tool to return",
    "tool_request": {{
        "requirement": "description of needed tool (if action_type=request_tool)",
        "context": "why existing tools are insufficient"
    }} or null,
    "completion_reason": "why this sub-task or phase is done (if action_type=completion)"
}}
"""


# ---------------------------------------------------------------------------
# GeneralPlanner
# ---------------------------------------------------------------------------

class GeneralPlanner:
    """
    General-purpose security planner extending RedaMon's pentest planning.

    Supports any security objective by:
    1. Classifying the task type.
    2. Generating phase-appropriate plans.
    3. Detecting tool gaps and requesting dynamic tool acquisition.
    4. Expanding sub-tasks into concrete actions for the OODA loop.
    5. Operating in benchmark mode for autonomous CTF solving.

    Integration points:
        - Called by ooda_loop.py in the "Decide" phase.
        - Uses tool_loader.py for dynamic tool acquisition.
        - Writes plans consumable by think_node and execute_plan_node.
    """

    def __init__(
        self,
        *,
        llm=None,                      # LLMClient / BaseChatModel
        tool_loader=None,              # ToolLoader instance
        context_manager=None,          # ContextManager instance
    ):
        """
        Initialize the general planner.

        Args:
            llm: LLM client for classification and plan generation.
            tool_loader: ToolLoader for dynamic tool acquisition.
            context_manager: ContextManager for relevant history retrieval.
        """
        self.llm = llm
        self.tool_loader = tool_loader
        self.context_manager = context_manager

        # Current active plan.
        self._active_plan: Optional[SecurityPlan] = None

        # Available tools (populated at init or dynamically).
        self._known_tools: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_plan(
        self,
        objective: str,
        context: Optional[dict] = None,
        available_tools: Optional[list[str]] = None,
        benchmark_mode: bool = False,
    ) -> SecurityPlan:
        """
        Create a hierarchical plan for a security objective.

        Full pipeline:
            1. Classify the task type.
            2. Generate phase-appropriate plan via LLM.
            3. Detect missing tools.
            4. (Optionally) auto-acquire missing tools.
            5. Set as the active plan.

        Args:
            objective: Natural language security objective.
            context: Optional dict with target info, artifacts, etc.
            available_tools: List of currently available tool names.
            benchmark_mode: If True, enable autonomous flag detection.

        Returns:
            A SecurityPlan with phases and sub-tasks.
        """
        if self.llm is None:
            raise RuntimeError("GeneralPlanner requires an LLM client")

        self._known_tools = set(available_tools or [])

        # Step 1: Classify the task.
        logger.info("Classifying objective: %s", objective[:100])
        classification = await self._classify(objective, context or {})

        category = TaskCategory(classification.get("category", "unknown"))
        target_desc = classification.get("target_description", "")
        flag_pattern = classification.get("flag_pattern")

        # Step 2: Generate the plan.
        logger.info("Generating plan for category: %s", category.value)
        phases_data = await self._generate_phases(
            objective=objective,
            category=category,
            target_description=target_desc,
            available_tools=sorted(self._known_tools),
        )

        # Step 3: Build the SecurityPlan.
        phases = []
        for pdata in phases_data.get("phases", []):
            phases.append(PlanPhase(
                name=pdata.get("name", ""),
                description=pdata.get("goal", ""),
                goal=pdata.get("goal", ""),
                sub_tasks=pdata.get("sub_tasks", []),
                required_tools=pdata.get("required_tools", []),
                success_criteria=pdata.get("success_criteria", ""),
            ))

        if phases:
            phases[0].status = "active"

        expected_tools = phases_data.get("expected_tools", [])
        missing_tools = [
            t for t in expected_tools
            if t not in self._known_tools
            and t not in {"python", "curl"}  # assume always available
        ]

        # Step 4: Detect missing tools.
        plan = SecurityPlan(
            objective=objective,
            category=category,
            phases=phases,
            target_description=target_desc,
            expected_tools=expected_tools,
            missing_tools=missing_tools,
            flag_pattern=flag_pattern or phases_data.get("flag_pattern"),
            created_at=time.time(),
        )

        # Step 5: Auto-acquire missing tools if tool_loader is available.
        if missing_tools and self.tool_loader and self.tool_loader.auto_install:
            logger.info("Auto-acquiring %d missing tools...", len(missing_tools))
            for tool_name in missing_tools:
                try:
                    acquired = await self.tool_loader.acquire_tool(
                        requirement=f"I need {tool_name} for {category.value} work",
                        context=objective[:200],
                    )
                    if acquired:
                        self._known_tools.add(tool_name)
                        plan.missing_tools.remove(tool_name)
                        logger.info("Acquired tool: %s", tool_name)
                except Exception as exc:
                    logger.warning(
                        "Failed to acquire tool '%s': %s", tool_name, exc
                    )

        self._active_plan = plan
        logger.info(
            "Plan created: %s, %d phases, %d missing tools",
            category.value, len(phases), len(plan.missing_tools),
        )
        return plan

    async def expand_subtask(
        self,
        phase_name: str,
        phase_goal: str,
        sub_task: str,
        world_model: str = "",
        previous_actions: str = "",
    ) -> dict:
        """
        Expand a sub-task into a concrete next action for the OODA loop.

        Args:
            phase_name: Name of the current phase.
            phase_goal: Goal of the current phase.
            sub_task: Sub-task description to expand.
            world_model: Current world model summary.
            previous_actions: Summary of previous actions.

        Returns:
            Dict with action_type, tool_name, tool_args, reasoning, etc.
        """
        if self.llm is None:
            raise RuntimeError("GeneralPlanner requires an LLM client")

        prompt = SUB_TASK_EXPANSION_PROMPT.format(
            phase_name=phase_name,
            phase_goal=phase_goal,
            sub_task=sub_task,
            world_model=world_model or "No world model yet.",
            previous_actions=previous_actions or "No previous actions.",
        )

        try:
            content = await self._llm_invoke(prompt)
            # Extract JSON.
            for match in re.finditer(r"\{[\s\S]*\}", content):
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
            # Try whole response.
            try:
                return json.loads(content.strip())
            except json.JSONDecodeError:
                pass

            logger.warning("Could not parse sub-task expansion: %s", content[:200])
            return {
                "action_type": "reasoning",
                "reasoning": "Failed to parse expansion, using default reasoning.",
                "expected_outcome": "Retry expansion",
            }

        except Exception as exc:
            logger.error("Sub-task expansion failed: %s", exc)
            return {
                "action_type": "reasoning",
                "reasoning": f"Expansion error: {exc}",
                "expected_outcome": "Retry expansion",
            }

    async def revise_plan(
        self,
        plan: SecurityPlan,
        stuck_reason: str,
        world_model: str = "",
    ) -> SecurityPlan:
        """
        Revise a plan when the OODA loop detects a stuck state.

        Args:
            plan: The current plan that hit a wall.
            stuck_reason: Description of why the plan is stuck.
            world_model: Current world model for context.

        Returns:
            A revised SecurityPlan with updated phases/sub-tasks.
        """
        if not self.llm:
            return plan

        logger.info("Revising plan due to stuck state: %s", stuck_reason[:100])

        # Regenerate from current position.
        prompt = """\
The current plan hit a wall. Revise it.

Original objective: {objective}
Current phase: {phase_name}
Stuck reason: {stuck_reason}
World model: {world_model}

Generate revised sub-tasks for the current phase as a JSON array of strings:
{{"revised_sub_tasks": ["new task 1", "new task 2", ...],
  "strategy_change": "description of what changed",
  "skip_phase": false}}
""".format(
            objective=plan.objective,
            phase_name=plan.current_phase().name if plan.current_phase() else "unknown",
            stuck_reason=stuck_reason,
            world_model=world_model or "No model available.",
        )

        try:
            content = await self._llm_invoke(prompt)
            for match in re.finditer(r"\{[\s\S]*\}", content):
                try:
                    revision = json.loads(match.group(0))
                    phase = plan.current_phase()
                    if phase and revision.get("revised_sub_tasks"):
                        phase.sub_tasks = revision["revised_sub_tasks"]
                        plan.current_subtask_idx = 0
                        logger.info(
                            "Plan revised: %s", revision.get("strategy_change", "")
                        )
                    if revision.get("skip_phase"):
                        plan.advance_phase()
                        logger.info("Skipping stuck phase")
                    return plan
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.error("Plan revision failed: %s", exc)

        return plan

    def get_active_plan(self) -> Optional[SecurityPlan]:
        """Get the currently active plan."""
        return self._active_plan

    def set_active_plan(self, plan: SecurityPlan) -> None:
        """Set the active plan."""
        self._active_plan = plan

    def get_task_category(self) -> TaskCategory:
        """Get the current task category."""
        if self._active_plan:
            return self._active_plan.category
        return TaskCategory.UNKNOWN

    def check_flag(self, text: str) -> Optional[str]:
        """
        Check if text contains a flag matching the expected pattern.

        Args:
            text: Text to search for flags.

        Returns:
            The captured flag string, or None.
        """
        if not self._active_plan or not self._active_plan.flag_pattern:
            return None

        pattern = self._active_plan.flag_pattern
        match = re.search(pattern, text)
        if match:
            flag = match.group(0)
            logger.info("FLAG FOUND: %s", flag)
            return flag
        return None

    # ------------------------------------------------------------------
    # Internal: Classification
    # ------------------------------------------------------------------

    async def _classify(self, objective: str, context: dict) -> dict:
        """Classify the objective into a task category."""
        prompt = CLASSIFICATION_PROMPT.format(
            objective=objective,
        )

        try:
            content = await self._llm_invoke(prompt)
            for match in re.finditer(r"\{[\s\S]*\}", content):
                try:
                    result = json.loads(match.group(0))
                    if "category" in result:
                        return result
                except json.JSONDecodeError:
                    pass
            try:
                result = json.loads(content.strip())
                if "category" in result:
                    return result
            except json.JSONDecodeError:
                pass

            logger.warning("Classification parse failed: %s", content[:200])
        except Exception as exc:
            logger.error("Classification LLM call failed: %s", exc)

        return {"category": "offensive", "confidence": 0.3}

    async def _generate_phases(
        self,
        objective: str,
        category: TaskCategory,
        target_description: str,
        available_tools: list[str],
    ) -> dict:
        """Generate phase plans for the objective."""
        phase_template = json.dumps(
            PHASE_TEMPLATES.get(category, PHASE_TEMPLATES[TaskCategory.OFFENSIVE]),
            indent=2,
        )

        prompt = PLAN_GENERATION_PROMPT.format(
            objective=objective,
            category=category.value,
            target_description=target_description,
            available_tools=", ".join(available_tools),
            phase_template=phase_template,
        )

        try:
            content = await self._llm_invoke(prompt)
            for match in re.finditer(r"\{[\s\S]*\}", content):
                try:
                    result = json.loads(match.group(0))
                    if "phases" in result:
                        return result
                except json.JSONDecodeError:
                    pass

            # Fallback: use default phase templates.
            logger.warning("Plan generation parse failed, using defaults")
            default_phases = PHASE_TEMPLATES.get(
                category, PHASE_TEMPLATES[TaskCategory.OFFENSIVE]
            )
            return {
                "phases": [
                    {
                        "name": p["name"],
                        "goal": p["description"],
                        "sub_tasks": [
                            f"Complete {p['name']} phase: {p['description']}"
                        ],
                        "required_tools": [],
                        "success_criteria": f"Phase {p['name']} complete",
                    }
                    for p in default_phases
                ],
                "expected_tools": [],
                "flag_pattern": None,
            }

        except Exception as exc:
            logger.error("Plan generation failed: %s", exc)
            return {"phases": [], "expected_tools": [], "flag_pattern": None}

    async def _llm_invoke(self, prompt: str) -> str:
        """Invoke the LLM with a prompt and return the text content."""
        if hasattr(self.llm, "ainvoke"):
            from langchain_core.messages import SystemMessage

            response = await self.llm.ainvoke([
                SystemMessage(content=prompt),
            ])
            return response.content if hasattr(response, "content") else str(response)
        elif hasattr(self.llm, "generate"):
            result = await self.llm.generate(prompt)
            return result if isinstance(result, str) else str(result)
        else:
            raise RuntimeError("LLM client has no recognized invoke method")


# ---------------------------------------------------------------------------
# Benchmark mode helper
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkTask:
    """A CTF-style benchmark task definition."""
    task_id: str
    objective: str
    target: str                           # IP, hostname, file path, etc.
    flag_format: str                      # Regex pattern for the flag
    hints: list[str] = field(default_factory=list)
    category: str = "puzzle"
    timeout_minutes: int = 60
    artifacts: list[str] = field(default_factory=list)  # Files provided

    @classmethod
    def from_json(cls, path: str) -> "BenchmarkTask":
        """Load a benchmark task from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            task_id=data.get("task_id", ""),
            objective=data.get("objective", ""),
            target=data.get("target", ""),
            flag_format=data.get("flag_format", r"FLAG\{[^}]+\}"),
            hints=data.get("hints", []),
            category=data.get("category", "puzzle"),
            timeout_minutes=data.get("timeout_minutes", 60),
            artifacts=data.get("artifacts", []),
        )


class BenchmarkRunner:
    """
    Autonomous benchmark runner for CTF-style challenges.

    Reads a task file, creates a plan, runs the OODA loop until:
        - A flag matching the pattern is found, or
        - The timeout is reached.

    Logs every step for reproducibility.
    """

    def __init__(
        self,
        *,
        planner: GeneralPlanner,
        ooda_loop=None,                  # OODALoop instance (set after creation)
        output_dir: str = "/tmp/redamon_benchmark",
    ):
        self.planner = planner
        self.ooda_loop = ooda_loop
        self.output_dir = output_dir

        import os as _os
        _os.makedirs(output_dir, exist_ok=True)

    async def run(self, task_path: str) -> dict:
        """
        Run a benchmark task autonomously.

        Args:
            task_path: Path to the benchmark JSON task file.

        Returns:
            dict with task_id, found_flag, steps_taken, elapsed_time, success.
        """
        task = BenchmarkTask.from_json(task_path)
        logger.info("=== BENCHMARK START: %s ===", task.task_id)
        logger.info("Objective: %s", task.objective)
        logger.info("Target: %s", task.target)
        logger.info("Flag format: %s", task.flag_format)

        start_time = time.time()
        steps = 0
        max_time = task.timeout_minutes * 60

        # Step 1: Create a plan.
        plan = await self.planner.create_plan(
            objective=task.objective,
            context={"target": task.target},
            benchmark_mode=True,
        )

        # Override flag pattern from task file.
        plan.flag_pattern = task.flag_format

        # Step 2: Run the OODA loop (if available) until flag found or timeout.
        if self.ooda_loop:
            result = await self.ooda_loop.run_until_flag(
                plan=plan,
                flag_pattern=task.flag_format,
                timeout=max_time,
            )
        else:
            # Fallback: simple loop with planner (no OODA loop available).
            result = {"found_flag": None, "steps": 0}

        elapsed = time.time() - start_time

        # Step 3: Write results.
        output = {
            "task_id": task.task_id,
            "objective": task.objective,
            "target": task.target,
            "found_flag": result.get("found_flag"),
            "steps_taken": result.get("steps", steps),
            "elapsed_seconds": elapsed,
            "success": result.get("found_flag") is not None,
            "plan_phases": [p.name for p in plan.phases],
        }

        output_path = f"{self.output_dir}/{task.task_id}_result.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        logger.info("=== BENCHMARK END: %s ===", task.task_id)
        logger.info("Result: %s", output)

        return output
