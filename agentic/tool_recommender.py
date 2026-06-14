"""
Technology-driven tool recommendation engine.

Backwards-compatible wrapper around ``heuristics.HeuristicEngine``.  It still
exports ``recommend_tools``, ``extract_already_run``, and
``format_recommendations`` so existing imports keep working, but the underlying
logic is now a structured, rule-based expert playbook instead of ad-hoc dict
lookups.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, overload

from heuristics import HeuristicEngine, build_context, format_recommendations as _format_recommendations, format_recommendation_trace as _format_recommendation_trace
from heuristics.rules import HeuristicRule

logger = logging.getLogger(__name__)


@dataclass
class ToolRecommendation:
    """A single recommended tool invocation."""

    tool_name: str
    priority: int  # 1 = highest
    rationale: str
    suggested_args: dict[str, Any] = field(default_factory=dict)
    follow_up: list[str] = field(default_factory=list)
    phase: str = "informational"
    task_cluster: str = ""
    cost_score: float = 0.5


_engine = HeuristicEngine(max_recommendations=10)


def _to_tool_recommendation(rule: HeuristicRule) -> ToolRecommendation:
    return ToolRecommendation(
        tool_name=rule.tool_name,
        priority=rule.priority,
        rationale=rule.rationale,
        suggested_args=dict(rule.suggested_args),
        follow_up=list(rule.follow_up),
        phase=rule.phase,
        task_cluster=rule.task_cluster,
        cost_score=rule.cost_score,
    )


@overload
def recommend_tools(
    technologies: list[str],
    already_run: set[str],
    phase: str = "informational",
    top_k: int = 10,
    ports: list[str | int] | None = None,
    target_info: dict[str, Any] | None = None,
    profile: str = "normal",
    attack_path_type: str = "",
    trace: bool = False,
    graph_client: Any = None,
) -> list[ToolRecommendation]: ...


@overload
def recommend_tools(
    technologies: list[str],
    already_run: set[str],
    phase: str = "informational",
    top_k: int = 10,
    ports: list[str | int] | None = None,
    target_info: dict[str, Any] | None = None,
    profile: str = "normal",
    attack_path_type: str = "",
    trace: bool = True,
    graph_client: Any = None,
) -> tuple[list[ToolRecommendation], dict[str, list[dict[str, Any]]]]: ...


def recommend_tools(
    technologies: list[str],
    already_run: set[str],
    phase: str = "informational",
    top_k: int = 10,
    ports: list[str | int] | None = None,
    target_info: dict[str, Any] | None = None,
    profile: str = "normal",
    attack_path_type: str = "",
    trace: bool = False,
    graph_client: Any = None,
):
    """Return recommended tools based on discovered context.

    Args:
        technologies: List of technology strings (e.g., "wordpress", "nginx").
        already_run: Set of tool names already executed in this session.
        phase: Current agent phase.
        top_k: Maximum recommendations to return.
        ports: List of open ports found so far.
        target_info: Full target_info dict for coverage-gap detection.
        profile: Scan profile ("stealth", "normal", "aggressive").
        attack_path_type: Classified attack path, used for path-bias nudges.
        trace: If True, also return a rule-activation trace dict.
        graph_client: Optional graph query adapter for graph-aware coverage gaps.

    Returns:
        List of ``ToolRecommendation``, or (recommendations, trace) when trace=True.
    """
    try:
        ctx = build_context(
            technologies=technologies,
            ports=ports or [],
            target_info=target_info,
            already_run=already_run,
            phase=phase,
            profile=profile,
            attack_path_type=attack_path_type,
            graph_client=graph_client,
        )
        _engine.max_recommendations = top_k
        result = _engine.recommend(ctx, trace=trace)
        if trace:
            rules, activation_trace = result
            return [_to_tool_recommendation(r) for r in rules], activation_trace
        rules = result
        return [_to_tool_recommendation(r) for r in rules]
    except Exception as exc:
        logger.warning("Heuristic recommendation failed: %s", exc, exc_info=True)
        if trace:
            return [], {}
        return []


def extract_already_run(execution_trace: list[dict]) -> set[str]:
    """Extract set of tool names already present in the execution trace."""
    return {
        step.get("tool_name", "")
        for step in execution_trace
        if step.get("tool_name")
    }


def json_dumps_safe(obj: Any, indent: int | None = None) -> str:
    """Safe JSON dump with fallback for non-serializable values."""
    try:
        return json.dumps(obj, indent=indent, default=str)
    except Exception:
        return str(obj)


def format_recommendations(recs: list[ToolRecommendation]) -> str:
    """Format recommendations as a compact text block for LLM context injection."""
    if not recs:
        return ""
    # Convert back to HeuristicRule for the shared formatter.
    rules = [
        HeuristicRule(
            id=f"legacy-{i}",
            name=r.tool_name,
            category="legacy",
            priority=r.priority,
            tool_name=r.tool_name,
            rationale=r.rationale,
            phase=r.phase,
            task_cluster=r.task_cluster,
            cost_score=r.cost_score,
            suggested_args=dict(r.suggested_args),
            follow_up=list(r.follow_up),
        )
        for i, r in enumerate(recs)
    ]
    return _format_recommendations(rules)


__all__ = [
    "ToolRecommendation",
    "recommend_tools",
    "extract_already_run",
    "format_recommendations",
]
