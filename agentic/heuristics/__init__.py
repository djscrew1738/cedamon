"""
Structured expert hacker heuristics for RedAmon.

Public API:
    from heuristics import HeuristicEngine, build_context, format_recommendations

    engine = HeuristicEngine(max_recommendations=10)
    ctx = build_context(
        technologies=["wordpress", "nginx"],
        ports=[80, 443],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    print(format_recommendations(recs))
"""

from typing import Any

from .engine import HeuristicEngine, build_context, render_rule_args
from .rules import HeuristicRule, RuleContext


def format_recommendations(recs: list[HeuristicRule]) -> str:
    """Format recommendations as a compact text block for LLM context injection."""
    if not recs:
        return ""
    lines = ["### Structured Expert Heuristic Recommendations"]
    for i, rec in enumerate(recs, 1):
        args_str = ""
        if rec.suggested_args:
            try:
                import json
                args_str = " args=" + json.dumps(rec.suggested_args, default=str)
            except Exception:
                args_str = " args=" + str(rec.suggested_args)
        cluster = f" [{rec.task_cluster}]" if rec.task_cluster else ""
        lines.append(f"  {i}. {rec.tool_name}{cluster} — {rec.rationale}{args_str}")
    return "\n".join(lines)


def format_recommendation_trace(trace: dict[str, list[dict[str, Any]]]) -> str:
    """Format a rule-activation trace for LLM context injection.

    The trace shows which heuristic categories fired and which rules within them
    were activated, helping explain why recommendations appear.
    """
    if not trace:
        return ""
    lines = ["### Heuristic Rule Activation Trace"]
    for category in sorted(trace.keys()):
        entries = trace[category]
        if not entries:
            continue
        lines.append(f"- {category}")
        for entry in entries:
            lines.append(
                f"  - {entry['tool_name']} ({entry['id']}, priority={entry['priority']}): {entry['rationale']}"
            )
    return "\n".join(lines)


__all__ = [
    "HeuristicEngine",
    "build_context",
    "format_recommendations",
    "format_recommendation_trace",
    "render_rule_args",
    "HeuristicRule",
    "RuleContext",
]
