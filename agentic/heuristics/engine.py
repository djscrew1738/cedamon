"""
HeuristicEngine — structured expert hacker playbooks.

Evaluates declarative rules against the current recon/attack context and returns
ranked tool recommendations.  The engine is intentionally deterministic and fast:
it replaces ad-hoc LLM reasoning with repeatable expert patterns.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from typing import Any, overload

from .rules import (
    HeuristicRule,
    RuleContext,
    PORT_RULES,
    TECH_RULES,
    TECH_KEYWORDS,
    COMBO_RULES,
    CVE_RULES,
    CVE_INTEL_RULES,
    PIPELINE_RULES,
    COVERAGE_RULES,
    PATH_BIAS_RULES,
    PORT_SERVICE_MAP,
)

logger = logging.getLogger(__name__)

# Known tool names are imported defensively so the engine can validate rules
# without creating a hard dependency on the tools module.
try:
    from tools import SYSTEM_MCP_TOOL_NAMES as _SYSTEM_MCP_TOOL_NAMES
    _KNOWN_TOOLS: set[str] = set(_SYSTEM_MCP_TOOL_NAMES)
except Exception:
    _KNOWN_TOOLS = set()

# Fallback tool list used when the tools module cannot be imported (e.g., tests).
_FALLBACK_TOOLS: set[str] = {
    "execute_curl", "execute_naabu", "execute_httpx", "execute_subfinder",
    "execute_amass", "execute_arjun", "execute_ffuf", "execute_gau",
    "execute_jsluice", "execute_katana", "execute_wpscan",
    "execute_nmap", "execute_nuclei", "execute_searchsploit",
    "kali_shell", "execute_playwright", "execute_hydra",
    "metasploit_console", "msf_restart", "execute_code", "cve_intel",
    "execute_masscan",
}

_ALLOWED_PHASES = {"informational", "exploitation", "post_exploitation"}
_ALLOWED_CLUSTERS = {"recon", "enum", "vuln_scan", "fuzz", "exploit", "other"}
# Template variables supported by _render_args.
_KNOWN_TEMPLATE_VARS = {
    "target", "host", "domain", "port", "bucket", "package",
    "user", "pass", "users", "lhost", "lport", "cve",
}
_TEMPLATE_VAR_RE = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")

# Tool clusters mirror those in tool_recommender for consistency.
TOOL_CLUSTERS: dict[str, str] = {
    "execute_nmap": "recon",
    "execute_naabu": "recon",
    "execute_masscan": "recon",
    "execute_subfinder": "recon",
    "execute_amass": "recon",
    "execute_httpx": "recon",
    "execute_gau": "recon",
    "execute_katana": "recon",
    "execute_curl": "recon",
    "execute_nuclei": "vuln_scan",
    "execute_wpscan": "vuln_scan",
    "execute_searchsploit": "vuln_scan",
    "execute_ffuf": "fuzz",
    "execute_arjun": "fuzz",
    "execute_jsluice": "enum",
    "execute_hydra": "exploit",
    "metasploit_console": "exploit",
    "kali_shell": "exploit",
}

_PROFILE_COST_MULTIPLIER = {"stealth": 1.8, "normal": 1.0, "aggressive": 0.6}


class HeuristicEngine:
    """Evaluate structured expert heuristics and return ranked tool recommendations."""

    def __init__(self, max_recommendations: int = 10, validate: bool = True):
        self.max_recommendations = max_recommendations
        if validate:
            self._validate_rules()

    @overload
    def recommend(self, ctx: RuleContext, trace: bool = False) -> list[HeuristicRule]: ...

    @overload
    def recommend(self, ctx: RuleContext, trace: bool = True) -> tuple[list[HeuristicRule], dict[str, list[dict[str, Any]]]]: ...

    def recommend(self, ctx: RuleContext, trace: bool = False):
        """Return ranked tool recommendations for the given context.

        Args:
            ctx: Rule context (technologies, ports, phase, etc.).
            trace: If True, also return a dict of fired rules grouped by category.

        Returns:
            List of recommendations, or (recommendations, trace_dict) when trace=True.
        """
        # Infer services from ports if not explicitly provided.
        ctx.services = list(dict.fromkeys(ctx.services + self._infer_services(ctx.ports)))

        results: list[HeuristicRule] = []
        seen: set[str] = set()
        trace_log: dict[str, list[dict[str, Any]]] = {}

        # Track best rule per tool_name so overlapping signals (port + tech + pipeline)
        # do not produce duplicate tool recommendations.
        best_by_tool: dict[str, HeuristicRule] = {}

        def add(rule: HeuristicRule) -> None:
            if rule.tool_name in ctx.already_run:
                return
            if rule.phase not in (ctx.phase, "informational"):
                return
            key = f"{rule.tool_name}:{rule.id}"
            if key in seen:
                return
            seen.add(key)
            existing = best_by_tool.get(rule.tool_name)
            if existing is None or rule.priority < existing.priority:
                best_by_tool[rule.tool_name] = rule
            elif rule.priority == existing.priority and not existing.suggested_args and rule.suggested_args:
                # Prefer the more specific recommendation when priorities tie.
                best_by_tool[rule.tool_name] = rule
            results.append(rule)
            if trace:
                trace_log.setdefault(rule.category, []).append({
                    "id": rule.id,
                    "tool_name": rule.tool_name,
                    "rationale": rule.rationale,
                    "priority": rule.priority,
                })

        # 1. CVE / exploit chaining first (highest priority when present).
        if ctx.has_cve():
            # 1a. Enrich CVEs with intelligence before attempting exploitation.
            for rule in CVE_INTEL_RULES:
                add(rule)
            # 1b. Existing exploit chain.
            for rule in CVE_RULES:
                add(rule)

        # 2. Port-based signals.
        for rule in PORT_RULES:
            port = self._rule_trigger_port(rule)
            if port is not None:
                if ctx.has_port(port):
                    add(rule)
            elif self._port_implies_web(ctx.ports) and rule.tool_name in ("execute_httpx", "execute_katana"):
                add(rule)

        # 3. Technology-based signals.
        techs = {t.lower() for t in ctx.technologies}
        for rule in TECH_RULES:
            # Derive the technology keyword from the rule id, with explicit overrides
            # for technologies that don't map cleanly (e.g., "asp.net").
            raw_keyword = rule.id.replace("tech-", "").split("-")[0]
            keywords = TECH_KEYWORDS.get(raw_keyword, raw_keyword)
            if isinstance(keywords, str):
                keywords = {keywords}
            if techs.intersection({k.lower() for k in keywords}):
                add(rule)

        # 4. Combination rules.
        for combo_techs, rules in COMBO_RULES:
            if combo_techs.issubset(techs):
                for rule in rules:
                    add(rule)

        # 5. Pipeline meta-recommendations.
        for pipeline in PIPELINE_RULES:
            try:
                if pipeline["trigger"](ctx):
                    for step in pipeline["steps"]:
                        if step["tool"] in ctx.already_run:
                            continue
                        if step["phase"] not in (ctx.phase, "informational"):
                            continue
                        add(HeuristicRule(
                            id=f"pipeline-{pipeline['id']}-{step['tool']}",
                            name=pipeline["id"],
                            category="pipeline",
                            priority=1,
                            tool_name=step["tool"],
                            rationale=step["rationale"],
                            phase=step["phase"],
                            task_cluster=TOOL_CLUSTERS.get(step["tool"], "recon"),
                            cost_score=0.4,
                        ))
            except Exception as exc:
                logger.warning("Pipeline trigger failed for %s: %s", pipeline.get("id"), exc)

        # 6. Coverage-gap rules.
        for evaluator in COVERAGE_RULES:
            try:
                for rule in evaluator(ctx):
                    add(rule)
            except Exception as exc:
                logger.warning("Coverage rule failed: %s", exc)

        # 7. Attack-path biases (additive nudges).
        for rule in PATH_BIAS_RULES:
            try:
                if rule.condition is not None and not rule.condition(ctx):
                    continue
                add(rule)
            except Exception as exc:
                logger.warning("Path-bias rule failed for %s: %s", rule.id, exc)

        # 8. Deduplicate by tool_name, keeping the highest-priority occurrence.
        deduped = list(best_by_tool.values())
        if not deduped:
            deduped = results

        # 8. Cost-aware re-rank and diversity.
        deduped = self._cost_aware_rerank(deduped, ctx.profile)
        deduped = self._ensure_cluster_diversity(deduped, self.max_recommendations)
        deduped.sort(key=lambda r: (r.priority, r.cost_score))
        final = deduped[: self.max_recommendations]

        # 9. Render template variables in suggested_args so recommendations are actionable.
        rendered = [
            HeuristicRule(
                id=r.id,
                name=r.name,
                category=r.category,
                priority=r.priority,
                tool_name=r.tool_name,
                rationale=r.rationale,
                phase=r.phase,
                task_cluster=r.task_cluster,
                cost_score=r.cost_score,
                suggested_args=self._render_args(r, ctx),
                follow_up=list(r.follow_up),
                condition=r.condition,
            )
            for r in final
        ]

        if trace:
            return rendered, trace_log
        return rendered

    @staticmethod
    def _infer_services(ports: list[int | str]) -> list[str]:
        services: list[str] = []
        for p in ports:
            try:
                service = PORT_SERVICE_MAP.get(int(p))
                if service:
                    services.append(service)
            except (ValueError, TypeError):
                continue
        return services

    @staticmethod
    def _port_implies_web(ports: list[int | str]) -> bool:
        web_ports = {80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 5000, 9090, 9306}
        for p in ports:
            try:
                if int(p) in web_ports:
                    return True
            except (ValueError, TypeError):
                continue
        return False

    @staticmethod
    def _rule_trigger_port(rule: HeuristicRule) -> int | None:
        """Heuristic: if the rationale mentions a port number, treat it as trigger."""
        import re
        match = re.search(r"port (\d+)", rule.rationale.lower())
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _cost_aware_rerank(recs: list[HeuristicRule], profile: str) -> list[HeuristicRule]:
        if not recs:
            return recs
        mult = _PROFILE_COST_MULTIPLIER.get(profile, 1.0)
        scored = []
        for rec in recs:
            base = 100.0 / max(rec.priority, 1)
            penalty = rec.cost_score * mult * 20
            scored.append((rec, base - penalty))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [s[0] for s in scored]

    @staticmethod
    def _ensure_cluster_diversity(recs: list[HeuristicRule], top_k: int) -> list[HeuristicRule]:
        if not recs:
            return recs
        by_cluster: dict[str, list[HeuristicRule]] = {}
        for rec in recs:
            cluster = rec.task_cluster or "other"
            by_cluster.setdefault(cluster, []).append(rec)

        diversified: list[HeuristicRule] = []
        clusters = sorted(by_cluster.keys(), key=lambda c: len(by_cluster[c]))
        max_len = max(len(v) for v in by_cluster.values())
        for i in range(max_len):
            for cluster in clusters:
                items = by_cluster[cluster]
                if i < len(items) and items[i] not in diversified:
                    diversified.append(items[i])
        for rec in recs:
            if rec not in diversified:
                diversified.append(rec)
        return diversified[:top_k]


    def _render_args(self, rule: HeuristicRule, ctx: RuleContext) -> dict[str, Any]:
        """Substitute template variables in rule.suggested_args using the context."""
        if not rule.suggested_args:
            return {}

        info = ctx.target_info or {}

        primary = info.get("primary_target") or ""
        target_type = info.get("target_type") or ""
        live_hosts = info.get("live_hosts") or []
        ports = [int(p) for p in ctx.ports if str(p).isdigit()]
        credentials = info.get("credentials") or []
        users = info.get("users") or []
        endpoints = info.get("endpoints") or []
        technologies = {t.lower() for t in ctx.technologies}

        first_user = ""
        first_pass = ""
        if credentials and isinstance(credentials[0], dict):
            first_user = credentials[0].get("user") or credentials[0].get("username") or ""
            first_pass = credentials[0].get("pass") or credentials[0].get("password") or ""

        cves = ctx.cves or []
        cve_value = ",".join(str(c) for c in cves) if cves else ""

        # Infer bucket from endpoints if present.
        bucket = ""
        for ep in endpoints:
            if isinstance(ep, str):
                m = re.search(r"([a-z0-9_-]+)\.s3\.amazonaws\.com", ep, re.I)
                if m:
                    bucket = m.group(1)
                    break
                m = re.search(r"([a-z0-9_-]+)\.blob\.core\.windows\.net", ep, re.I)
                if m:
                    bucket = m.group(1)
                    break
                m = re.search(r"([a-z0-9_-]+)\.storage\.googleapis\.com", ep, re.I)
                if m:
                    bucket = m.group(1)
                    break

        # Infer package name from technologies.
        package = ""
        for tech in technologies:
            if tech in ("npm", "maven", "pypi", "package-registry"):
                package = tech
                break

        # Build users temp file if needed.
        users_file = ""
        rendered_str = json.dumps(rule.suggested_args, default=str)
        if "{{users}}" in rendered_str and users:
            try:
                fd, users_file = tempfile.mkstemp(prefix="redamon_users_", suffix=".txt")
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(str(u) for u in users))
            except Exception as exc:
                logger.warning("Failed to write users temp file: %s", exc)

        def resolve(match: re.Match) -> str:
            name = match.group(1)
            if name == "target" or name == "host":
                return primary or (live_hosts[0] if live_hosts else "")
            if name == "domain":
                if target_type == "domain" and primary:
                    return primary
                # Try to derive a domain from primary target.
                if primary and "." in primary and not primary.replace(".", "").isdigit():
                    return primary
                return live_hosts[0] if live_hosts else primary
            if name == "port":
                return str(ports[0]) if ports else ""
            if name == "bucket":
                return bucket
            if name == "package":
                return package
            if name == "user":
                return first_user
            if name == "pass":
                return first_pass
            if name == "users":
                return users_file
            if name == "lhost":
                return info.get("lhost") or ""
            if name == "lport":
                return str(info.get("lport") or "4444")
            if name == "cve":
                return cve_value
            return match.group(0)

        def render(obj: Any) -> Any:
            if isinstance(obj, str):
                return _TEMPLATE_VAR_RE.sub(resolve, obj)
            if isinstance(obj, list):
                return [render(item) for item in obj]
            if isinstance(obj, dict):
                return {k: render(v) for k, v in obj.items()}
            return obj

        return render(dict(rule.suggested_args))

    def _validate_rules(self) -> None:
        """Log warnings for common rule-definition mistakes. Non-fatal."""
        seen_ids: set[str] = set()
        all_rules: list[HeuristicRule] = (
            list(PORT_RULES) + list(TECH_RULES) + list(CVE_RULES) +
            [r for _, rules in COMBO_RULES for r in rules] +
            list(PATH_BIAS_RULES)
        )
        known_tools = _KNOWN_TOOLS or _FALLBACK_TOOLS
        for rule in all_rules:
            if rule.id in seen_ids:
                logger.warning("Duplicate heuristic rule id: %s", rule.id)
            seen_ids.add(rule.id)
            if rule.tool_name not in known_tools:
                logger.warning("Rule %s references unknown tool %s", rule.id, rule.tool_name)
            if not (1 <= rule.priority <= 10):
                logger.warning("Rule %s has unusual priority %s", rule.id, rule.priority)
            if rule.phase not in _ALLOWED_PHASES:
                logger.warning("Rule %s has unknown phase %s", rule.id, rule.phase)
            if rule.task_cluster not in _ALLOWED_CLUSTERS:
                logger.warning("Rule %s has unknown task_cluster %s", rule.id, rule.task_cluster)
            # Check for unknown template variables in suggested_args.
            if rule.suggested_args:
                args_str = json.dumps(rule.suggested_args, default=str)
                for var in _TEMPLATE_VAR_RE.findall(args_str):
                    if var not in _KNOWN_TEMPLATE_VARS:
                        logger.warning("Rule %s uses unknown template variable {{%s}}", rule.id, var)

    def render_rule_args(self, rule: HeuristicRule, ctx: RuleContext) -> dict[str, Any]:
        """Public helper to render a single rule's suggested_args."""
        return self._render_args(rule, ctx)


def render_rule_args(rule: HeuristicRule, ctx: RuleContext) -> dict[str, Any]:
    """Render template variables in a rule's suggested_args using the context."""
    return HeuristicEngine(validate=False)._render_args(rule, ctx)


def build_context(
    technologies: list[str] | None = None,
    ports: list[int | str] | None = None,
    services: list[str] | None = None,
    cves: list[str] | None = None,
    target_info: dict[str, Any] | None = None,
    already_run: set[str] | None = None,
    phase: str = "informational",
    profile: str = "normal",
    attack_path_type: str = "",
    graph_client: Any = None,
) -> RuleContext:
    """Convenience helper to build a RuleContext."""
    info = target_info or {}
    # Coalesce common target_info fields if not explicitly provided.
    techs = list(technologies or info.get("technologies", []))
    port_list = list(ports or info.get("open_ports", []))
    svc_list = list(services or info.get("services", []))
    cve_list = list(cves or info.get("cves", []))
    return RuleContext(
        phase=phase,
        technologies=techs,
        ports=port_list,
        services=svc_list,
        cves=cve_list,
        target_info=info,
        already_run=set(already_run or []),
        profile=profile,
        attack_path_type=attack_path_type or info.get("attack_path_type", ""),
        graph_client=graph_client,
    )
