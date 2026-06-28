"""Verify that all tool metadata registries stay in sync.

Every MCP tool added to the canonical list (``tools.SYSTEM_MCP_TOOL_NAMES``)
should also appear in the metadata registries that derive from it — otherwise
the agent silently loses cost models, parser support, danger gating, or phase
filtering for that tool.

The canonical list is duplicated here to avoid importing ``tools.py`` (which
carries heavy Neo4j / LangChain dependencies unsuitable for unit tests).
Update ``CANONICAL_MCP_TOOLS`` when ``tools.SYSTEM_MCP_TOOL_NAMES`` changes.

Run with::

    uv run python3 -m pytest tests/test_tool_registry_consistency.py -v
"""

from __future__ import annotations

import os
import sys
import unittest

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

# ---------------------------------------------------------------------------
# Canonical list — mirrors tools.SYSTEM_MCP_TOOL_NAMES
# ---------------------------------------------------------------------------
CANONICAL_MCP_TOOLS: set[str] = {
    "execute_curl",
    "execute_naabu",
    "execute_masscan",
    "execute_httpx",
    "execute_subfinder",
    "execute_amass",
    "execute_arjun",
    "execute_ffuf",
    "execute_gau",
    "execute_jsluice",
    "execute_katana",
    "execute_wpscan",
    "execute_nmap",
    "execute_nuclei",
    "execute_searchsploit",
    "kali_shell",
    "kali_ssh",
    "execute_playwright",
    "execute_hydra",
    "metasploit_console",
    "msf_restart",
    "execute_code",
    "execute_exploit",
    "run_test_sequence",
    "cve_intel",
}

from output_parsers import PARSER_REGISTRY  # noqa: E402
from tool_cost_model import TOOL_COST_MODEL  # noqa: E402
from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS  # noqa: E402
from heuristics.engine import _FALLBACK_TOOLS, TOOL_CLUSTERS  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402

# TOOL_PHASE_MAP lives inside DEFAULT_AGENT_SETTINGS.
TOOL_PHASE_MAP: dict[str, list[str]] = DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"]

# Registries whose purpose is to carry *every* MCP tool.
# Tools intentionally absent from certain registries (documented reasons).
# Format: {registry_name: {tool_name: "reason"}}
_KNOWN_MISSING: dict[str, dict[str, str]] = {
    # These tools are intentionally excluded from specific registries.
    # Each entry documents the rationale so future readers know it's deliberate.
    "TOOL_COST_MODEL": {},
    "TOOL_PHASE_MAP": {},
    "TOOL_CLUSTERS": {},
    "_FALLBACK_TOOLS": {},
    # TOOL_REGISTRY includes fs_* and job_* tools not in the MCP canonical list.
    "TOOL_REGISTRY": {},
}


class TestToolRegistryConsistency(unittest.TestCase):
    maxDiff = None

    def _check_registry(self, registry: dict | frozenset | set,
                        registry_name: str):
        """Assert that every canonical tool appears in *registry*."""
        if isinstance(registry, (frozenset, set)):
            reg_names = registry
        else:
            reg_names = set(registry.keys())

        known_missing = _KNOWN_MISSING.get(registry_name, {})
        expected = set(CANONICAL_MCP_TOOLS) - set(known_missing.keys())
        missing = sorted(expected - reg_names)
        self.assertEqual(
            missing, [],
            f"{registry_name} is missing {len(missing)} canonical tool(s): "
            f"{missing}",
        )

    def test_tool_cost_model(self):
        self._check_registry(TOOL_COST_MODEL, "TOOL_COST_MODEL")

    def test_tool_phase_map(self):
        self._check_registry(TOOL_PHASE_MAP, "TOOL_PHASE_MAP")

    def test_tool_clusters(self):
        self._check_registry(TOOL_CLUSTERS, "TOOL_CLUSTERS")

    def test_fallback_tools(self):
        self._check_registry(_FALLBACK_TOOLS, "_FALLBACK_TOOLS")

    def test_tool_registry(self):
        """Every canonical MCP tool (except dynamically-injected) must have a
        TOOL_REGISTRY entry so the LLM sees it in the available-tools prompt."""
        self._check_registry(TOOL_REGISTRY, "TOOL_REGISTRY")

    def test_parser_registry(self):
        """Parser registry is a subset — only tools with structured output."""
        missing = sorted(
            set(PARSER_REGISTRY.keys()) - set(CANONICAL_MCP_TOOLS)
        )
        self.assertEqual(
            missing, [],
            f"PARSER_REGISTRY has tools unknown to canonical list: {missing}",
        )

    def test_dangerous_tools(self):
        """Dangerous tools are a subset — only tools with exploit capability."""
        missing = sorted(
            set(DANGEROUS_TOOLS) - set(CANONICAL_MCP_TOOLS)
        )
        self.assertEqual(
            missing, [],
            f"DANGEROUS_TOOLS has tools unknown to canonical list: {missing}",
        )

    def test_no_stale_known_missing_entries(self):
        """If a tool appears in CANONICAL_MCP_TOOLS, don't keep it in
        _KNOWN_MISSING for a universal registry — that's dead config."""
        for registry_name, missing_map in _KNOWN_MISSING.items():
            for tool_name in list(missing_map.keys()):
                if tool_name not in CANONICAL_MCP_TOOLS:
                    self.fail(
                        f"{tool_name} is listed in _KNOWN_MISSING[{registry_name!r}] "
                        f"but is no longer in the canonical list — remove the entry."
                    )


if __name__ == "__main__":
    unittest.main()
