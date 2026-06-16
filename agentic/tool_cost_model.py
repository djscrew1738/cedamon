"""
Tool cost model — annotates each tool with estimated runtime and network cost.

Used to inject a cost column into the "Available Tools" section of the prompt
so the LLM can weigh trade-offs (e.g. "nmap is slow but precise; curl is fast
but narrow") instead of always reaching for the heaviest hammer.

Cost tiers
----------
* ``cost`` — relative resource intensity (1 = cheap, 10 = expensive)
* ``time_estimate`` — human-readable approximation
* ``parallel_safe`` — whether multiple instances can safely run concurrently
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Cost annotations per tool
# ---------------------------------------------------------------------------

TOOL_COST_MODEL: dict[str, dict[str, Any]] = {
    # ---- Recon / fast ----
    "execute_curl": {
        "cost": 1,
        "time_estimate": "< 2s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_naabu": {
        "cost": 2,
        "time_estimate": "5-30s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_httpx": {
        "cost": 2,
        "time_estimate": "5-30s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_subfinder": {
        "cost": 3,
        "time_estimate": "10-60s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_amass": {
        "cost": 5,
        "time_estimate": "30-300s",
        "parallel_safe": False,  # dns heavy
        "category": "recon",
    },
    "execute_nmap": {
        "cost": 4,
        "time_estimate": "15-120s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_masscan": {
        "cost": 2,
        "time_estimate": "5-20s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_gau": {
        "cost": 3,
        "time_estimate": "10-60s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_katana": {
        "cost": 4,
        "time_estimate": "10-120s",
        "parallel_safe": False,  # crawls the same target
        "category": "recon",
    },
    "execute_jsluice": {
        "cost": 1,
        "time_estimate": "2-10s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_arjun": {
        "cost": 4,
        "time_estimate": "20-120s",
        "parallel_safe": True,
        "category": "recon",
    },
    "execute_ffuf": {
        "cost": 4,
        "time_estimate": "20-180s",
        "parallel_safe": False,  # fuzz same endpoint
        "category": "recon",
    },

    # ---- Vulnerability scanning ----
    "execute_nuclei": {
        "cost": 5,
        "time_estimate": "30-300s",
        "parallel_safe": True,
        "category": "vuln_scan",
    },
    "execute_wpscan": {
        "cost": 4,
        "time_estimate": "30-180s",
        "parallel_safe": False,  # single WP target
        "category": "vuln_scan",
    },
    "cve_intel": {
        "cost": 1,
        "time_estimate": "< 3s",
        "parallel_safe": True,
        "category": "intel",
    },

    # ---- Exploitation ----
    "execute_hydra": {
        "cost": 6,
        "time_estimate": "60-600s",
        "parallel_safe": False,  # single target
        "category": "exploit",
    },
    "metasploit_console": {
        "cost": 4,
        "time_estimate": "10-120s",
        "parallel_safe": False,  # single console
        "category": "exploit",
    },
    "kali_shell": {
        "cost": 3,
        "time_estimate": "5-60s",
        "parallel_safe": False,  # stateful
        "category": "exploit",
    },
    "execute_code": {
        "cost": 2,
        "time_estimate": "2-30s",
        "parallel_safe": True,
        "category": "exploit",
    },
    "execute_playwright": {
        "cost": 3,
        "time_estimate": "5-30s",
        "parallel_safe": False,  # browser context
        "category": "exploit",
    },
    "execute_searchsploit": {
        "cost": 2,
        "time_estimate": "2-10s",
        "parallel_safe": True,
        "category": "vuln_scan",
    },

    # ---- Intelligence ----
    "query_graph": {
        "cost": 1,
        "time_estimate": "< 2s",
        "parallel_safe": True,
        "category": "intel",
    },
    "web_search": {
        "cost": 2,
        "time_estimate": "3-10s",
        "parallel_safe": True,
        "category": "intel",
    },
    "shodan": {
        "cost": 2,
        "time_estimate": "2-5s",
        "parallel_safe": True,
        "category": "intel",
    },
    "google_dork": {
        "cost": 2,
        "time_estimate": "5-15s",
        "parallel_safe": True,
        "category": "intel",
    },
    "tradecraft_lookup": {
        "cost": 1,
        "time_estimate": "< 3s",
        "parallel_safe": True,
        "category": "intel",
    },
}


def tool_cost(tool_name: str) -> dict[str, Any]:
    """Return the cost annotation for *tool_name*, or a default."""
    return TOOL_COST_MODEL.get(tool_name, {
        "cost": 5,
        "time_estimate": "unknown",
        "parallel_safe": False,
        "category": "unknown",
    })


def cost_column(tool_names: list[str]) -> str:
    """Build a ``# cost`` comment column for `tool_name_enum`.

    Returns something like::

        # Cost column:  (1=cheap … 10=expensive)
        #   execute_nmap — cost 4, ~15-120s, parallel-safe
        #   execute_curl — cost 1, < 2s, parallel-safe
    """
    lines = ["# Cost column:  (1 = cheap … 10 = expensive)"]
    for name in tool_names:
        info = tool_cost(name)
        ps = "parallel-safe" if info["parallel_safe"] else "serial"
        lines.append(
            f"#   {name} — cost {info['cost']}, ~{info['time_estimate']}, {ps}"
        )
    return "\n".join(lines)
