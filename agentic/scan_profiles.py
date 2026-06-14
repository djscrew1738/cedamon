"""
Scan profiles — Stealth / Normal / Aggressive.

Each profile adjusts tool arguments to trade off speed against
detectability.  The currently active profile is stored as a setting
(``SCAN_PROFILE``) and can be toggled mid-session.  Tools that accept
a ``--rate-limit`` / ``-rate`` / ``-t`` / ``--threads`` / ``-p`` (parallelism)
argument get their values tweaked accordingly.

Usage
-----
    from scan_profiles import apply_profile, SCAN_PROFILES

    tool_args = apply_profile("execute_nmap", {"args": "-sV 10.0.0.1"}, profile="stealth")
    # => {"args": "-sV 10.0.0.1 -T1 --max-rate 10 --min-rate 1"}
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

#: Default profile when none is explicitly set.
DEFAULT_PROFILE = "normal"

#: Per-tool argument modifiers for each profile.
#: ``add_args`` are flags appended verbatim to the ``args`` string.
#: ``timing_template`` is used for nmap's ``-T`` flag.
_PROFILES: dict[str, dict[str, Any]] = {
    "stealth": {
        "label": "Stealth — minimise detectability, slow",
        "timing": {
            "execute_nmap": {"timing_template": "-T1", "add_args": "--max-rate 10 --min-rate 1"},
            "execute_naabu": {"add_args": "-rate 10"},
            "execute_httpx": {"add_args": "-rate 5 -concurrency 5"},
            "execute_nuclei": {"add_args": "-rate-limit 10 -bulk-size 5"},
            "execute_subfinder": {"add_args": "-t 5"},
            "execute_amass": {"add_args": "-max-dns-queries 10"},
            "execute_ffuf": {"add_args": "-t 10 -rate 5"},
            "execute_katana": {"add_args": "-rate-limit 5 -concurrency 3"},
            "execute_gau": {"add_args": "-rate-limit 5"},
            "execute_arjun": {"add_args": "-t 5"},
            "execute_jsluice": {"add_args": ""},
            "execute_wpscan": {"add_args": "--stealthy"},
            "execute_hydra": {"add_args": "-t 4"},
            "execute_curl": {"add_args": "--limit-rate 10K"},
        },
    },
    "normal": {
        "label": "Normal — balanced speed and detectability",
        "timing": {
            "execute_nmap": {"timing_template": "-T4", "add_args": ""},
            "execute_naabu": {"add_args": "-rate 100"},
            "execute_httpx": {"add_args": "-rate 50 -concurrency 30"},
            "execute_nuclei": {"add_args": "-rate-limit 150 -bulk-size 25"},
            "execute_subfinder": {"add_args": "-t 50"},
            "execute_amass": {"add_args": "-max-dns-queries 100"},
            "execute_ffuf": {"add_args": "-t 40 -rate 50"},
            "execute_katana": {"add_args": "-rate-limit 30 -concurrency 10"},
            "execute_gau": {"add_args": "-rate-limit 30"},
            "execute_arjun": {"add_args": "-t 20"},
            "execute_jsluice": {"add_args": ""},
            "execute_wpscan": {"add_args": "--random-user-agent"},
            "execute_hydra": {"add_args": "-t 16"},
            "execute_curl": {"add_args": ""},
        },
    },
    "aggressive": {
        "label": "Aggressive — maximum speed, high detectability",
        "timing": {
            "execute_nmap": {"timing_template": "-T5", "add_args": "--max-rate 10000 --min-rate 100"},
            "execute_naabu": {"add_args": "-rate 1000"},
            "execute_httpx": {"add_args": "-rate 200 -concurrency 100"},
            "execute_nuclei": {"add_args": "-rate-limit 500 -bulk-size 50"},
            "execute_subfinder": {"add_args": "-t 200"},
            "execute_amass": {"add_args": "-max-dns-queries 500"},
            "execute_ffuf": {"add_args": "-t 200 -rate 500"},
            "execute_katana": {"add_args": "-rate-limit 100 -concurrency 30"},
            "execute_gau": {"add_args": "-rate-limit 100"},
            "execute_arjun": {"add_args": "-t 50"},
            "execute_jsluice": {"add_args": ""},
            "execute_wpscan": {"add_args": ""},
            "execute_hydra": {"add_args": "-t 64"},
            "execute_curl": {"add_args": ""},
        },
    },
}


def apply_profile(
    tool_name: str,
    tool_args: dict[str, Any],
    profile: str | None = None,
) -> dict[str, Any]:
    """Apply *profile* timing overrides to *tool_args*.

    If *profile* is ``None`` the default profile is used.
    If the tool has no overrides for the selected profile the args are
    returned unmodified.
    """
    profile = profile or DEFAULT_PROFILE
    pdef = _PROFILES.get(profile)
    if not pdef:
        return tool_args

    timing = pdef.get("timing", {})
    override = timing.get(tool_name)
    if not override:
        return tool_args

    result = dict(tool_args)  # shallow copy

    # nmap: replace or inject timing template
    if timing.get(tool_name, {}).get("timing_template") and tool_name == "execute_nmap":
        existing = result.get("args", "")
        # Strip any existing -T flag
        cleaned = _strip_nmap_timing(existing)
        result["args"] = f"{cleaned} {override['timing_template']} {override.get('add_args', '')}".strip()
    else:
        add = override.get("add_args", "")
        if add:
            existing = result.get("args", "")
            result["args"] = f"{existing} {add}".strip()

    return result


def _strip_nmap_timing(args: str) -> str:
    """Remove any ``-T<level>`` flag from *args*."""
    import re
    return re.sub(r"-T[0-5]", "", args).strip()


def get_available_profiles() -> dict[str, str]:
    """Return ``{profile_name: label}`` for all defined profiles."""
    return {k: v["label"] for k, v in _PROFILES.items()}


def profile_label(profile: str | None) -> str:
    """Return the human-readable label for *profile*."""
    p = profile or DEFAULT_PROFILE
    pdef = _PROFILES.get(p)
    return pdef["label"] if pdef else p
