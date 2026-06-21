"""
Structured output parsers for penetration-testing tools.

Each parser function takes a raw tool-output string and returns a dict of
structured findings that can be merged into ``TargetInfo`` (ports, services,
technologies, vulnerabilities, credentials).  A parser never raises —
anything unexpected is silently skipped / logged at DEBUG level.

Usage
-----
    parsed = parse_tool_output("execute_nmap", nmap_output)
    if parsed:
        target_info = merge_parsed(target_info, parsed)
"""

from __future__ import annotations

import logging
from typing import Any

from ._base import _dedup, _info_findings, _iter_json_lines
from ._creds import parse_curl, parse_hydra, parse_playwright
from ._discovery import (
    parse_amass,
    parse_arjun,
    parse_ffuf,
    parse_gau,
    parse_jsluice,
    parse_katana,
    parse_subfinder,
)
from ._httpx import parse_httpx
from ._nmap import parse_masscan, parse_naabu, parse_nmap
from ._nuclei import parse_nuclei
from ._searchsploit import parse_searchsploit
from ._wpscan import parse_wpscan

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

PARSER_REGISTRY: dict[str, Any] = {
    "execute_nmap": "parse_nmap",
    "execute_naabu": "parse_naabu",
    "execute_httpx": "parse_httpx",
    "execute_subfinder": "parse_subfinder",
    "execute_amass": "parse_amass",
    "execute_nuclei": "parse_nuclei",
    "execute_wpscan": "parse_wpscan",
    "execute_katana": "parse_katana",
    "execute_gau": "parse_gau",
    "execute_ffuf": "parse_ffuf",
    "execute_arjun": "parse_arjun",
    "execute_jsluice": "parse_jsluice",
    "execute_hydra": "parse_hydra",
    "execute_masscan": "parse_masscan",
    "execute_curl": "parse_curl",
    "execute_playwright": "parse_playwright",
    "execute_searchsploit": "parse_searchsploit",
}


def parse_tool_output(tool_name: str, raw: str | None) -> dict[str, Any] | None:
    """Parse *raw* output from *tool_name* and return structured findings.

    Returns ``None`` when there is no output to parse or the tool name is
    unknown.  The returned dict contains the same keys as ``TargetInfo``:

    * ``ports``
    * ``services``
    * ``technologies``
    * ``vulnerabilities``
    * ``credentials``
    * ``findings`` (free-form list of dicts with ``type``, ``detail``, ``severity``)
    * ``subdomains``
    * ``endpoints``
    * ``parameters``
    """
    if not raw:
        return None
    handler_name = PARSER_REGISTRY.get(tool_name)
    if handler_name is None:
        return None
    handler = globals().get(handler_name)
    if handler is None:
        return None
    try:
        return handler(raw)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        logger.debug("output_parsers: %s failed on %s output", handler_name, tool_name, exc_info=True)
        return None


__all__ = [
    "_dedup",
    "_info_findings",
    "_iter_json_lines",
    "PARSER_REGISTRY",
    "parse_tool_output",
    "parse_nmap",
    "parse_naabu",
    "parse_masscan",
    "parse_httpx",
    "parse_subfinder",
    "parse_amass",
    "parse_nuclei",
    "parse_wpscan",
    "parse_katana",
    "parse_gau",
    "parse_ffuf",
    "parse_arjun",
    "parse_jsluice",
    "parse_hydra",
    "parse_curl",
    "parse_playwright",
    "parse_searchsploit",
]
