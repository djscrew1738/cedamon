"""Shared helpers, regex patterns, and result types for output parsers."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any


def _iter_json_lines(raw: str) -> Iterator[dict[str, Any]]:
    """Yield dicts for each JSON-object line in *raw*."""
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, ValueError):
            pass


def _dedup(items: list) -> list:
    """Return *items* deduplicated, preserving insertion order."""
    return list(dict.fromkeys(items))


def _info_findings(
    items: list[str],
    type_name: str,
    max_items: int = 0,
) -> list[dict]:
    """Build info-severity findings from *items*."""
    if max_items > 0:
        items = items[:max_items]
    return [
        {"type": type_name, "detail": item, "severity": "info"}
        for item in items
    ]


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Matches any Nmap port state
NMAP_PORT = re.compile(
    r"^(\d+)/(tcp|udp)\s+(?:open(?:\|filtered)?|filtered)\s+(\S+)?\s*(.+)?$",
    re.MULTILINE,
)
NMAP_OS = re.compile(
    r"OS (?:details|guess|CPE):\s*(.+)$",
    re.MULTILINE,
)
NMAP_CVE = re.compile(
    r"\b(\d{4}-\d{4,7})\b",
)

HTTPX_TITLE = re.compile(r"\[(\d{3})\].*?title[=:]\s*([^\s,}\]]+)", re.IGNORECASE)
HTTPX_TECH = re.compile(r"\[(\d{3})\].*?(?:tech|framework)[=:]\s*\[?([^\]]+)\]?", re.IGNORECASE)
HTTPX_STATUS = re.compile(r"\[(\d{3})\]")

NUCLEI_FINDING = re.compile(
    r"\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\].*?(?:(\d{4}-\d{4,7}))?",
)
NUCLEI_SEVERITY = re.compile(r"\[(info|low|medium|high|critical)\]", re.IGNORECASE)

WPSCAN_VERSION = re.compile(
    r"\[\+\]\sWordPress\sversion[:\s]+([\d.]+)",
    re.IGNORECASE,
)
WPSCAN_PLUGIN = re.compile(
    r"\[\+\]\s+(.+?)\s+v([\d.]+)",
    re.IGNORECASE,
)
WPSCAN_VULN = re.compile(
    r"\[\!\]\s*(.+?)(?:\s*-\s*(\d{4}-\d{4,7}))?",
    re.IGNORECASE,
)

SUBFINDER_DOMAIN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$",
    re.MULTILINE,
)

NAABU_PORT = re.compile(
    r"Found\s+(\d+)\.",
)
MASSCAN_PORT = re.compile(
    r"discovered\s+port\s+(\d+)/",
)

AMASS_DOMAIN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}\s*$",
    re.MULTILINE,
)

URL_PATTERN = re.compile(r"(https?://[^\s\"'>]+)")

FFUF_STATUS = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)

ARJUN_PARAM = re.compile(
    r"\[\+\]\s*(?:Found|Parameter)\s*[:\s]+(\S+)",
    re.IGNORECASE,
)

JSLUICE_ENDPOINT = re.compile(
    r"(?:URL|Endpoint|Path)[:\s]+(.+)",
    re.IGNORECASE,
)

HYDRA_FOUND = re.compile(
    r"\[(\d+)\]\[([^\]]+)\]\s*host:\s*(\S+)\s+(?:login|user|username):\s*(\S+)\s+password:\s*(\S+)",
    re.IGNORECASE,
)
