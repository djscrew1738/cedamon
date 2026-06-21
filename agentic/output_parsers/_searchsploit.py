"""Searchsploit parser — JSON output with exploit metadata and CVE refs."""

from __future__ import annotations

import json
from typing import Any

from ._base import NMAP_CVE, _dedup


def parse_searchsploit(raw: str) -> dict[str, Any]:
    """Parse searchsploit ``-j`` JSON output."""
    exploits: list[dict] = []
    findings: list[dict] = []
    vulns: list[str] = []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"exploits": [], "findings": [], "vulnerabilities": []}

    results = data if isinstance(data, list) else data.get("RESULTS", [])
    if not isinstance(results, list):
        return {"exploits": [], "findings": [], "vulnerabilities": []}

    for entry in results:
        if not isinstance(entry, dict):
            continue
        edb_id = str(entry.get("EDB-ID") or entry.get("id", ""))
        title = str(entry.get("Title") or entry.get("title", ""))
        exploit_type = str(entry.get("Type") or entry.get("type", ""))
        platform = str(entry.get("Platform") or entry.get("platform", ""))
        path = str(entry.get("Path") or entry.get("path", ""))

        exploit = {
            "edb_id": edb_id,
            "title": title,
            "type": exploit_type,
            "platform": platform,
            "path": path,
        }
        exploits.append(exploit)

        for cve in NMAP_CVE.findall(title):
            vulns.append(cve)

        severity = "high" if exploit_type.lower() in ("remote", "dos") else "medium"
        findings.append({
            "type": "exploit",
            "detail": f"[{edb_id}] {title} ({platform}/{exploit_type})",
            "severity": severity,
            "edb_id": edb_id,
        })

    return {
        "exploits": exploits,
        "findings": findings,
        "vulnerabilities": _dedup(vulns),
    }
