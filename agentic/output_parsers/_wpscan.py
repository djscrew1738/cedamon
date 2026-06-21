"""WPScan parser — WordPress version, plugins, vulnerabilities, users."""

from __future__ import annotations

import re
from typing import Any

from ._base import WPSCAN_PLUGIN, WPSCAN_VERSION, WPSCAN_VULN, _dedup


def parse_wpscan(raw: str) -> dict[str, Any]:
    technologies: list[str] = ["wordpress"]
    vulns: list[str] = []
    findings: list[dict] = []
    credentials: list[dict] = []

    for m in WPSCAN_VERSION.finditer(raw):
        technologies.append(f"wordpress_{m.group(1)}")
        findings.append({"type": "wp_version", "detail": m.group(1), "severity": "info"})

    for m in WPSCAN_PLUGIN.finditer(raw):
        technologies.append(f"{m.group(1)}_{m.group(2)}")
        findings.append({"type": "wp_plugin", "detail": f"{m.group(1)} v{m.group(2)}", "severity": "info"})

    for m in WPSCAN_VULN.finditer(raw):
        desc = m.group(1).strip()
        cve = m.group(2)
        if cve:
            vulns.append(cve)
        findings.append({"type": "wp_vuln", "detail": desc, "severity": "medium"})

    _WPSCAN_USER_EXCLUDE = frozenset({
        "id", "login", "display_name", "slug", "user_email", "user_login",
        "user_nicename", "user_registered", "displayname", "user",
        "password", "email", "url", "role", "status", "name",
    })
    for m in re.finditer(r"\[\+\]\s*\|?\s*([a-z0-9_\-]+)\s*\|", raw, re.IGNORECASE):
        username = m.group(1).strip()
        if len(username) > 1 and username.lower() not in _WPSCAN_USER_EXCLUDE:
            credentials.append({"username": username, "type": "wp_user"})
            findings.append({"type": "wp_user", "detail": username, "severity": "medium"})

    return {
        "technologies": _dedup(technologies),
        "vulnerabilities": _dedup(vulns),
        "credentials": credentials,
        "findings": findings,
    }
