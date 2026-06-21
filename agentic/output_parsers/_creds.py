"""Credential and technology detection parsers — hydra, curl, playwright."""

from __future__ import annotations

import re
from typing import Any

from ._base import HYDRA_FOUND, _dedup


def parse_hydra(raw: str) -> dict[str, Any]:
    credentials: list[dict] = []
    findings: list[dict] = []
    for m in HYDRA_FOUND.finditer(raw):
        cred = {
            "service": m.group(2),
            "host": m.group(3),
            "username": m.group(4),
            "password": m.group(5),
        }
        credentials.append(cred)
        findings.append({
            "type": "credential",
            "detail": f"{m.group(4)}:{m.group(5)} @ {m.group(2)}",
            "severity": "critical",
        })
    return {"credentials": credentials, "findings": findings}


def parse_curl(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    m = re.search(r"(?i)^server:\s*([a-z/0-9.\-_]+)", raw, re.MULTILINE)
    if m:
        technologies.append(m.group(1).strip())
    m = re.search(r"(?i)content-type:\s*([a-z0-9/._\-]+)", raw)
    if m:
        technologies.append(m.group(1).strip())
    return {
        "technologies": _dedup(technologies),
        "findings": [],
    }


def parse_playwright(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    findings: list[dict] = []

    m = re.search(r"<title>([^<]+)</title>", raw, re.IGNORECASE)
    if m:
        findings.append({"type": "page_title", "detail": m.group(1).strip(), "severity": "info"})

    tech_patterns = [
        (r"wp-content|wp-includes", "wordpress"),
        (r"csrf-token|__VIEWSTATE", "asp.net"),
        (r"ng-app|ng-controller|angular", "angular"),
        (r"react-root|__NEXT_DATA__|nextjs", "react/nextjs"),
        (r"jquery\.js|jQuery", "jquery"),
        (r"bootstrap\.min\.css|bootstrap-", "bootstrap"),
        (r"api\.js|graphql", "graphql"),
    ]
    for pattern, tech in tech_patterns:
        if re.search(pattern, raw, re.IGNORECASE):
            technologies.append(tech)

    return {
        "technologies": _dedup(technologies),
        "findings": findings,
    }
