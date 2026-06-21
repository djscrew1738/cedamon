"""HTTPx parser — title, technology, status detection."""

from __future__ import annotations

from typing import Any

from ._base import HTTPX_STATUS, HTTPX_TECH, HTTPX_TITLE, _dedup, _iter_json_lines


def parse_httpx(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    statuses: list[int] = []
    titles: list[str] = []
    findings: list[dict] = []

    for m in HTTPX_TECH.finditer(raw):
        techs = m.group(2).strip("[]").split(",")
        technologies.extend(t.strip() for t in techs)
    for m in HTTPX_TITLE.finditer(raw):
        titles.append(m.group(2))
    for m in HTTPX_STATUS.finditer(raw):
        try:
            statuses.append(int(m.group(1)))
        except ValueError:
            pass

    for obj in _iter_json_lines(raw):
        if "tech" in obj and isinstance(obj["tech"], list):
            technologies.extend(obj["tech"])
        if "title" in obj and obj["title"]:
            titles.append(obj["title"])
        if "webserver" in obj and obj["webserver"]:
            technologies.append(obj["webserver"])
        if "status_code" in obj:
            statuses.append(int(obj["status_code"]))

    return {
        "technologies": _dedup(technologies),
        "services": [],
        "findings": [{"type": "title", "detail": t, "severity": "info"} for t in _dedup(titles)],
        "endpoints": [],
    }
