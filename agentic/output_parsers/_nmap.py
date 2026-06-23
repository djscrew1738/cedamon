"""Nmap, naabu, and masscan port-scan parsers."""

from __future__ import annotations

import re
from typing import Any

from ._base import (
    MASSCAN_PORT,
    NAABU_PORT,
    NMAP_CVE,
    NMAP_OS,
    NMAP_PORT,
    _dedup,
    _iter_json_lines,
)


def parse_nmap(raw: str) -> dict[str, Any]:
    ports: list[int] = []
    services: list[str] = []
    technologies: list[str] = []
    vulns: list[str] = []
    findings: list[dict] = []

    for m in NMAP_PORT.finditer(raw):
        port = int(m.group(1))
        ports.append(port)
        svc = (m.group(3) or "").strip()
        if svc:
            services.append(svc)
        extra = (m.group(4) or "").strip()
        if extra:
            technologies.append(extra)

    os_match = NMAP_OS.search(raw)
    if os_match:
        technologies.append(os_match.group(1).strip())

    for cve in NMAP_CVE.findall(raw):
        vulns.append(cve)
        findings.append({"type": "vulnerability", "detail": cve, "severity": "unknown"})

    return {
        "ports": sorted(set(ports)),
        "services": _dedup(services),
        "technologies": _dedup(technologies),
        "vulnerabilities": _dedup(vulns),
        "findings": findings,
    }


def parse_naabu(raw: str) -> dict[str, Any]:
    """Also handles masscan plain-text output."""
    ports: list[int] = []
    for m in NAABU_PORT.finditer(raw):
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            pass
    for m in MASSCAN_PORT.finditer(raw):
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            pass
    for obj in _iter_json_lines(raw):
        p = obj.get("port")
        if isinstance(p, (int, str)):
            try:
                ports.append(int(p))
            except (ValueError, TypeError):
                pass
    return {
        "ports": sorted(set(ports)),
        "findings": [],
    }


def parse_masscan(raw: str) -> dict[str, Any]:
    """Parse masscan output into ports & findings.

    Handles multiple masscan output formats:
    - ``-oL`` (list format):  ``open tcp <port> <ip> <timestamp>``
    - JSON lines (``-oJ``):   ``{"ip": ..., "ports": [{"port": <n>, ...}]}``
    - Default text:           ``discovered port <port>/tcp on <ip> at ...``
    """
    ports: list[int] = []

    # -oL format: open tcp PORT IP TIMESTAMP
    for m in re.finditer(r"^open\s+tcp\s+(\d+)", raw, re.MULTILINE):
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            pass

    # default text format: discovered port PORT/protocol on ...
    for m in MASSCAN_PORT.finditer(raw):
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            pass

    # JSON lines format (-oJ)
    for obj in _iter_json_lines(raw):
        p = obj.get("port")
        if isinstance(p, (int, str)):
            try:
                ports.append(int(p))
            except (ValueError, TypeError):
                pass
        ports_list = obj.get("ports")
        if isinstance(ports_list, list):
            for entry in ports_list:
                if isinstance(entry, dict):
                    ep = entry.get("port")
                    if isinstance(ep, (int, str)):
                        try:
                            ports.append(int(ep))
                        except (ValueError, TypeError):
                            pass

    return {"ports": sorted(set(ports)), "findings": []}
