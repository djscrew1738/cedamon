"""Nuclei parser — template findings with severity and CVE."""

from __future__ import annotations

from typing import Any

from ._base import NUCLEI_FINDING, NUCLEI_SEVERITY, _dedup, _iter_json_lines


def parse_nuclei(raw: str) -> dict[str, Any]:
    vulnerabilities: list[str] = []
    findings: list[dict] = []
    technologies: list[str] = []

    for m in NUCLEI_FINDING.finditer(raw):
        severity = m.group(1).lower()
        template = m.group(2)
        url = m.group(3)
        cve = m.group(4)
        detail = f"[{template}] {url}"
        if cve:
            vulnerabilities.append(cve)
            detail += f" ({cve})"
        findings.append({"type": "nuclei_finding", "detail": detail, "severity": severity})

    for m in NUCLEI_SEVERITY.finditer(raw):
        pass

    for obj in _iter_json_lines(raw):
        info = obj.get("info", {})
        sev = info.get("severity", "info") if isinstance(info, dict) else "info"
        template_id = obj.get("template-id", "")
        matched = obj.get("matched-at", "")
        cve = ""
        if isinstance(info, dict):
            for tag in info.get("tags", []):
                if isinstance(tag, str) and tag.startswith("cve,"):
                    cve = tag[4:]
                    vulnerabilities.append(cve)
                    break
        findings.append({
            "type": "nuclei_finding",
            "detail": f"[{template_id}] {matched} ({cve})" if cve else f"[{template_id}] {matched}",
            "severity": sev,
        })

    return {
        "vulnerabilities": _dedup(vulnerabilities),
        "findings": findings,
        "technologies": _dedup(technologies),
    }
