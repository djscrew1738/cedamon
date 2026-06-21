"""Discovery parsers — subdomains, endpoints, URLs, params."""

from __future__ import annotations

from typing import Any

from ._base import (
    AMASS_DOMAIN,
    ARJUN_PARAM,
    FFUF_STATUS,
    JSLUICE_ENDPOINT,
    SUBFINDER_DOMAIN,
    URL_PATTERN,
    _dedup,
    _info_findings,
    _iter_json_lines,
)


def parse_subfinder(raw: str) -> dict[str, Any]:
    subdomains: list[str] = []
    for m in SUBFINDER_DOMAIN.finditer(raw):
        subdomains.append(m.group(0).strip())
    for obj in _iter_json_lines(raw):
        if "host" in obj:
            subdomains.append(obj["host"])
    return {
        "subdomains": _dedup(subdomains),
        "findings": _info_findings(_dedup(subdomains), "subdomain"),
    }


def parse_amass(raw: str) -> dict[str, Any]:
    subdomains: list[str] = []
    for obj in _iter_json_lines(raw):
        if "name" in obj:
            subdomains.append(obj["name"])
    for line in raw.splitlines():
        line = line.strip()
        if AMASS_DOMAIN.match(line):
            subdomains.append(line)
    return {
        "subdomains": _dedup(subdomains),
        "findings": _info_findings(_dedup(subdomains), "subdomain"),
    }


def parse_katana(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    for m in URL_PATTERN.finditer(raw):
        endpoints.append(m.group(1))
    for obj in _iter_json_lines(raw):
        if "url" in obj:
            endpoints.append(obj["url"])
        elif "endpoint" in obj:
            endpoints.append(obj["endpoint"])
        elif "request-response" in obj and isinstance(obj["request-response"], list):
            for rr in obj["request-response"]:
                if isinstance(rr, dict) and "endpoint" in rr:
                    endpoints.append(rr["endpoint"])
    return {
        "endpoints": _dedup(endpoints),
        "findings": _info_findings(_dedup(endpoints), "endpoint", max_items=50),
    }


def parse_gau(raw: str) -> dict[str, Any]:
    urls: list[str] = []
    for m in URL_PATTERN.finditer(raw):
        urls.append(m.group(1))
    return {
        "endpoints": _dedup(urls),
        "findings": _info_findings(_dedup(urls), "url", max_items=50),
    }


def parse_ffuf(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    findings: list[dict] = []
    for m in FFUF_STATUS.finditer(raw):
        url = m.group(1)
        status = m.group(2)
        endpoints.append(url)
        findings.append({"type": "ffuf_finding", "detail": f"{url} (HTTP {status})", "severity": "info"})
    for obj in _iter_json_lines(raw):
        url = obj.get("url", "")
        status = obj.get("status", 0)
        if url:
            endpoints.append(url)
            findings.append({"type": "ffuf_finding", "detail": f"{url} (HTTP {status})", "severity": "info"})
    return {
        "endpoints": _dedup(endpoints),
        "findings": findings,
    }


def parse_arjun(raw: str) -> dict[str, Any]:
    params: list[str] = []
    for m in ARJUN_PARAM.finditer(raw):
        params.append(m.group(1).strip())
    for obj in _iter_json_lines(raw):
        if "param" in obj:
            params.append(str(obj["param"]))
        elif "parameter" in obj:
            params.append(str(obj["parameter"]))
    return {
        "parameters": _dedup(params),
        "findings": _info_findings(_dedup(params), "parameter"),
    }


def parse_jsluice(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    for m in JSLUICE_ENDPOINT.finditer(raw):
        endpoints.append(m.group(1).strip())
    return {
        "endpoints": _dedup(endpoints),
        "findings": _info_findings(_dedup(endpoints), "js_endpoint", max_items=50),
    }
