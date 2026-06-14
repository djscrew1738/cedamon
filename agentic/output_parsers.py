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

Hook this into the tool-execution pipeline (e.g. execute_tool_node or the
think node) so that *every* tool invocation automatically enriches the
shared target-intelligence model without relying on the LLM to manually
extract facts from raw text.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

_NMAP_PORT = re.compile(
    r"^(\d+)/(tcp|udp)\s+open\s+(\S+)?\s*(.+)?$",
    re.MULTILINE,
)
_NMAP_OS = re.compile(
    r"OS (?:details|guess|CPE):\s*(.+)$",
    re.MULTILINE,
)
_NMAP_CVE = re.compile(
    r"(\d{4}-\d{4,7})",
)

_HTTPX_TITLE = re.compile(r"\[(\d{3})\].*?title[=:]\s*([^\s,}\]]+)", re.IGNORECASE)
_HTTPX_TECH = re.compile(r"\[(\d{3})\].*?(?:tech|framework)[=:]\s*\[?([^\]]+)\]?", re.IGNORECASE)
_HTTPX_STATUS = re.compile(r"\[(\d{3})\]")

_NUCLEI_FINDING = re.compile(
    r"\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\].*?(?:(\d{4}-\d{4,7}))?",
)
_NUCLEI_SEVERITY = re.compile(r"\[(info|low|medium|high|critical)\]", re.IGNORECASE)

_WPSCAN_VERSION = re.compile(
    r"\[\+\]\sWordPress\sversion[:\s]+([\d.]+)",
    re.IGNORECASE,
)
_WPSCAN_PLUGIN = re.compile(
    r"\[\+\]\s+(.+?)\s+v([\d.]+)",
    re.IGNORECASE,
)
_WPSCAN_VULN = re.compile(
    r"\[\!\]\s*(.+?)(?:\s*-\s*(\d{4}-\d{4,7}))?",
    re.IGNORECASE,
)

_SUBFINDER_DOMAIN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$",
    re.MULTILINE,
)

_NAABU_PORT = re.compile(
    r"Found\s+(\d+)\.",  # typical naabu -json output
)

_AMASS_DOMAIN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}\s*$",
    re.MULTILINE,
)

_KATANA_URL = re.compile(
    r"(https?://[^\s\"'>]+)",
)

_GAU_URL = re.compile(r"(https?://[^\s\"'>]+)")

_FFUF_STATUS = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)

_ARJUN_PARAM = re.compile(
    r"\[\+\]\s*(?:Found|Parameter)\s*[:\s]+(.+)",
    re.IGNORECASE,
)

_JSLUICE_ENDPOINT = re.compile(
    r"(?:URL|Endpoint|Path)[:\s]+(.+)",
    re.IGNORECASE,
)

_HYDRA_FOUND = re.compile(
    r"\[(\d+)\]\[([^\]]+)\]\s*host:\s*(\S+)\s*(?:login|user):\s*(\S+)\s*password:\s*(\S+)",
    re.IGNORECASE,
)

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
    "execute_masscan": "parse_naabu",  # same format as naabu
    "execute_curl": "parse_curl",
    "execute_playwright": "parse_playwright",
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
    except Exception:
        logger.debug("output_parsers: %s failed on %s output", handler_name, tool_name, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

def parse_nmap(raw: str) -> dict[str, Any]:
    ports: list[int] = []
    services: list[str] = []
    technologies: list[str] = []
    vulns: list[str] = []
    findings: list[dict] = []

    for m in _NMAP_PORT.finditer(raw):
        port = int(m.group(1))
        ports.append(port)
        svc = (m.group(3) or "").strip()
        if svc:
            services.append(svc)
        # service version info
        extra = (m.group(4) or "").strip()
        if extra:
            technologies.append(extra)

    os_match = _NMAP_OS.search(raw)
    if os_match:
        technologies.append(os_match.group(1).strip())

    for cve in _NMAP_CVE.findall(raw):
        vulns.append(cve)
        findings.append({"type": "vulnerability", "detail": cve, "severity": "unknown"})

    return {
        "ports": sorted(set(ports)),
        "services": list(dict.fromkeys(services)),
        "technologies": list(dict.fromkeys(technologies)),
        "vulnerabilities": list(dict.fromkeys(vulns)),
        "findings": findings,
    }


def parse_naabu(raw: str) -> dict[str, Any]:
    """Also handles masscan (same output shape)."""
    ports: list[int] = []
    for m in _NAABU_PORT.finditer(raw):
        try:
            ports.append(int(m.group(1)))
        except ValueError:
            pass
    # also try JSON-line format
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if "port" in obj:
                ports.append(int(obj["port"]))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    return {"ports": sorted(set(ports)), "findings": []}


def parse_httpx(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    statuses: list[int] = []
    titles: list[str] = []
    findings: list[dict] = []

    for m in _HTTPX_TECH.finditer(raw):
        techs = m.group(2).strip("[]").split(",")
        technologies.extend(t.strip() for t in techs)
    for m in _HTTPX_TITLE.finditer(raw):
        titles.append(m.group(2))
    for m in _HTTPX_STATUS.finditer(raw):
        try:
            statuses.append(int(m.group(1)))
        except ValueError:
            pass

    # also try JSON-line format (httpx -json)
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if "tech" in obj and isinstance(obj["tech"], list):
                technologies.extend(obj["tech"])
            if "title" in obj and obj["title"]:
                titles.append(obj["title"])
            if "webserver" in obj and obj["webserver"]:
                technologies.append(obj["webserver"])
            if "status_code" in obj:
                statuses.append(int(obj["status_code"]))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    return {
        "technologies": list(dict.fromkeys(technologies)),
        "services": [],
        "findings": [
            {"type": "title", "detail": t, "severity": "info"} for t in dict.fromkeys(titles)
        ],
        "endpoints": [],
    }


def parse_subfinder(raw: str) -> dict[str, Any]:
    domains: list[str] = []
    for m in _SUBFINDER_DOMAIN.finditer(raw):
        domains.append(m.group(0).strip())
    # also handle JSON-line
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "host" in obj:
                    domains.append(obj["host"])
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    return {
        "subdomains": list(dict.fromkeys(domains)),
        "findings": [
            {"type": "subdomain", "detail": d, "severity": "info"} for d in dict.fromkeys(domains)
        ],
    }


def parse_amass(raw: str) -> dict[str, Any]:
    domains: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "name" in obj:
                    domains.append(obj["name"])
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        elif _AMASS_DOMAIN.match(line):
            domains.append(line)
    return {
        "subdomains": list(dict.fromkeys(domains)),
        "findings": [
            {"type": "subdomain", "detail": d, "severity": "info"} for d in dict.fromkeys(domains)
        ],
    }


def parse_nuclei(raw: str) -> dict[str, Any]:
    vulns: list[str] = []
    findings: list[dict] = []
    severities: dict[str, int] = {}

    for m in _NUCLEI_FINDING.finditer(raw):
        severity = m.group(1).lower()
        template = m.group(2)
        url = m.group(3)
        cve = m.group(4)
        severities[severity] = severities.get(severity, 0) + 1
        detail = f"[{severity}] {template} @ {url}"
        if cve:
            vulns.append(cve)
        findings.append({
            "type": "nuclei_finding",
            "detail": detail,
            "severity": severity,
            "template": template,
        })

    for m in _NUCLEI_SEVERITY.finditer(raw):
        sev = m.group(1).lower()
        severities[sev] = severities.get(sev, 0) + 1

    # also handle JSON-line format
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                sev = (obj.get("info", {}).get("severity") or obj.get("severity", "info")).lower()
                template = obj.get("template-id", "") or obj.get("templateID", "")
                matcher = obj.get("matcher-name", "")
                host = obj.get("host", "")
                detail = f"[{sev}] {template}/{matcher} @ {host}" if matcher else f"[{sev}] {template} @ {host}"
                extract = obj.get("extracted-results", [])
                cve = None
                if extract:
                    for val in extract:
                        if re.match(r"\d{4}-\d{4,7}", str(val)):
                            cve = str(val)
                            vulns.append(cve)
                            break
                findings.append({
                    "type": "nuclei_finding",
                    "detail": detail,
                    "severity": sev,
                    "template": template,
                })
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

    return {
        "vulnerabilities": list(dict.fromkeys(vulns)),
        "findings": findings,
    }


def parse_wpscan(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    vulns: list[str] = []
    credentials: list[dict] = []
    findings: list[dict] = []

    technologies.append("wordpress")

    m = _WPSCAN_VERSION.search(raw)
    if m:
        technologies.append(f"wordpress_{m.group(1)}")
        findings.append({"type": "wp_version", "detail": m.group(1), "severity": "info"})

    for m in _WPSCAN_PLUGIN.finditer(raw):
        technologies.append(f"{m.group(1)}_{m.group(2)}")
        findings.append({"type": "wp_plugin", "detail": f"{m.group(1)} v{m.group(2)}", "severity": "info"})

    for m in _WPSCAN_VULN.finditer(raw):
        desc = m.group(1).strip()
        cve = m.group(2)
        if cve:
            vulns.append(cve)
        findings.append({"type": "wp_vuln", "detail": desc, "severity": "medium"})

    # detect users
    for m in re.finditer(r"\[\+\]\s*\|?\s*([a-z0-9_\-]+)\s*\|", raw, re.IGNORECASE):
        username = m.group(1).strip()
        if username and len(username) > 1 and username not in ("Id", "Login", "Display Name", "Slug"):
            credentials.append({"username": username, "type": "wp_user"})
            findings.append({"type": "wp_user", "detail": username, "severity": "medium"})

    return {
        "technologies": list(dict.fromkeys(technologies)),
        "vulnerabilities": list(dict.fromkeys(vulns)),
        "credentials": credentials,
        "findings": findings,
    }


def parse_katana(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    for m in _KATANA_URL.finditer(raw):
        endpoints.append(m.group(1))
    # JSON-line format
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "url" in obj:
                    endpoints.append(obj["url"])
                elif "endpoint" in obj:
                    endpoints.append(obj["endpoint"])
                elif "request-response" in obj and isinstance(obj["request-response"], list):
                    for rr in obj["request-response"]:
                        if isinstance(rr, dict) and "endpoint" in rr:
                            endpoints.append(rr["endpoint"])
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    return {
        "endpoints": list(dict.fromkeys(endpoints)),
        "findings": [
            {"type": "endpoint", "detail": e, "severity": "info"}
            for e in list(dict.fromkeys(endpoints))[:50]
        ],
    }


def parse_gau(raw: str) -> dict[str, Any]:
    urls: list[str] = []
    for m in _GAU_URL.finditer(raw):
        urls.append(m.group(1))
    return {
        "endpoints": list(dict.fromkeys(urls)),
        "findings": [
            {"type": "url", "detail": u, "severity": "info"}
            for u in list(dict.fromkeys(urls))[:50]
        ],
    }


def parse_ffuf(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    findings: list[dict] = []
    for m in _FFUF_STATUS.finditer(raw):
        url = m.group(1)
        status = m.group(2)
        endpoints.append(url)
        findings.append({"type": "ffuf_finding", "detail": f"{url} (HTTP {status})", "severity": "info"})
    # JSON-line format
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                status = obj.get("status", 0)
                if url:
                    endpoints.append(url)
                    findings.append({"type": "ffuf_finding", "detail": f"{url} (HTTP {status})", "severity": "info"})
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    return {
        "endpoints": list(dict.fromkeys(endpoints)),
        "findings": findings,
    }


def parse_arjun(raw: str) -> dict[str, Any]:
    params: list[str] = []
    for m in _ARJUN_PARAM.finditer(raw):
        params.append(m.group(1).strip())
    # JSON output
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "param" in obj:
                    params.append(str(obj["param"]))
                elif "parameter" in obj:
                    params.append(str(obj["parameter"]))
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    return {
        "parameters": list(dict.fromkeys(params)),
        "findings": [
            {"type": "parameter", "detail": p, "severity": "info"}
            for p in list(dict.fromkeys(params))
        ],
    }


def parse_jsluice(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    for m in _JSLUICE_ENDPOINT.finditer(raw):
        endpoints.append(m.group(1).strip())
    return {
        "endpoints": list(dict.fromkeys(endpoints)),
        "findings": [
            {"type": "js_endpoint", "detail": e, "severity": "info"}
            for e in list(dict.fromkeys(endpoints))[:50]
        ],
    }


def parse_hydra(raw: str) -> dict[str, Any]:
    credentials: list[dict] = []
    findings: list[dict] = []
    for m in _HYDRA_FOUND.finditer(raw):
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
    # Detect server header
    m = re.search(r"(?i)^(?:<|server:\s*)([a-z/0-9.\-_]+)", raw)
    if m:
        technologies.append(m.group(1).strip())
    # Detect content-type
    m = re.search(r"(?i)content-type:\s*([a-z0-9/._\-]+)", raw)
    if m:
        technologies.append(m.group(1).strip())
    return {
        "technologies": list(dict.fromkeys(technologies)),
        "findings": [],
    }


def parse_playwright(raw: str) -> dict[str, Any]:
    technologies: list[str] = []
    findings: list[dict] = []

    # Extract title from HTML
    m = re.search(r"<title>([^<]+)</title>", raw, re.IGNORECASE)
    if m:
        findings.append({"type": "page_title", "detail": m.group(1).strip(), "severity": "info"})

    # Detect common technologies from page content
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
        "technologies": list(dict.fromkeys(technologies)),
        "findings": findings,
    }
