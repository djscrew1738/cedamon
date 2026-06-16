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

import json
import logging
import re
from collections.abc import Iterator
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_json_lines(raw: str) -> Iterator[dict[str, Any]]:
    """Yield dicts for each JSON-object line in *raw*.

    Skips non-``{`` lines and lines that fail to parse as JSON so callers
    can mix text-format and JSON-line output without extra guards.
    """
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
    """Build info-severity findings from *items*.

    When *max_items* is > 0 only that many items are included (useful for
    high-volume findings such as discovered endpoints).
    """
    if max_items > 0:
        items = items[:max_items]
    return [
        {"type": type_name, "detail": item, "severity": "info"}
        for item in items
    ]


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Matches any Nmap port state: open, filtered, open|filtered, closed|filtered, ...
_NMAP_PORT = re.compile(
    r"^(\d+)/(tcp|udp)\s+(?:open(?:\|filtered)?|filtered)\s+(\S+)?\s*(.+)?$",
    re.MULTILINE,
)
_NMAP_OS = re.compile(
    r"OS (?:details|guess|CPE):\s*(.+)$",
    re.MULTILINE,
)
# CVE pattern with word boundaries to avoid matching date-like numbers
_NMAP_CVE = re.compile(
    r"\b(\d{4}-\d{4,7})\b",
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

# Shared URL regex used by both katana and gau parsers
_URL_PATTERN = re.compile(r"(https?://[^\s\"'>]+)")

_FFUF_STATUS = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)", re.MULTILINE)

_ARJUN_PARAM = re.compile(
    r"\[\+\]\s*(?:Found|Parameter)\s*[:\s]+(\S+)",
    re.IGNORECASE,
)

_JSLUICE_ENDPOINT = re.compile(
    r"(?:URL|Endpoint|Path)[:\s]+(.+)",
    re.IGNORECASE,
)

# Hydra output can vary by service module; support both common forms.
# Format 1: [22][ssh] host: 10.0.0.1 login: root password: p@ss
# Format 2: [80][http-post-form] host: 10.0.0.1   login: admin   password: secret
_HYDRA_FOUND = re.compile(
    r"\[(\d+)\]\[([^\]]+)\]\s*host:\s*(\S+)\s+(?:login|user|username):\s*(\S+)\s+password:\s*(\S+)",
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
        "services": _dedup(services),
        "technologies": _dedup(technologies),
        "vulnerabilities": _dedup(vulns),
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
    for obj in _iter_json_lines(raw):
        if "port" in obj:
            ports.append(int(obj["port"]))
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


def parse_subfinder(raw: str) -> dict[str, Any]:
    domains: list[str] = []
    for m in _SUBFINDER_DOMAIN.finditer(raw):
        domains.append(m.group(0).strip())
    # also handle JSON-line
    for obj in _iter_json_lines(raw):
        if "host" in obj:
            domains.append(obj["host"])
    return {
        "subdomains": _dedup(domains),
        "findings": _info_findings(_dedup(domains), "subdomain"),
    }


def parse_amass(raw: str) -> dict[str, Any]:
    domains: list[str] = []
    for obj in _iter_json_lines(raw):
        if "name" in obj:
            domains.append(obj["name"])
    for line in raw.splitlines():
        line = line.strip()
        if _AMASS_DOMAIN.match(line):
            domains.append(line)
    return {
        "subdomains": _dedup(domains),
        "findings": _info_findings(_dedup(domains), "subdomain"),
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
    for obj in _iter_json_lines(raw):
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

    return {
        "vulnerabilities": _dedup(vulns),
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

    # detect users from the user enumeration table
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


def parse_katana(raw: str) -> dict[str, Any]:
    endpoints: list[str] = []
    for m in _URL_PATTERN.finditer(raw):
        endpoints.append(m.group(1))
    # JSON-line format
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
    for m in _URL_PATTERN.finditer(raw):
        urls.append(m.group(1))
    return {
        "endpoints": _dedup(urls),
        "findings": _info_findings(_dedup(urls), "url", max_items=50),
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
    for m in _ARJUN_PARAM.finditer(raw):
        params.append(m.group(1).strip())
    # JSON output
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
    for m in _JSLUICE_ENDPOINT.finditer(raw):
        endpoints.append(m.group(1).strip())
    return {
        "endpoints": _dedup(endpoints),
        "findings": _info_findings(_dedup(endpoints), "js_endpoint", max_items=50),
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
    # Detect server header — works with curl -v, -i, and -sI output
    m = re.search(r"(?i)^server:\s*([a-z/0-9.\-_]+)", raw, re.MULTILINE)
    if m:
        technologies.append(m.group(1).strip())
    # Detect content-type
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
        "technologies": _dedup(technologies),
        "findings": findings,
    }


def parse_searchsploit(raw: str) -> dict[str, Any]:
    """Parse searchsploit ``-j`` JSON output.

    Returns exploits, findings with EDB-ID references, and linked CVEs when
    they appear in the title or description.
    """
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

        # Extract CVE references from title / description.
        for cve in _NMAP_CVE.findall(title):
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
