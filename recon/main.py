#!/usr/bin/env python3
"""
RedAmon - Main Reconnaissance Controller
=========================================
Orchestrates all OSINT reconnaissance modules:
1. WHOIS lookup (integrated into domain recon JSON)
2. Subdomain discovery & DNS resolution
3. Port scanning (fast, lightweight)
4. HTTP probing & technology detection
5. Resource enumeration (endpoint discovery & classification)
6. Vulnerability scanning + MITRE CWE/CAPEC enrichment

Pipeline: domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan

Note: vuln_scan automatically includes MITRE CWE/CAPEC enrichment for all CVEs.

Run this file to execute the full recon pipeline.
"""

import sys
import json
import copy
from pathlib import Path
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path for imports (needed for graph_db, utils modules)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import settings from project_settings (fetches from API or falls back to params.py)
from recon.project_settings import get_settings

# Runtime helpers: orphan cleanup, disk checks, monitored subprocess execution
from recon.helpers.scan_runtime import (
    cleanup_orphan_containers,
    check_disk_space,
)

# Scan quality improvements (v4.16)
from recon.helpers import (
    # Pre-scan network health check
    run_pre_scan_health_check,
    NetworkHealthReport,
    # Checkpoint/resumability
    ScanCheckpoint,
    should_resume_scan,
    # DNS pre-validation
    prevalidate_subdomains,
    filter_dns_stale,
    # Target prioritization
    prioritize_from_http_probe,
    print_priority_summary,
    # Template selection (service-aware)
    select_templates_from_http_probe,
    print_template_selection_summary,
    # Finding deduplication
    deduplicate_scan_results,
    # Coverage tracking
    get_coverage_tracker,
    reset_coverage_tracker,
    ScanStatus,
    # CVE version correlation
    correlate_vulns_with_versions,
)

# Settings are loaded lazily in main() to avoid blocking the module import with
# synchronous HTTP calls to the webapp API. This keeps container cold-start fast
# and makes the module safe to import in tests/other tooling.
_settings = None

# Module-level placeholders; populated by _load_settings() at pipeline start.
TARGET_DOMAIN = None
SUBDOMAIN_LIST = None
USE_TOR_FOR_RECON = None
USE_BRUTEFORCE_FOR_SUBDOMAINS = None
SCAN_MODULES = None
UPDATE_GRAPH_DB = None
USER_ID = None
PROJECT_ID = None
VERIFY_DOMAIN_OWNERSHIP = None
OWNERSHIP_TOKEN = None
OWNERSHIP_TXT_PREFIX = None
IP_MODE = None
TARGET_IPS = None


def _load_settings():
    """Load project settings and populate module-level globals."""
    global _settings, TARGET_DOMAIN, SUBDOMAIN_LIST, USE_TOR_FOR_RECON
    global USE_BRUTEFORCE_FOR_SUBDOMAINS, SCAN_MODULES, UPDATE_GRAPH_DB
    global USER_ID, PROJECT_ID, VERIFY_DOMAIN_OWNERSHIP, OWNERSHIP_TOKEN
    global OWNERSHIP_TXT_PREFIX, IP_MODE, TARGET_IPS

    _settings = get_settings()
    TARGET_DOMAIN = _settings['TARGET_DOMAIN']
    SUBDOMAIN_LIST = _settings['SUBDOMAIN_LIST']
    USE_TOR_FOR_RECON = _settings['USE_TOR_FOR_RECON']
    USE_BRUTEFORCE_FOR_SUBDOMAINS = _settings['USE_BRUTEFORCE_FOR_SUBDOMAINS']
    SCAN_MODULES = _settings['SCAN_MODULES']
    UPDATE_GRAPH_DB = _settings['UPDATE_GRAPH_DB']
    USER_ID = _settings['USER_ID']
    PROJECT_ID = _settings['PROJECT_ID']
    VERIFY_DOMAIN_OWNERSHIP = _settings['VERIFY_DOMAIN_OWNERSHIP']
    OWNERSHIP_TOKEN = _settings['OWNERSHIP_TOKEN']
    OWNERSHIP_TXT_PREFIX = _settings['OWNERSHIP_TXT_PREFIX']
    IP_MODE = _settings['IP_MODE']
    TARGET_IPS = _settings['TARGET_IPS']

# Import recon modules
from recon.main_recon_modules.whois_recon import whois_lookup
from recon.main_recon_modules.domain_recon import discover_subdomains, verify_domain_ownership, reverse_dns_lookup
from recon.main_recon_modules.port_scan import run_port_scan, run_port_scan_isolated
from recon.main_recon_modules.masscan_scan import run_masscan_scan, run_masscan_scan_isolated
from recon.main_recon_modules.http_probe import run_http_probe
from recon.main_recon_modules.resource_enum import run_resource_enum
from recon.main_recon_modules.ai_surface_recon import run_ai_surface_recon
from recon.main_recon_modules.vuln_scan import run_vuln_scan
from recon.main_recon_modules.add_mitre import run_mitre_enrichment

# Output directory
OUTPUT_DIR = Path(__file__).parent / "output"

# ---------------------------------------------------------------------------
# Background Graph DB update helper
# ---------------------------------------------------------------------------
# Serialized via max_workers=1 so Neo4j never gets concurrent writes,
# but the main pipeline thread is not blocked.
# Re-created per pipeline run via _graph_reset() to be safe across calls.
_graph_executor = None
_graph_futures = []


def _graph_reset():
    """Create a fresh background executor for a new pipeline run."""
    global _graph_executor, _graph_futures
    _graph_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="graph-db")
    _graph_futures = []


def _graph_update_bg(update_method_name: str, combined_result: dict,
                     user_id: str, project_id: str):
    """Submit a graph DB update to the background thread.

    Deep-copies inside the executor thread so the main thread is never
    blocked by a large dict copy.
    """
    if not UPDATE_GRAPH_DB or _graph_executor is None:
        return

    def _do_update():
        try:
            # Deep-copy inside the executor thread so the main pipeline
            # thread can keep mutating combined_result without waiting.
            snapshot = copy.deepcopy(combined_result)
            from graph_db import Neo4jClient
            with Neo4jClient() as client:
                if client.verify_connection():
                    method = getattr(client, update_method_name)
                    method(snapshot, user_id, project_id)
                    print(f"[graph-db] {update_method_name} complete")
                else:
                    print(f"[!][graph-db] Neo4j not reachable — skipped {update_method_name}")
        except Exception as e:
            print(f"[!][graph-db] Background graph update ({update_method_name}) failed: {e}")

    future = _graph_executor.submit(_do_update)
    _graph_futures.append(future)


def _graph_wait_all():
    """Wait for every queued graph DB update to finish, then tear down the executor."""
    global _graph_executor
    if _graph_executor is None:
        return
    _graph_executor.shutdown(wait=True)
    for f in _graph_futures:
        exc = f.exception()
        if exc:
            print(f"[!][graph-db] Graph update error: {exc}")
    _graph_executor = None


def _is_roe_excluded(host: str, excluded_list: list) -> bool:
    """Check if a host (IP or domain) matches any RoE exclusion entry.

    Supports:
    - Exact IP/domain match: "10.0.0.5" matches "10.0.0.5"
    - CIDR match: "10.0.0.5" matches "10.0.0.0/24"
    - Subdomain match: "payments.example.com" matches "payments.example.com"
    """
    import ipaddress as _ipaddress

    for entry in excluded_list:
        entry = entry.strip()
        if not entry:
            continue
        # Exact string match (works for both IPs and domains)
        if host == entry:
            return True
        # CIDR match: check if host IP falls within an excluded network
        if '/' in entry:
            try:
                network = _ipaddress.ip_network(entry, strict=False)
                try:
                    if _ipaddress.ip_address(host) in network:
                        return True
                except ValueError:
                    pass  # host is a domain, not an IP — skip CIDR check
            except ValueError:
                pass  # invalid CIDR in exclusion list
        # Domain suffix match: "payments.example.com" should be excluded
        # if the exclusion is a parent domain pattern
        elif host.endswith('.' + entry):
            return True
    return False


def _filter_roe_excluded(hosts: list, settings: dict, label: str = "host") -> list:
    """Filter a list of hosts/IPs against ROE_EXCLUDED_HOSTS. Returns the filtered list."""
    roe_excluded = settings.get('ROE_EXCLUDED_HOSTS', [])
    if not settings.get('ROE_ENABLED', False) or not roe_excluded:
        return hosts
    before_count = len(hosts)
    filtered = [h for h in hosts if not _is_roe_excluded(h, roe_excluded)]
    removed = before_count - len(filtered)
    if removed:
        print(f"[RoE] Excluded {removed} {label}(s) per Rules of Engagement")
    return filtered


def _check_roe_time_window(settings: dict, _now=None) -> tuple[bool, str]:
    """Check if current time is within the RoE-allowed window.

    Returns (allowed, reason_message). Always returns (True, "") if
    RoE or its time window is disabled. Pass _now for testing.
    """
    if not settings.get('ROE_ENABLED') or not settings.get('ROE_TIME_WINDOW_ENABLED'):
        return True, ""

    from datetime import datetime as _dt
    import zoneinfo as _zi

    tz_name = settings.get('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
    try:
        tz = _zi.ZoneInfo(tz_name)
    except Exception:
        print(f"[RoE] Unknown timezone '{tz_name}', falling back to UTC")
        tz = _zi.ZoneInfo('UTC')

    now = _now or _dt.now(tz)

    # Check day of week
    allowed_days = [d.lower() for d in settings.get('ROE_TIME_WINDOW_DAYS', [])]
    current_day = now.strftime('%A').lower()
    if current_day not in allowed_days:
        return False, f"Current day ({current_day}) is not in allowed days: {', '.join(allowed_days)} ({tz_name})"

    # Check time range
    start = settings.get('ROE_TIME_WINDOW_START_TIME', '09:00')
    end = settings.get('ROE_TIME_WINDOW_END_TIME', '18:00')
    current_time = now.strftime('%H:%M')
    if current_time < start or current_time >= end:
        return False, f"Current time ({current_time} {tz_name}) is outside allowed window ({start}\u2013{end})"

    return True, ""


def _merge_external_domain(aggregated: dict, entry: dict):
    """Merge a single external domain entry into the aggregated dict."""
    domain = entry.get("domain", "").strip().lower()
    if not domain:
        return
    if domain not in aggregated:
        aggregated[domain] = {
            "domain": domain, "sources": [], "redirect_from_urls": [],
            "redirect_to_urls": [], "status_codes_seen": [], "titles_seen": [],
            "servers_seen": [], "ips_seen": [], "countries_seen": [], "times_seen": 0,
        }
    rec = aggregated[domain]
    rec["times_seen"] += 1
    for val, key in [
        (entry.get("source"), "sources"),
        (entry.get("url"), "redirect_to_urls"),
        (entry.get("redirect_from_url"), "redirect_from_urls"),
        (entry.get("title"), "titles_seen"),
        (entry.get("server"), "servers_seen"),
        (entry.get("ip"), "ips_seen"),
        (entry.get("country"), "countries_seen"),
    ]:
        if val and val not in rec[key]:
            rec[key].append(val)
    sc = entry.get("status_code")
    if sc is not None:
        sc_str = str(sc)
        if sc_str not in rec["status_codes_seen"]:
            rec["status_codes_seen"].append(sc_str)


def _aggregate_external_domains(combined_result: dict) -> list:
    """Aggregate external domains from all pipeline sources."""
    aggregated = {}
    for e in combined_result.get("http_probe", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("urlscan", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("resource_enum", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("domain_discovery_external_domains", []):
        _merge_external_domain(aggregated, e)
    return list(aggregated.values())


def should_skip_active_scans(recon_data: dict) -> tuple:
    """
    Check if active scanning modules (resource_enum, vuln_scan) should be skipped.
    
    These modules require live targets to work with. If http_probe found no live URLs,
    there's nothing to crawl or scan.
    
    Args:
        recon_data: Current reconnaissance data
        
    Returns:
        Tuple of (should_skip: bool, reason: str)
    """
    http_probe_data = recon_data.get('http_probe', {})
    http_summary = http_probe_data.get('summary', {})
    
    live_urls = http_summary.get('live_urls', 0)
    total_hosts = http_summary.get('total_hosts', 0)
    
    # Check if http_probe ran but found nothing
    if 'http_probe' in recon_data:
        if live_urls == 0 and total_hosts == 0:
            # Also check by_url to be sure
            by_url = http_probe_data.get('by_url', {})
            if len(by_url) == 0:
                return True, "No live URLs found by http_probe - nothing to scan"
    
    return False, ""


def _auto_enable_contextual_modules(settings: dict, combined_result: dict) -> bool:
    """
    Automatically enable contextual scanning modules when live attack surface
    is discovered. This prevents scans that find endpoints from returning no
    vulnerability / JS / GraphQL data just because those toggles were off.

    Gated by AUTO_ENABLE_CONTEXTUAL_MODULES (default True). Respects explicit
    user disables — if a user turns that master switch off, no auto-enabling
    happens.
    """
    if not settings.get('AUTO_ENABLE_CONTEXTUAL_MODULES', True):
        return False

    http_summary = combined_result.get('http_probe', {}).get('summary', {})
    resource_summary = combined_result.get('resource_enum', {}).get('summary', {})
    live_urls = http_summary.get('live_urls', 0)
    endpoints = resource_summary.get('total_endpoints', 0)

    if live_urls == 0 and endpoints == 0:
        return False

    changed = False
    if not settings.get('JS_RECON_ENABLED', False):
        settings['JS_RECON_ENABLED'] = True
        print(f"[auto-enable] Live attack surface found ({live_urls} URLs, {endpoints} endpoints) — enabling JS Recon")
        changed = True

    if not settings.get('GRAPHQL_SECURITY_ENABLED', False):
        settings['GRAPHQL_SECURITY_ENABLED'] = True
        print(f"[auto-enable] Live attack surface found ({live_urls} URLs, {endpoints} endpoints) — enabling GraphQL Security Scan")
        changed = True

    global SCAN_MODULES
    if 'vuln_scan' not in SCAN_MODULES:
        SCAN_MODULES = list(SCAN_MODULES) + ['vuln_scan']
        settings['SCAN_MODULES'] = SCAN_MODULES
        print(f"[auto-enable] Live attack surface found ({live_urls} URLs, {endpoints} endpoints) — adding vuln_scan to SCAN_MODULES")
        changed = True

    return changed


def parse_target(target: str, subdomain_list: list = None) -> dict:
    """
    Parse target domain and determine scan mode based on SUBDOMAIN_LIST.

    Args:
        target: Root domain (e.g., "example.com", "vulnweb.com")
                TARGET_DOMAIN in params.py must always be a root domain.
        subdomain_list: List of subdomain prefixes to filter (e.g., ["testphp.", "www."])
                       Empty list = full discovery mode (scan all subdomains)
                       Special prefix "." = include root domain directly (no subdomain)

    Returns:
        Dictionary with:
        - target: original target (root domain)
        - root_domain: the root domain (same as target)
        - filtered_mode: True if SUBDOMAIN_LIST has entries (filtered scan)
        - subdomain_list: list of subdomain prefixes to scan
        - full_subdomains: list of full subdomain names (prefix + root domain)
        - include_root_domain: True if "." is in subdomain_list (scan root domain directly)
    """
    # TARGET_DOMAIN is always the root domain (e.g., "vulnweb.com")
    root_domain = target

    # Parse subdomain list and determine scan mode
    subdomain_list = subdomain_list or []
    include_root_domain = False

    # Build full subdomain names from prefixes
    full_subdomains = []
    for prefix in subdomain_list:
        # Handle "." as special case meaning root domain itself
        clean_prefix = prefix.rstrip('.')
        if clean_prefix == "" or prefix == ".":
            # "." means include root domain directly (e.g., vulnweb.com)
            include_root_domain = True
            # Add root domain to the list
            if root_domain not in full_subdomains:
                full_subdomains.append(root_domain)
        else:
            # Normal subdomain prefix (e.g., "testphp." -> testphp.vulnweb.com)
            full_subdomain = f"{clean_prefix}.{root_domain}"
            if full_subdomain not in full_subdomains:
                full_subdomains.append(full_subdomain)

    # Filtered mode only when actual subdomain prefixes are specified (not just ".")
    # "." alone means "include root domain" — it should NOT skip subdomain discovery
    actual_prefixes = [p for p in subdomain_list if p.rstrip('.') != "" and p != "."]
    filtered_mode = len(actual_prefixes) > 0

    return {
        "target": target,
        "root_domain": root_domain,
        "filtered_mode": filtered_mode,
        "subdomain_list": subdomain_list,
        "full_subdomains": full_subdomains,
        "include_root_domain": include_root_domain
    }


def build_scan_type() -> str:
    """Build dynamic scan type based on enabled modules."""
    modules = []
    if "domain_discovery" in SCAN_MODULES:
        modules.append("domain_discovery")
    if "port_scan" in SCAN_MODULES:
        modules.append("port_scan")
    if "http_probe" in SCAN_MODULES:
        modules.append("http_probe")
    if "resource_enum" in SCAN_MODULES:
        modules.append("resource_enum")
    if "vuln_scan" in SCAN_MODULES:
        modules.append("vuln_scan")
    return "_".join(modules) if modules else "custom"


_save_lock = threading.Lock()


def save_recon_file(data: dict, output_file: Path, pretty: bool = False):
    """Save recon data to JSON file atomically (thread-safe).

    Writes to a temp file first, then renames into place so a crash
    mid-write never corrupts the output file.

    Args:
        data: Recon data dict to serialize.
        output_file: Path to the output JSON file.
        pretty: If True, use pretty-print (indent=2). Use only for the
                final save — intermediate saves use compact JSON which is
                2-3x faster to serialize and produces ~60% smaller files.
    """
    tmp_file = output_file.with_name(f".{output_file.name}.tmp")
    with _save_lock:
        try:
            with open(tmp_file, 'w') as f:
                if pretty:
                    json.dump(data, f, indent=2, default=str)
                else:
                    json.dump(data, f, separators=(',', ':'), default=str)
            tmp_file.replace(output_file)
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)
            raise


def _maybe_run_ai_surface(result: dict, settings: dict, output_file: Path) -> dict:
    """GROUP 4.5 — AI Surface Recon. Runs after resource_enum at every call site.

    Gated purely on AI_SURFACE_RECON_ENABLED (the js_recon pattern), not
    SCAN_MODULES. Failure-soft: a probe error records a phase_error and the
    pipeline continues.
    """
    if not settings.get('AI_SURFACE_RECON_ENABLED', True):
        return result
    try:
        result = run_ai_surface_recon(result, output_file=output_file, settings=settings)
        result.setdefault("metadata", {}).setdefault("modules_executed", [])
        if "ai_surface_recon" not in result["metadata"]["modules_executed"]:
            result["metadata"]["modules_executed"].append("ai_surface_recon")
        save_recon_file(result, output_file)
        _graph_update_bg("update_graph_from_ai_surface_recon", result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][AISurfaceRecon] failed: {e}")
        result.setdefault("metadata", {}).setdefault("phase_errors", {})["ai_surface_recon"] = str(e)
        try:
            save_recon_file(result, output_file)
        except Exception:
            print(f"[!] _maybe_run_ai_surface: save_recon_file(result, output_file)")
            pass
    return result


def merge_port_scan_results(combined_result: dict) -> None:
    """
    Merge masscan_scan results into port_scan for downstream consumers.

    http_probe, graph_db, and other modules only read recon_data["port_scan"].
    This function merges masscan-discovered ports into that key, deduplicating
    by host+port. If only masscan ran (no naabu), its data becomes port_scan.
    """
    masscan_data = combined_result.get("masscan_scan")
    if not masscan_data:
        return

    port_scan = combined_result.get("port_scan")

    if not port_scan:
        combined_result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }
        return

    # Both scanners ran — merge masscan into port_scan, deduplicating
    for host, mdata in masscan_data.get("by_host", {}).items():
        if host not in port_scan["by_host"]:
            port_scan["by_host"][host] = mdata
        else:
            existing = port_scan["by_host"][host]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for pd in mdata.get("port_details", []):
                if pd["port"] not in [x["port"] for x in existing.get("port_details", [])]:
                    existing.setdefault("port_details", []).append(pd)
            existing["ports"].sort()
            if "port_details" in existing:
                existing["port_details"].sort(key=lambda x: x["port"])

    for ip, mdata in masscan_data.get("by_ip", {}).items():
        if ip not in port_scan["by_ip"]:
            port_scan["by_ip"][ip] = mdata
        else:
            existing = port_scan["by_ip"][ip]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for hn in mdata.get("hostnames", []):
                if hn not in existing.get("hostnames", []):
                    existing.setdefault("hostnames", []).append(hn)
            existing["ports"].sort()

    merged_ports = sorted(set(port_scan.get("all_ports", []) + masscan_data.get("all_ports", [])))
    port_scan["all_ports"] = merged_ports

    for ip, hosts in masscan_data.get("ip_to_hostnames", {}).items():
        existing_hosts = port_scan.setdefault("ip_to_hostnames", {}).setdefault(ip, [])
        for h in (hosts if isinstance(hosts, list) else [hosts]):
            if h not in existing_hosts:
                existing_hosts.append(h)

    existing_meta = port_scan.get("scan_metadata", {})
    scanners = existing_meta.get("scanners", ["naabu"])
    if "masscan" not in scanners:
        scanners.append("masscan")
    existing_meta["scanners"] = scanners

    by_host = port_scan["by_host"]
    by_ip = port_scan["by_ip"]
    port_scan["summary"] = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h.get("ports")]),
        "total_open_ports": sum(len(h.get("ports", [])) for h in by_host.values()),
        "unique_ports": merged_ports,
        "unique_port_count": len(merged_ports),
        "cdn_hosts": len([h for h in by_host.values() if h.get("is_cdn")]),
    }


def merge_nmap_into_port_scan(combined_result: dict) -> None:
    """
    Merge Nmap service version data into port_scan.port_details.

    Enriches existing port_details entries (from Naabu/Masscan) with Nmap's
    product, version, CPE, and NSE script results. Does NOT add new ports.
    """
    nmap_data = combined_result.get("nmap_scan", {})
    port_scan = combined_result.get("port_scan", {})
    if not nmap_data or not port_scan:
        return

    enriched_count = 0

    for host, nmap_host in nmap_data.get("by_host", {}).items():
        ps_host = port_scan.get("by_host", {}).get(host)
        if not ps_host:
            continue
        for nmap_pd in nmap_host.get("port_details", []):
            for ps_pd in ps_host.get("port_details", []):
                if ps_pd.get("port") == nmap_pd.get("port"):
                    if nmap_pd.get("product"):
                        ps_pd["product"] = nmap_pd["product"]
                    if nmap_pd.get("version"):
                        ps_pd["version"] = nmap_pd["version"]
                    if nmap_pd.get("cpe"):
                        ps_pd["cpe"] = nmap_pd["cpe"]
                    if nmap_pd.get("scripts"):
                        ps_pd["scripts"] = nmap_pd["scripts"]
                    enriched_count += 1
                    break

    # Update scan_metadata to include nmap
    scanners = port_scan.get("scan_metadata", {}).get("scanners", [])
    if "nmap" not in scanners:
        scanners.append("nmap")
        port_scan.get("scan_metadata", {})["scanners"] = scanners

    if enriched_count:
        print(f"[+][Nmap] Enriched {enriched_count} port(s) with service version data")


def run_ip_recon(target_ips: list, settings: dict) -> dict:
    """
    Run IP-based reconnaissance: expand CIDRs, reverse DNS, IP WHOIS.

    Produces a recon data structure compatible with the domain-based pipeline
    using mock Domain/Subdomain names derived from reverse DNS or IP addresses.

    Args:
        target_ips: List of IP addresses and/or CIDR ranges
        settings: Full settings dictionary

    Returns:
        Complete reconnaissance data dict (same shape as run_domain_recon output)
    """
    import ipaddress
    from recon.main_recon_modules.domain_recon import dns_lookup

    print("\n" + "=" * 70)
    print("               RedAmon - IP-Based Reconnaissance")
    print("=" * 70)
    print(f"  [*][Pipeline] Target IPs/CIDRs: {', '.join(target_ips)}")
    scan_modules = settings.get('SCAN_MODULES', [])
    print(
        f"  [*][Pipeline] Scan modules: "
        f"{','.join(scan_modules) if isinstance(scan_modules, list) else scan_modules}"
    )
    print(f"  [*][Pipeline] Stealth mode: {settings.get('STEALTH_MODE', False)} | AI pipeline: {settings.get('AI_IN_PIPELINE', False)}")
    print("=" * 70 + "\n")

    _graph_reset()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"recon_{PROJECT_ID}.json"

    mock_domain = f"ip-targets.{PROJECT_ID}"

    # Step 1: Expand CIDRs into individual IPs
    expanded_ips = []
    original_cidrs = []
    for entry in target_ips:
        entry = entry.strip()
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                original_cidrs.append(entry)
                for host in network.hosts():
                    expanded_ips.append(str(host))
                # For /32 (IPv4) or /128 (IPv6) single-host networks, hosts() is empty
                if network.prefixlen in (32, 128):
                    expanded_ips.append(str(network.network_address))
            except ValueError as e:
                print(f"[!][Pipeline] Invalid CIDR {entry}: {e}")
        else:
            expanded_ips.append(entry)

    expanded_ips = list(dict.fromkeys(expanded_ips))  # deduplicate preserving order
    print(f"[*][Pipeline] Expanded {len(target_ips)} entries to {len(expanded_ips)} individual IPs")

    # RoE: filter out excluded hosts (supports exact match + CIDR)
    expanded_ips = _filter_roe_excluded(expanded_ips, settings, label="IP")

    # Step 2: Reverse DNS for each IP
    ip_to_hostname = {}
    all_hostnames = []
    subdomains_dns = {}

    dns_enabled = settings.get('DNS_ENABLED', True)

    if dns_enabled:
        print(f"\n[*][DNS] PHASE 1: Reverse DNS Lookup (parallel)")
        print("-" * 40)
        dns_max_retries = settings.get('DNS_MAX_RETRIES', 3)

        def _reverse_dns_one(ip: str) -> tuple[str, str]:
            """Resolve a single IP. Returns (ip, hostname_or_none)."""
            hostname = reverse_dns_lookup(ip, max_retries=dns_max_retries)
            return ip, hostname

        dns_workers = min(len(expanded_ips), settings.get('DNS_MAX_WORKERS', 50))
        with ThreadPoolExecutor(max_workers=dns_workers, thread_name_prefix="rdns") as rdns_exec:
            rdns_futures = {rdns_exec.submit(_reverse_dns_one, ip): ip for ip in expanded_ips}
            for future in as_completed(rdns_futures):
                try:
                    ip, hostname = future.result()
                    if hostname:
                        ip_to_hostname[ip] = hostname
                        all_hostnames.append(hostname)
                        print(f"[+][DNS] {ip} -> {hostname}")
                    else:
                        mock_name = ip.replace('.', '-').replace(':', '-')
                        ip_to_hostname[ip] = mock_name
                        print(f"[-][DNS] {ip} -> no PTR (using {mock_name})")
                except Exception as e:
                    ip = rdns_futures[future]
                    mock_name = ip.replace('.', '-').replace(':', '-')
                    ip_to_hostname[ip] = mock_name
                    print(f"[!][DNS] {ip} -> lookup error ({e}), using {mock_name}")
    else:
        print(f"\n[-][DNS] PHASE 1: Reverse DNS Lookup — SKIPPED (disabled)")
        for ip in expanded_ips:
            mock_name = ip.replace('.', '-').replace(':', '-')
            ip_to_hostname[ip] = mock_name

    # Step 3: Build DNS data structure for each "subdomain"
    subdomain_names = []
    if dns_enabled:
        print(f"\n[*][DNS] PHASE 2: DNS Resolution for Discovered Hosts (parallel)")
        print("-" * 40)

        def _resolve_one(item: tuple) -> tuple:
            ip, hostname = item
            is_real = hostname in all_hostnames and not hostname.replace('-', '').replace('.', '').isdigit()
            if is_real:
                dns = dns_lookup(hostname)
                return hostname, dns, ip, True
            return hostname, None, ip, False

        dns_workers = min(len(ip_to_hostname), settings.get('DNS_MAX_WORKERS', 50))
        with ThreadPoolExecutor(max_workers=dns_workers, thread_name_prefix="dns-resolv") as dns_exec:
            items = list(ip_to_hostname.items())
            dns_futures = {dns_exec.submit(_resolve_one, item): item for item in items}
            # Collect mock entries first so we can process real ones
            temp_mock = {}
            real_results = {}
            for future in as_completed(dns_futures):
                try:
                    hostname, host_dns, ip, is_real = future.result()
                    if is_real:
                        real_results[hostname] = host_dns
                        print(f"[+][DNS] Resolved: {hostname}")
                    else:
                        is_v6 = ':' in ip
                        temp_mock[hostname] = {
                            "has_records": True,
                            "ips": {"ipv4": [] if is_v6 else [ip], "ipv6": [ip] if is_v6 else []},
                            "records": {},
                            "is_mock": True,
                            "actual_ip": ip,
                        }
                        subdomain_names.append(hostname)
                except Exception as e:
                    item = dns_futures[future]
                    ip, hostname = item
                    print(f"[!][DNS] Resolution error for {hostname}: {e}")

        # Merge real results and mock entries
        for hostname, host_dns in real_results.items():
            subdomains_dns[hostname] = host_dns
            subdomain_names.append(hostname)
        subdomains_dns.update(temp_mock)
    else:
        print(f"\n[-][DNS] PHASE 2: DNS Resolution — SKIPPED (disabled)")
        for ip, hostname in ip_to_hostname.items():
            is_v6 = ':' in ip
            subdomains_dns[hostname] = {
                "has_records": True,
                "ips": {
                    "ipv4": [] if is_v6 else [ip],
                    "ipv6": [ip] if is_v6 else [],
                },
                "records": {},
                "is_mock": True,
                "actual_ip": ip,
            }
            subdomain_names.append(hostname)

    # Step 4: IP WHOIS (best-effort)
    ip_whois = {}
    if settings.get('WHOIS_ENABLED', True):
        print(f"\n[*][WHOIS] PHASE 3: IP WHOIS Lookup")
        print("-" * 40)
        try:
            from recon.main_recon_modules.whois_recon import whois_lookup as ip_whois_lookup
            # WHOIS a sample of IPs (first one per /24 block to avoid flooding)
            seen_blocks = set()
            for ip in expanded_ips:
                block = '.'.join(ip.split('.')[:3]) if '.' in ip else ip[:16]
                if block in seen_blocks:
                    continue
                seen_blocks.add(block)
                try:
                    result = ip_whois_lookup(ip, save_output=False, settings=settings)
                    ip_whois[ip] = result.get("whois_data", {})
                    org = ip_whois[ip].get("org", "unknown")
                    print(f"[+][WHOIS] {ip}: org={org}")
                except Exception as e:
                    print(f"[-][WHOIS] WHOIS for {ip} failed: {e}")
        except Exception as e:
            print(f"[!][WHOIS] IP WHOIS module error: {e}")
    else:
        print(f"\n[-][WHOIS] PHASE 3: IP WHOIS Lookup — SKIPPED (disabled)")

    # Build the subdomain_filter (all IPs + any PTR-resolved hostnames)
    # This becomes allowed_hosts for http_probe scope checking
    subdomain_filter = list(set(expanded_ips + all_hostnames + subdomain_names))

    # Build result structure compatible with domain-based pipeline
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target": mock_domain,
            "root_domain": mock_domain,
            "user_id": USER_ID,
            "project_id": PROJECT_ID,
            "ip_mode": True,
            "target_ips": target_ips,
            "expanded_ips": expanded_ips,
            "original_cidrs": original_cidrs,
            "ip_to_hostname": ip_to_hostname,
            "filtered_mode": True,
            "subdomain_filter": subdomain_filter,
            "anonymous_mode": settings.get('USE_TOR_FOR_RECON', False),
            "bruteforce_mode": False,
            "modules_executed": ["ip_recon", "reverse_dns"],
        },
        "domain": mock_domain,
        "whois": {"ip_whois": ip_whois},
        "subdomains": subdomain_names,
        "subdomain_count": len(subdomain_names),
        "dns": {
            "domain": {},
            "subdomains": subdomains_dns,
        },
    }

    save_recon_file(combined_result, output_file)
    print(f"\n[✓][Pipeline] Saved: {output_file}")

    # Background graph update: IP recon
    _graph_update_bg("update_graph_from_ip_recon", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 2b — Uncover Target Expansion (before port scan / OSINT)
    # =====================================================================
    if settings.get('OSINT_ENRICHMENT_ENABLED', False) and settings.get('UNCOVER_ENABLED', False):
        try:
            from recon.main_recon_modules.uncover_enrich import run_uncover_expansion, merge_uncover_into_pipeline
            uncover_data = run_uncover_expansion(combined_result, settings)
            if uncover_data:
                combined_result["uncover"] = uncover_data
                merge_uncover_into_pipeline(combined_result, uncover_data, combined_result.get('domain', ''))
                combined_result["metadata"]["modules_executed"].append("uncover_expansion")
                _graph_update_bg("update_graph_from_uncover", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Uncover] Expansion failed: {e}")

    # =====================================================================
    # Shodan + Port Scan (parallel fan-out) — same pattern as domain recon
    # =====================================================================
    shodan_enabled = settings.get('SHODAN_ENABLED', True) and any([
        settings.get('SHODAN_HOST_LOOKUP'),
        settings.get('SHODAN_REVERSE_DNS'),
        settings.get('SHODAN_DOMAIN_DNS'),
        settings.get('SHODAN_PASSIVE_CVES'),
    ])

    naabu_enabled = settings.get('NAABU_ENABLED', True)
    masscan_enabled = settings.get('MASSCAN_ENABLED', True)

    if "port_scan" in SCAN_MODULES and not naabu_enabled and not masscan_enabled:
        print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
        print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")

    if shodan_enabled or "port_scan" in SCAN_MODULES:
        print(f"\n[*][Pipeline] GROUP: Shodan + Port Scan (parallel fan-out)")
        print("-" * 40)

        port_scan_workers = (1 if naabu_enabled else 0) + (1 if masscan_enabled else 0)
        max_workers = (1 if shodan_enabled else 0) + (port_scan_workers if "port_scan" in SCAN_MODULES else 0)
        max_workers = max(max_workers, 1)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ip-g3") as g3_exec:
            g3_futures = {}
            if shodan_enabled:
                from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated
                g3_futures["shodan"] = g3_exec.submit(
                    run_shodan_enrichment_isolated, combined_result, settings
                )
            if naabu_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["port_scan"] = g3_exec.submit(
                    run_port_scan_isolated, combined_result, settings
                )
            if masscan_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["masscan_scan"] = g3_exec.submit(
                    run_masscan_scan_isolated, combined_result, settings
                )

            for name, future in g3_futures.items():
                try:
                    data = future.result()
                    if name == "shodan" and data:
                        combined_result["shodan"] = data
                        combined_result["metadata"]["modules_executed"].append("shodan_enrich")
                    elif name == "port_scan" and data:
                        combined_result["port_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("port_scan")
                    elif name == "masscan_scan" and data:
                        combined_result["masscan_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("masscan_scan")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        save_recon_file(combined_result, output_file)

        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", combined_result, USER_ID, PROJECT_ID)

        if "port_scan" in combined_result:
            _graph_update_bg("update_graph_from_port_scan", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 3.5 — Nmap Service Version Detection + NSE Vulnerability Scripts
    # IP-mode equivalent of the domain-mode block at run_domain_recon().
    # Without this, Service.product / Service.version / Service.ai_runtime_version
    # never get populated in IP-mode scans (recon's port_scan only carries
    # IANA-derived service names, not real banner-read versions).
    # Depends on: port_scan output. Runs sequentially BEFORE HTTP probe so
    # http_probe sees the enriched port_details.
    # =====================================================================
    nmap_enabled = settings.get('NMAP_ENABLED', True)
    if nmap_enabled and "port_scan" in combined_result:
        print(f"\n[*][Pipeline] GROUP 3.5: Nmap Service Detection (IP mode)")
        print("-" * 40)

        from recon.main_recon_modules.nmap_scan import run_nmap_scan
        combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=settings)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")

        # Merge Nmap service versions (incl. ai_runtime_version) into port_scan.port_details
        if "nmap_scan" in combined_result:
            merge_nmap_into_port_scan(combined_result)

        if "nmap_scan" in combined_result:
            _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)

    # OSINT Enrichment (parallel, same logic as domain recon Group 3b)
    _ip_osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.main_recon_modules.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.main_recon_modules.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.main_recon_modules.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.main_recon_modules.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.main_recon_modules.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.main_recon_modules.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.main_recon_modules.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }
    if not settings.get('OSINT_ENRICHMENT_ENABLED', False):
        enabled_ip_osint = {}
    else:
        enabled_ip_osint = {
            name: cfg for name, cfg in _ip_osint_tools.items()
            if settings.get(cfg[0], False)
            and (
                settings.get(f'{name.upper()}_API_KEY', '')
                or (name == 'censys' and settings.get('CENSYS_API_TOKEN', ''))
                or name == 'otx'  # OTX supports anonymous requests without an API key
            )
        }
    if enabled_ip_osint:
        print(f"\n[*][Pipeline] OSINT Enrichment ({', '.join(enabled_ip_osint.keys())}) — parallel")
        print("-" * 40)
        import importlib
        osint_workers = min(len(enabled_ip_osint), 5)
        with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="ip-osint") as osint_exec:
            osint_futures = {}
            for name, (_, module_path, func_name, _) in enabled_ip_osint.items():
                mod = importlib.import_module(module_path)
                fn = getattr(mod, func_name)
                osint_futures[name] = osint_exec.submit(fn, combined_result, settings)
            for name, future in osint_futures.items():
                try:
                    data = future.result()
                    if data:
                        combined_result[name] = data
                        combined_result["metadata"]["modules_executed"].append(f"{name}_enrich")
                        print(f"[+][{name.upper()}] Enrichment merged")
                except Exception as e:
                    print(f"[!][{name.upper()}] Enrichment failed: {e}")
        for name, (_, _, _, graph_method) in enabled_ip_osint.items():
            if name in combined_result:
                _graph_update_bg(graph_method, combined_result, USER_ID, PROJECT_ID)

    # HTTP Probe
    if "http_probe" in SCAN_MODULES:
        if not settings.get('HTTPX_ENABLED', True):
            print("\n[*][httpx] HTTP probing disabled -- skipping")
        else:
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
                if 'urlscan' in combined_result:
                    _graph_update_bg("update_graph_from_urlscan_enrichment", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
                save_recon_file(combined_result, output_file)

    # Check if active scans should be skipped
    skip_active_scans, skip_reason = should_skip_active_scans(combined_result)

    # Auto-enable JS Recon / GraphQL Scan / vuln_scan when live targets exist
    _auto_enable_contextual_modules(settings, combined_result)

    if skip_active_scans:
        print(f"\n[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
        combined_result["metadata"]["active_scans_skipped"] = True
        combined_result["metadata"]["active_scans_skip_reason"] = skip_reason
        save_recon_file(combined_result, output_file)
    else:
        if "resource_enum" in SCAN_MODULES:
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                save_recon_file(combined_result, output_file)

    # GROUP 4.5 -- AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_ai_surface(combined_result, settings, output_file)

    # GROUP 5b -- JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if settings.get('JS_RECON_ENABLED', False):
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            combined_result = run_js_recon(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")

    if not skip_active_scans:
        if "vuln_scan" in SCAN_MODULES:
            try:
                combined_result = run_vuln_scan(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("vuln_scan")
                save_recon_file(combined_result, output_file)

                if settings.get('MITRE_ENABLED', True):
                    try:
                        combined_result = run_mitre_enrichment(combined_result, output_file=output_file, settings=settings)
                    except Exception as e:
                        print(f"[!][Pipeline] mitre_enrichment failed: {e}")
                        combined_result["metadata"].setdefault("phase_errors", {})["mitre_enrichment"] = str(e)
                _graph_update_bg("update_graph_from_vuln_scan", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] vuln_scan failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["vuln_scan"] = str(e)
                save_recon_file(combined_result, output_file)

    # External Domains -- aggregate from all sources and persist
    try:
        ext_domains = _aggregate_external_domains(combined_result)
        if ext_domains:
            combined_result["external_domains_aggregated"] = ext_domains
            _graph_update_bg("update_graph_from_external_domains", combined_result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] external_domains aggregation failed: {e}")

    # Wait for all background graph DB updates to finish
    _graph_wait_all()

    # Final pretty-print save for human readability
    save_recon_file(combined_result, output_file, pretty=True)

    print(f"\n{'=' * 70}")
    print(f"[✓][Pipeline] IP RECON COMPLETE")
    print(f"[+][Pipeline] IPs scanned: {len(expanded_ips)}")
    print(f"[+][Pipeline] Hostnames resolved: {len(all_hostnames)}")
    print(f"[+][Pipeline] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


def run_domain_recon(target: str, anonymous: bool = False, bruteforce: bool = False,
                     target_info: dict = None) -> dict:
    """
    Run combined WHOIS + subdomain discovery + DNS resolution.
    Produces a single unified JSON file with incremental saves.

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)

    Args:
        target: Root domain (e.g., "vulnweb.com", "example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode (only for full discovery mode)
        target_info: Parsed target info from parse_target()

    Returns:
        Complete reconnaissance data including WHOIS and subdomains
    """
    # Parse target if not provided
    if target_info is None:
        target_info = parse_target(target, SUBDOMAIN_LIST)

    # Auto-promote to FILTERED MODE when discovery is disabled and only the root
    # domain is in scope. Without this, the FULL DISCOVERY branch runs but the
    # discovery step is skipped, leaving subdomains/dns empty and the rest of
    # the pipeline with no targets to chew on (silent failure).
    if (
        not target_info["filtered_mode"]
        and target_info.get("include_root_domain")
        and not _settings.get('SUBDOMAIN_DISCOVERY_ENABLED', True)
    ):
        target_info["filtered_mode"] = True
        if target_info["root_domain"] not in target_info["full_subdomains"]:
            target_info["full_subdomains"].append(target_info["root_domain"])
        print("[*][Pipeline] Discovery disabled + root-domain-only → forcing FILTERED MODE")

    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    print(f"[*][Pipeline] Target: {root_domain}")
    if filtered_mode:
        print(f"[*][Pipeline] Mode: FILTERED SUBDOMAIN SCAN")
        print(f"[*][Pipeline] Subdomains: {', '.join(full_subdomains)}")
    else:
        print(f"[*][Pipeline] Mode: FULL DISCOVERY (all subdomains)")

    # Setup output file and background graph executor
    _graph_reset()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"recon_{PROJECT_ID}.json"

    # Check for resumable scan checkpoint
    checkpoint = ScanCheckpoint(PROJECT_ID, str(OUTPUT_DIR))
    resume_data = None
    if should_resume_scan(PROJECT_ID, str(OUTPUT_DIR)):
        resume_data = checkpoint.load()
        if resume_data:
            print(f"[*][Pipeline] Resuming from checkpoint: {resume_data.get('last_phase', 'unknown')}")
            print(f"[*][Pipeline] Last checkpoint: {resume_data.get('timestamp', 'unknown')}")

    # Initialize result structure with dynamic scan_type and empty modules_executed
    # If resuming, use checkpoint data as base
    if resume_data and resume_data.get('combined_result'):
        combined_result = resume_data['combined_result']
        # Update timestamp for resumed scan
        combined_result["metadata"]["resumed_at"] = datetime.now().isoformat()
        combined_result["metadata"]["resumed_from_phase"] = resume_data.get('last_phase')
        print(f"[+][Pipeline] Loaded {len(combined_result.get('subdomains', []))} subdomains from checkpoint")
    else:
        combined_result = {
            "metadata": {
                "scan_type": build_scan_type(),
                "scan_timestamp": datetime.now().isoformat(),
                "target": root_domain,
                "root_domain": root_domain,
                "user_id": USER_ID,
                "project_id": PROJECT_ID,
                "filtered_mode": filtered_mode,
                "subdomain_filter": full_subdomains if filtered_mode else [],
                "anonymous_mode": anonymous,
                "bruteforce_mode": bruteforce if not filtered_mode else False,
                "modules_executed": []
            },
            "domain": root_domain,
            "whois": {},
            "subdomains": [],
            "subdomain_count": 0,
            "dns": {}
        }

    print(
        f"[*][Pipeline] Scan plan: type={combined_result['metadata']['scan_type']} "
        f"modules={','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}"
    )
    print(f"[*][Pipeline] Settings loaded: {len(_settings)} keys | Stealth={_settings.get('STEALTH_MODE', False)} | AI={_settings.get('AI_IN_PIPELINE', False)}")

    # =====================================================================
    # GROUP 1 — Fan-Out: WHOIS + Subdomain Discovery + URLScan (parallel)
    # All three only need root_domain — no dependencies between them.
    # =====================================================================
    dns_enabled = _settings.get('DNS_ENABLED', True)

    if filtered_mode:
        # FILTERED MODE: skip discovery, just resolve the specified subdomains
        # WHOIS + URLScan can still run in parallel
        combined_result["subdomains"] = full_subdomains
        combined_result["subdomain_count"] = len(full_subdomains)

        print(f"\n[*][Pipeline] GROUP 1: WHOIS + URLScan (parallel)")
        print("-" * 40)
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}
            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    whois_lookup, root_domain, save_output=False, settings=_settings
                )
            if _settings.get('URLSCAN_ENABLED'):
                from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
                g1_futures["urlscan"] = g1_exec.submit(
                    run_urlscan_discovery_only, root_domain, _settings
                )

            for name, future in g1_futures.items():
                try:
                    result = future.result()
                    if name == "whois":
                        combined_result["whois"] = result.get("whois_data", {})
                        combined_result["metadata"]["modules_executed"].append("whois")
                        print(f"[+][WHOIS] Data retrieved successfully")
                    elif name == "urlscan":
                        if result:
                            combined_result["urlscan"] = result
                            combined_result["metadata"]["modules_executed"].append("urlscan_enrich")
                            print(f"[+][URLScan] Discovery complete")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")

        if not _settings.get('WHOIS_ENABLED', True):
            combined_result["whois"] = {"skipped": True}

        # DNS resolution for filtered subdomains
        if dns_enabled:
            print(f"\n[*][DNS] GROUP 2: Filtered Subdomain DNS Resolution")
            print("-" * 40)
            from recon.main_recon_modules.domain_recon import dns_lookup, resolve_all_dns
            include_root = target_info.get("include_root_domain", False)
            # Use parallel resolve_all_dns for filtered subdomains too
            dns_workers = _settings.get('DNS_MAX_WORKERS', 50)
            dns_record_parallel = _settings.get('DNS_RECORD_PARALLELISM', True)
            dns_result = resolve_all_dns(root_domain, full_subdomains, max_workers=dns_workers, record_parallelism=dns_record_parallel, settings=_settings)
            domain_dns = dns_result["domain"] if include_root else {}
            combined_result["dns"] = {
                "domain": domain_dns,
                "subdomains": dns_result["subdomains"]
            }
            combined_result["metadata"]["include_root_domain"] = include_root
            combined_result["metadata"]["modules_executed"].append("dns_resolution")
        else:
            print(f"\n[-][DNS] GROUP 2: DNS Resolution — SKIPPED (disabled)")
            combined_result["metadata"]["include_root_domain"] = target_info.get("include_root_domain", False)

    else:
        # FULL DISCOVERY MODE: WHOIS + Discovery + URLScan all in parallel
        print(f"\n[*][Pipeline] GROUP 1: WHOIS + Subdomain Discovery + URLScan (parallel fan-out)")
        print("-" * 40)

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}

            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    whois_lookup, root_domain, save_output=False, settings=_settings
                )

            if _settings.get('SUBDOMAIN_DISCOVERY_ENABLED', True):
                g1_futures["discovery"] = g1_exec.submit(
                    discover_subdomains, root_domain,
                    anonymous=anonymous, bruteforce=bruteforce,
                    resolve=dns_enabled, save_output=False, settings=_settings
                )
            else:
                print(f"[-][Discovery] Subdomain discovery disabled -- using root domain only")

            if _settings.get('URLSCAN_ENABLED'):
                from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
                g1_futures["urlscan"] = g1_exec.submit(
                    run_urlscan_discovery_only, root_domain, _settings
                )

            g1_results = {}
            for name, future in g1_futures.items():
                try:
                    g1_results[name] = future.result()
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    g1_results[name] = None

        # Fan-in: merge Group 1 results
        print(f"\n[*][Pipeline] Fan-in — merging parallel results")

        # WHOIS
        whois_data = g1_results.get("whois")
        if whois_data:
            combined_result["whois"] = whois_data.get("whois_data", {})
            combined_result["metadata"]["modules_executed"].append("whois")
            print(f"[+][WHOIS] Data merged")
        elif not _settings.get('WHOIS_ENABLED', True):
            combined_result["whois"] = {"skipped": True}

        # Subdomain discovery
        recon_result = g1_results.get("discovery")
        if recon_result:
            discovered_subs = recon_result.get("subdomains", [])
            discovered_subs = _filter_roe_excluded(discovered_subs, _settings, label="discovered subdomain")
            # Ensure root domain is included when "Include Root Domain" is toggled
            include_root = target_info.get("include_root_domain", False)
            if include_root and root_domain not in discovered_subs:
                discovered_subs.insert(0, root_domain)
            combined_result["subdomains"] = discovered_subs
            combined_result["subdomain_count"] = len(discovered_subs)
            combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
            if recon_result.get("external_domains"):
                combined_result["domain_discovery_external_domains"] = recon_result["external_domains"]
            combined_result["dns"] = recon_result.get("dns") or {}
            # Pass subdomain status map (filtered to match ROE-filtered subdomains)
            status_map = recon_result.get("subdomain_status_map", {})
            status_map = {s: st for s, st in status_map.items() if s in set(discovered_subs)}
            combined_result["subdomain_status_map"] = status_map
            combined_result["metadata"]["include_root_domain"] = include_root
            combined_result["metadata"]["modules_executed"].append("dns_resolution")
            print(f"[+][Discovery] Merged: {len(discovered_subs)} subdomains")
        else:
            print(f"[!][Discovery] Produced no results")

        # URLScan
        urlscan_data = g1_results.get("urlscan")
        if urlscan_data:
            combined_result["urlscan"] = urlscan_data
            combined_result["metadata"]["modules_executed"].append("urlscan_enrich")
            print(f"[+][URLScan] Data merged")

    save_recon_file(combined_result, output_file)
    print(f"[✓][Pipeline] Saved: {output_file}")

    # Background graph update: domain discovery + URLScan discovery
    _graph_update_bg("update_graph_from_domain_discovery", combined_result, USER_ID, PROJECT_ID)
    if "urlscan" in combined_result:
        _graph_update_bg("update_graph_from_urlscan_discovery", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 2b — Uncover Target Expansion (before port scan / OSINT)
    # =====================================================================
    if _settings.get('OSINT_ENRICHMENT_ENABLED', False) and _settings.get('UNCOVER_ENABLED', False):
        try:
            from recon.main_recon_modules.uncover_enrich import run_uncover_expansion, merge_uncover_into_pipeline
            uncover_data = run_uncover_expansion(combined_result, _settings)
            if uncover_data:
                combined_result["uncover"] = uncover_data
                merge_uncover_into_pipeline(combined_result, uncover_data, TARGET_DOMAIN)
                combined_result["metadata"]["modules_executed"].append("uncover_expansion")
                _graph_update_bg("update_graph_from_uncover", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Uncover] Expansion failed: {e}")

    # =====================================================================
    # GROUP 3 — Fan-Out: Shodan + Port Scan (parallel)
    # Both need IPs/hostnames from DNS. Independent of each other.
    # =====================================================================
    shodan_enabled = _settings.get('SHODAN_ENABLED', True) and any([
        _settings.get('SHODAN_HOST_LOOKUP'),
        _settings.get('SHODAN_REVERSE_DNS'),
        _settings.get('SHODAN_DOMAIN_DNS'),
        _settings.get('SHODAN_PASSIVE_CVES'),
    ])

    naabu_enabled = _settings.get('NAABU_ENABLED', True)
    masscan_enabled = _settings.get('MASSCAN_ENABLED', True)

    if "port_scan" in SCAN_MODULES and not naabu_enabled and not masscan_enabled:
        print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
        print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")

    if shodan_enabled or "port_scan" in SCAN_MODULES:
        host_count = len(combined_result.get("dns", {}).get("subdomains", {}))
        print(f"\n[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out) — hosts={host_count} naabu={naabu_enabled} masscan={masscan_enabled} shodan={shodan_enabled}")
        print("-" * 40)

        port_scan_workers = (1 if naabu_enabled else 0) + (1 if masscan_enabled else 0)
        max_workers = (1 if shodan_enabled else 0) + (port_scan_workers if "port_scan" in SCAN_MODULES else 0)
        max_workers = max(max_workers, 1)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="group3") as g3_exec:
            g3_futures = {}

            if shodan_enabled:
                from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated
                g3_futures["shodan"] = g3_exec.submit(
                    run_shodan_enrichment_isolated, combined_result, _settings
                )

            if naabu_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["port_scan"] = g3_exec.submit(
                    run_port_scan_isolated, combined_result, _settings
                )

            if masscan_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["masscan_scan"] = g3_exec.submit(
                    run_masscan_scan_isolated, combined_result, _settings
                )

            # Fan-in: merge results sequentially (safe — each writes different key)
            for name, future in g3_futures.items():
                try:
                    data = future.result()
                    if name == "shodan" and data:
                        combined_result["shodan"] = data
                        combined_result["metadata"]["modules_executed"].append("shodan_enrich")
                        print(f"[+][Shodan] Enrichment merged")
                    elif name == "port_scan" and data:
                        combined_result["port_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("port_scan")
                        print(f"[+][Naabu] Port scan merged")
                    elif name == "masscan_scan" and data:
                        combined_result["masscan_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("masscan_scan")
                        print(f"[+][Masscan] Port scan merged")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        save_recon_file(combined_result, output_file)

        # Background graph updates for Shodan + port scan
        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", combined_result, USER_ID, PROJECT_ID)

        if "port_scan" in combined_result:
            _graph_update_bg("update_graph_from_port_scan", combined_result, USER_ID, PROJECT_ID)

        # Checkpoint after port_scan phase
        checkpoint.complete_phase("port_scan", combined_result.get("port_scan", {}))

        # Track coverage for port scan targets
        port_scan_hosts = list(combined_result.get("port_scan", {}).get("by_host", {}).keys())
        if port_scan_hosts:
            coverage.register_targets(port_scan_hosts, "port_scan")
            for host in port_scan_hosts:
                host_data = combined_result["port_scan"]["by_host"][host]
                ports_found = len(host_data.get("port_details", []))
                coverage.complete_target(host, "port_scan", ScanStatus.SUCCESS, findings_count=ports_found)

    # =====================================================================
    # GROUP 3.5 — Nmap Service Version Detection + NSE Vulnerability Scripts
    # Depends on: merged port_scan data (needs discovered open ports)
    # Runs sequentially AFTER port scan merge, BEFORE HTTP probe
    # =====================================================================
    nmap_enabled = _settings.get('NMAP_ENABLED', True)
    if nmap_enabled and "port_scan" in combined_result:
        nmap_targets = len(combined_result["port_scan"].get("by_host", {}))
        nmap_ports = len(combined_result["port_scan"].get("all_ports", []))
        print(f"\n[*][Pipeline] GROUP 3.5: Nmap Service Detection + NSE Vuln Scripts — targets={nmap_targets} unique_ports={nmap_ports}")
        print("-" * 40)

        from recon.main_recon_modules.nmap_scan import run_nmap_scan
        combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=_settings)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")

        # Merge Nmap service versions into port_scan.port_details
        if "nmap_scan" in combined_result:
            merge_nmap_into_port_scan(combined_result)

        if "nmap_scan" in combined_result:
            _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 3b — OSINT Enrichment (parallel, passive — no packets to target)
    # Runs independently from port scanning; data feeds into the graph only.
    # =====================================================================
    _osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.main_recon_modules.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.main_recon_modules.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.main_recon_modules.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.main_recon_modules.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.main_recon_modules.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.main_recon_modules.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.main_recon_modules.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }

    if not _settings.get('OSINT_ENRICHMENT_ENABLED', False):
        enabled_osint = {}
    else:
        enabled_osint = {
            name: cfg for name, cfg in _osint_tools.items()
            if _settings.get(cfg[0], False)
            and (
                _settings.get(f'{name.upper()}_API_KEY', '')
                or (name == 'censys' and _settings.get('CENSYS_API_TOKEN', ''))
                or name == 'otx'  # OTX supports anonymous requests without an API key
            )
        }

    if enabled_osint:
        print(f"\n[*][Pipeline] GROUP 3b: OSINT Enrichment ({', '.join(enabled_osint.keys())}) — parallel")
        print("-" * 40)

        import importlib
        osint_workers = min(len(enabled_osint), 5)
        with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="osint") as osint_exec:
            osint_futures = {}
            for name, (_, module_path, func_name, _) in enabled_osint.items():
                mod = importlib.import_module(module_path)
                fn = getattr(mod, func_name)
                osint_futures[name] = osint_exec.submit(fn, combined_result, _settings)

            for name, future in osint_futures.items():
                try:
                    data = future.result()
                    if data:
                        combined_result[name] = data
                        combined_result["metadata"]["modules_executed"].append(f"{name}_enrich")
                        print(f"[+][{name.upper()}] Enrichment merged")
                except Exception as e:
                    print(f"[!][{name.upper()}] Enrichment failed: {e}")

        # Queue graph updates for completed OSINT tools
        for name, (_, _, _, graph_method) in enabled_osint.items():
            if name in combined_result:
                _graph_update_bg(graph_method, combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 4 — HTTP Probe (sequential, internally parallel via httpx threads)
    # Depends on: port scan data (open ports) + hostnames
    # =====================================================================
    if "http_probe" in SCAN_MODULES:
        if not _settings.get('HTTPX_ENABLED', True):
            print("\n[*][httpx] HTTP probing disabled -- skipping")
        else:
            http_probe_hosts = len(combined_result.get("port_scan", {}).get("by_host", {}))
            http_probe_ports = len(combined_result.get("port_scan", {}).get("all_ports", []))
            print(f"\n[*][Pipeline] GROUP 4: HTTP Probe — hosts={http_probe_hosts} ports={http_probe_ports}")
            print("-" * 40)
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                # Background graph updates
                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
                if 'urlscan' in combined_result:
                    _graph_update_bg("update_graph_from_urlscan_enrichment", combined_result, USER_ID, PROJECT_ID)

                # Checkpoint after http_probe phase
                checkpoint.complete_phase("http_probe", combined_result.get("http_probe", {}))

                # Track coverage for http_probe targets
                http_probe_urls = list(combined_result.get("http_probe", {}).get("by_url", {}).keys())
                if http_probe_urls:
                    coverage.register_targets(http_probe_urls, "http_probe")
                    for url in http_probe_urls:
                        url_data = combined_result["http_probe"]["by_url"][url]
                        status_code = url_data.get("status_code", 0)
                        if 200 <= status_code < 400:
                            coverage.complete_target(url, "http_probe", ScanStatus.SUCCESS)
                        elif status_code >= 500:
                            coverage.complete_target(url, "http_probe", ScanStatus.ERROR)
                        else:
                            coverage.complete_target(url, "http_probe", ScanStatus.SUCCESS)

            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
                save_recon_file(combined_result, output_file)
                checkpoint.fail_phase("http_probe", str(e))

    # Check if we should skip active scanning modules (resource_enum, vuln_scan)
    # These require live targets from http_probe to work
    skip_active_scans, skip_reason = should_skip_active_scans(combined_result)

    # Auto-enable JS Recon / GraphQL Scan / vuln_scan when live targets exist
    _auto_enable_contextual_modules(_settings, combined_result)

    if skip_active_scans:
        print(f"\n{'=' * 70}")
        print(f"[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
        print(f"[!][Pipeline] Modules skipped: resource_enum, vuln_scan")
        print(f"{'=' * 70}")
        combined_result["metadata"]["active_scans_skipped"] = True
        combined_result["metadata"]["active_scans_skip_reason"] = skip_reason
        save_recon_file(combined_result, output_file)
    else:
        # GROUP 5 — Resource Enum (already parallel internally: Katana || GAU || Kiterunner)
        if "resource_enum" in SCAN_MODULES:
            live_urls = combined_result.get("http_probe", {}).get("summary", {}).get("live_urls", 0)
            print(f"\n[*][Pipeline] GROUP 5: Resource Enum — live_urls={live_urls}")
            print("-" * 40)
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)

                # Checkpoint after resource_enum phase
                checkpoint.complete_phase("resource_enum", combined_result.get("resource_enum", {}))

                # Track coverage for resource_enum targets (crawled URLs)
                resource_by_url = combined_result.get("resource_enum", {}).get("by_url", {})
                if resource_by_url:
                    crawled_urls = list(resource_by_url.keys())
                    coverage.register_targets(crawled_urls, "resource_enum")
                    for url in crawled_urls:
                        url_data = resource_by_url[url]
                        endpoints_found = len(url_data.get("endpoints", []))
                        coverage.complete_target(url, "resource_enum", ScanStatus.SUCCESS, findings_count=endpoints_found)

            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                save_recon_file(combined_result, output_file)
                checkpoint.fail_phase("resource_enum", str(e))

    # GROUP 4.5 — AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_ai_surface(combined_result, _settings, output_file)

    # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if _settings.get('JS_RECON_ENABLED', False):
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            combined_result = run_js_recon(combined_result, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")

    if not skip_active_scans:
        # ================================================================
        # GROUP 6 Phase A — Parallel active vuln scanners (Nuclei || GraphQL)
        # ================================================================
        # Both scanners read BaseURL/Endpoint/Technology, both write Vulnerability,
        # and they have zero data dependency on each other. Run concurrently via
        # ThreadPoolExecutor using _isolated wrappers (each deep-copies the
        # combined_result so there's no shared-dict race).
        # ----------------------------------------------------------------
        phase_a_tools: dict = {}
        if "vuln_scan" in SCAN_MODULES:
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            phase_a_tools['vuln_scan'] = run_vuln_scan_isolated
        if _settings.get('GRAPHQL_SECURITY_ENABLED', False):
            from recon.graphql_scan import run_graphql_scan_isolated
            phase_a_tools['graphql_scan'] = run_graphql_scan_isolated
        if _settings.get('SUBDOMAIN_TAKEOVER_ENABLED', False):
            from recon.main_recon_modules.subdomain_takeover import run_subdomain_takeover_isolated
            phase_a_tools['subdomain_takeover'] = run_subdomain_takeover_isolated
        if _settings.get('VHOST_SNI_ENABLED', False):
            from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment_isolated
            phase_a_tools['vhost_sni'] = run_vhost_sni_enrichment_isolated

        if phase_a_tools:
            vuln_input_endpoints = combined_result.get("resource_enum", {}).get("summary", {}).get("total_endpoints", 0)
            vuln_input_urls = len(combined_result.get("http_probe", {}).get("by_url", {}))
            print(
                f"\n[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning "
                f"(fan-out: {', '.join(phase_a_tools.keys())}) — "
                f"endpoints={vuln_input_endpoints} live_urls={vuln_input_urls}"
            )
            print("-" * 40)
            phase_a_errors = {}
            with ThreadPoolExecutor(max_workers=len(phase_a_tools)) as pool:
                futures = {pool.submit(fn, combined_result, _settings): key
                           for key, fn in phase_a_tools.items()}
                for fut in as_completed(futures):
                    key = futures[fut]
                    try:
                        combined_result[key] = fut.result()
                        combined_result["metadata"]["modules_executed"].append(key)
                        save_recon_file(combined_result, output_file)
                        _graph_update_bg(f"update_graph_from_{key}", combined_result, USER_ID, PROJECT_ID)
                    except Exception as e:
                        print(f"[!][Pipeline] {key} failed: {e}")
                        combined_result["metadata"].setdefault("phase_errors", {})[key] = str(e)
                        phase_a_errors[key] = str(e)
                        save_recon_file(combined_result, output_file)

            # Checkpoint after vuln_scan phase (GROUP 6 Phase A)
            if "vuln_scan" in combined_result:
                checkpoint.complete_phase("vuln_scan", combined_result.get("vuln_scan", {}))

                # Track coverage for vuln_scan targets
                vuln_by_target = combined_result.get("vuln_scan", {}).get("by_target", {})
                if vuln_by_target:
                    vuln_targets = list(vuln_by_target.keys())
                    coverage.register_targets(vuln_targets, "vuln_scan")
                    for target in vuln_targets:
                        target_data = vuln_by_target[target]
                        findings_count = target_data.get("finding_count", 0)
                        coverage.complete_target(target, "vuln_scan", ScanStatus.SUCCESS, findings_count=findings_count)
            elif "vuln_scan" in phase_a_errors:
                checkpoint.fail_phase("vuln_scan", phase_a_errors["vuln_scan"])

        # ================================================================
        # GROUP 6 Phase B — MITRE enrichment (depends on Nuclei CVEs)
        # ================================================================
        if "vuln_scan" in SCAN_MODULES and _settings.get('MITRE_ENABLED', True) and 'vuln_scan' in combined_result:
            print(f"\n[*][Pipeline] GROUP 6 Phase B: MITRE CVE Enrichment")
            print("-" * 40)
            try:
                combined_result = run_mitre_enrichment(combined_result, output_file=output_file, settings=_settings)
                _graph_update_bg("update_graph_from_vuln_scan", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] mitre_enrichment failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["mitre_enrichment"] = str(e)
                save_recon_file(combined_result, output_file)

    # External Domains — aggregate from all sources and persist
    try:
        ext_domains = _aggregate_external_domains(combined_result)
        if ext_domains:
            combined_result["external_domains_aggregated"] = ext_domains
            _graph_update_bg("update_graph_from_external_domains", combined_result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] external_domains aggregation failed: {e}")

    # Wait for all background graph DB updates to finish before returning
    _graph_wait_all()

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[✓][Pipeline] DOMAIN RECON COMPLETE")
    if filtered_mode:
        print(f"[+][Pipeline] Mode: Filtered ({len(full_subdomains)} subdomain(s))")
    else:
        print(f"[+][Pipeline] Subdomains found: {combined_result['subdomain_count']}")

    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in combined_result:
        port_summary = combined_result["port_scan"].get("summary", {})
        naabu_ports = port_summary.get('total_open_ports', 0)
        print(f"[+][Naabu] Open ports: {naabu_ports}")

    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in combined_result:
        http_summary = combined_result["http_probe"].get("summary", {})
        live_urls = http_summary.get('live_urls', 0)
        print(f"[+][Httpx] Live URLs: {live_urls}")
        print(f"[+][Httpx] Technologies: {http_summary.get('technology_count', 0)}")
        # Report httpx-discovered service ports when Naabu found none
        if live_urls > 0 and "port_scan" in combined_result:
            naabu_ports_count = combined_result["port_scan"].get("summary", {}).get("total_open_ports", 0)
            if naabu_ports_count == 0:
                from urllib.parse import urlparse
                httpx_ports = set()
                for url in combined_result["http_probe"].get("by_url", {}):
                    p = urlparse(url)
                    httpx_ports.add(p.port or (443 if p.scheme == "https" else 80))
                if httpx_ports:
                    print(f"[+][Httpx] Service ports (from httpx): {', '.join(str(p) for p in sorted(httpx_ports))}")

    # Check if active scans were skipped
    active_scans_skipped = combined_result.get("metadata", {}).get("active_scans_skipped", False)

    # Resource enumeration stats
    if active_scans_skipped:
        print(f"[!][Pipeline] Resource enum: SKIPPED (no live targets)")
    elif "resource_enum" in SCAN_MODULES and "resource_enum" in combined_result:
        resource_summary = combined_result["resource_enum"].get("summary", {})
        print(f"[+][ResourceEnum] Endpoints: {resource_summary.get('total_endpoints', 0)}")
        print(f"[+][ResourceEnum] Parameters: {resource_summary.get('total_parameters', 0)}")
        print(f"[+][ResourceEnum] Forms (POST): {resource_summary.get('total_forms', 0)}")

    # Vuln scan stats (includes MITRE enrichment)
    if active_scans_skipped:
        print(f"[!][Pipeline] Vuln scan: SKIPPED (no live targets)")
    elif "vuln_scan" in SCAN_MODULES and "vuln_scan" in combined_result:
        vuln_summary = combined_result["vuln_scan"].get("summary", {})
        vuln_total = combined_result["vuln_scan"].get("vulnerabilities", {}).get("total", 0)
        print(f"[+][Nuclei] Vuln findings: {vuln_summary.get('total_findings', 0)} ({vuln_total} vulnerabilities)")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = combined_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            print(f"[+][MITRE] Enriched: {mitre_meta.get('total_cves_enriched', 0)}/{mitre_meta.get('total_cves_processed', 0)} CVEs")

    # GraphQL security stats
    if _settings.get('GRAPHQL_SECURITY_ENABLED', False) and "graphql_scan" in combined_result:
        graphql_summary = combined_result["graphql_scan"].get("summary", {})
        endpoints_tested = graphql_summary.get('endpoints_tested', 0)
        if endpoints_tested > 0:
            print(f"[+][GraphQL] Endpoints tested: {endpoints_tested}")
            print(f"[+][GraphQL] Introspection enabled: {graphql_summary.get('introspection_enabled', 0)}")
            vulns = graphql_summary.get('vulnerabilities_found', 0)
            if vulns > 0:
                print(f"[+][GraphQL] Vulnerabilities: {vulns} " +
                      f"(Critical: {graphql_summary['by_severity']['critical']}, " +
                      f"High: {graphql_summary['by_severity']['high']}, " +
                      f"Medium: {graphql_summary['by_severity']['medium']})")

    # Coverage metrics report
    print(f"\n[*][Pipeline] SCAN COVERAGE METRICS")
    print("-" * 40)
    coverage_report = coverage.get_report()
    for phase, phase_data in coverage_report.get("by_phase", {}).items():
        total = phase_data.get("total", 0)
        success = phase_data.get("success", 0)
        pct = (success / total * 100) if total > 0 else 0
        failed = phase_data.get("failed", [])
        print(f"[+][Coverage] {phase}: {success}/{total} ({pct:.1f}%)")
        if failed:
            print(f"    Failed: {', '.join(failed[:5])}" + (f" (+{len(failed)-5} more)" if len(failed) > 5 else ""))

    # Add coverage metrics to result metadata
    combined_result["metadata"]["scan_coverage"] = coverage_report

    # Mark checkpoint as complete
    checkpoint.complete_phase("pipeline_complete", {"status": "success"})

    # Final pretty-print save for human readability
    save_recon_file(combined_result, output_file, pretty=True)
    print(f"\n[+][Pipeline] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


def main():
    """
    Main entry point - runs the complete recon pipeline.

    Pipeline: domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)
    """
    start_time = datetime.now()

    # Load settings lazily so the module can be imported without a live webapp API.
    print("[*][Pipeline] Loading project settings...")
    _load_settings()
    print(
        f"[*][Pipeline] Settings loaded: project={PROJECT_ID} user={USER_ID} "
        f"modules={','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}"
    )

    # Preflight checks: disk space and stale containers.
    # These run early so scans do not fail halfway through due to avoidable
    # resource issues or volume collisions from previous runs.
    check_disk_space(min_gb=5.0, path="/")
    try:
        cleanup_orphan_containers(project_id=PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] Could not clean stale containers: {e}")

    # Initialize scan quality tracking
    reset_coverage_tracker()
    coverage = get_coverage_tracker()

    # Pre-scan network health check (Tor/proxy assessment)
    if USE_TOR_FOR_RECON:
        print("\n[*][Pipeline] Pre-scan network health check...")
        health_report = run_pre_scan_health_check(
            use_tor=True,
            test_count=_settings.get('TOR_HEALTH_CHECK_COUNT', 3),
        )
        if not health_report.tor_healthy:
            print(f"[!][Pipeline] Tor health check FAILED: {health_report.tor_recommendation}")
            if health_report.tor_success_rate < 0.3:
                print("[!][Pipeline] Tor success rate critically low — scan quality will be degraded")
                # Record health warning in metadata (will be saved with results)
        else:
            print(f"[✓][Pipeline] Tor health OK: {health_report.tor_success_rate*100:.0f}% success, "
                  f"{health_report.tor_avg_latency:.1f}s avg latency")
            if health_report.tor_avg_latency > 5:
                print(f"[!][Pipeline] High Tor latency detected — auto-reducing rate limits")
                # Dynamically reduce rate limits for high-latency Tor
                for key in ['NUCLEI_RATE_LIMIT', 'HTTPX_RATE_LIMIT', 'KATANA_RATE_LIMIT']:
                    if key in _settings and _settings[key] > 20:
                        _settings[key] = max(20, _settings[key] // 2)
                        print(f"    {key}: reduced to {_settings[key]}")

    # IP Mode: skip domain verification and run IP-based recon instead
    if IP_MODE and TARGET_IPS:
        print(f"  [*][Pipeline] MODE:              IP-BASED TARGETING")
        print(f"  [*][Pipeline] TARGET_IPS:        {', '.join(TARGET_IPS)}")
        print(f"  [*][Pipeline] SCAN_MODULES:      {','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}")
        print(f"  [*][Pipeline] UPDATE_GRAPH_DB:   {UPDATE_GRAPH_DB}")
        print(f"  [*][Pipeline] USER_ID:           {USER_ID}")
        print(f"  [*][Pipeline] PROJECT_ID:        {PROJECT_ID}")
        print("═" * 63)

        # Clear previous graph data
        if UPDATE_GRAPH_DB:
            print("[*][graph-db] Clearing previous graph data for this project...")
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        clear_stats = graph_client.clear_project_data(USER_ID, PROJECT_ID)
                        print(f"[+][graph-db] Previous data cleared: {clear_stats['nodes_deleted']} nodes removed\n")
                    else:
                        print("[!][graph-db] Could not connect to Neo4j - skipping clear\n")
            except Exception as e:
                print(f"[!][graph-db] Failed to clear previous graph data: {e}\n")

        run_ip_recon(TARGET_IPS, _settings)

        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n[✓][Pipeline] Total time: {duration}")
        return 0

    # Domain Ownership Verification (if enabled)
    # This MUST be the first check before any scanning to ensure we only
    # scan domains the user controls.
    if VERIFY_DOMAIN_OWNERSHIP:
        ownership_result = verify_domain_ownership(
            TARGET_DOMAIN,
            OWNERSHIP_TOKEN,
            OWNERSHIP_TXT_PREFIX
        )

        if not ownership_result["verified"]:
            print(f"\n[!][Pipeline] SCAN ABORTED: Domain ownership verification failed!")
            print(f"[!][Pipeline] Add TXT record: {ownership_result['record_name']} → \"{ownership_result['expected_value']}\"")
            print(f"[!][Pipeline] Set VERIFY_DOMAIN_OWNERSHIP = False in params.py to disable\n")
            return 1

    # Parse target with SUBDOMAIN_LIST filter
    target_info = parse_target(TARGET_DOMAIN, SUBDOMAIN_LIST)
    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    # RoE: check if root domain itself is excluded
    if _settings.get('ROE_ENABLED') and _settings.get('ROE_EXCLUDED_HOSTS'):
        if _is_roe_excluded(TARGET_DOMAIN, _settings['ROE_EXCLUDED_HOSTS']):
            print(f"\n[RoE] BLOCKED: Root domain '{TARGET_DOMAIN}' is in ROE excluded hosts list.")
            print(f"[RoE] Reconnaissance aborted — target domain excluded by Rules of Engagement.")
            return 1

    # RoE: filter out excluded hosts from subdomains
    full_subdomains = _filter_roe_excluded(full_subdomains, _settings, label="subdomain")
    target_info["full_subdomains"] = full_subdomains

    # Display full configuration (values loaded from DB/API)
    print("═" * 63)
    print("[*][Pipeline] Configuration:")
    print(f"  [*][Pipeline] TARGET_DOMAIN:     {TARGET_DOMAIN}")
    print(f"  [*][Pipeline] SUBDOMAIN_LIST:    {SUBDOMAIN_LIST if SUBDOMAIN_LIST else '[] (full discovery)'}")
    print(f"  [*][Pipeline] SCAN_MODULES:      {','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}")
    print(f"  [*][Pipeline] USE_TOR_FOR_RECON: {USE_TOR_FOR_RECON}")
    print(f"  [*][Pipeline] NAABU_USE_TOR:     {_settings.get('NAABU_USE_TOR', False)}")
    print(f"  [*][Pipeline] STEALTH_MODE:      {_settings.get('STEALTH_MODE', False)}")
    print(f"  [*][Pipeline] UPDATE_GRAPH_DB:   {UPDATE_GRAPH_DB}")
    print(f"  [*][Pipeline] USER_ID:           {USER_ID}")
    print(f"  [*][Pipeline] PROJECT_ID:        {PROJECT_ID}")
    if filtered_mode:
        print(f"  [*][Pipeline] MODE:              FILTERED SUBDOMAIN SCAN")
        print(f"  [*][Pipeline] SUBDOMAINS:        {', '.join(full_subdomains)}")
    else:
        print(f"  [*][Pipeline] MODE:              FULL DISCOVERY (all subdomains)")
    print("═" * 63)

    if _settings.get('STEALTH_MODE', False):
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║  STEALTH MODE ACTIVE — passive/low-noise only           ║")
        print("  ║  Kiterunner: OFF | Banner Grab: OFF | Brute Force: OFF  ║")
        print("  ║  Naabu: passive | httpx: 2 req/s | Nuclei: no DAST     ║")
        print("  ╚══════════════════════════════════════════════════════════╝")

    print()

    # RoE: check time window before starting any scanning
    allowed, reason = _check_roe_time_window(_settings)
    if not allowed:
        print(f"\n[RoE] BLOCKED: {reason}")
        print(f"[RoE] Reconnaissance aborted — outside Rules of Engagement time window.")
        return 1

    # Clear previous graph data for this project before starting new scan
    if UPDATE_GRAPH_DB:
        print("[*][graph-db] Clearing previous graph data for this project...")
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    clear_stats = graph_client.clear_project_data(USER_ID, PROJECT_ID)
                    print(f"[+][graph-db] Previous data cleared: {clear_stats['nodes_deleted']} nodes removed\n")
                else:
                    print("[!][graph-db] Could not connect to Neo4j - skipping clear\n")
        except Exception as e:
            print(f"[!][graph-db] Failed to clear previous graph data: {e}\n")

    # Check anonymity status if Tor is enabled
    if USE_TOR_FOR_RECON:
        try:
            from recon.helpers.anonymity import print_anonymity_status
            print_anonymity_status()
            naabu_tor = _settings.get('NAABU_USE_TOR', False)
            print("[*][Pipeline] Phase-specific anonymity:")
            print(f"    Port scan (Naabu): {'Tor' if naabu_tor else 'direct (fast, no Tor)'} "
                  f"(controlled by NAABU_USE_TOR)")
            print("    HTTP probe / Resource enum / Vuln scan: Tor")
        except ImportError:
            print("[!][Pipeline] Anonymity module not found, proceeding without Tor status check")

    # Phase 1 & 2: Domain recon (WHOIS + Subdomains + DNS) - Combined JSON
    output_file = Path(__file__).parent / "output" / f"recon_{PROJECT_ID}.json"

    if "domain_discovery" in SCAN_MODULES:
        domain_result = run_domain_recon(
            TARGET_DOMAIN,
            anonymous=USE_TOR_FOR_RECON,
            bruteforce=USE_BRUTEFORCE_FOR_SUBDOMAINS,
            target_info=target_info
        )
    else:
        # Load existing recon file if domain_discovery not in modules
        if output_file.exists():
            with open(output_file, 'r') as f:
                domain_result = json.load(f)
            print(f"[*][Pipeline] Loaded existing recon file: {output_file}")

            # RoE: filter excluded hosts from loaded recon data
            if _settings.get('ROE_ENABLED') and _settings.get('ROE_EXCLUDED_HOSTS'):
                roe_excluded = _settings['ROE_EXCLUDED_HOSTS']
                dns_data = domain_result.get('dns', {})
                subs = dns_data.get('subdomains', {})
                excluded_subs = [s for s in subs if _is_roe_excluded(s, roe_excluded)]
                for s in excluded_subs:
                    del subs[s]
                if excluded_subs:
                    print(f"[RoE] Removed {len(excluded_subs)} excluded subdomain(s) from loaded recon file")
        else:
            print(f"[!][Pipeline] No existing recon file found: {output_file}")
            print(f"[!][Pipeline] Add 'domain_discovery' to SCAN_MODULES to create it first")
            return 1
        
        # Initialize skip_reasons tracker in metadata so every skipped phase
        # records why, not just that it didn't run.
        if "metadata" not in domain_result:
            domain_result["metadata"] = {}
        if "skip_reasons" not in domain_result["metadata"]:
            domain_result["metadata"]["skip_reasons"] = {}

        # Record why each phase is not running (helps downstream operators
        # distinguish "disabled by config" from "no targets" from "bug")
        _all_phases = ["port_scan", "http_probe", "resource_enum", "vuln_scan"]
        for _phase in _all_phases:
            if _phase not in SCAN_MODULES:
                domain_result["metadata"]["skip_reasons"].setdefault(
                    _phase, f"Not in SCAN_MODULES list"
                )

        # Run port_scan if in SCAN_MODULES (when domain_discovery is skipped)
        if "port_scan" in SCAN_MODULES:
            _naabu_on = _settings.get('NAABU_ENABLED', True)
            _masscan_on = _settings.get('MASSCAN_ENABLED', True)

            if not _naabu_on and not _masscan_on:
                domain_result["metadata"]["skip_reasons"]["port_scan"] = (
                    "Both Naabu and Masscan are disabled"
                )
                print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
                print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")
            else:
                if _naabu_on:
                    domain_result = run_port_scan(domain_result, output_file=output_file, settings=_settings)
                    if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                        if "port_scan" not in domain_result["metadata"]["modules_executed"]:
                            domain_result["metadata"]["modules_executed"].append("port_scan")

                if _masscan_on:
                    domain_result = run_masscan_scan(domain_result, output_file=None, settings=_settings)
                    merge_port_scan_results(domain_result)
                    if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                        if "masscan_scan" not in domain_result["metadata"]["modules_executed"]:
                            domain_result["metadata"]["modules_executed"].append("masscan_scan")

            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Update Graph DB with port scan data
            if UPDATE_GRAPH_DB:
                print(f"\n[*][graph-db] GRAPH UPDATE: Port Scan Data")
                print("-" * 40)
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            port_stats = graph_client.update_graph_from_port_scan(domain_result, USER_ID, PROJECT_ID)
                            domain_result["metadata"]["graph_db_port_scan_updated"] = True
                            domain_result["metadata"]["graph_db_port_scan_stats"] = port_stats
                            print(f"[+][graph-db] Graph database updated with port scan data")
                        else:
                            print(f"[!][graph-db] Could not connect to Neo4j - skipping port scan graph update")
                            domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except ImportError:
                    print(f"[!][graph-db] Neo4j client not available - skipping port scan graph update")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except Exception as e:
                    print(f"[!][graph-db] Port scan graph update failed: {e}")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                    domain_result["metadata"]["graph_db_port_scan_error"] = str(e)

                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)
        
        # Run http_probe if in SCAN_MODULES (when domain_discovery is skipped)
        if "http_probe" in SCAN_MODULES:
            if not _settings.get('HTTPX_ENABLED', True):
                domain_result["metadata"]["skip_reasons"]["http_probe"] = (
                    "httpx is disabled"
                )
                print("\n[*][httpx] HTTP probing disabled -- skipping")
            else:
                domain_result = run_http_probe(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "http_probe" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("http_probe")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with http probe data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: HTTP Probe Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                http_stats = graph_client.update_graph_from_http_probe(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_http_probe_updated"] = True
                                domain_result["metadata"]["graph_db_http_probe_stats"] = http_stats
                                print(f"[+][graph-db] Graph database updated with http probe data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping http probe graph update")
                                domain_result["metadata"]["graph_db_http_probe_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping http probe graph update")
                        domain_result["metadata"]["graph_db_http_probe_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] HTTP probe graph update failed: {e}")
                        domain_result["metadata"]["graph_db_http_probe_updated"] = False
                        domain_result["metadata"]["graph_db_http_probe_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

        # Check if we should skip active scanning modules (resource_enum, vuln_scan)
        # These require live targets from http_probe to work
        skip_active_scans, skip_reason = should_skip_active_scans(domain_result)
        
        if skip_active_scans:
            print(f"\n{'=' * 70}")
            print(f"[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
            print(f"[!][Pipeline] Modules skipped: resource_enum, vuln_scan")
            print(f"{'=' * 70}")
            if "metadata" in domain_result:
                domain_result["metadata"]["active_scans_skipped"] = True
                domain_result["metadata"]["active_scans_skip_reason"] = skip_reason
                domain_result["metadata"]["skip_reasons"]["resource_enum"] = skip_reason
                domain_result["metadata"]["skip_reasons"]["vuln_scan"] = skip_reason
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)
        else:
            # Run resource_enum if in SCAN_MODULES (when domain_discovery is skipped)
            if "resource_enum" in SCAN_MODULES:
                domain_result = run_resource_enum(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "resource_enum" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("resource_enum")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with resource enumeration data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: Resource Enumeration Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                resource_stats = graph_client.update_graph_from_resource_enum(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_resource_enum_updated"] = True
                                domain_result["metadata"]["graph_db_resource_enum_stats"] = resource_stats
                                print(f"[+][graph-db] Graph database updated with resource enumeration data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping resource enum graph update")
                                domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping resource enum graph update")
                        domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] Resource enum graph update failed: {e}")
                        domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                        domain_result["metadata"]["graph_db_resource_enum_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

        # GROUP 4.5 — AI Surface Recon (runs after resource_enum)
        domain_result = _maybe_run_ai_surface(domain_result, _settings, output_file)

        # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
        # runs even when active scans are skipped -- uploaded files don't need live targets)
        if _settings.get('JS_RECON_ENABLED', False):
            try:
                from recon.main_recon_modules.js_recon import run_js_recon
                domain_result = run_js_recon(domain_result, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "js_recon" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("js_recon")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                if UPDATE_GRAPH_DB:
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                graph_client.update_graph_from_js_recon(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_js_recon_updated"] = True
                                print(f"[+][graph-db] Graph database updated with JS Recon data")
                    except Exception as e:
                        print(f"[!][graph-db] JS Recon graph update failed: {e}")
                        domain_result["metadata"]["graph_db_js_recon_updated"] = False

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)
            except Exception as e:
                print(f"[!][JsRecon] Error: {e}")

        if not skip_active_scans:
            # Run vuln_scan if in SCAN_MODULES (when domain_discovery is skipped)
            # vuln_scan automatically includes MITRE CWE/CAPEC enrichment
            if "vuln_scan" in SCAN_MODULES:
                domain_result = run_vuln_scan(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "vuln_scan" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("vuln_scan")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Automatically run MITRE CWE/CAPEC enrichment after vuln_scan
                if _settings.get('MITRE_ENABLED', True):
                    domain_result = run_mitre_enrichment(domain_result, output_file=output_file, settings=_settings)
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with vuln scan data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: Vuln Scan Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                vuln_stats = graph_client.update_graph_from_vuln_scan(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_vuln_scan_updated"] = True
                                domain_result["metadata"]["graph_db_vuln_scan_stats"] = vuln_stats
                                print(f"[+][graph-db] Graph database updated with vuln scan data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping vuln scan graph update")
                                domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping vuln scan graph update")
                        domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] Vuln scan graph update failed: {e}")
                        domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                        domain_result["metadata"]["graph_db_vuln_scan_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n")
    print("─" * 50)
    print("  [✓][Pipeline] RECON PIPELINE COMPLETE")
    print("─" * 50)
    print(f"  [*][Pipeline] Duration: {duration:.2f} seconds")
    print(f"  [*][Pipeline] Target: {root_domain}")
    if filtered_mode:
        print(f"  [*][Pipeline] Mode: Filtered ({len(full_subdomains)} subdomain(s))")
    else:
        print(f"  [*][Pipeline] Mode: Full discovery")
        print(f"  [+][Pipeline] Subdomains found: {domain_result.get('subdomain_count', 0)}")

    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in domain_result:
        port_summary = domain_result["port_scan"].get("summary", {})
        naabu_ports = port_summary.get('total_open_ports', 0)
        hosts = port_summary.get('hosts_with_open_ports', 0)
        print(f"  [+][Naabu] Port Scan: {hosts} hosts, {naabu_ports} ports")
    elif "port_scan" not in SCAN_MODULES:
        print("  [-][Naabu] Port Scan: SKIPPED")

    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in domain_result:
        http_summary = domain_result["http_probe"].get("summary", {})
        live = http_summary.get('live_urls', 0)
        techs = http_summary.get('technology_count', 0)
        print(f"  [+][Httpx] HTTP Probe: {live} live URLs, {techs} technologies")
        if live > 0 and "port_scan" in domain_result:
            if domain_result["port_scan"].get("summary", {}).get("total_open_ports", 0) == 0:
                from urllib.parse import urlparse
                httpx_ports = set()
                for url in domain_result.get("http_probe", {}).get("by_url", {}):
                    p = urlparse(url)
                    httpx_ports.add(p.port or (443 if p.scheme == "https" else 80))
                if httpx_ports:
                    print(f"  [+][Httpx] Service ports (httpx): {', '.join(str(p) for p in sorted(httpx_ports))}")
    elif "http_probe" not in SCAN_MODULES:
        print("  [-][Httpx] HTTP Probe: SKIPPED")

    # Check if active scans were skipped due to no live targets
    active_scans_skipped = domain_result.get("metadata", {}).get("active_scans_skipped", False)
    skip_reason = domain_result.get("metadata", {}).get("active_scans_skip_reason", "")

    # Resource enumeration stats
    if active_scans_skipped:
        print(f"  [!][ResourceEnum] Resources: SKIPPED (no live targets)")
    elif "resource_enum" in SCAN_MODULES and "resource_enum" in domain_result:
        res_summary = domain_result["resource_enum"].get("summary", {})
        endpoints = res_summary.get('total_endpoints', 0)
        params = res_summary.get('total_parameters', 0)
        forms = res_summary.get('total_forms', 0)
        print(f"  [+][ResourceEnum] Resources: {endpoints} endpoints, {params} params, {forms} forms")
    elif "resource_enum" not in SCAN_MODULES:
        print("  [-][ResourceEnum] Resources: SKIPPED")

    # Vuln scan stats (includes MITRE enrichment)
    if active_scans_skipped:
        print(f"  [!][Nuclei] Vuln Scan: SKIPPED (no live targets)")
    elif "vuln_scan" in SCAN_MODULES and "vuln_scan" in domain_result:
        vuln_summary = domain_result["vuln_scan"].get("summary", {})
        total_findings = vuln_summary.get("total_findings", 0)
        crit = vuln_summary.get("critical", 0)
        high = vuln_summary.get("high", 0)
        vuln_info = f"{total_findings} findings"
        if crit > 0 or high > 0:
            vuln_info += f" ({crit} critical, {high} high)"
        print(f"  [+][Nuclei] Vuln Scan: {vuln_info}")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = domain_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            enriched = mitre_meta.get('total_cves_enriched', 0)
            total = mitre_meta.get('total_cves_processed', 0)
            print(f"  [+][MITRE] CWE/CAPEC: {enriched}/{total} CVEs enriched")
    elif "vuln_scan" not in SCAN_MODULES:
        print("  [-][Nuclei] Vuln Scan: SKIPPED")

    print("─" * 50)
    print("  [+][Pipeline] Output: recon_{}.json".format(PROJECT_ID))
    print("─" * 50)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
