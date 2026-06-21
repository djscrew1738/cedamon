#!/usr/bin/env python3
"""Replace silent ``except Exception: pass`` with logged warnings.

Two modes:
- Files with module-level ``logger`` → add ``logger.warning(..., exc_info=True)``
- Files without logger (they use ``print()`` for Docker-captured stdout) → add ``print()``
"""

import re
import ast
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fix_except_pass")

REPO = Path("/home/djscrew/redamon")

TARGETS = [
    "recon/helpers/security_checks.py",
    "recon/partial_recon_modules/web_crawling.py",
    "recon_orchestrator/container_manager.py",
    "recon/partial_recon_modules/parameter_discovery.py",
    "recon/main_recon_modules/ai_surface_recon.py",
    "recon/main_recon_modules/subdomain_takeover.py",
    "recon/helpers/scan_runtime.py",
    "recon/main_recon_modules/http_probe.py",
    "recon/helpers/anonymity.py",
    "recon/partial_recon_modules/port_scanning.py",
    "recon/partial_recon_modules/http_probing.py",
    "recon/main_recon_modules/vuln_scan.py",
    "recon/main_recon_modules/port_scan.py",
    "recon/main_recon_modules/nmap_scan.py",
    "recon/main_recon_modules/masscan_scan.py",
    "recon/main_recon_modules/domain_recon.py",
    "recon/main_recon_modules/resource_enum.py",
    "recon/main_recon_modules/add_mitre.py",
    "recon/main_recon_modules/js_recon.py",
    "recon/main_recon_modules/urlscan_enrich.py",
    "recon/partial_recon_modules/js_analysis.py",
    "recon_orchestrator/api.py",
    "recon/helpers/resource_enum/katana_helpers.py",
    "recon/helpers/resource_enum/kiterunner_helpers.py",
    "recon/helpers/resource_enum/paramspider_helpers.py",
    "recon/helpers/resource_enum/zap_ajax_spider_helpers.py",
    "recon/helpers/resource_enum/arjun_helpers.py",
    "recon/helpers/resource_enum/gau_helpers.py",
    "recon/helpers/resource_enum/jsluice_helpers.py",
    "recon/helpers/resource_enum/waymore_helpers.py",
    "recon/helpers/resource_enum/ffuf_helpers.py",
    "recon/helpers/resource_enum/hakrawler_helpers.py",
    "recon/helpers/domain_recon/alterx_helpers.py",
    "recon/helpers/domain_recon/cloudlist_helpers.py",
    "recon/helpers/domain_recon/bbot_helpers.py",
    "recon/helpers/domain_recon/_tool_docker_utils.py",
    "recon/helpers/js_recon/sourcemap.py",
    "recon/main_recon_modules/criminalip_enrich.py",
    "recon/main_recon_modules/zoomeye_enrich.py",
    "recon/main_recon_modules/fofa_enrich.py",
    "recon/main_recon_modules/shodan_enrich.py",
    "recon/main_recon_modules/virustotal_enrich.py",
    "recon/main_recon_modules/netlas_enrich.py",
    "recon/main_recon_modules/whois_recon.py",
    "recon/helpers/cve_helpers.py",
    "recon/helpers/domain_recon/dnsx_helpers.py",
    "recon/helpers/js_recon/validators.py",
    "recon/main_recon_modules/otx_enrich.py",
    "recon/main.py",
    "recon/project_settings.py",
    "recon/helpers/resource_enum/endpoint_helpers.py",
    # Tier 1.1 — Non-recon silent excepts
    "github_secret_hunt/github_secret_hunt.py",
    "graph_db/mixins/recon/js_recon_mixin.py",
    "graph_db/neo4j_client_legacy.py",
    "graph_db/schema.py",
    "guinea_pigs/ai_surface_target/smart_recon_surface_automation.py",
    "gvm_scan/gvm_scanner.py",
    "gvm_scan/ready_probe.py",
    "knowledge_base/curation/data_ingestion.py",
    "mcp/servers/metasploit_server.py",
    "mcp/servers/network_recon_server.py",
    "mcp/servers/nuclei_server.py",
    "mcp/servers/terminal_server.py",
]


def file_has_logger(path: Path) -> bool:
    """Check if *path* already has a ``logger =`` binding."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "logger":
                    return True
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "logger":
                return True
    return False


def uses_print_logging(path: Path) -> bool:
    """Heuristic: does the file already use ``print()`` for status output?"""
    text = path.read_text()
    # Check for common recon-module print patterns like print(f"[!] ...") or print("[*] ...")
    if re.search(r"print\(\s*f?[\"'][\[!]", text):
        return True
    # Check for custom _log() wrappers that call print() internally
    if re.search(r"def _log\(.*print\(", text):
        return True
    return False


def get_function_name(lines: list[str], except_line: int) -> str:
    """Walk backwards from *except_line* to find the enclosing function."""
    for i in range(except_line - 2, -1, -1):
        m = re.match(r"^(\s*)def\s+(\w+)\s*\(", lines[i])
        if m:
            return m.group(2)
    return "<module>"


def find_best_context_hint(lines: list[str], except_line: int) -> str:
    """Walk backwards from the except to find the most descriptive context.

    Tries (in order):
    1. A comment on the line(s) above
    2. The first significant statement in the try block
    """
    # Look for comment
    for i in range(except_line - 2, max(except_line - 6, -1), -1):
        line = lines[i].strip()
        if line.startswith("#"):
            return line.lstrip("# ").strip()

    # Look for first statement inside try block
    depth = 0
    for i in range(except_line - 2, -1, -1):
        stripped = lines[i].strip()
        if stripped.startswith("try:"):
            # Now look forward from try to find the first real statement
            for j in range(i + 1, except_line):
                s = lines[j].strip()
                if s and not s.startswith("#") and not s == "try:" and not s.startswith("except"):
                    # Remove common prefixes
                    for prefix in ("result = ", "return ", "self.", "_"):
                        if s.startswith(prefix):
                            s = s[len(prefix):]
                            break
                    return s.rstrip(":")
        if stripped.startswith("except "):
            depth += 1
        elif stripped == "" or stripped.startswith("#"):
            continue
        elif depth == 0 and not stripped.startswith(("elif", "else", "finally", "return", "raise")):
            # Not inside a nested except — this is probably the try statement
            pass

    return ""


def make_warning_message(lines: list[str], except_line: int) -> str:
    """Build a meaningful warning message from context."""
    func = get_function_name(lines, except_line)
    hint = find_best_context_hint(lines, except_line)
    if hint:
        # Shorten to 80 chars max and sanitize quotes
        short_hint = hint[:80].replace('"', "'").replace('\\', "/")
        return f"{func}: {short_hint}"
    return f"{func}: best-effort operation"


def fix_file(rel_path: str) -> bool:
    path = REPO / rel_path
    if not path.exists():
        logger.warning("SKIP: %s not found", rel_path)
        return False

    has_logger = file_has_logger(path)
    use_print = uses_print_logging(path)

    if not has_logger and not use_print:
        logger.warning("SKIP: %s has no logger and no print-logging pattern", rel_path)
        return False

    with open(path) as f:
        text = f.read()
    lines = text.splitlines(keepends=True)

    changes = 0
    i = 0
    new_lines = list(lines)
    while i < len(new_lines):
        stripped = new_lines[i].strip()
        # Match both bare "except:" and "except Exception:" (but not "except Exception as e:")
        if re.match(r"except(\s+Exception)?\s*:\s*$", stripped):
            if i + 1 < len(new_lines):
                next_stripped = new_lines[i + 1].strip()
                if next_stripped == "pass" or next_stripped.startswith("pass  #"):
                    msg = make_warning_message(lines, i)
                    indent = new_lines[i][:len(new_lines[i]) - len(new_lines[i].lstrip())]
                    if has_logger:
                        log_line = f'{indent}    logger.warning("{msg}", exc_info=True)\n'
                    else:
                        log_line = f'{indent}    print(f"[!] {msg}")\n'
                    new_lines.insert(i + 1, log_line)
                    changes += 1
                    i += 2
                    continue
        i += 1

    if changes:
        with open(path, "w") as f:
            f.writelines(new_lines)
        logger.info("FIXED %s (%d changes)", rel_path, changes)
    else:
        logger.info("NO_CHANGE %s", rel_path)
    return changes > 0


def main():
    fixed = 0
    for target in TARGETS:
        if fix_file(target):
            fixed += 1
    # Also fix the messages from container_manager.py that were already edited
    # (run it again to catch any remaining instances)
    for extra in ["recon_orchestrator/container_manager.py"]:
        fix_file(extra)
    logger.info("Done. Fixed %d / %d files.", fixed, len(TARGETS))


if __name__ == "__main__":
    main()
