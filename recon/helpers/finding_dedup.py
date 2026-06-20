"""
RedAmon - Cross-Phase Finding Deduplication
============================================
Deduplicate vulnerabilities found by multiple tools across different scan phases.

When the same issue is reported by nuclei, security_checks, nmap, and takeover_scan,
this module creates a single canonical finding with attribution to all sources.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CanonicalFinding:
    """A deduplicated finding with multi-source attribution."""
    canonical_id: str
    host: str
    port: Optional[int]
    category: str
    severity: str
    title: str
    description: str
    sources: list[str] = field(default_factory=list)
    source_details: list[dict] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    matched_at: str = ""
    first_seen_by: str = ""
    confidence: str = "high"  # high if multiple sources agree
    
    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "host": self.host,
            "port": self.port,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "sources": self.sources,
            "source_count": len(self.sources),
            "cves": self.cves,
            "cwes": self.cwes,
            "matched_at": self.matched_at,
            "first_seen_by": self.first_seen_by,
            "confidence": self.confidence,
            "corroborated": len(self.sources) > 1,
        }


# Severity ranking for picking the highest
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


# Category normalization map
CATEGORY_ALIASES = {
    # Version disclosure variants
    "version-disclosure": "information_disclosure",
    "version_disclosure": "information_disclosure",
    "server-version": "information_disclosure",
    "technology-detection": "information_disclosure",
    "tech-detect": "information_disclosure",
    
    # XSS variants
    "cross-site-scripting": "xss",
    "reflected-xss": "xss",
    "stored-xss": "xss",
    "dom-xss": "xss",
    
    # SQL injection variants
    "sql-injection": "sqli",
    "blind-sqli": "sqli",
    "time-based-sqli": "sqli",
    
    # Auth variants
    "authentication": "auth",
    "auth-bypass": "auth",
    "default-login": "auth",
    "default-credentials": "auth",
    "weak-password": "auth",
    
    # Exposure variants
    "exposed-panel": "exposure",
    "exposed_panel": "exposure",
    "admin-panel": "exposure",
    "sensitive-file": "exposure",
    "backup-file": "exposure",
    "config-exposure": "exposure",
    
    # Misconfig variants
    "misconfiguration": "misconfig",
    "security-misconfiguration": "misconfig",
    "insecure-configuration": "misconfig",
    
    # Header variants
    "missing-header": "header",
    "security-header": "header",
    "missing-security-header": "header",
    
    # TLS/SSL variants
    "ssl": "tls",
    "tls-issue": "tls",
    "certificate": "tls",
    "ssl-tls": "tls",
    
    # Takeover variants
    "subdomain-takeover": "takeover",
    "service-takeover": "takeover",
}

# Title patterns that indicate the same underlying issue
TITLE_SIMILARITY_PATTERNS = [
    # Server version disclosure
    (r"(apache|nginx|iis|tomcat).*version", "server_version"),
    (r"server.*header.*version", "server_version"),
    (r"x-powered-by", "powered_by_header"),
    
    # Missing headers
    (r"missing.*x-frame-options", "missing_xfo"),
    (r"missing.*x-content-type-options", "missing_xcto"),
    (r"missing.*strict-transport-security", "missing_hsts"),
    (r"missing.*content-security-policy", "missing_csp"),
    (r"missing.*referrer-policy", "missing_referrer"),
    
    # Default credentials
    (r"default.*(login|credential|password)", "default_creds"),
    
    # Directory listing
    (r"directory.*listing", "directory_listing"),
    (r"index.*of", "directory_listing"),
    
    # Backup files
    (r"backup.*file", "backup_file"),
    (r"\.(bak|backup|old|orig)", "backup_file"),
    
    # Git exposure
    (r"\.git", "git_exposure"),
    (r"git.*config", "git_exposure"),
    
    # Environment files
    (r"\.env", "env_exposure"),
    (r"environment.*file", "env_exposure"),
]


def normalize_category(category: str) -> str:
    """Normalize category to canonical form."""
    if not category:
        return "general"
    
    normalized = category.lower().strip().replace(" ", "_").replace("-", "_")
    return CATEGORY_ALIASES.get(normalized, normalized)


def normalize_severity(severity: str) -> str:
    """Normalize severity to lowercase standard form."""
    if not severity:
        return "unknown"
    return severity.lower().strip()


def extract_host_port(finding: dict) -> tuple[str, Optional[int]]:
    """Extract host and port from a finding."""
    # Try different field names
    host = (
        finding.get("host") or
        finding.get("target") or
        finding.get("url", "").split("/")[2] if "://" in finding.get("url", "") else ""
    )
    
    # Clean host (remove port if present in host string)
    if ":" in host and not host.startswith("["):  # Not IPv6
        parts = host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])
            return host, port
    
    port = finding.get("port")
    if port is not None:
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = None
    
    return host, port


def get_title_fingerprint(title: str) -> Optional[str]:
    """Get a fingerprint for the title based on known patterns."""
    if not title:
        return None
    
    title_lower = title.lower()
    for pattern, fingerprint in TITLE_SIMILARITY_PATTERNS:
        if re.search(pattern, title_lower):
            return fingerprint
    
    return None


def compute_finding_key(host: str, port: Optional[int], category: str, title_fp: Optional[str]) -> str:
    """Compute a deduplication key for a finding."""
    # Include title fingerprint if available for more precise dedup
    components = [
        host.lower(),
        str(port) if port else "0",
        normalize_category(category),
    ]
    if title_fp:
        components.append(title_fp)
    
    key_string = "|".join(components)
    return hashlib.md5(key_string.encode()).hexdigest()[:16]


def highest_severity(*severities: str) -> str:
    """Return the highest severity from a list."""
    normalized = [normalize_severity(s) for s in severities if s]
    if not normalized:
        return "unknown"
    
    return max(normalized, key=lambda s: SEVERITY_RANK.get(s, 0))


class FindingDeduplicator:
    """
    Deduplicate findings from multiple sources.
    
    Usage:
        dedup = FindingDeduplicator()
        
        # Add findings from different sources
        dedup.add_findings(nuclei_findings, source="nuclei")
        dedup.add_findings(security_check_findings, source="security_checks")
        dedup.add_findings(nmap_vulns, source="nmap")
        
        # Get deduplicated results
        results = dedup.get_deduplicated_findings()
    """
    
    def __init__(self):
        self._findings: dict[str, CanonicalFinding] = {}  # key -> canonical finding
        self._raw_count = 0
        
    def add_finding(self, finding: dict, source: str):
        """Add a single finding from a source."""
        host, port = extract_host_port(finding)
        if not host:
            return  # Can't deduplicate without host
        
        category = normalize_category(
            finding.get("category") or 
            finding.get("type") or 
            finding.get("vulnerability_type") or 
            "general"
        )
        
        title = finding.get("title") or finding.get("name") or finding.get("template_id", "")
        title_fp = get_title_fingerprint(title)
        
        key = compute_finding_key(host, port, category, title_fp)
        severity = normalize_severity(finding.get("severity", "unknown"))
        
        self._raw_count += 1
        
        if key in self._findings:
            # Merge with existing
            existing = self._findings[key]
            if source not in existing.sources:
                existing.sources.append(source)
                existing.source_details.append({
                    "source": source,
                    "original_title": title,
                    "original_severity": severity,
                })
            
            # Keep highest severity
            existing.severity = highest_severity(existing.severity, severity)
            
            # Merge CVEs
            for cve in finding.get("cves", []):
                cve_id = cve.get("id") if isinstance(cve, dict) else cve
                if cve_id and cve_id not in existing.cves:
                    existing.cves.append(cve_id)
            
            # Merge CWEs
            for cwe in finding.get("cwe_id", []) or finding.get("cwes", []):
                if cwe and cwe not in existing.cwes:
                    existing.cwes.append(cwe)
            
            # Update confidence if multiple sources
            if len(existing.sources) > 1:
                existing.confidence = "high"
        else:
            # Create new canonical finding
            cves = []
            for cve in finding.get("cves", []):
                cve_id = cve.get("id") if isinstance(cve, dict) else cve
                if cve_id:
                    cves.append(cve_id)
            
            self._findings[key] = CanonicalFinding(
                canonical_id=key,
                host=host,
                port=port,
                category=category,
                severity=severity,
                title=title,
                description=finding.get("description", ""),
                sources=[source],
                source_details=[{
                    "source": source,
                    "original_title": title,
                    "original_severity": severity,
                }],
                cves=cves,
                cwes=list(finding.get("cwe_id", []) or finding.get("cwes", [])),
                matched_at=finding.get("matched_at", "") or finding.get("url", ""),
                first_seen_by=source,
                confidence="medium",  # Single source = medium
            )
    
    def add_findings(self, findings: list[dict], source: str):
        """Add multiple findings from a source."""
        for finding in findings:
            self.add_finding(finding, source)
    
    def get_deduplicated_findings(self) -> list[dict]:
        """Get list of deduplicated findings as dictionaries."""
        return [f.to_dict() for f in sorted(
            self._findings.values(),
            key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.host, f.category)
        )]
    
    def get_summary(self) -> dict:
        """Get deduplication summary statistics."""
        findings = list(self._findings.values())
        
        # Count by severity
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        # Count corroborated (multi-source)
        corroborated = sum(1 for f in findings if len(f.sources) > 1)
        
        # Source contribution
        source_counts = {}
        for f in findings:
            for src in f.sources:
                source_counts[src] = source_counts.get(src, 0) + 1
        
        dedup_count = len(findings)
        dedup_rate = ((self._raw_count - dedup_count) / self._raw_count * 100) if self._raw_count else 0
        
        return {
            "raw_finding_count": self._raw_count,
            "deduplicated_count": dedup_count,
            "duplicates_removed": self._raw_count - dedup_count,
            "deduplication_rate": round(dedup_rate, 1),
            "corroborated_findings": corroborated,
            "by_severity": by_severity,
            "by_source": source_counts,
        }
    
    def print_summary(self):
        """Print human-readable deduplication summary."""
        summary = self.get_summary()
        
        print(f"\n[*][FindingDedup] Cross-Phase Deduplication Results")
        print(f"    Raw findings: {summary['raw_finding_count']}")
        print(f"    After dedup: {summary['deduplicated_count']}")
        print(f"    Duplicates removed: {summary['duplicates_removed']} ({summary['deduplication_rate']}%)")
        print(f"    Multi-source corroborated: {summary['corroborated_findings']}")
        
        if summary['by_severity']:
            print(f"    By severity:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = summary['by_severity'].get(sev, 0)
                if count:
                    print(f"      • {sev}: {count}")


def deduplicate_scan_results(
    vuln_scan_findings: list[dict] = None,
    security_check_findings: list[dict] = None,
    nmap_vulns: list[dict] = None,
    takeover_findings: list[dict] = None,
    js_recon_findings: list[dict] = None,
    graphql_findings: list[dict] = None,
) -> dict:
    """
    Convenience function to deduplicate findings from all scan phases.
    
    Args:
        vuln_scan_findings: Nuclei vulnerability scan results
        security_check_findings: Custom security check results
        nmap_vulns: Nmap script scan vulnerabilities
        takeover_findings: Subdomain takeover scan results
        js_recon_findings: JavaScript recon findings (secrets, endpoints)
        graphql_findings: GraphQL security scan findings
        
    Returns:
        Dictionary with deduplicated findings and statistics
    """
    dedup = FindingDeduplicator()
    
    if vuln_scan_findings:
        dedup.add_findings(vuln_scan_findings, "nuclei")
    
    if security_check_findings:
        dedup.add_findings(security_check_findings, "security_checks")
    
    if nmap_vulns:
        dedup.add_findings(nmap_vulns, "nmap")
    
    if takeover_findings:
        dedup.add_findings(takeover_findings, "takeover_scan")
    
    if js_recon_findings:
        dedup.add_findings(js_recon_findings, "js_recon")
    
    if graphql_findings:
        dedup.add_findings(graphql_findings, "graphql_scan")
    
    dedup.print_summary()
    
    return {
        "findings": dedup.get_deduplicated_findings(),
        "summary": dedup.get_summary(),
    }
