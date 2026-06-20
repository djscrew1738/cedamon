"""
RedAmon - CVE to Service Version Correlation
=============================================
Cross-validates Nuclei CVE findings against Nmap service versions.

Reduces false positives by:
- Checking if detected service version falls within CVE's affected range
- Flagging version mismatches for manual review
- Adding confidence scores based on version correlation

Usage:
    from recon.helpers import CVEVersionCorrelator
    
    correlator = CVEVersionCorrelator()
    
    # Load service versions from nmap
    correlator.load_service_versions(nmap_results)
    
    # Correlate CVE findings
    enhanced_findings = correlator.correlate_findings(nuclei_findings)
    
    # Each finding now has:
    # - version_correlated: True/False
    # - version_confidence: "high"/"medium"/"low"/"unknown"
    # - version_mismatch_reason: "Detected v2.4.41, CVE affects <2.4.39"
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Try to import packaging for robust version comparison, fall back to basic
try:
    from packaging import version as pkg_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False
    logger.debug("packaging module not available, using fallback version comparison")


class _FallbackVersion:
    """Simple version comparison when packaging module is unavailable."""
    
    def __init__(self, version_str: str):
        self.raw = version_str
        # Extract numeric parts for comparison
        parts = re.findall(r'\d+', version_str)
        self.parts = [int(p) for p in parts] if parts else [0]
    
    def __lt__(self, other):
        return self.parts < other.parts
    
    def __le__(self, other):
        return self.parts <= other.parts
    
    def __gt__(self, other):
        return self.parts > other.parts
    
    def __ge__(self, other):
        return self.parts >= other.parts
    
    def __eq__(self, other):
        return self.parts == other.parts
    
    def __str__(self):
        return self.raw


def _parse_version(version_str: str):
    """Parse version string using packaging or fallback."""
    if HAS_PACKAGING:
        try:
            return pkg_version.parse(version_str)
        except Exception:
            return _FallbackVersion(version_str)
    return _FallbackVersion(version_str)


@dataclass 
class ServiceVersion:
    """Parsed service version information."""
    product: str
    version: str
    raw_string: str
    host: str
    port: int
    protocol: str = "tcp"
    cpe: str = ""
    extra_info: str = ""
    
    def matches_product(self, product_pattern: str) -> bool:
        """Check if this service matches a product pattern."""
        pattern = product_pattern.lower()
        return (
            pattern in self.product.lower() or
            pattern in self.raw_string.lower() or
            pattern in self.cpe.lower()
        )


@dataclass
class VersionRange:
    """Represents a version range for CVE affected products."""
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    min_inclusive: bool = True
    max_inclusive: bool = False
    fixed_version: Optional[str] = None
    
    def contains(self, test_version: str) -> tuple[bool, str]:
        """
        Check if a version falls within this range.
        
        Returns:
            Tuple of (is_affected, reason)
        """
        try:
            test_v = self._normalize_version(test_version)
            
            # Check against fixed version
            if self.fixed_version:
                fixed_v = self._normalize_version(self.fixed_version)
                if test_v >= fixed_v:
                    return False, f"Version {test_version} >= fixed version {self.fixed_version}"
            
            # Check min version
            if self.min_version:
                min_v = self._normalize_version(self.min_version)
                if self.min_inclusive:
                    if test_v < min_v:
                        return False, f"Version {test_version} < min {self.min_version}"
                else:
                    if test_v <= min_v:
                        return False, f"Version {test_version} <= min {self.min_version}"
            
            # Check max version
            if self.max_version:
                max_v = self._normalize_version(self.max_version)
                if self.max_inclusive:
                    if test_v > max_v:
                        return False, f"Version {test_version} > max {self.max_version}"
                else:
                    if test_v >= max_v:
                        return False, f"Version {test_version} >= max {self.max_version}"
            
            return True, "Version in affected range"
            
        except Exception as e:
            return True, f"Could not compare versions: {e}"
    
    def _normalize_version(self, v: str):
        """Normalize version string for comparison."""
        # Remove common prefixes
        v = re.sub(r'^[vV]', '', v)
        # Handle versions like "2.4.41-ubuntu4.13"
        v = re.split(r'[-+~]', v)[0]
        # Handle versions like "1.2.3p1" -> "1.2.3.1"
        v = re.sub(r'p(\d)', r'.\1', v)
        return _parse_version(v)


# Known CVE version mappings for common products
# Format: CVE -> { "product_patterns": [...], "affected_range": VersionRange }
KNOWN_CVE_VERSIONS = {
    # Apache
    "CVE-2021-41773": {
        "products": ["apache", "httpd", "apache http server"],
        "range": VersionRange(min_version="2.4.49", max_version="2.4.49", max_inclusive=True),
    },
    "CVE-2021-42013": {
        "products": ["apache", "httpd", "apache http server"],
        "range": VersionRange(min_version="2.4.49", max_version="2.4.50", max_inclusive=True),
    },
    "CVE-2019-0211": {
        "products": ["apache", "httpd"],
        "range": VersionRange(min_version="2.4.17", max_version="2.4.38", max_inclusive=True),
    },
    
    # Nginx
    "CVE-2021-23017": {
        "products": ["nginx"],
        "range": VersionRange(max_version="1.20.1", fixed_version="1.20.1"),
    },
    
    # OpenSSH
    "CVE-2023-38408": {
        "products": ["openssh", "ssh"],
        "range": VersionRange(max_version="9.3p1", fixed_version="9.3p2"),
    },
    "CVE-2016-20012": {
        "products": ["openssh", "ssh"],
        "range": VersionRange(max_version="8.7"),
    },
    
    # OpenSSL
    "CVE-2022-3602": {
        "products": ["openssl"],
        "range": VersionRange(min_version="3.0.0", max_version="3.0.6", max_inclusive=True),
    },
    "CVE-2022-3786": {
        "products": ["openssl"],
        "range": VersionRange(min_version="3.0.0", max_version="3.0.6", max_inclusive=True),
    },
    
    # MySQL
    "CVE-2012-2122": {
        "products": ["mysql", "mariadb"],
        "range": VersionRange(max_version="5.1.63", max_inclusive=True),
    },
    
    # PHP
    "CVE-2019-11043": {
        "products": ["php"],
        "range": VersionRange(min_version="7.1.0", max_version="7.3.11", max_inclusive=True),
    },
    
    # Redis
    "CVE-2022-0543": {
        "products": ["redis"],
        "range": VersionRange(max_version="6.2.6", max_inclusive=True),
    },
    
    # Elasticsearch
    "CVE-2015-1427": {
        "products": ["elasticsearch"],
        "range": VersionRange(max_version="1.4.2", max_inclusive=True),
    },
    
    # Tomcat
    "CVE-2020-1938": {
        "products": ["tomcat", "apache tomcat"],
        "range": VersionRange(max_version="9.0.30", max_inclusive=True),
    },
}


class CVEVersionCorrelator:
    """
    Correlates CVE findings with detected service versions.
    
    Improves finding accuracy by validating that detected CVEs
    actually apply to the service versions found by Nmap.
    """
    
    def __init__(self, custom_mappings: dict | None = None):
        """
        Initialize correlator.
        
        Args:
            custom_mappings: Additional CVE->version mappings
        """
        self._service_versions: dict[str, list[ServiceVersion]] = {}
        self._correlations: list[dict] = []
        
        # Merge custom mappings with known
        self._cve_mappings = dict(KNOWN_CVE_VERSIONS)
        if custom_mappings:
            self._cve_mappings.update(custom_mappings)
        
        self._stats = {
            'findings_processed': 0,
            'version_correlated': 0,
            'version_mismatch': 0,
            'no_version_data': 0,
            'unknown_cve': 0,
        }
    
    def load_service_versions(self, nmap_results: dict):
        """
        Load service versions from Nmap scan results.
        
        Args:
            nmap_results: Nmap scan results dict with by_host structure
        """
        by_host = nmap_results.get('by_host', {})
        
        for host, host_data in by_host.items():
            if host not in self._service_versions:
                self._service_versions[host] = []
            
            ports = host_data.get('port_details', [])
            for port_info in ports:
                service = port_info.get('service', {})
                if not service:
                    continue
                
                product = service.get('product', '')
                version = service.get('version', '')
                
                if product or version:
                    sv = ServiceVersion(
                        product=product,
                        version=version,
                        raw_string=service.get('name', '') + ' ' + product + ' ' + version,
                        host=host,
                        port=port_info.get('port', 0),
                        protocol=port_info.get('protocol', 'tcp'),
                        cpe=service.get('cpe', ''),
                        extra_info=service.get('extrainfo', ''),
                    )
                    self._service_versions[host].append(sv)
        
        total_services = sum(len(v) for v in self._service_versions.values())
        print(f"[+][CVE] Loaded {total_services} service versions from {len(self._service_versions)} hosts")
    
    def _find_matching_service(self, host: str, cve_id: str) -> ServiceVersion | None:
        """Find a service version that matches the CVE's target product."""
        if cve_id not in self._cve_mappings:
            return None
        
        mapping = self._cve_mappings[cve_id]
        products = mapping.get('products', [])
        
        services = self._service_versions.get(host, [])
        for service in services:
            for product_pattern in products:
                if service.matches_product(product_pattern):
                    return service
        
        return None
    
    def _extract_host_from_finding(self, finding: dict) -> str:
        """Extract host from a Nuclei finding."""
        # Try various fields
        host = finding.get('host', '')
        if host:
            # Strip protocol and path
            host = re.sub(r'^https?://', '', host)
            host = host.split('/')[0].split(':')[0]
            return host.lower()
        
        matched_at = finding.get('matched_at', '')
        if matched_at:
            matched_at = re.sub(r'^https?://', '', matched_at)
            return matched_at.split('/')[0].split(':')[0].lower()
        
        return ''
    
    def correlate_finding(self, finding: dict) -> dict:
        """
        Correlate a single CVE finding with service version data.
        
        Args:
            finding: Nuclei finding dict
            
        Returns:
            Enhanced finding with version correlation data
        """
        self._stats['findings_processed'] += 1
        
        # Extract CVE IDs
        cves = finding.get('cves', [])
        if not cves:
            # Try to extract from template_id
            template_id = finding.get('template_id', '')
            cve_match = re.search(r'CVE-\d{4}-\d+', template_id, re.IGNORECASE)
            if cve_match:
                cves = [{'id': cve_match.group(0).upper()}]
        
        if not cves:
            finding['version_correlated'] = False
            finding['version_confidence'] = 'unknown'
            finding['version_correlation_note'] = 'No CVE ID in finding'
            self._stats['unknown_cve'] += 1
            return finding
        
        # Extract host
        host = self._extract_host_from_finding(finding)
        if not host:
            finding['version_correlated'] = False
            finding['version_confidence'] = 'unknown'
            finding['version_correlation_note'] = 'Could not determine host'
            return finding
        
        # Check each CVE
        correlations = []
        for cve in cves:
            cve_id = cve.get('id', '').upper()
            
            if cve_id not in self._cve_mappings:
                correlations.append({
                    'cve': cve_id,
                    'status': 'no_mapping',
                    'note': 'CVE not in version database'
                })
                continue
            
            # Find matching service
            service = self._find_matching_service(host, cve_id)
            if not service:
                correlations.append({
                    'cve': cve_id,
                    'status': 'no_service',
                    'note': 'No matching service version found'
                })
                self._stats['no_version_data'] += 1
                continue
            
            if not service.version:
                correlations.append({
                    'cve': cve_id,
                    'status': 'no_version',
                    'note': f'Service {service.product} detected but no version'
                })
                continue
            
            # Check version range
            mapping = self._cve_mappings[cve_id]
            version_range = mapping.get('range')
            
            if version_range:
                is_affected, reason = version_range.contains(service.version)
                correlations.append({
                    'cve': cve_id,
                    'status': 'affected' if is_affected else 'not_affected',
                    'detected_version': service.version,
                    'detected_product': service.product,
                    'port': service.port,
                    'note': reason,
                })
                
                if is_affected:
                    self._stats['version_correlated'] += 1
                else:
                    self._stats['version_mismatch'] += 1
        
        # Summarize correlations
        affected_count = sum(1 for c in correlations if c.get('status') == 'affected')
        not_affected_count = sum(1 for c in correlations if c.get('status') == 'not_affected')
        
        finding['version_correlations'] = correlations
        
        if not_affected_count > 0 and affected_count == 0:
            # All checked CVEs show version mismatch
            finding['version_correlated'] = False
            finding['version_confidence'] = 'low'
            finding['version_mismatch'] = True
            mismatch_notes = [c.get('note', '') for c in correlations if c.get('status') == 'not_affected']
            finding['version_mismatch_reason'] = '; '.join(mismatch_notes[:2])
        elif affected_count > 0:
            # At least one CVE confirmed by version
            finding['version_correlated'] = True
            finding['version_confidence'] = 'high'
        else:
            # Could not correlate (no mapping or no service data)
            finding['version_correlated'] = False
            finding['version_confidence'] = 'medium'
        
        return finding
    
    def correlate_findings(self, findings: list[dict]) -> list[dict]:
        """
        Correlate a list of CVE findings with service versions.
        
        Args:
            findings: List of Nuclei findings
            
        Returns:
            List of enhanced findings with version correlation
        """
        if not self._service_versions:
            logger.warning("[CVE] No service versions loaded - correlation will be limited")
        
        enhanced = []
        for finding in findings:
            enhanced.append(self.correlate_finding(finding))
        
        # Print summary
        print(f"[+][CVE] Version correlation complete:")
        print(f"    Processed: {self._stats['findings_processed']}")
        print(f"    Correlated (high confidence): {self._stats['version_correlated']}")
        print(f"    Mismatches (potential FP): {self._stats['version_mismatch']}")
        print(f"    No version data: {self._stats['no_version_data']}")
        
        return enhanced
    
    def get_likely_false_positives(self, findings: list[dict]) -> list[dict]:
        """
        Get findings that are likely false positives based on version mismatch.
        
        These findings have CVEs that don't match the detected service version.
        """
        return [
            f for f in findings
            if f.get('version_mismatch') and f.get('version_confidence') == 'low'
        ]
    
    def get_stats(self) -> dict:
        """Get correlation statistics."""
        return self._stats.copy()
    
    def add_cve_mapping(self, cve_id: str, products: list[str], 
                        version_range: VersionRange):
        """
        Add a custom CVE->version mapping.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")
            products: List of product name patterns to match
            version_range: VersionRange defining affected versions
        """
        self._cve_mappings[cve_id.upper()] = {
            'products': products,
            'range': version_range,
        }


def correlate_vulns_with_versions(
    nuclei_findings: list[dict],
    nmap_results: dict,
) -> list[dict]:
    """
    Convenience function to correlate Nuclei findings with Nmap versions.
    
    Args:
        nuclei_findings: List of Nuclei vulnerability findings
        nmap_results: Nmap scan results dict
    
    Returns:
        Enhanced findings with version correlation
    """
    correlator = CVEVersionCorrelator()
    correlator.load_service_versions(nmap_results)
    return correlator.correlate_findings(nuclei_findings)
