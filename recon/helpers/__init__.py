"""
RedAmon - Vulnerability Scan Helpers
=====================================

This package contains helper functions organized by category:

- docker_helpers: Docker utilities (container management, image pulls, permissions)
- target_helpers: Target extraction and URL building from recon data
- nuclei_helpers: Nuclei command building, output parsing, false positive detection
- katana_helpers: Katana web crawler for URL discovery
- cve_helpers: CVE lookup from NVD and Vulners APIs
- security_checks: Custom security checks (direct IP access, TLS, headers, etc.)
- adaptive_rate: Dynamic rate limiting based on target response patterns
- coverage_metrics: Scan coverage tracking and gap analysis
- template_selector: Service-aware Nuclei template selection
- finding_dedup: Cross-phase finding deduplication
- network_health: Pre-scan Tor/proxy health assessment
- scan_checkpoint: Scan checkpoint and resumability
- smart_retry: Unified retry decorator with failure classification
- target_priority: Target prioritization queue based on attack surface
- dns_prevalidation: DNS pre-validation before port scanning
- cve_version_correlation: CVE to service version correlation
"""

# Standard logging
from .log_helpers import (
    print_effective_settings,
    is_sensitive_key,
)

# Shared file/process utilities
from ._file_utils import (
    get_real_user_ids,
    fix_file_ownership,
)

# Docker utilities
from .docker_helpers import (
    is_docker_installed,
    is_docker_running,
    pull_nuclei_docker_image,
    pull_katana_docker_image,
    ensure_templates_volume,
    is_tor_running,
    NUCLEI_TEMPLATES_VOLUME,
)

# Target extraction and URL building
from .target_helpers import (
    extract_targets_from_recon,
    build_target_urls_from_httpx,
    build_target_urls_from_resource_enum,
    build_target_urls,
)

# Nuclei-specific helpers
from .nuclei_helpers import (
    build_nuclei_command,
    parse_nuclei_finding,
    is_false_positive,
    set_fp_ai_ctx,
)

# Katana web crawler
from .katana_helpers import (
    run_katana_crawler,
)

# CVE lookup
from .cve_helpers import (
    split_server_header,
    parse_technology_string,
    normalize_product_name,
    classify_cvss_score,
    lookup_cves_nvd,
    lookup_cves_vulners,
    run_cve_lookup,
    CPE_MAPPINGS,
    NVD_API_URL,
    VULNERS_API_URL,
)

# Security checks
from .security_checks import (
    run_security_checks,
)

# Subdomain takeover helpers
from .takeover_helpers import (
    build_subjack_command,
    build_baddns_command,
    normalize_subjack_result,
    normalize_nuclei_takeover,
    normalize_baddns_finding,
    dedupe_findings,
    score_finding,
    finding_id,
    provider_from_cname,
    provider_from_signal,
    resolve_cname_target,
    AUTO_EXPLOITABLE_PROVIDERS,
    PROVIDER_FROM_SIGNAL,
    BADDNS_MODULES,
    BADDNS_DEFAULT_MODULES,
)

# Anonymity/Tor utilities
from .anonymity import (
    is_tor_running as is_tor_running_anonymity,
    is_proxychains_available,
    get_proxychains_cmd,
    get_tor_session,
    get_tor_exit_ip,
    check_tor_connection,
    print_anonymity_status,
    run_through_tor,
    run_command_anonymous,
    get_real_ip,
    require_tor,
    TorProxy,
)

# Scan quality improvements
from .adaptive_rate import (
    AdaptiveRateLimiter,
    TargetHealthMonitor,
    RateDecision,
)

from .coverage_metrics import (
    CoverageTracker,
    ScanStatus,
    get_coverage_tracker,
    reset_coverage_tracker,
)

from .template_selector import (
    select_templates_for_fingerprint,
    select_templates_from_http_probe,
    build_nuclei_template_args,
    print_template_selection_summary,
    normalize_tech_name,
)

from .finding_dedup import (
    FindingDeduplicator,
    deduplicate_scan_results,
    CanonicalFinding,
)

from .network_health import (
    assess_tor_health,
    assess_direct_connectivity,
    run_pre_scan_health_check,
    check_tor_port,
    request_new_tor_circuit,
    NetworkHealthReport,
)

# Additional scan quality improvements (batch 2)
from .scan_checkpoint import (
    ScanCheckpoint,
    should_resume_scan,
)

from .smart_retry import (
    smart_retry,
    retry_api_call,
    retry_dns_lookup,
    retry_network_request,
    RetryConfig,
    RetryStats,
    ErrorClass,
    CircuitBreakerOpen,
    get_all_retry_stats,
    classify_error,
)

from .target_priority import (
    TargetPriorityQueue,
    ScoredTarget,
    prioritize_from_http_probe,
    print_priority_summary,
)

from .dns_prevalidation import (
    DNSPreValidator,
    DNSValidationResult,
    prevalidate_subdomains,
    filter_dns_stale,
)

from .cve_version_correlation import (
    CVEVersionCorrelator,
    VersionRange,
    ServiceVersion,
    correlate_vulns_with_versions,
    KNOWN_CVE_VERSIONS,
)

__all__ = [
    # Docker
    "is_docker_installed",
    "is_docker_running",
    "get_real_user_ids",
    "fix_file_ownership",
    "pull_nuclei_docker_image",
    "pull_katana_docker_image",
    "ensure_templates_volume",
    "is_tor_running",
    "NUCLEI_TEMPLATES_VOLUME",
    # Targets
    "extract_targets_from_recon",
    "build_target_urls_from_httpx",
    "build_target_urls_from_resource_enum",
    "build_target_urls",
    # Nuclei
    "build_nuclei_command",
    "parse_nuclei_finding",
    "is_false_positive",
    "set_fp_ai_ctx",
    # Katana
    "run_katana_crawler",
    # CVE
    "split_server_header",
    "parse_technology_string",
    "normalize_product_name",
    "classify_cvss_score",
    "lookup_cves_nvd",
    "lookup_cves_vulners",
    "run_cve_lookup",
    "CPE_MAPPINGS",
    "NVD_API_URL",
    "VULNERS_API_URL",
    # Security checks
    "run_security_checks",
    # Takeover
    "build_subjack_command",
    "build_baddns_command",
    "normalize_subjack_result",
    "normalize_nuclei_takeover",
    "normalize_baddns_finding",
    "dedupe_findings",
    "score_finding",
    "finding_id",
    "provider_from_cname",
    "provider_from_signal",
    "resolve_cname_target",
    "AUTO_EXPLOITABLE_PROVIDERS",
    "PROVIDER_FROM_SIGNAL",
    "BADDNS_MODULES",
    "BADDNS_DEFAULT_MODULES",
    # Anonymity/Tor
    "is_tor_running_anonymity",
    "is_proxychains_available",
    "get_proxychains_cmd",
    "get_tor_session",
    "get_tor_exit_ip",
    "check_tor_connection",
    "print_anonymity_status",
    "run_through_tor",
    "run_command_anonymous",
    "get_real_ip",
    "require_tor",
    "TorProxy",
    # Scan quality improvements
    "AdaptiveRateLimiter",
    "TargetHealthMonitor",
    "RateDecision",
    "CoverageTracker",
    "ScanStatus",
    "get_coverage_tracker",
    "reset_coverage_tracker",
    "select_templates_for_fingerprint",
    "select_templates_from_http_probe",
    "build_nuclei_template_args",
    "print_template_selection_summary",
    "normalize_tech_name",
    "FindingDeduplicator",
    "deduplicate_scan_results",
    "CanonicalFinding",
    "assess_tor_health",
    "assess_direct_connectivity",
    "run_pre_scan_health_check",
    "check_tor_port",
    "request_new_tor_circuit",
    "NetworkHealthReport",
    # Scan checkpoint & resumability
    "ScanCheckpoint",
    "should_resume_scan",
    # Smart retry
    "smart_retry",
    "retry_api_call",
    "retry_dns_lookup",
    "retry_network_request",
    "RetryConfig",
    "RetryStats",
    "ErrorClass",
    "CircuitBreakerOpen",
    "get_all_retry_stats",
    "classify_error",
    # Target priority
    "TargetPriorityQueue",
    "ScoredTarget",
    "prioritize_from_http_probe",
    "print_priority_summary",
    # DNS pre-validation
    "DNSPreValidator",
    "DNSValidationResult",
    "prevalidate_subdomains",
    "filter_dns_stale",
    # CVE version correlation
    "CVEVersionCorrelator",
    "VersionRange",
    "ServiceVersion",
    "correlate_vulns_with_versions",
    "KNOWN_CVE_VERSIONS",
]

