"""
GVM Project Settings - Fetch GVM scan configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_GVM_SETTINGS for standalone usage.

Mirrors the pattern from agentic/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields
# =============================================================================

DEFAULT_GVM_SETTINGS: dict[str, Any] = {
    # Scan configuration preset:
    # - "Full and fast" - Comprehensive scan, good performance (recommended)
    # - "Full and fast ultimate" - Most thorough, slower
    # - "Full and very deep" - Deep scan, very slow
    # - "Full and very deep ultimate" - Maximum coverage, very slow
    # - "Discovery" - Network discovery only, no vulnerability tests
    # - "Host Discovery" - Basic host enumeration
    # - "System Discovery" - System enumeration
    'SCAN_CONFIG': 'Full and fast',

    # Scan targets strategy:
    # - "both" - Scan IPs and hostnames separately for thorough coverage
    # - "ips_only" - Only scan IP addresses
    # - "hostnames_only" - Only scan hostnames/subdomains
    'SCAN_TARGETS': 'both',

    # Maximum time to wait for a single scan task (seconds, 0 = unlimited)
    # Note: "Full and fast" scans can take 1-2+ hours per target
    'TASK_TIMEOUT': 14400,  # 4 hours

    # Poll interval for checking scan status (seconds)
    'POLL_INTERVAL': 30,

    # Cleanup targets and tasks after scan completion
    'CLEANUP_AFTER_SCAN': True,

    # Port list to use for the scan target.
    # Available options depend on the loaded GVM data objects; common values:
    # - "All IANA assigned TCP and UDP" (thorough, default)
    # - "All IANA assigned TCP"
    # - "All TCP and Nmap top 100 UDP" (quick preset)
    'PORT_LIST': 'All IANA assigned TCP and UDP',

    # Number of targets grouped into a single GVM task.  Higher values reduce
    # GVM task/target creation overhead but make per-task runtime longer.
    'TARGET_BATCH_SIZE': 5,

    # Scanner concurrency preferences (0 or unset = use GVM default).
    # Lower values make scans gentler; higher values speed up scanning.
    'MAX_HOSTS': 0,
    'MAX_CHECKS': 0,

    # Scan preset that overrides the above defaults when set to a named profile.
    # Supported: "default", "fast", "thorough"
    'SCAN_PRESET': 'default',

    # Number of GVM batches to run in parallel within each phase (IP / hostname).
    # Higher values reduce wall-clock time but increase GVM load.
    # Set to 1 for fully sequential scanning (same as before).
    'BATCH_CONCURRENCY': 4,
}


def fetch_gvm_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch GVM scan settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching GVM settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_GVM_SETTINGS.copy()

    # Map camelCase API fields to SCREAMING_SNAKE_CASE
    settings['SCAN_CONFIG'] = project.get('gvmScanConfig', DEFAULT_GVM_SETTINGS['SCAN_CONFIG'])
    settings['SCAN_TARGETS'] = project.get('gvmScanTargets', DEFAULT_GVM_SETTINGS['SCAN_TARGETS'])
    settings['TASK_TIMEOUT'] = project.get('gvmTaskTimeout', DEFAULT_GVM_SETTINGS['TASK_TIMEOUT'])
    settings['POLL_INTERVAL'] = project.get('gvmPollInterval', DEFAULT_GVM_SETTINGS['POLL_INTERVAL'])
    settings['CLEANUP_AFTER_SCAN'] = project.get('gvmCleanupAfterScan', DEFAULT_GVM_SETTINGS['CLEANUP_AFTER_SCAN'])

    # Performance / batching settings (optional UI fields)
    settings['PORT_LIST'] = project.get('gvmPortList', DEFAULT_GVM_SETTINGS['PORT_LIST'])
    settings['TARGET_BATCH_SIZE'] = project.get('gvmTargetBatchSize', DEFAULT_GVM_SETTINGS['TARGET_BATCH_SIZE'])
    settings['MAX_HOSTS'] = project.get('gvmMaxHosts', DEFAULT_GVM_SETTINGS['MAX_HOSTS'])
    settings['MAX_CHECKS'] = project.get('gvmMaxChecks', DEFAULT_GVM_SETTINGS['MAX_CHECKS'])
    settings['SCAN_PRESET'] = project.get('gvmScanPreset', DEFAULT_GVM_SETTINGS['SCAN_PRESET'])
    settings['BATCH_CONCURRENCY'] = project.get('gvmBatchConcurrency', DEFAULT_GVM_SETTINGS['BATCH_CONCURRENCY'])

    logger.info(f"Loaded {len(settings)} GVM settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get current GVM settings.

    Returns cached settings if loaded for a project, otherwise defaults.
    Use load_project_settings() to fetch settings for a specific project.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings
    if _settings is not None:
        return _settings
    logger.info("Using DEFAULT_GVM_SETTINGS (no project loaded yet)")
    return DEFAULT_GVM_SETTINGS.copy()


# Singleton settings instance
_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def load_project_settings(project_id: str) -> dict[str, Any]:
    """
    Fetch and cache settings for a specific project from webapp API.

    Args:
        project_id: The project ID received from the frontend

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings, _current_project_id

    # Skip if already loaded for this project
    if _current_project_id == project_id and _settings is not None:
        return _settings

    webapp_url = os.environ.get('WEBAPP_API_URL')

    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_GVM_SETTINGS")
        _settings = DEFAULT_GVM_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_gvm_settings(project_id, webapp_url)
        _current_project_id = project_id
        logger.info(f"Loaded {len(_settings)} GVM settings from API for project {project_id}")
        return _settings

    except Exception as e:
        logger.error(f"Failed to fetch GVM settings for project {project_id}: {e}")
        logger.warning("Falling back to DEFAULT_GVM_SETTINGS")
        _settings = DEFAULT_GVM_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single GVM setting value.

    Args:
        key: Setting name in SCREAMING_SNAKE_CASE
        default: Default value if setting not found

    Returns:
        Setting value or default
    """
    return get_settings().get(key, default)


def reload_settings(project_id: Optional[str] = None) -> dict[str, Any]:
    """Force reload of settings for a project."""
    global _settings, _current_project_id
    if project_id:
        _current_project_id = None  # Force refetch
        return load_project_settings(project_id)
    _settings = None
    _current_project_id = None
    return get_settings()
