"""
RedAmon Agent Prompts Package

System prompts for the ReAct agent orchestrator.
Includes phase-aware reasoning, tool descriptions, and structured output formats.
"""

# Re-export from base
from .base import (
    TOOL_REGISTRY,
    MODE_DECISION_MATRIX,
    REACT_SYSTEM_PROMPT,
    PENDING_OUTPUT_ANALYSIS_SECTION,
    PENDING_PLAN_OUTPUTS_SECTION,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    CONVERSATIONAL_RESPONSE_PROMPT,
    SUMMARY_RESPONSE_PROMPT,
    determine_response_tier,
    TEXT_TO_CYPHER_SYSTEM,
    # Dynamic prompt builders
    build_tool_availability_table,
    build_informational_tool_descriptions,
    build_compact_tool_list,
    build_informational_guidance,
    build_attack_path_behavior,
    build_tool_args_section,
    build_tool_name_enum,
    build_phase_definitions,
    build_kali_install_prompt,
    DEEP_THINK_PROMPT,
    DEEP_THINK_SECTION,
    DEEP_THINK_SELF_REQUEST_INSTRUCTION,
)

# Re-export from classification
from .classification import ATTACK_PATH_CLASSIFICATION_PROMPT, build_classification_prompt

# Re-export from CVE exploit prompts
from .cve_exploit_prompts import (
    CVE_EXPLOIT_TOOLS,
    CVE_PAYLOAD_GUIDANCE_STATEFULL,
    CVE_PAYLOAD_GUIDANCE_STATELESS,
    NO_MODULE_FALLBACK_STATEFULL,
    NO_MODULE_FALLBACK_STATELESS,
)

# Re-export from Hydra brute force prompts
from .brute_force_credential_guess_prompts import (
    HYDRA_BRUTE_FORCE_TOOLS,
    HYDRA_WORDLIST_GUIDANCE,
)

# Re-export from phishing / social engineering prompts
from .phishing_social_engineering_prompts import (
    PHISHING_SOCIAL_ENGINEERING_TOOLS,
    PHISHING_PAYLOAD_FORMAT_GUIDANCE,
)

# Re-export from denial of service prompts
from .denial_of_service_prompts import (
    DOS_TOOLS,
    DOS_VECTOR_SELECTION,
    DOS_VERIFICATION_GUIDE,
)

# Re-export from SQL injection prompts
from .sql_injection_prompts import (
    SQLI_TOOLS,
    SQLI_OOB_WORKFLOW,
    SQLI_PAYLOAD_REFERENCE,
)

# Re-export from XSS prompts
from .xss_prompts import (
    XSS_TOOLS,
    XSS_BLIND_WORKFLOW,
    XSS_PAYLOAD_REFERENCE,
)

# Re-export from SSRF prompts
from .ssrf_prompts import (
    SSRF_TOOLS,
    SSRF_OOB_WORKFLOW,
    SSRF_GOPHER_CHAINS,
    SSRF_DNS_REBINDING,
    SSRF_PAYLOAD_REFERENCE,
    SSRF_CLOUD_PROVIDER_BLOCKS,
    SSRF_CLOUD_DISABLED_STUB,
)

# Re-export from RCE prompts
from .rce_prompts import (
    RCE_TOOLS,
    RCE_AGGRESSIVE_DISABLED,
    RCE_AGGRESSIVE_ENABLED,
    RCE_OOB_WORKFLOW,
    RCE_DESERIALIZATION_WORKFLOW,
    RCE_PAYLOAD_REFERENCE,
)

# Re-export from Path Traversal / LFI / RFI prompts
from .path_traversal_prompts import (
    PATH_TRAVERSAL_TOOLS,
    PATH_TRAVERSAL_PHP_WRAPPERS,
    PATH_TRAVERSAL_OOB_WORKFLOW,
    PATH_TRAVERSAL_ARCHIVE_EXTRACTION,
    PATH_TRAVERSAL_PAYLOAD_REFERENCE,
)

# Re-export from Active Directory Kill Chain prompts
from .ad_kill_chain_prompts import (
    AD_KILL_CHAIN_TOOLS,
    AD_KILL_CHAIN_PAYLOAD_REFERENCE,
)

# Re-export from Cloud Infrastructure Exploitation prompts
from .cloud_infra_exploitation_prompts import (
    CLOUD_INFRA_TOOLS,
    CLOUD_INFRA_PAYLOAD_REFERENCE,
)

# Re-export from API Security Testing prompts
from .api_security_testing_prompts import (
    API_SECURITY_TOOLS,
    API_SECURITY_PAYLOAD_REFERENCE,
)

# Re-export from Supply Chain Poisoning prompts
from .supply_chain_poisoning_prompts import (
    SUPPLY_CHAIN_TOOLS,
    SUPPLY_CHAIN_PAYLOAD_REFERENCE,
)

# Re-export from Domain Takeover prompts
from .domain_takeover_prompts import (
    DOMAIN_TAKEOVER_TOOLS,
    DOMAIN_TAKEOVER_PAYLOAD_REFERENCE,
)

# Re-export from Attack Surface Mapping prompts
from .attack_surface_mapping_prompts import (
    ATTACK_SURFACE_MAPPING_TOOLS,
    ATTACK_SURFACE_MAPPING_PAYLOAD_REFERENCE,
)

# Re-export from Subdomain Reconnaissance prompts
from .subdomain_reconnaissance_prompts import (
    SUBDOMAIN_RECON_TOOLS,
    SUBDOMAIN_RECON_PAYLOAD_REFERENCE,
)

# Re-export from Email Security Assessment prompts
from .email_security_assessment_prompts import (
    EMAIL_SECURITY_TOOLS,
    EMAIL_SECURITY_PAYLOAD_REFERENCE,
)

# Re-export from Web Cache Poisoning prompts
from .web_cache_poisoning_prompts import (
    WEB_CACHE_POISONING_TOOLS,
    WEB_CACHE_POISONING_PAYLOAD_REFERENCE,
)

# Re-export from Web Application Reconnaissance prompts
from .web_application_reconnaissance_prompts import (
    WEBAPP_RECON_TOOLS,
    WEBAPP_RECON_PAYLOAD_REFERENCE,
)

# Re-export from Transport Security Assessment prompts
from .transport_security_assessment_prompts import (
    TRANSPORT_SECURITY_TOOLS,
    TRANSPORT_SECURITY_PAYLOAD_REFERENCE,
)

# Re-export from Infrastructure Exposure Analysis prompts
from .infrastructure_exposure_analysis_prompts import (
    INFRASTRUCTURE_EXPOSURE_TOOLS,
    INFRASTRUCTURE_EXPOSURE_PAYLOAD_REFERENCE,
)

# Re-export from unclassified attack path prompts
from .unclassified_prompts import UNCLASSIFIED_EXPLOIT_TOOLS

# Re-export from post-exploitation prompts
from .post_exploitation import (
    POST_EXPLOITATION_TOOLS_STATEFULL,
    POST_EXPLOITATION_TOOLS_STATELESS,
)

# Re-export from stealth rules
from .stealth_rules import STEALTH_MODE_RULES

# Import utilities
from utils import get_session_config_prompt
from project_settings import get_setting, get_allowed_tools_for_phase, get_hydra_flags_from_settings, get_dos_settings_dict


def _msf_search_failed(execution_trace: list) -> bool:
    """Check if a Metasploit `search` command returned no results in the trace."""
    for step in execution_trace:
        if step.get("tool_name") != "metasploit_console":
            continue
        output = step.get("tool_output") or ""
        args = step.get("tool_args") or {}
        command = args.get("command", "") if isinstance(args, dict) else str(args)
        # Only match actual search commands, not other msf commands
        if "search " in command.lower() and (
            "No results" in output
            or "0 results" in output
            or "did not match" in output.lower()
        ):
            return True
    return False


def get_phase_tools(
    phase: str,
    activate_post_expl: bool = True,
    post_expl_type: str = "stateless",
    attack_path_type: str = "",
    execution_trace: list = None,
    tool_filter: set = None,
) -> str:
    """Get tool descriptions for the current phase with attack path-specific guidance.

    All tool references are dynamically filtered based on the DB TOOL_PHASE_MAP,
    so the LLM only sees tools that are actually allowed in the current phase.

    Args:
        phase: Current agent phase (informational, exploitation, post_exploitation)
        activate_post_expl: If True, post-exploitation phase is available.
                           If False, exploitation is the final phase.
        post_expl_type: "statefull" for Meterpreter sessions, "stateless" for single commands.
        attack_path_type: Type of attack path ("cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", "sql_injection")
        execution_trace: List of execution steps (used to detect MSF search failures).
        tool_filter: Optional whitelist of tool names. When set, the rendered output is
                     restricted to the intersection of phase-allowed tools and this set.
                     Used by fireteam members to render a "primary tools" view limited
                     to their declared skills. None means no filtering (full phase view).

    Returns:
        Concatenated tool descriptions appropriate for the phase, mode, and attack path.
    """
    parts = []
    is_statefull = post_expl_type == "statefull"

    # Stealth mode header — reminds LLM that stealth constraints apply to all tools below
    if get_setting('STEALTH_MODE', False):
        parts.append(
            "## STEALTH MODE ACTIVE\n\n"
            "All tools below MUST be used with stealth constraints. "
            "See STEALTH MODE rules above for per-tool restrictions.\n"
        )

    # Add phase-specific custom system prompt if configured
    informational_prompt = get_setting('INFORMATIONAL_SYSTEM_PROMPT', '')
    expl_prompt = get_setting('EXPL_SYSTEM_PROMPT', '')
    post_expl_prompt = get_setting('POST_EXPL_SYSTEM_PROMPT', '')

    if phase == "informational" and informational_prompt:
        parts.append(f"## Custom Instructions\n\n{informational_prompt}\n")
    elif phase == "exploitation" and expl_prompt:
        parts.append(f"## Custom Instructions\n\n{expl_prompt}\n")
    elif phase == "post_exploitation" and post_expl_prompt:
        parts.append(f"## Custom Instructions\n\n{post_expl_prompt}\n")

    # Determine allowed tools for current phase (dynamic from TOOL_PHASE_MAP in DB)
    phase_allowed_unfiltered = get_allowed_tools_for_phase(phase)
    # Optional fireteam-member filter: render only the intersection with the
    # member's declared skills, so the "primary tools" view stays focused.
    # Phase-allowlisting still applies — filter is a SUBSET operation, never a
    # superset.
    if tool_filter is not None:
        allowed_tools = [t for t in phase_allowed_unfiltered if t in tool_filter]
    else:
        allowed_tools = phase_allowed_unfiltered

    # Kali shell library installation rules (prompt-based control).
    # IMPORTANT: check the UNFILTERED phase allowlist. A fireteam member may
    # render the "primary tools" view without kali_shell in its declared
    # skills, but kali_shell still appears in the member's fallback toolbox
    # and is callable. The install constraints must be communicated regardless
    # of which view we're rendering — otherwise the model may try `apt install`
    # via a fallback kali_shell call without seeing the warning.
    if "kali_shell" in phase_allowed_unfiltered:
        parts.append(build_kali_install_prompt())

    # Dynamic tool availability table — render in EVERY phase so the LLM
    # always sees the same purpose + when_to_use columns for any allowed
    # tool. Phase toggles control whether a tool appears at all (via
    # allowed_tools), not which fields render.
    #
    # When a tool_filter is active (fireteam member primary view), suppress
    # the "Current phase allows: ..." summary line — the filtered list is
    # NOT what the phase fully allows, and emitting it as such would lie to
    # the model and could discourage legitimate fallback-tool calls.
    parts.append(build_tool_availability_table(
        phase, allowed_tools,
        show_phase_allows_line=(tool_filter is None),
    ))

    # Add mode decision matrix for exploitation only (not needed in post-expl, mode already determined)
    if phase == "exploitation" and attack_path_type == "cve_exploit":
        # Mode context
        target_types = "Dropper/Staged/Meterpreter" if is_statefull else "Command/In-Memory/Exec"
        post_expl_note = "Interactive session commands available" if is_statefull else "Re-run exploit with different CMD values"

        parts.append(MODE_DECISION_MATRIX.format(
            mode=post_expl_type,
            target_types=target_types,
            post_expl_note=post_expl_note
        ))

    # Pre-configured payload settings (LHOST/LPORT/tunnel: ngrok or chisel) — injected BEFORE attack
    # chain so the agent knows the payload direction regardless of attack path type.
    #
    # Injection conditions:
    #   1. exploitation phase + statefull mode (CVE exploit, brute force)
    #   2. phishing attack path in ANY phase — payloads are generated before
    #      exploitation (agent runs msfvenom during informational phase,
    #      and the "exploitation" in phishing IS when the target opens the file)
    needs_session_config = (
        (phase == "exploitation" and is_statefull)
        or attack_path_type == "phishing_social_engineering"
    )
    if needs_session_config:
        session_config = get_session_config_prompt()
        if session_config:
            parts.append(session_config)

    # Helper: resolve user skill content (used across all phases)
    def _resolve_user_skill() -> str | None:
        if not attack_path_type.startswith("user_skill:"):
            return None
        from project_settings import get_enabled_user_skills
        skill_id = attack_path_type.split(":", 1)[1]
        skill = next((s for s in get_enabled_user_skills() if s['id'] == skill_id), None)
        return f"## User Attack Skill: {skill['name']}\n\n{skill['content']}" if skill else None

    # Helper: inject built-in skill workflow prompts (used in both informational and exploitation)
    def _inject_builtin_skill_workflow() -> bool:
        """Inject skill-specific workflow if attack_path_type matches an enabled built-in skill.
        Returns True if a workflow was injected, False otherwise."""
        from project_settings import get_enabled_builtin_skills
        enabled_builtins = get_enabled_builtin_skills()

        if (attack_path_type == "brute_force_credential_guess"
                and "brute_force_credential_guess" in enabled_builtins
                and "execute_hydra" in allowed_tools
                and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False))):
            # Hydra-based brute force workflow
            hydra_flags = get_hydra_flags_from_settings()
            import re as _re
            hydra_flags_no_t = _re.sub(r'-t\s+\d+\s*', '', hydra_flags).strip()
            parts.append(HYDRA_BRUTE_FORCE_TOOLS.format(
                hydra_max_attempts=get_setting('HYDRA_MAX_WORDLIST_ATTEMPTS', 3),
                hydra_flags=hydra_flags,
                hydra_flags_no_t=hydra_flags_no_t
            ))
            parts.append(HYDRA_WORDLIST_GUIDANCE)
            return True
        elif (attack_path_type == "phishing_social_engineering"
                and "phishing_social_engineering" in enabled_builtins
                and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False))):
            parts.append(PHISHING_SOCIAL_ENGINEERING_TOOLS)
            parts.append(PHISHING_PAYLOAD_FORMAT_GUIDANCE)
            smtp_config = get_setting('PHISHING_SMTP_CONFIG', '')
            if smtp_config:
                parts.append(
                    f"## Pre-Configured SMTP Settings\n\n"
                    f"Use these for email delivery via execute_code (Python smtplib):\n{smtp_config}\n"
                )
            return True
        elif (attack_path_type == "denial_of_service"
                and "denial_of_service" in enabled_builtins
                and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_DOS', False))):
            dos_settings = get_dos_settings_dict()
            assessment_only = get_setting('DOS_ASSESSMENT_ONLY', False)
            dos_assessment_block = (
                "\n## ASSESSMENT ONLY MODE (ACTIVE)\n"
                "You are in ASSESSMENT-ONLY mode. Do NOT execute any DoS attack.\n"
                "Only research and report whether the target is VULNERABLE to DoS:\n"
                "- Run nmap scripts (--script dos, --script rdp-ms12-020)\n"
                "- Run nuclei -tags dos\n"
                "- Research known DoS CVEs for detected service versions\n"
                '- Report findings with action="complete"\n'
            ) if assessment_only else ""
            parts.append(DOS_TOOLS.format(
                **dos_settings,
                dos_assessment_only_block=dos_assessment_block,
            ))
            parts.append(DOS_VECTOR_SELECTION.format(**dos_settings))
            parts.append(DOS_VERIFICATION_GUIDE)
            return True
        elif (attack_path_type == "sql_injection"
                and "sql_injection" in enabled_builtins
                and "kali_shell" in allowed_tools):
            sqli_settings = {
                'sqli_level': get_setting('SQLI_LEVEL', 1),
                'sqli_risk': get_setting('SQLI_RISK', 1),
                'sqli_tamper_scripts': get_setting('SQLI_TAMPER_SCRIPTS', '') or 'none configured',
            }
            parts.append(SQLI_TOOLS.format(**sqli_settings))
            parts.append(SQLI_OOB_WORKFLOW)
            parts.append(SQLI_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "xss"
                and "xss" in enabled_builtins
                and "execute_curl" in allowed_tools):
            xss_settings = {
                'xss_dalfox_enabled': get_setting('XSS_DALFOX_ENABLED', True),
                'xss_blind_callback_enabled': get_setting('XSS_BLIND_CALLBACK_ENABLED', False),
                'xss_csp_bypass_enabled': get_setting('XSS_CSP_BYPASS_ENABLED', True),
            }
            parts.append(XSS_TOOLS.format(**xss_settings))
            if xss_settings['xss_blind_callback_enabled'] and "kali_shell" in allowed_tools:
                parts.append(XSS_BLIND_WORKFLOW)
            parts.append(XSS_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "ssrf"
                and "ssrf" in enabled_builtins
                and "execute_curl" in allowed_tools):
            ssrf_oob_enabled = get_setting('SSRF_OOB_CALLBACK_ENABLED', True)
            ssrf_cloud_enabled = get_setting('SSRF_CLOUD_METADATA_ENABLED', True)
            ssrf_gopher_enabled = get_setting('SSRF_GOPHER_ENABLED', True)
            ssrf_rebind_enabled = get_setting('SSRF_DNS_REBINDING_ENABLED', True)
            ssrf_payref_enabled = get_setting('SSRF_PAYLOAD_REFERENCE_ENABLED', True)

            # Build cloud section: filter SSRF_CLOUD_PROVIDER_BLOCKS by enabled
            # providers if cloud-metadata is on, else inject the disabled stub.
            if ssrf_cloud_enabled:
                providers_csv = get_setting('SSRF_CLOUD_PROVIDERS', 'aws,gcp,azure,digitalocean,alibaba')
                requested = [p.strip().lower() for p in providers_csv.split(',') if p.strip()]
                cloud_blocks = [SSRF_CLOUD_PROVIDER_BLOCKS[p] for p in requested if p in SSRF_CLOUD_PROVIDER_BLOCKS]
                ssrf_cloud_section = "\n".join(cloud_blocks) if cloud_blocks else SSRF_CLOUD_DISABLED_STUB
            else:
                ssrf_cloud_section = SSRF_CLOUD_DISABLED_STUB

            # Build custom-targets section from free-text setting
            custom_targets = (get_setting('SSRF_CUSTOM_INTERNAL_TARGETS', '') or '').strip()
            if custom_targets:
                ssrf_custom_targets_section = (
                    "## SITE-SPECIFIC INTERNAL TARGETS\n\n"
                    "The operator has flagged these internal hosts/IPs for prioritized probing:\n\n"
                    f"```\n{custom_targets}\n```\n\n"
                    "Probe these alongside the generic loopback / RFC1918 sweep in Step 3."
                )
            else:
                ssrf_custom_targets_section = ""

            ssrf_settings = {
                'ssrf_oob_callback_enabled': ssrf_oob_enabled,
                'ssrf_cloud_metadata_enabled': ssrf_cloud_enabled,
                'ssrf_gopher_enabled': ssrf_gopher_enabled,
                'ssrf_dns_rebinding_enabled': ssrf_rebind_enabled,
                'ssrf_payload_reference_enabled': ssrf_payref_enabled,
                'ssrf_request_timeout': get_setting('SSRF_REQUEST_TIMEOUT', 10),
                'ssrf_port_scan_ports': get_setting('SSRF_PORT_SCAN_PORTS',
                    '22,80,443,2375,3306,5432,6379,8080,8500,9200,27017'),
                'ssrf_internal_ranges': get_setting('SSRF_INTERNAL_RANGES',
                    '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16'),
                'ssrf_oob_provider': get_setting('SSRF_OOB_PROVIDER', 'oast.fun'),
                'ssrf_cloud_providers': get_setting('SSRF_CLOUD_PROVIDERS',
                    'aws,gcp,azure,digitalocean,alibaba') if ssrf_cloud_enabled else 'disabled',
                'ssrf_cloud_section': ssrf_cloud_section,
                'ssrf_custom_targets_section': ssrf_custom_targets_section,
            }
            parts.append(SSRF_TOOLS.format(**ssrf_settings))
            if ssrf_oob_enabled and "kali_shell" in allowed_tools:
                parts.append(SSRF_OOB_WORKFLOW)
            if ssrf_gopher_enabled:
                parts.append(SSRF_GOPHER_CHAINS)
            if ssrf_rebind_enabled:
                parts.append(SSRF_DNS_REBINDING)
            if ssrf_payref_enabled:
                parts.append(SSRF_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "path_traversal"
                and "path_traversal" in enabled_builtins
                and "execute_curl" in allowed_tools):
            pt_oob_enabled = get_setting('PATH_TRAVERSAL_OOB_CALLBACK_ENABLED', True)
            pt_php_enabled = get_setting('PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED', True)
            pt_archive_enabled = get_setting('PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED', False)
            pt_payref_enabled = get_setting('PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED', True)
            pt_settings = {
                'path_traversal_oob_callback_enabled': pt_oob_enabled,
                'path_traversal_php_wrappers_enabled': pt_php_enabled,
                'path_traversal_archive_extraction_enabled': pt_archive_enabled,
                'path_traversal_payload_reference_enabled': pt_payref_enabled,
                'path_traversal_request_timeout': get_setting('PATH_TRAVERSAL_REQUEST_TIMEOUT', 10),
                'path_traversal_oob_provider': get_setting('PATH_TRAVERSAL_OOB_PROVIDER', 'oast.fun'),
            }
            parts.append(PATH_TRAVERSAL_TOOLS.format(**pt_settings))
            if pt_php_enabled:
                parts.append(PATH_TRAVERSAL_PHP_WRAPPERS)
            if pt_oob_enabled and "kali_shell" in allowed_tools:
                parts.append(PATH_TRAVERSAL_OOB_WORKFLOW)
            if pt_archive_enabled and "execute_code" in allowed_tools:
                parts.append(PATH_TRAVERSAL_ARCHIVE_EXTRACTION)
            if pt_payref_enabled:
                parts.append(PATH_TRAVERSAL_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "rce"
                and "rce" in enabled_builtins
                and "kali_shell" in allowed_tools):
            rce_oob_enabled = get_setting('RCE_OOB_CALLBACK_ENABLED', True)
            rce_deser_enabled = get_setting('RCE_DESERIALIZATION_ENABLED', True)
            rce_aggressive = get_setting('RCE_AGGRESSIVE_PAYLOADS', False)
            rce_aggressive_block = RCE_AGGRESSIVE_ENABLED if rce_aggressive else RCE_AGGRESSIVE_DISABLED
            rce_settings = {
                'rce_oob_callback_enabled': rce_oob_enabled,
                'rce_deserialization_enabled': rce_deser_enabled,
                'rce_aggressive_payloads': rce_aggressive,
                'rce_aggressive_block': rce_aggressive_block,
            }
            parts.append(RCE_TOOLS.format(**rce_settings))
            if rce_oob_enabled:
                parts.append(RCE_OOB_WORKFLOW)
            if rce_deser_enabled:
                parts.append(RCE_DESERIALIZATION_WORKFLOW)
            parts.append(RCE_PAYLOAD_REFERENCE)
            return True
        elif ("cve_exploit" == attack_path_type
                and "cve_exploit" in enabled_builtins
                and "metasploit_console" in allowed_tools):
            parts.append(CVE_EXPLOIT_TOOLS)
            payload_guidance = CVE_PAYLOAD_GUIDANCE_STATEFULL if is_statefull else CVE_PAYLOAD_GUIDANCE_STATELESS
            parts.append(payload_guidance)
            if _msf_search_failed(execution_trace or []):
                if is_statefull:
                    parts.append(NO_MODULE_FALLBACK_STATEFULL)
                else:
                    parts.append(NO_MODULE_FALLBACK_STATELESS)
            return True
        elif (attack_path_type == "ad_kill_chain"
                and "ad_kill_chain" in enabled_builtins
                and "kali_shell" in allowed_tools):
            ad_settings = {
                'ad_bh_enabled': get_setting('AD_BH_ENABLED', True),
                'ad_kerberoast_enabled': get_setting('AD_KERBEROAST_ENABLED', True),
                'ad_spray_enabled': get_setting('AD_SPRAY_ENABLED', True),
                'ad_relay_enabled': get_setting('AD_RELAY_ENABLED', False),
                'ad_certipy_enabled': get_setting('AD_CERTIPY_ENABLED', True),
                'ad_dcsync_enabled': get_setting('AD_DCSYNC_ENABLED', False),
                'ad_aggressive_enabled': get_setting('AD_AGGRESSIVE_ENABLED', False),
                'ad_domain_hint': get_setting('AD_DOMAIN_HINT', '') or 'none configured',
                'ad_dc_ip_hint': get_setting('AD_DC_IP_HINT', '') or 'none configured',
                'ad_user_wordlist': get_setting('AD_USER_WORDLIST', '') or 'default',
                'ad_pass_wordlist': get_setting('AD_PASS_WORDLIST', '') or 'default',
            }
            parts.append(AD_KILL_CHAIN_TOOLS.format(**ad_settings))
            parts.append(AD_KILL_CHAIN_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "cloud_infra_exploitation"
                and "cloud_infra_exploitation" in enabled_builtins
                and "execute_code" in allowed_tools):
            cloud_settings = {
                'cloud_aws_enabled': get_setting('CLOUD_AWS_ENABLED', True),
                'cloud_gcp_enabled': get_setting('CLOUD_GCP_ENABLED', True),
                'cloud_azure_enabled': get_setting('CLOUD_AZURE_ENABLED', True),
                'cloud_metadata_enabled': get_setting('CLOUD_METADATA_ENABLED', True),
                'cloud_storage_enabled': get_setting('CLOUD_STORAGE_ENABLED', True),
                'cloud_serverless_enabled': get_setting('CLOUD_SERVERLESS_ENABLED', True),
                'cloud_cred_exfil_enabled': get_setting('CLOUD_CRED_EXFIL_ENABLED', False),
                'cloud_aggressive_enabled': get_setting('CLOUD_AGGRESSIVE_ENABLED', False),
                'cloud_target_account': get_setting('CLOUD_TARGET_ACCOUNT', '') or 'none configured',
                'cloud_known_roles': get_setting('CLOUD_KNOWN_ROLES', '') or 'none configured',
            }
            parts.append(CLOUD_INFRA_TOOLS.format(**cloud_settings))
            parts.append(CLOUD_INFRA_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "api_security_testing"
                and "api_security_testing" in enabled_builtins
                and "execute_curl" in allowed_tools):
            api_settings = {
                'api_graphql_introspection_enabled': get_setting('API_GRAPHQL_INTROSPECTION_ENABLED', True),
                'api_jwt_enabled': get_setting('API_JWT_ENABLED', True),
                'api_oauth_enabled': get_setting('API_OAUTH_ENABLED', True),
                'api_rate_limit_enabled': get_setting('API_RATE_LIMIT_ENABLED', True),
                'api_mass_assignment_enabled': get_setting('API_MASS_ASSIGNMENT_ENABLED', True),
                'api_bola_enabled': get_setting('API_BOLA_ENABLED', True),
                'api_doc_discovery_enabled': get_setting('API_DOC_DISCOVERY_ENABLED', True),
                'api_request_timeout': get_setting('API_REQUEST_TIMEOUT', 10),
            }
            parts.append(API_SECURITY_TOOLS.format(**api_settings))
            parts.append(API_SECURITY_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "supply_chain_poisoning"
                and "supply_chain_poisoning" in enabled_builtins
                and "kali_shell" in allowed_tools):
            sc_settings = {
                'sc_dep_confusion_enabled': get_setting('SC_DEP_CONFUSION_ENABLED', True),
                'sc_typosquat_enabled': get_setting('SC_TYPOSQUAT_ENABLED', True),
                'sc_malicious_build_enabled': get_setting('SC_MALICIOUS_BUILD_ENABLED', False),
                'sc_manifest_poison_enabled': get_setting('SC_MANIFEST_POISON_ENABLED', True),
                'sc_sig_bypass_enabled': get_setting('SC_SIG_BYPASS_ENABLED', False),
                'sc_target_registries': get_setting('SC_TARGET_REGISTRIES', 'npm,pypi') or 'npm,pypi',
                'sc_internal_scope': get_setting('SC_INTERNAL_SCOPE', '') or 'none configured',
                'sc_public_targets': get_setting('SC_PUBLIC_TARGETS', '') or 'none configured',
            }
            parts.append(SUPPLY_CHAIN_TOOLS.format(**sc_settings))
            parts.append(SUPPLY_CHAIN_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "domain_takeover"
                and "domain_takeover" in enabled_builtins
                and "execute_curl" in allowed_tools):
            dto_settings = {
                'dto_subdomain_enabled': get_setting('DTO_SUBDOMAIN_ENABLED', True),
                'dto_ns_hijack_enabled': get_setting('DTO_NS_HIJACK_ENABLED', False),
                'dto_expiry_enabled': get_setting('DTO_EXPIRY_ENABLED', True),
                'dto_dns_misconfig_enabled': get_setting('DTO_DNS_MISCONFIG_ENABLED', True),
                'dto_cloud_providers': get_setting('DTO_CLOUD_PROVIDERS', 'aws,gcp,azure,github,heroku') or 'aws,gcp,azure,github,heroku',
                'dto_excluded_domains': get_setting('DTO_EXCLUDED_DOMAINS', '') or 'none',
            }
            parts.append(DOMAIN_TAKEOVER_TOOLS.format(**dto_settings))
            parts.append(DOMAIN_TAKEOVER_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "attack_surface_mapping"
                and "attack_surface_mapping" in enabled_builtins
                and "execute_httpx" in allowed_tools):
            asm_settings = {
                'asm_passive_enabled': get_setting('ASM_PASSIVE_ENABLED', True),
                'asm_active_enabled': get_setting('ASM_ACTIVE_ENABLED', True),
                'asm_crawl_enabled': get_setting('ASM_CRAWL_ENABLED', True),
                'asm_tech_enabled': get_setting('ASM_TECH_ENABLED', True),
                'asm_port_scope': get_setting('ASM_PORT_SCOPE', '80,443,8080,8443,3000,5000,8000,9000') or '80,443,8080,8443,3000,5000,8000,9000',
                'asm_screenshots_enabled': get_setting('ASM_SCREENSHOTS_ENABLED', False),
                'asm_excluded_hosts': get_setting('ASM_EXCLUDED_HOSTS', '') or 'none',
                'asm_target_domain': get_setting('ASM_TARGET_DOMAIN', '') or 'none configured',
            }
            parts.append(ATTACK_SURFACE_MAPPING_TOOLS.format(**asm_settings))
            parts.append(ATTACK_SURFACE_MAPPING_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "subdomain_reconnaissance"
                and "subdomain_reconnaissance" in enabled_builtins
                and "kali_shell" in allowed_tools):
            sdr_settings = {
                'sdr_passive_enabled': get_setting('SDR_PASSIVE_ENABLED', True),
                'sdr_active_enabled': get_setting('SDR_ACTIVE_ENABLED', True),
                'sdr_permutations_enabled': get_setting('SDR_PERMUTATIONS_ENABLED', True),
                'sdr_resolution_enabled': get_setting('SDR_RESOLUTION_ENABLED', True),
                'sdr_takeover_check_enabled': get_setting('SDR_TAKEOVER_CHECK_ENABLED', True),
                'sdr_dns_records_enabled': get_setting('SDR_DNS_RECORDS_ENABLED', True),
                'sdr_target_domain': get_setting('SDR_TARGET_DOMAIN', '') or 'none configured',
            }
            parts.append(SUBDOMAIN_RECON_TOOLS.format(**sdr_settings))
            parts.append(SUBDOMAIN_RECON_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "email_security_assessment"
                and "email_security_assessment" in enabled_builtins
                and "kali_shell" in allowed_tools):
            email_settings = {
                'email_dns_analysis_enabled': get_setting('EMAIL_DNS_ANALYSIS_ENABLED', True),
                'email_spoofing_enabled': get_setting('EMAIL_SPOOFING_ENABLED', False),
                'email_open_relay_enabled': get_setting('EMAIL_OPEN_RELAY_ENABLED', False),
                'email_enum_enabled': get_setting('EMAIL_ENUM_ENABLED', False),
                'email_header_injection_enabled': get_setting('EMAIL_HEADER_INJECTION_ENABLED', True),
                'email_bec_enabled': get_setting('EMAIL_BEC_ENABLED', True),
                'email_target_domain': get_setting('EMAIL_TARGET_DOMAIN', '') or 'none configured',
                'email_executives': get_setting('EMAIL_EXECUTIVES', '') or 'none configured',
                'email_smtp_hint': get_setting('EMAIL_SMTP_HINT', '') or 'none configured',
            }
            parts.append(EMAIL_SECURITY_TOOLS.format(**email_settings))
            parts.append(EMAIL_SECURITY_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "web_cache_poisoning"
                and "web_cache_poisoning" in enabled_builtins
                and "execute_curl" in allowed_tools):
            wcp_settings = {
                'wcp_fingerprint_enabled': get_setting('WCP_FINGERPRINT_ENABLED', True),
                'wcp_header_poison_enabled': get_setting('WCP_HEADER_POISON_ENABLED', False),
                'wcp_cloak_enabled': get_setting('WCP_CLOAK_ENABLED', True),
                'wcp_deception_enabled': get_setting('WCP_DECEPTION_ENABLED', False),
                'wcp_cdn_providers': get_setting('WCP_CDN_PROVIDERS', 'cloudflare,fastly,akamai,cloudfront,varnish') or 'cloudflare,fastly,akamai,cloudfront,varnish',
                'wcp_max_attempts': get_setting('WCP_MAX_ATTEMPTS', 20),
                'wcp_target_domain': get_setting('WCP_TARGET_DOMAIN', '') or 'none configured',
            }
            parts.append(WEB_CACHE_POISONING_TOOLS.format(**wcp_settings))
            parts.append(WEB_CACHE_POISONING_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "web_application_reconnaissance"
                and "web_application_reconnaissance" in enabled_builtins
                and "execute_curl" in allowed_tools):
            war_settings = {
                'war_endpoint_discovery_enabled': get_setting('WAR_ENDPOINT_DISCOVERY_ENABLED', True),
                'war_tech_fingerprint_enabled': get_setting('WAR_TECH_FINGERPRINT_ENABLED', True),
                'war_waf_detection_enabled': get_setting('WAR_WAF_DETECTION_ENABLED', True),
                'war_js_analysis_enabled': get_setting('WAR_JS_ANALYSIS_ENABLED', True),
                'war_form_mapping_enabled': get_setting('WAR_FORM_MAPPING_ENABLED', True),
                'war_comment_analysis_enabled': get_setting('WAR_COMMENT_ANALYSIS_ENABLED', True),
                'war_target_domain': get_setting('WAR_TARGET_DOMAIN', '') or 'none configured',
            }
            parts.append(WEBAPP_RECON_TOOLS.format(**war_settings))
            parts.append(WEBAPP_RECON_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "transport_security_assessment"
                and "transport_security_assessment" in enabled_builtins
                and "kali_shell" in allowed_tools):
            tsa_settings = {
                'tsa_tls_scan_enabled': get_setting('TSA_TLS_SCAN_ENABLED', True),
                'tsa_cipher_enabled': get_setting('TSA_CIPHER_ENABLED', True),
                'tsa_cert_validation_enabled': get_setting('TSA_CERT_VALIDATION_ENABLED', True),
                'tsa_hsts_enabled': get_setting('TSA_HSTS_ENABLED', True),
                'tsa_downgrade_enabled': get_setting('TSA_DOWNGRADE_ENABLED', False),
                'tsa_ct_enabled': get_setting('TSA_CT_ENABLED', True),
                'tsa_deep_scan_enabled': get_setting('TSA_DEEP_SCAN_ENABLED', False),
                'tsa_target_domain': get_setting('TSA_TARGET_DOMAIN', '') or 'none configured',
            }
            parts.append(TRANSPORT_SECURITY_TOOLS.format(**tsa_settings))
            parts.append(TRANSPORT_SECURITY_PAYLOAD_REFERENCE)
            return True
        elif (attack_path_type == "infrastructure_exposure_analysis"
                and "infrastructure_exposure_analysis" in enabled_builtins
                and "execute_curl" in allowed_tools):
            iea_settings = {
                'iea_storage_enabled': get_setting('IEA_STORAGE_ENABLED', True),
                'iea_db_api_enabled': get_setting('IEA_DB_API_ENABLED', True),
                'iea_mgmt_enabled': get_setting('IEA_MGMT_ENABLED', True),
                'iea_shadow_enabled': get_setting('IEA_SHADOW_ENABLED', True),
                'iea_secrets_enabled': get_setting('IEA_SECRETS_ENABLED', True),
                'iea_shodan_enabled': get_setting('IEA_SHODAN_ENABLED', True),
                'iea_dorking_enabled': get_setting('IEA_DORKING_ENABLED', True),
                'iea_target_domain': get_setting('IEA_TARGET_DOMAIN', '') or 'none configured',
                'iea_ip_ranges': get_setting('IEA_IP_RANGES', '') or 'none configured',
            }
            parts.append(INFRASTRUCTURE_EXPOSURE_TOOLS.format(**iea_settings))
            parts.append(INFRASTRUCTURE_EXPOSURE_PAYLOAD_REFERENCE)
            return True
        return False

    # Tool descriptions: render in EVERY phase for every allowed tool.
    # Phase toggle = enable/disable per phase, NOT field selection. If a
    # tool is in allowed_tools for the current phase, the LLM sees all
    # four fields (purpose, when_to_use, args_format, description) — same
    # contract across the three phases.
    parts.append(build_informational_tool_descriptions(allowed_tools))

    # Skill workflows are now ADDITIVE on top of the descriptions, not
    # replacements. The descriptions teach the LLM what each tool does;
    # the skill workflow tells it the playbook for the current attack.
    if phase == "informational":
        user_skill_content = _resolve_user_skill()
        if user_skill_content:
            parts.append(
                user_skill_content + "\n\n"
                "**Current phase is informational.** Follow the skill's reconnaissance "
                "steps to gather target info, then request transition to exploitation."
            )
        else:
            _inject_builtin_skill_workflow()

    elif phase == "exploitation":
        # Built-in skill workflows have curated tool playbooks for known
        # attack paths (CVE exploit, brute force, etc.). They append to
        # — not replace — the generic tool descriptions above.
        if not _inject_builtin_skill_workflow():
            if attack_path_type.startswith("user_skill:"):
                user_skill_content = _resolve_user_skill()
                if user_skill_content:
                    parts.append(user_skill_content)
                else:
                    parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            elif attack_path_type.endswith("-unclassified"):
                parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            # else: descriptions above are sufficient

        if not activate_post_expl:
            parts.append("\n**NOTE:** Post-exploitation phase is DISABLED. Complete exploitation and use action='complete'.\n")

    elif phase == "post_exploitation":
        user_skill_content = _resolve_user_skill()
        if user_skill_content:
            parts.append(
                user_skill_content + "\n\n"
                "**Current phase is post-exploitation.** Follow the skill's "
                "post-exploitation steps if defined, or use available tools."
            )
        elif "metasploit_console" in allowed_tools:
            if is_statefull:
                parts.append(POST_EXPLOITATION_TOOLS_STATEFULL)
            else:
                parts.append(POST_EXPLOITATION_TOOLS_STATELESS)
        # else: descriptions above are sufficient

    return "\n".join(parts)


# Export list for explicit imports
__all__ = [
    # Tool registry and builders
    "TOOL_REGISTRY",
    "build_tool_availability_table",
    "build_informational_tool_descriptions",
    "build_compact_tool_list",
    "build_informational_guidance",
    "build_attack_path_behavior",
    "build_tool_args_section",
    "build_tool_name_enum",
    "build_phase_definitions",
    # Base prompts
    "MODE_DECISION_MATRIX",
    "REACT_SYSTEM_PROMPT",
    "PENDING_OUTPUT_ANALYSIS_SECTION",
    "PENDING_PLAN_OUTPUTS_SECTION",
    "PHASE_TRANSITION_MESSAGE",
    "USER_QUESTION_MESSAGE",
    "FINAL_REPORT_PROMPT",
    "CONVERSATIONAL_RESPONSE_PROMPT",
    "SUMMARY_RESPONSE_PROMPT",
    "determine_response_tier",
    "TEXT_TO_CYPHER_SYSTEM",
    # Classification
    "ATTACK_PATH_CLASSIFICATION_PROMPT",
    "build_classification_prompt",
    # CVE exploit
    "CVE_EXPLOIT_TOOLS",
    "CVE_PAYLOAD_GUIDANCE_STATEFULL",
    "CVE_PAYLOAD_GUIDANCE_STATELESS",
    "NO_MODULE_FALLBACK_STATEFULL",
    "NO_MODULE_FALLBACK_STATELESS",
    # Hydra brute force
    "HYDRA_BRUTE_FORCE_TOOLS",
    "HYDRA_WORDLIST_GUIDANCE",
    # Phishing / Social Engineering
    "PHISHING_SOCIAL_ENGINEERING_TOOLS",
    "PHISHING_PAYLOAD_FORMAT_GUIDANCE",
    # Denial of Service
    "DOS_TOOLS",
    "DOS_VECTOR_SELECTION",
    "DOS_VERIFICATION_GUIDE",
    # SQL Injection
    "SQLI_TOOLS",
    "SQLI_OOB_WORKFLOW",
    "SQLI_PAYLOAD_REFERENCE",
    # XSS
    "XSS_TOOLS",
    "XSS_BLIND_WORKFLOW",
    "XSS_PAYLOAD_REFERENCE",
    # SSRF
    "SSRF_TOOLS",
    "SSRF_OOB_WORKFLOW",
    "SSRF_GOPHER_CHAINS",
    "SSRF_DNS_REBINDING",
    "SSRF_PAYLOAD_REFERENCE",
    "SSRF_CLOUD_PROVIDER_BLOCKS",
    "SSRF_CLOUD_DISABLED_STUB",
    # RCE
    "RCE_TOOLS",
    "RCE_AGGRESSIVE_DISABLED",
    "RCE_AGGRESSIVE_ENABLED",
    "RCE_OOB_WORKFLOW",
    "RCE_DESERIALIZATION_WORKFLOW",
    "RCE_PAYLOAD_REFERENCE",
    # Path Traversal / LFI / RFI
    "PATH_TRAVERSAL_TOOLS",
    "PATH_TRAVERSAL_PHP_WRAPPERS",
    "PATH_TRAVERSAL_OOB_WORKFLOW",
    "PATH_TRAVERSAL_ARCHIVE_EXTRACTION",
    "PATH_TRAVERSAL_PAYLOAD_REFERENCE",
    # Active Directory Kill Chain
    "AD_KILL_CHAIN_TOOLS",
    "AD_KILL_CHAIN_PAYLOAD_REFERENCE",
    # Cloud Infrastructure Exploitation
    "CLOUD_INFRA_TOOLS",
    "CLOUD_INFRA_PAYLOAD_REFERENCE",
    # API Security Testing
    "API_SECURITY_TOOLS",
    "API_SECURITY_PAYLOAD_REFERENCE",
    # Supply Chain Poisoning
    "SUPPLY_CHAIN_TOOLS",
    "SUPPLY_CHAIN_PAYLOAD_REFERENCE",
    # Domain Takeover
    "DOMAIN_TAKEOVER_TOOLS",
    "DOMAIN_TAKEOVER_PAYLOAD_REFERENCE",
    # Attack Surface Mapping
    "ATTACK_SURFACE_MAPPING_TOOLS",
    "ATTACK_SURFACE_MAPPING_PAYLOAD_REFERENCE",
    # Email Security Assessment
    "EMAIL_SECURITY_TOOLS",
    "EMAIL_SECURITY_PAYLOAD_REFERENCE",
    # Web Cache Poisoning
    "WEB_CACHE_POISONING_TOOLS",
    "WEB_CACHE_POISONING_PAYLOAD_REFERENCE",
    # Transport Security Assessment
    "TRANSPORT_SECURITY_TOOLS",
    "TRANSPORT_SECURITY_PAYLOAD_REFERENCE",
    # Infrastructure Exposure Analysis
    "INFRASTRUCTURE_EXPOSURE_TOOLS",
    "INFRASTRUCTURE_EXPOSURE_PAYLOAD_REFERENCE",
    # Unclassified attack path
    "UNCLASSIFIED_EXPLOIT_TOOLS",
    # Post-exploitation
    "POST_EXPLOITATION_TOOLS_STATEFULL",
    "POST_EXPLOITATION_TOOLS_STATELESS",
    # Stealth rules
    "STEALTH_MODE_RULES",
    # Deep Think
    "DEEP_THINK_PROMPT",
    "DEEP_THINK_SECTION",
    "DEEP_THINK_SELF_REQUEST_INSTRUCTION",
    # Function
    "get_phase_tools",
]
