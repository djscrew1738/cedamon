"""Tests for the structured expert heuristics engine."""

import os

import pytest
from heuristics import HeuristicEngine, build_context, format_recommendations
from heuristics.rules import HeuristicRule


@pytest.fixture
def engine():
    return HeuristicEngine(max_recommendations=10)


def test_wordpress_recommendations(engine):
    ctx = build_context(technologies=["wordpress"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_wpscan" in names
    assert "execute_nuclei" in names


def test_port_80_triggers_httpx(engine):
    ctx = build_context(ports=[80], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_httpx" in names


def test_redis_port_high_priority(engine):
    ctx = build_context(ports=[6379], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names
    redis_rec = next(r for r in recs if r.tool_name == "execute_nmap")
    assert redis_rec.priority == 1


def test_cve_triggers_exploit_chain(engine):
    ctx = build_context(
        technologies=["apache"],
        ports=[80],
        cves=["CVE-2021-41773"],
        phase="exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_searchsploit" in names
    assert "metasploit_console" in names


def test_already_run_tools_excluded(engine):
    ctx = build_context(
        technologies=["wordpress"],
        already_run={"execute_wpscan"},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_wpscan" not in names


def test_deduplication(engine):
    ctx = build_context(
        technologies=["wordpress", "nginx"],
        ports=[80, 443],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert names.count("execute_nuclei") == 1
    assert names.count("execute_httpx") == 1


def test_phase_restriction(engine):
    ctx = build_context(
        technologies=["wordpress"],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_hydra" not in names


def test_format_recommendations(engine):
    ctx = build_context(technologies=["wordpress"], phase="informational")
    recs = engine.recommend(ctx)
    text = format_recommendations(recs)
    assert "Structured Expert Heuristic Recommendations" in text
    assert "execute_wpscan" in text


def test_coverage_gap_subdomain_enum(engine):
    ctx = build_context(
        technologies=["domain"],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_subfinder" in names


def test_aspnet_tech_matching(engine):
    ctx = build_context(technologies=["asp.net"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_stealth_profile_prefers_cheaper_tools(engine):
    ctx = build_context(
        technologies=["wordpress", "apache"],
        phase="informational",
        profile="stealth",
    )
    recs_stealth = engine.recommend(ctx)
    ctx.profile = "aggressive"
    recs_aggressive = engine.recommend(ctx)
    # Both should still recommend wpscan and nuclei; ordering may shift.
    assert {r.tool_name for r in recs_stealth} == {r.tool_name for r in recs_aggressive}


def test_tomcat_recommendations(engine):
    ctx = build_context(technologies=["tomcat"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
    nuclei_rec = next(r for r in recs if r.tool_name == "execute_nuclei")
    templates = nuclei_rec.suggested_args.get("templates", [])
    assert any("tomcat" in t for t in templates)


def test_jenkins_recommendations(engine):
    ctx = build_context(technologies=["jenkins"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_kubernetes_recommendations(engine):
    ctx = build_context(technologies=["kubernetes"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
    nuclei_rec = next(r for r in recs if r.tool_name == "execute_nuclei")
    templates = nuclei_rec.suggested_args.get("templates", [])
    assert any("kubernetes" in t for t in templates)


def test_memcached_port(engine):
    ctx = build_context(ports=[11211], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_dns_port(engine):
    ctx = build_context(ports=[53], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_nfs_port(engine):
    ctx = build_context(ports=[2049], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_elasticsearch_port(engine):
    ctx = build_context(ports=[9200], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_combo_cicd_pipeline(engine):
    ctx = build_context(technologies=["jenkins", "gitlab"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
    assert "execute_katana" in names


def test_credentials_trigger_hydra(engine):
    ctx = build_context(
        target_info={"credentials": [{"user": "admin", "pass": "secret"}]},
        phase="exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_hydra" in names


def test_credentials_do_not_trigger_hydra_in_informational(engine):
    ctx = build_context(
        target_info={"credentials": [{"user": "admin", "pass": "secret"}]},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_hydra" not in names


def test_endpoints_trigger_arjun(engine):
    ctx = build_context(
        target_info={"endpoints": ["/api/v1/users", "/api/v1/search"]},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_arjun" in names


def test_js_files_trigger_jsluice(engine):
    ctx = build_context(
        target_info={"js_files": ["/app.js", "/bundle.js"]},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_jsluice" in names


def test_attack_path_container_k8s(engine):
    ctx = build_context(
        technologies=["http"],
        attack_path_type="container_k8s",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
    # Path-bias rule uses kubernetes templates; pipeline rule has no templates.
    nuclei_recs = [r for r in recs if r.tool_name == "execute_nuclei"]
    assert any(
        any("kubernetes" in t for t in r.suggested_args.get("templates", []))
        for r in nuclei_recs
    )


def test_attack_path_brute_force(engine):
    ctx = build_context(
        attack_path_type="brute_force_credential_guess",
        phase="exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_hydra" in names


def test_attack_path_rce(engine):
    ctx = build_context(
        cves=["CVE-2021-41773"],
        attack_path_type="rce",
        phase="exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_searchsploit" in names
    assert "metasploit_console" in names


def test_attack_path_empty_no_bias(engine):
    ctx = build_context(
        technologies=["http"],
        attack_path_type="",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    # Empty attack path should not add path-bias tools such as arjun (katana may
    # be added by the web recon pipeline because "http" is present, which is OK).
    assert "execute_arjun" not in names


# ---------------------------------------------------------------------------
# High-level recon / attack rules
# ---------------------------------------------------------------------------


def test_aws_metadata_probe(engine):
    ctx = build_context(technologies=["aws"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "169.254.169.254" in curl_rec.suggested_args.get("url", "")


def test_azure_metadata_probe(engine):
    ctx = build_context(technologies=["azure"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "169.254.169.254" in curl_rec.suggested_args.get("url", "")


def test_gcp_metadata_probe(engine):
    ctx = build_context(technologies=["gcp"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "metadata.google.internal" in curl_rec.suggested_args.get("url", "")


def test_active_directory_nmap(engine):
    ctx = build_context(technologies=["active directory"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_domain_controller_kali(engine):
    ctx = build_context(technologies=["domain controller"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_llm_endpoint_probe(engine):
    ctx = build_context(technologies=["llm"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "/v1/models" in curl_rec.suggested_args.get("path", "")


def test_mcp_endpoint_probe(engine):
    ctx = build_context(technologies=["mcp"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "/mcp" in curl_rec.suggested_args.get("path", "")


def test_vector_db_probe(engine):
    ctx = build_context(technologies=["vector db"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_github_actions_probe(engine):
    ctx = build_context(technologies=["github actions"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_ollama_port(engine):
    ctx = build_context(ports=[11434], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_kubernetes_api_port(engine):
    ctx = build_context(ports=[6443], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_ldap_port(engine):
    ctx = build_context(ports=[389], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_kerberoast_with_user_list(engine):
    ctx = build_context(
        target_info={"users": ["alice", "bob"]},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_container_escape_foothold(engine):
    ctx = build_context(
        target_info={"container_foothold": True},
        phase="post_exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_lateral_movement_credentials(engine):
    ctx = build_context(
        target_info={"credentials": [{"user": "admin", "pass": "secret"}]},
        ports=[445],
        phase="exploitation",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_active_directory_attack_path(engine):
    ctx = build_context(
        attack_path_type="active_directory",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_llm_security_attack_path(engine):
    ctx = build_context(
        attack_path_type="llm_security",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_supply_chain_attack_path(engine):
    ctx = build_context(
        attack_path_type="supply_chain",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


# ---------------------------------------------------------------------------
# Engine improvements
# ---------------------------------------------------------------------------


def test_trace_mode_returns_activations(engine):
    ctx = build_context(technologies=["wordpress"], phase="informational")
    recs, trace = engine.recommend(ctx, trace=True)
    assert isinstance(recs, list)
    assert isinstance(trace, dict)
    assert any("wordpress" in str(entry["id"]) for entries in trace.values() for entry in entries)


def test_trace_mode_default_off(engine):
    ctx = build_context(technologies=["wordpress"], phase="informational")
    result = engine.recommend(ctx)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# TargetInfo merge
# ---------------------------------------------------------------------------


def test_target_info_merge_preserves_extended_fields():
    from state import TargetInfo
    a = TargetInfo(endpoints=["/a"], subdomains=["sub1.example.com"])
    b = TargetInfo(endpoints=["/b"], subdomains=["sub2.example.com"], users=["alice"])
    merged = a.merge_from(b)
    assert "/a" in merged.endpoints
    assert "/b" in merged.endpoints
    assert "sub1.example.com" in merged.subdomains
    assert "sub2.example.com" in merged.subdomains
    assert "alice" in merged.users


# ---------------------------------------------------------------------------
# Argument templating
# ---------------------------------------------------------------------------


def test_render_target_placeholder(engine):
    rule = HeuristicRule(
        id="test-target",
        name="Test target",
        category="test",
        priority=1,
        tool_name="execute_curl",
        rationale="Test",
        suggested_args={"url": "http://{{target}}/path"},
    )
    ctx = build_context(target_info={"primary_target": "example.com"})
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["url"] == "http://example.com/path"


def test_render_domain_placeholder(engine):
    rule = HeuristicRule(
        id="test-domain",
        name="Test domain",
        category="test",
        priority=1,
        tool_name="execute_curl",
        rationale="Test",
        suggested_args={"path": "/{{domain}}/config"},
    )
    ctx = build_context(target_info={"primary_target": "example.com", "target_type": "domain"})
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["path"] == "/example.com/config"


def test_render_credentials_placeholder(engine):
    rule = HeuristicRule(
        id="test-creds",
        name="Test creds",
        category="test",
        priority=1,
        tool_name="kali_shell",
        rationale="Test",
        suggested_args={"command": "nxc smb {{target}} -u {{user}} -p {{pass}}"},
    )
    ctx = build_context(
        target_info={
            "primary_target": "10.0.0.1",
            "credentials": [{"user": "admin", "pass": "secret"}],
        }
    )
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["command"] == "nxc smb 10.0.0.1 -u admin -p secret"


def test_render_users_placeholder_creates_temp_file(engine):
    rule = HeuristicRule(
        id="test-users",
        name="Test users",
        category="test",
        priority=1,
        tool_name="kali_shell",
        rationale="Test",
        suggested_args={"command": "impacket-GetNPUsers -usersfile {{users}}"},
    )
    ctx = build_context(target_info={"users": ["alice", "bob"]})
    rendered = engine.render_rule_args(rule, ctx)
    users_file = rendered["command"].replace("impacket-GetNPUsers -usersfile ", "")
    assert os.path.exists(users_file)
    with open(users_file) as f:
        content = f.read()
    assert "alice" in content
    assert "bob" in content
    os.unlink(users_file)


def test_render_unknown_placeholder_left_as_is(engine, caplog):
    rule = HeuristicRule(
        id="test-unknown",
        name="Test unknown",
        category="test",
        priority=1,
        tool_name="execute_curl",
        rationale="Test",
        suggested_args={"path": "/{{unknown_var}}"},
    )
    ctx = build_context()
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["path"] == "/{{unknown_var}}"


def test_render_nested_args(engine):
    rule = HeuristicRule(
        id="test-nested",
        name="Test nested",
        category="test",
        priority=1,
        tool_name="execute_nuclei",
        rationale="Test",
        suggested_args={"templates": ["{{target}}/foo"], "extra": {"host": "{{host}}"}},
    )
    ctx = build_context(target_info={"primary_target": "example.com"})
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["templates"] == ["example.com/foo"]
    assert rendered["extra"]["host"] == "example.com"


# ---------------------------------------------------------------------------
# Rule validation
# ---------------------------------------------------------------------------


def test_validation_warns_on_unknown_tool(caplog):
    from heuristics.engine import HeuristicEngine
    from heuristics import rules
    import logging

    bad_rule = HeuristicRule(
        id="test-bad-tool",
        name="Bad tool",
        category="test",
        priority=1,
        tool_name="execute_nonexistent_tool",
        rationale="Test",
    )
    # Modify the list in-place so engine.py's imported reference sees the change.
    original = list(rules.TECH_RULES)
    rules.TECH_RULES[:] = [bad_rule]
    try:
        with caplog.at_level(logging.WARNING, logger="heuristics.engine"):
            HeuristicEngine(validate=True)
    finally:
        rules.TECH_RULES[:] = original
    assert any("unknown tool" in record.message.lower() for record in caplog.records)


def test_validation_warns_on_duplicate_id(caplog):
    from heuristics.engine import HeuristicEngine
    from heuristics import rules
    import logging

    dup_rule = HeuristicRule(
        id="tech-wordpress",
        name="Duplicate",
        category="test",
        priority=1,
        tool_name="execute_curl",
        rationale="Test",
    )
    original = list(rules.TECH_RULES)
    rules.TECH_RULES[:] = [dup_rule, dup_rule]
    try:
        with caplog.at_level(logging.WARNING, logger="heuristics.engine"):
            HeuristicEngine(validate=True)
    finally:
        rules.TECH_RULES[:] = original
    assert any("duplicate" in record.message.lower() for record in caplog.records)


def test_validation_warns_on_unknown_template_variable(caplog):
    from heuristics.engine import HeuristicEngine
    from heuristics import rules
    import logging

    bad_rule = HeuristicRule(
        id="test-bad-template",
        name="Bad template",
        category="test",
        priority=1,
        tool_name="execute_curl",
        rationale="Test",
        suggested_args={"path": "/{{weird_var}}"},
    )
    original = list(rules.TECH_RULES)
    rules.TECH_RULES[:] = [bad_rule]
    try:
        with caplog.at_level(logging.WARNING, logger="heuristics.engine"):
            HeuristicEngine(validate=True)
    finally:
        rules.TECH_RULES[:] = original
    assert any("unknown template variable" in record.message.lower() for record in caplog.records)


# ---------------------------------------------------------------------------
# Trace formatting
# ---------------------------------------------------------------------------


def test_format_recommendation_trace():
    from heuristics import format_recommendation_trace
    trace = {
        "technology": [
            {"id": "tech-wordpress", "tool_name": "execute_wpscan", "rationale": "WordPress", "priority": 1},
        ],
        "port": [
            {"id": "port-80", "tool_name": "execute_httpx", "rationale": "Web", "priority": 1},
        ],
    }
    text = format_recommendation_trace(trace)
    assert "Heuristic Rule Activation Trace" in text
    assert "execute_wpscan" in text
    assert "execute_httpx" in text


# ---------------------------------------------------------------------------
# Tool recommender rendering
# ---------------------------------------------------------------------------


def test_recommend_tools_renders_args():
    from tool_recommender import recommend_tools
    recs = recommend_tools(
        technologies=["wordpress"],
        already_run=set(),
        target_info={"primary_target": "example.com"},
        phase="informational",
    )
    # WordPress rule has enum args without placeholders, so just ensure it returns.
    assert any(r.tool_name == "execute_wpscan" for r in recs)


# ---------------------------------------------------------------------------
# Additional attack-surface rules
# ---------------------------------------------------------------------------


def test_swagger_probe(engine):
    ctx = build_context(technologies=["swagger"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names
    curl_rec = next(r for r in recs if r.tool_name == "execute_curl")
    assert "/openapi.json" in curl_rec.suggested_args.get("path", "")


def test_openapi_tech_keyword(engine):
    ctx = build_context(technologies=["openapi"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_grpc_probe(engine):
    ctx = build_context(technologies=["grpc"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "kali_shell" in names


def test_vpn_tech(engine):
    ctx = build_context(technologies=["vpn"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
    nuclei_rec = next(r for r in recs if r.tool_name == "execute_nuclei")
    assert any("vpn" in t for t in nuclei_rec.suggested_args.get("templates", []))


def test_cdn_tech(engine):
    ctx = build_context(technologies=["cdn"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_load_balancer_tech(engine):
    ctx = build_context(technologies=["load balancer"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_smtp_port(engine):
    ctx = build_context(ports=[25], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_imap_port(engine):
    ctx = build_context(ports=[143], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_ipsec_port(engine):
    ctx = build_context(ports=[500], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_pptp_port(engine):
    ctx = build_context(ports=[1723], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_port_8000_triggers_httpx(engine):
    ctx = build_context(ports=[8000], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_httpx" in names


def test_port_5000_api_dev(engine):
    ctx = build_context(ports=[5000], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_cve_intel_triggered_by_cve(engine):
    ctx = build_context(cves=["CVE-2021-41773"], phase="informational")
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "cve_intel" in names


def test_cve_intel_renders_cve_list(engine):
    rule = HeuristicRule(
        id="test-cve-intel",
        name="Test CVE intel",
        category="cve_intel",
        priority=1,
        tool_name="cve_intel",
        rationale="Test",
        suggested_args={"query": "{{cve}}"},
    )
    ctx = build_context(cves=["CVE-2021-41773", "CVE-2021-42013"])
    rendered = engine.render_rule_args(rule, ctx)
    assert rendered["query"] == "CVE-2021-41773,CVE-2021-42013"


def test_attack_path_api_security(engine):
    ctx = build_context(
        attack_path_type="api_security",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_arjun" in names


def test_attack_path_domain_takeover(engine):
    ctx = build_context(
        attack_path_type="domain_takeover",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_attack_path_path_traversal(engine):
    ctx = build_context(
        attack_path_type="path_traversal",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_ffuf" in names


def test_attack_path_transport_security(engine):
    ctx = build_context(
        attack_path_type="transport_security",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_attack_path_email_security(engine):
    ctx = build_context(
        attack_path_type="email_security",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_attack_path_web_cache_poisoning(engine):
    ctx = build_context(
        attack_path_type="web_cache_poisoning",
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_curl" in names


def test_coverage_gap_cve_intel(engine):
    ctx = build_context(
        cves=["CVE-2021-41773"],
        already_run=set(),
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "cve_intel" in names


def test_coverage_gap_swagger_katana(engine):
    ctx = build_context(
        technologies=["swagger"],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_katana" in names


def test_coverage_gap_email_security(engine):
    ctx = build_context(
        technologies=["email"],
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


# ---------------------------------------------------------------------------
# Graph-aware coverage gaps
# ---------------------------------------------------------------------------


def test_graph_subdomains_without_ports_triggers_httpx(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "subdomains_without_ports": [{"name": "sub.example.com"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_httpx" in names


def test_graph_ips_without_services_triggers_nmap(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "ips_without_services": [{"ip": "10.0.0.1"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nmap" in names


def test_graph_services_without_vulns_triggers_nuclei(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "services_without_vulns": [{"service": "apache"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names


def test_graph_baseurls_without_endpoints_triggers_katana(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "baseurls_without_endpoints": [{"url": "https://example.com"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_katana" in names


def test_graph_no_client_no_crash(engine):
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=None,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    assert isinstance(recs, list)


def test_graph_query_failure_no_crash(engine):
    class FailingAdapter:
        def query(self, cypher, params=None):
            raise RuntimeError("graph down")

    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=FailingAdapter(),
        phase="informational",
    )
    recs = engine.recommend(ctx)
    assert isinstance(recs, list)


def test_graph_already_run_excludes_graph_gap(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "subdomains_without_ports": [{"name": "sub.example.com"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        already_run={"execute_httpx"},
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_httpx" not in names


def test_graph_domain_without_subdomains_triggers_subfinder(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "domain_without_subdomains": [{"domain": "example.com"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_subfinder" in names


def test_graph_tech_with_cves_triggers_nuclei(engine):
    from heuristics.graph_adapter import InMemoryGraphAdapter
    adapter = InMemoryGraphAdapter({
        "tech_with_cves_without_vulns": [{"tech": "apache"}],
    })
    ctx = build_context(
        target_info={"primary_target": "example.com"},
        graph_client=adapter,
        phase="informational",
    )
    recs = engine.recommend(ctx)
    names = [r.tool_name for r in recs]
    assert "execute_nuclei" in names
