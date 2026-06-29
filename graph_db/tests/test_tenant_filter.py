"""
Tenant filter tests for graph_db.tenant_filter.

Stubs neo4j at module level — no live Neo4j connection needed.
"""
import sys
from unittest.mock import MagicMock

_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())

import pytest
from graph_db.tenant_filter import (
    inject_tenant_filter,
    find_disallowed_write_operation,
    TENANT_PARAMS,
)


class TestFindDisallowedWrite:
    """Write-operation detection."""

    def test_detects_create(self):
        assert find_disallowed_write_operation("CREATE (n:Node)") is not None

    def test_detects_merge(self):
        assert find_disallowed_write_operation("MERGE (n:Node)") is not None

    def test_detects_delete(self):
        result = find_disallowed_write_operation("MATCH (n) DELETE n")
        assert result is not None
        assert "DELETE" in result

    def test_detects_detach_delete(self):
        result = find_disallowed_write_operation("MATCH (n) DETACH DELETE n")
        assert result is not None
        assert "DETACH DELETE" in result

    def test_detects_set(self):
        assert find_disallowed_write_operation("MATCH (n) SET n.foo = 1") is not None

    def test_allows_pure_read(self):
        assert find_disallowed_write_operation("MATCH (n) RETURN n") is None

    def test_allows_read_with_where(self):
        assert find_disallowed_write_operation(
            "MATCH (n:Host) WHERE n.active = true RETURN n"
        ) is None

    def test_case_insensitive(self):
        assert find_disallowed_write_operation("create (n:Node)") is not None
        assert find_disallowed_write_operation("match (n:Node) RETURN n") is None


class TestInjectTenantFilter:
    """Inline tenant property injection."""

    def test_adds_tenant_props_to_bare_node(self):
        result = inject_tenant_filter("MATCH (d:Domain) RETURN d", "user1", "proj1")
        assert "user_id: $tenant_user_id" in result
        assert "project_id: $tenant_project_id" in result
        assert "(d:Domain {" in result

    def test_preserves_existing_props(self):
        result = inject_tenant_filter(
            'MATCH (d:Domain {name: "example.com"}) RETURN d', "user1", "proj1"
        )
        assert 'name: "example.com"' in result
        assert "user_id: $tenant_user_id" in result
        assert "project_id: $tenant_project_id" in result

    def test_handles_multiple_nodes(self):
        result = inject_tenant_filter(
            "MATCH (d:Domain)-[:HAS_IP]->(i:IP) RETURN d, i", "user1", "proj1"
        )
        assert result.count("user_id: $tenant_user_id") == 2
        assert result.count("project_id: $tenant_project_id") == 2

    def test_handles_empty_props(self):
        result = inject_tenant_filter("MATCH (d:Domain {}) RETURN d", "user1", "proj1")
        assert "user_id: $tenant_user_id" in result
        assert "{" in result

    def test_idempotent(self):
        query = "MATCH (d:Domain) RETURN d"
        once = inject_tenant_filter(query, "user1", "proj1")
        twice = inject_tenant_filter(once, "user1", "proj1")
        assert "user_id: $tenant_user_id" in twice

    def test_does_not_modify_non_node_patterns(self):
        result = inject_tenant_filter("RETURN 1 AS test", "user1", "proj1")
        assert result == "RETURN 1 AS test"

    def test_tenant_params_constant(self):
        assert "tenant_user_id" in TENANT_PARAMS
        assert "tenant_project_id" in TENANT_PARAMS


class TestCypherRequiringInjection:
    """Edge cases where injection must succeed."""

    def test_with_clause(self):
        result = inject_tenant_filter(
            "MATCH (d:Domain) WITH d MATCH (d)-[:HAS_PORT]->(p:Port) RETURN p",
            "user1", "proj1",
        )
        assert result.count("user_id: $tenant_user_id") == 2

    def test_optional_match(self):
        result = inject_tenant_filter(
            "MATCH (d:Domain) OPTIONAL MATCH (d)-[:HAS_VULN]->(v:Vulnerability) RETURN d, v",
            "user1", "proj1",
        )
        assert result.count("user_id: $tenant_user_id") == 2
