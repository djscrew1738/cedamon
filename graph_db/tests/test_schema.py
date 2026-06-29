"""
Schema constant tests for graph_db.schema.

Stubs neo4j at module level — no live Neo4j connection needed.
"""
import sys
import re
from unittest.mock import MagicMock

# ── Install neo4j stub before any graph_db import ────────────────────────
_neo4j_mock = MagicMock()
_neo4j_mock.GraphDatabase.driver = MagicMock()
sys.modules.setdefault("neo4j", _neo4j_mock)
sys.modules.setdefault("dotenv", MagicMock())

import pytest
from graph_db import schema


class TestConstraints:
    """Verify constraint definitions are well-formed."""

    def test_all_constraints_have_if_not_exists(self):
        """Every CREATE CONSTRAINT must use IF NOT EXISTS for idempotency."""
        for stmt in schema.CONSTRAINTS:
            assert "IF NOT EXISTS" in stmt, f"Missing IF NOT EXISTS: {stmt[:80]}"

    def test_unique_constraint_names(self):
        """No duplicate constraint names across the list."""
        names = []
        for stmt in schema.CONSTRAINTS:
            m = re.search(r"CREATE CONSTRAINT (\S+)", stmt)
            assert m, f"Cannot parse constraint name: {stmt[:60]}"
            names.append(m.group(1))
        assert len(names) == len(set(names)), f"Duplicate names: {names}"

    def test_constraints_are_non_empty(self):
        assert len(schema.CONSTRAINTS) > 10, "Expected >10 constraints"


class TestDropLegacy:
    """Verify legacy constraint drops."""

    def test_drops_use_if_exists(self):
        for stmt in schema.DROP_LEGACY_CONSTRAINTS:
            assert "IF EXISTS" in stmt, f"Missing IF EXISTS: {stmt}"

    def test_drops_are_non_empty(self):
        assert len(schema.DROP_LEGACY_CONSTRAINTS) >= 3


class TestTenantIndexes:
    """Verify tenant composite indexes."""

    def test_all_indexes_have_if_not_exists(self):
        for stmt in schema.TENANT_INDEXES:
            assert "IF NOT EXISTS" in stmt, f"Missing IF NOT EXISTS: {stmt[:80]}"

    def test_tenant_indexes_are_non_empty(self):
        assert len(schema.TENANT_INDEXES) > 5, "Expected >5 tenant indexes"


class TestAdditionalIndexes:
    """Verify functional indexes."""

    def test_all_indexes_have_if_not_exists(self):
        for stmt in schema.ADDITIONAL_INDEXES:
            assert "IF NOT EXISTS" in stmt, f"Missing IF NOT EXISTS: {stmt[:80]}"

    def test_additional_indexes_are_non_empty(self):
        assert len(schema.ADDITIONAL_INDEXES) > 10, "Expected >10 additional indexes"


class TestInitSchema:
    """Test schema initialization function."""

    def test_init_schema_runs_all_stanzas(self):
        """init_schema should run drop + constraints + tenant + additional."""
        mock_session = MagicMock()
        schema.init_schema(mock_session)

        expected_min = (len(schema.DROP_LEGACY_CONSTRAINTS) +
                        len(schema.CONSTRAINTS) +
                        len(schema.TENANT_INDEXES) +
                        len(schema.ADDITIONAL_INDEXES))
        actual = mock_session.run.call_count
        assert actual >= expected_min, \
            f"init_schema ran {actual} statements, expected >= {expected_min}"

    def test_init_schema_tolerates_errors(self):
        """init_schema must not raise even when constraints already exist."""
        mock_session = MagicMock()
        mock_session.run.side_effect = Exception("already exists")
        try:
            schema.init_schema(mock_session)
        except Exception as exc:
            pytest.fail(f"init_schema raised: {exc}")

    def test_init_schema_handles_other_errors(self):
        """Non-'already exists' errors should be tolerated (logged, not raised)."""
        mock_session = MagicMock()
        mock_session.run.side_effect = RuntimeError("some unexpected error")
        try:
            schema.init_schema(mock_session)
        except Exception as exc:
            pytest.fail(f"init_schema raised on unexpected error: {exc}")
