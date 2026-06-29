"""
Tests for ContextManager — TF-IDF retrieval and action recording.

Verifies:
    - Action recording and retrieval
    - TF-IDF relevance scoring
    - World model persistence
    - Pruning old records
    - Session isolation
"""

import json
import pytest
from context_manager import (
    ContextManager,
    TfidfRetriever,
    build_context_augmented_prompt,
    ActionRecord,
)


class TestTfidfRetriever:
    """TF-IDF retriever unit tests."""

    def test_empty_returns_nothing(self):
        ret = TfidfRetriever()
        results = ret.query("anything")
        assert results == []

    def test_single_document_perfect_match(self):
        ret = TfidfRetriever()
        ret.add_documents(["nmap scan discovered port 22 and port 80"])
        results = ret.query("nmap scan port 22", top_k=1)
        assert len(results) == 1
        assert results[0][0] == 0
        assert results[0][1] > 0.0  # score should be positive

    def test_relevance_ordering(self):
        ret = TfidfRetriever()
        ret.add_documents([
            "nmap scan discovered port 22 ssh",
            "hydra brute force ssh login",
            "nuclei template cve-2024-1234 wordpress",
            "metasploit exploit against port 445",
        ])
        results = ret.query("ssh port 22 nmap", top_k=3)
        # First doc should be most relevant (contains nmap, port 22, ssh)
        assert results[0][0] == 0
        # Second should be hydra (contains ssh)
        assert results[1][0] == 1
        # Scores should be in descending order
        assert results[0][1] >= results[1][1] >= results[2][1]

    def test_no_match_returns_all_with_zero_scores(self):
        ret = TfidfRetriever()
        ret.add_documents(["nmap found port 80", "hydra found ssh"])
        results = ret.query("zzzxyz notfound")
        assert len(results) == 2
        assert all(score == 0.0 for _, score in results)

    def test_multiple_documents_same_content(self):
        ret = TfidfRetriever()
        ret.add_documents(["same content here", "same content here"])
        results = ret.query("same content")
        assert len(results) == 2
        # Both should have identical scores
        assert results[0][1] == results[1][1]

    def test_tokenization_filters_short_words(self):
        ret = TfidfRetriever()
        tokens = ret.tokenize("a bb ccc dddd eeeee")
        # 'a' is one char, filtered. 'bb' is two chars, so included.
        # Actually min length is 2.
        assert "bb" in tokens
        assert "ccc" in tokens
        assert "dddd" in tokens
        assert "eeeee" in tokens
        assert "a" not in tokens


class TestContextManager:
    """ContextManager integration tests (in-memory SQLite)."""

    @pytest.fixture
    def ctx(self):
        """Create an in-memory context manager for testing."""
        cm = ContextManager(db_path=":memory:")
        cm.initialize()
        yield cm
        cm.close()

    def test_initialize_creates_tables(self, ctx):
        conn = ctx._get_conn()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {r["name"] for r in tables}
        assert "action_records" in table_names
        assert "world_model" in table_names
        assert "schema_version" in table_names

    def test_record_and_retrieve(self, ctx):
        ctx.record_action(
            session_id="test-session",
            action_name="nmap_scan",
            summary="Discovered ports 22, 80, 443",
            key_findings=["SSH on 22", "nginx on 80"],
            opened_ports=[22, 80, 443],
            success=True,
        )

        ctx.record_action(
            session_id="test-session",
            action_name="hydra_brute",
            summary="Cracked SSH password for admin",
            key_findings=["admin:hunter2"],
            credentials_found=["admin:hunter2"],
            success=True,
        )

        context = ctx.get_context(
            current_task="exploit port 22 ssh",
            session_id="test-session",
        )
        assert "nmap_scan" in context
        assert "hydra_brute" in context
        assert "SSH on 22" in context

    def test_get_context_empty_session(self, ctx):
        result = ctx.get_context(
            current_task="anything",
            session_id="no-such-session",
        )
        assert "No prior actions" in result

    def test_world_model_persistence(self, ctx):
        ctx.save_world_model("target_ip", "10.0.0.1")
        ctx.save_world_model("found_flag", "FLAG{test}")

        assert ctx.load_world_model("target_ip") == "10.0.0.1"
        assert ctx.load_world_model("found_flag") == "FLAG{test}"
        assert ctx.load_world_model("nonexistent") is None

        summary = ctx.get_world_model_summary()
        assert summary["target_ip"] == "10.0.0.1"
        assert summary["found_flag"] == "FLAG{test}"

    def test_session_isolation(self, ctx):
        ctx.record_action(
            session_id="session-a",
            action_name="nmap_a",
            summary="Session A nmap",
        )
        ctx.record_action(
            session_id="session-b",
            action_name="nmap_b",
            summary="Session B nmap",
        )

        context_a = ctx.get_context(
            current_task="nmap",
            session_id="session-a",
        )
        context_b = ctx.get_context(
            current_task="nmap",
            session_id="session-b",
        )

        assert "nmap_a" in context_a
        assert "nmap_b" not in context_a
        assert "nmap_b" in context_b
        assert "nmap_a" not in context_b

    def test_stats(self, ctx):
        ctx.record_action(
            session_id="test",
            action_name="nmap",
            phase="informational",
            success=True,
        )
        ctx.record_action(
            session_id="test",
            action_name="exploit",
            phase="exploitation",
            success=False,
        )

        stats = ctx.stats(session_id="test")
        assert stats["total_actions"] == 2
        assert stats["successful"] == 1
        assert stats["failed"] == 1
        assert stats["phases"]["informational"] == 1
        assert stats["phases"]["exploitation"] == 1

    def test_pruning(self, ctx):
        # Use a low max_records to trigger pruning.
        ctx.max_records = 5
        for i in range(10):
            ctx.record_action(
                session_id="test",
                action_name=f"action_{i}",
                summary=f"Action {i}",
            )

        # Should have pruned back to ~max_records.
        stats = ctx.stats(session_id="test")
        assert stats["total_actions"] <= 7  # 5 + some buffer

    def test_raw_output_truncation(self, ctx):
        big_output = "A" * 100_000
        ctx.record_action(
            session_id="test",
            action_name="big_output",
            raw_output=big_output,
        )

        conn = ctx._get_conn()
        row = conn.execute(
            "SELECT raw_output FROM action_records WHERE action_name = 'big_output'"
        ).fetchone()
        raw = row["raw_output"]
        assert len(raw) <= 55_000  # truncated + truncation notice
        assert "[TRUNCATED" in raw

    def test_error_summary_preserved(self, ctx):
        ctx.record_action(
            session_id="test",
            action_name="failed_exploit",
            summary="Tried SQL injection",
            error_summary="Connection refused on port 3306",
            success=False,
        )

        context = ctx.get_context(
            current_task="sql injection",
            session_id="test",
        )
        assert "Connection refused" in context

    def test_include_phase_filter(self, ctx):
        for i in range(5):
            ctx.record_action(
                session_id="test",
                action_name=f"recon_{i}",
                phase="informational",
                summary=f"Recon step {i}",
            )
        ctx.record_action(
            session_id="test",
            action_name="exploit_1",
            phase="exploitation",
            summary="Exploit step",
        )

        context = ctx.get_context(
            current_task="exploit",
            session_id="test",
            include_phase="exploitation",
        )
        assert "exploit_1" in context


class TestBuildContextAugmentedPrompt:
    """Tests for the prompt builder helper."""

    def test_builds_complete_prompt(self):
        ctx = ContextManager(db_path=":memory:")
        ctx.initialize()

        ctx.record_action(
            session_id="test",
            action_name="nmap",
            summary="Found port 22",
            key_findings=["SSH on 22"],
        )

        prompt = build_context_augmented_prompt(
            base_prompt="You are a pentester.",
            current_task="Exploit SSH on port 22",
            context_manager=ctx,
            session_id="test",
            world_model_summary="Target: 10.0.0.1\nPorts: 22",
            top_k=3,
        )
        ctx.close()

        assert "You are a pentester" in prompt
        assert "Exploit SSH on port 22" in prompt
        assert "nmap" in prompt
        assert "Target: 10.0.0.1" in prompt

    def test_no_world_model(self):
        ctx = ContextManager(db_path=":memory:")
        ctx.initialize()

        prompt = build_context_augmented_prompt(
            base_prompt="Base prompt",
            current_task="Task",
            context_manager=ctx,
            session_id="empty",
            world_model_summary="",
        )
        ctx.close()

        assert "Base prompt" in prompt
        assert "Task" in prompt
        assert "No prior actions" in prompt


class TestActionRecord:
    """Tests for the ActionRecord dataclass."""

    def test_defaults(self):
        record = ActionRecord()
        assert record.id == 0
        assert record.session_id == ""
        assert record.phase == "informational"
        assert record.key_findings == []
        assert record.success is True

    def test_custom_fields(self):
        record = ActionRecord(
            id=42,
            session_id="sess-1",
            action_name="exploit",
            phase="exploitation",
            summary="Cracked it",
            key_findings=["flag found"],
            error_summary="",
            credentials_found=["admin:pass"],
            opened_ports=[22, 443],
            success=True,
        )
        assert record.id == 42
        assert record.phase == "exploitation"
        assert len(record.opened_ports) == 2
