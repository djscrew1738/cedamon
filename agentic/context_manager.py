"""
Intelligent Context Manager for RedaMon XBOW Integration.

Prevents context window overflow during long-running missions (50+ actions)
by maintaining a structured SQLite-backed action log, assets registry, and
vulnerability database. Uses TF-IDF retrieval to select only the most
relevant past context for each LLM call.

Key additions (Phase 1 hardening):
    - `assets` table: extracted IPs, domains, hostnames, credentials
    - `vulnerabilities` table: type, endpoint, confidence, exploitation status
    - `query_assets()` and `query_vulnerabilities()` for planner lookups
    - `get_structured_summary()` returning a JSON-compatible dict of
      all assets and vulnerabilities for world model updates

Architecture:
    1. After every action, the raw output is stored in SQLite.
    2. Assets (IPs, domains, creds) and vulnerabilities are extracted and
       stored in dedicated tables.
    3. When the LLM is called, the context manager selects the top-K most
       relevant past summaries using TF-IDF cosine similarity.
    4. The planner can query assets and vulnerabilities for historical data.
"""

import json
import logging
import math
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_RECORDS = 10_000
DEFAULT_TOP_K = 5
MIN_TERM_FREQUENCY = 1
SCHEMA_VERSION = 2  # bumped for assets + vulnerabilities tables


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ActionRecord:
    """A single action with its raw output and structured summary."""
    id: int = 0
    session_id: str = ""
    action_name: str = ""
    phase: str = "informational"
    summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    error_summary: str = ""
    credentials_found: list[str] = field(default_factory=list)
    opened_ports: list[int] = field(default_factory=list)
    raw_output: str = ""
    timestamp: str = ""
    success: bool = True


@dataclass
class Asset:
    """A discovered asset (IP, domain, credential, hostname)."""
    asset_type: str       # ip, domain, hostname, credential, subnet, url
    value: str            # The actual asset value
    source_action: str = ""  # Which action discovered it
    confidence: float = 0.8  # 0.0–1.0
    metadata: str = ""       # JSON blob for extra info


@dataclass
class Vulnerability:
    """A discovered vulnerability."""
    vuln_type: str           # sqli, xss, rce, cve, misconfig, etc.
    endpoint: str = ""       # Affected URL/port/service
    description: str = ""
    confidence: float = 0.5  # 0.0–1.0
    cve_id: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    exploited: bool = False
    exploit_code: str = ""
    source_action: str = ""
    metadata: str = ""       # JSON blob for extra info


# ---------------------------------------------------------------------------
# TF-IDF Retriever
# ---------------------------------------------------------------------------

class TfidfRetriever:
    """Lightweight TF-IDF retriever using pure Python."""

    def __init__(self):
        self._documents: list[str] = []
        self._tokenized: list[list[str]] = []
        self._idf: dict[str, float] = {}
        self._vocab: set[str] = set()

    @staticmethod
    def tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9]{2,}", text.lower())

    def add_documents(self, documents: list[str]) -> None:
        self._documents = documents
        self._tokenized = [self.tokenize(doc) for doc in documents]
        df: Counter = Counter()
        for tokens in self._tokenized:
            df.update(set(tokens))
        N = len(documents)
        self._idf = {}
        if N == 0:
            return
        self._vocab = set()
        for term, doc_freq in df.items():
            if doc_freq >= MIN_TERM_FREQUENCY:
                self._idf[term] = math.log((N + 1) / (doc_freq + 1)) + 1.0
                self._vocab.add(term)

    def query(self, query_text: str, top_k: int = 5) -> list[tuple[int, float]]:
        if not self._documents:
            return []
        query_tokens = self.tokenize(query_text)
        if not query_tokens:
            return []
        query_tf: Counter = Counter(query_tokens)
        scores: list[tuple[int, float]] = []
        query_norm = math.sqrt(
            sum((query_tf[t] * self._idf.get(t, 0)) ** 2 for t in query_tf)
        )
        if query_norm == 0:
            return list(enumerate([0.0] * len(self._documents)))[:top_k]
        for idx, doc_tokens in enumerate(self._tokenized):
            doc_tf = Counter(doc_tokens)
            dot = 0.0
            doc_norm_sq = 0.0
            common_terms = set(query_tf.keys()) & set(doc_tf.keys())
            for term in common_terms:
                idf = self._idf.get(term, 0)
                q_weight = query_tf[term] * idf
                d_weight = doc_tf[term] * idf
                dot += q_weight * d_weight
                doc_norm_sq += d_weight ** 2
            doc_norm = math.sqrt(doc_norm_sq)
            if doc_norm == 0:
                scores.append((idx, 0.0))
            else:
                scores.append((idx, dot / (query_norm * doc_norm)))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


# ---------------------------------------------------------------------------
# Context Manager
# ---------------------------------------------------------------------------

class ContextManager:
    """Intelligent context manager for long-horizon RedaMon missions.

    Stores action records, assets, and vulnerabilities in SQLite. Uses TF-IDF
    retrieval for relevant context selection.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        top_k: int = DEFAULT_TOP_K,
        max_records: int = MAX_RECORDS,
    ):
        self.db_path = db_path
        self.top_k = top_k
        self.max_records = max_records
        self._retriever = TfidfRetriever()
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def initialize(self) -> None:
        """Create tables and indexes if they don't exist."""
        if self._initialized:
            return
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS action_records (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                action_name     TEXT NOT NULL,
                phase           TEXT NOT NULL DEFAULT 'informational',
                summary         TEXT NOT NULL DEFAULT '',
                key_findings    TEXT NOT NULL DEFAULT '[]',
                error_summary   TEXT NOT NULL DEFAULT '',
                credentials_found TEXT NOT NULL DEFAULT '[]',
                opened_ports    TEXT NOT NULL DEFAULT '[]',
                raw_output      TEXT NOT NULL DEFAULT '',
                timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
                success         INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_action_session
                ON action_records(session_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_action_phase
                ON action_records(phase);

            -- Assets: IPs, domains, hostnames, credentials discovered
            CREATE TABLE IF NOT EXISTS assets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                asset_type      TEXT NOT NULL,
                value           TEXT NOT NULL,
                source_action   TEXT NOT NULL DEFAULT '',
                confidence      REAL NOT NULL DEFAULT 0.8,
                metadata        TEXT NOT NULL DEFAULT '{}',
                timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(session_id, asset_type, value)
            );

            CREATE INDEX IF NOT EXISTS idx_assets_session
                ON assets(session_id, asset_type);

            -- Vulnerabilities: discovered weaknesses with exploitation status
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                vuln_type       TEXT NOT NULL,
                endpoint        TEXT NOT NULL DEFAULT '',
                description     TEXT NOT NULL DEFAULT '',
                confidence      REAL NOT NULL DEFAULT 0.5,
                cve_id          TEXT NOT NULL DEFAULT '',
                severity        TEXT NOT NULL DEFAULT 'medium',
                exploited       INTEGER NOT NULL DEFAULT 0,
                exploit_code    TEXT NOT NULL DEFAULT '',
                source_action   TEXT NOT NULL DEFAULT '',
                metadata        TEXT NOT NULL DEFAULT '{}',
                timestamp       TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_vulns_session
                ON vulnerabilities(session_id, severity);

            CREATE TABLE IF NOT EXISTS world_model (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
        """)

        cur = conn.execute("SELECT version FROM schema_version")
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        conn.commit()
        self._initialized = True
        logger.info("ContextManager initialized (db=%s)", self.db_path)

    # ------------------------------------------------------------------
    # Action recording
    # ------------------------------------------------------------------

    def record_action(
        self,
        *,
        session_id: str,
        action_name: str,
        phase: str = "informational",
        raw_output: str = "",
        summary: str = "",
        key_findings: Optional[list[str]] = None,
        error_summary: str = "",
        credentials_found: Optional[list[str]] = None,
        opened_ports: Optional[list[int]] = None,
        success: bool = True,
    ) -> int:
        """Record an action and auto-extract assets/vulns from findings."""
        self.initialize()

        if len(raw_output) > 50_000:
            raw_output = (
                f"[TRUNCATED from {len(raw_output)} bytes]\n"
                + raw_output[-49_000:]
            )

        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO action_records
               (session_id, action_name, phase, summary, key_findings,
                error_summary, credentials_found, opened_ports,
                raw_output, timestamp, success)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)""",
            (
                session_id, action_name, phase, summary,
                json.dumps(key_findings or []),
                error_summary,
                json.dumps(credentials_found or []),
                json.dumps(opened_ports or []),
                raw_output, 1 if success else 0,
            ),
        )
        conn.commit()
        record_id = cursor.lastrowid or 0

        # Auto-extract assets from findings and output.
        self._extract_assets(
            session_id, action_name,
            findings=key_findings or [],
            credentials=credentials_found or [],
            ports=opened_ports or [],
            raw_output=raw_output,
        )

        # Rebuild index periodically.
        if self.db_path == ":memory:" or record_id % 10 == 0:
            self._rebuild_index(session_id)
        self._prune_if_needed(session_id)

        logger.debug("Recorded action %d: %s", record_id, action_name)
        return record_id

    # ------------------------------------------------------------------
    # Asset extraction and query
    # ------------------------------------------------------------------

    def _extract_assets(
        self,
        session_id: str,
        source_action: str,
        findings: list[str],
        credentials: list[str],
        ports: list[int],
        raw_output: str,
    ) -> None:
        """Extract IPs, domains, credentials from findings and output."""
        conn = self._get_conn()

        # Extract IPs from raw output.
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for match in ip_pattern.finditer(raw_output):
            ip = match.group(1)
            # Skip private/reserved ranges unless they're the target.
            if not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO assets
                           (session_id, asset_type, value, source_action, confidence)
                           VALUES (?, 'ip', ?, ?, 0.9)""",
                        (session_id, ip, source_action),
                    )
                except Exception:
                    pass

        # Extract domains from findings.
        domain_pattern = re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE,
        )
        for finding in findings:
            for match in domain_pattern.finditer(finding):
                domain = match.group(0).lower()
                if len(domain) > 4 and not domain.endswith((".py", ".txt", ".json")):
                    try:
                        conn.execute(
                            """INSERT OR IGNORE INTO assets
                               (session_id, asset_type, value, source_action,
                                confidence)
                               VALUES (?, 'domain', ?, ?, 0.7)""",
                            (session_id, domain, source_action),
                        )
                    except Exception:
                        pass

        # Store credentials.
        for cred in credentials:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO assets
                       (session_id, asset_type, value, source_action,
                        confidence)
                       VALUES (?, 'credential', ?, ?, 0.9)""",
                    (session_id, cred[:200], source_action),
                )
            except Exception:
                pass

        # Store ports as metadata on the target IP (if we have one).
        if ports:
            try:
                port_ids = [str(p) for p in ports if 1 <= p <= 65535]
                if port_ids:
                    conn.execute(
                        """UPDATE assets SET metadata = json_set(
                               COALESCE(json(metadata), '{{}}'),
                               '$.ports', json(?)
                           ) WHERE session_id = ? AND asset_type = 'ip'
                           AND id = (SELECT id FROM assets
                                     WHERE session_id = ? AND asset_type = 'ip'
                                     ORDER BY timestamp DESC LIMIT 1)""",
                        (json.dumps(port_ids), session_id, session_id),
                    )
            except Exception:
                pass

        conn.commit()

    def add_asset(
        self,
        session_id: str,
        asset_type: str,
        value: str,
        source_action: str = "",
        confidence: float = 0.8,
    ) -> int:
        """Manually add an asset to the registry."""
        self.initialize()
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT OR REPLACE INTO assets
               (session_id, asset_type, value, source_action, confidence)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, asset_type, value, source_action, confidence),
        )
        conn.commit()
        return cursor.lastrowid or 0

    def query_assets(
        self,
        session_id: str,
        asset_type: Optional[str] = None,
    ) -> list[Asset]:
        """Query discovered assets, optionally filtered by type."""
        self.initialize()
        conn = self._get_conn()
        if asset_type:
            rows = conn.execute(
                """SELECT * FROM assets
                   WHERE session_id = ? AND asset_type = ?
                   ORDER BY timestamp DESC""",
                (session_id, asset_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM assets WHERE session_id = ? ORDER BY timestamp DESC",
                (session_id,),
            ).fetchall()
        return [
            Asset(
                asset_type=r["asset_type"],
                value=r["value"],
                source_action=r["source_action"],
                confidence=r["confidence"],
                metadata=r["metadata"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Vulnerability tracking
    # ------------------------------------------------------------------

    def add_vulnerability(
        self,
        session_id: str,
        vuln_type: str,
        endpoint: str = "",
        description: str = "",
        confidence: float = 0.5,
        cve_id: str = "",
        severity: str = "medium",
        source_action: str = "",
    ) -> int:
        """Record a vulnerability."""
        self.initialize()
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO vulnerabilities
               (session_id, vuln_type, endpoint, description, confidence,
                cve_id, severity, source_action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, vuln_type, endpoint, description, confidence,
             cve_id, severity, source_action),
        )
        conn.commit()
        return cursor.lastrowid or 0

    def mark_vulnerability_exploited(
        self, session_id: str, vuln_type: str, endpoint: str,
        exploit_code: str = "",
    ) -> None:
        """Mark a vulnerability as successfully exploited."""
        self.initialize()
        conn = self._get_conn()
        conn.execute(
            """UPDATE vulnerabilities SET exploited = 1, exploit_code = ?
               WHERE session_id = ? AND vuln_type = ? AND endpoint = ?""",
            (exploit_code[:5000], session_id, vuln_type, endpoint),
        )
        conn.commit()

    def mark_vulnerability_unexploitable(
        self, session_id: str, vuln_type: str, endpoint: str,
        error_trace: str = "",
    ) -> None:
        """Mark a vulnerability as unexploitable with error trace."""
        self.initialize()
        conn = self._get_conn()
        conn.execute(
            """UPDATE vulnerabilities SET exploited = -1,
               metadata = json_set(COALESCE(json(metadata), '{{}}'),
                                   '$.error_trace', ?)
               WHERE session_id = ? AND vuln_type = ? AND endpoint = ?""",
            (error_trace[:5000], session_id, vuln_type, endpoint),
        )
        conn.commit()

    def query_vulnerabilities(
        self,
        session_id: str,
        severity: Optional[str] = None,
        exploited: Optional[bool] = None,
    ) -> list[Vulnerability]:
        """Query vulnerabilities, optionally filtered."""
        self.initialize()
        conn = self._get_conn()
        query = "SELECT * FROM vulnerabilities WHERE session_id = ?"
        params: list = [session_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if exploited is not None:
            query += " AND exploited = ?"
            params.append(1 if exploited else 0)
        query += " ORDER BY timestamp DESC"
        rows = conn.execute(query, params).fetchall()
        return [
            Vulnerability(
                vuln_type=r["vuln_type"],
                endpoint=r["endpoint"],
                description=r["description"],
                confidence=r["confidence"],
                cve_id=r["cve_id"],
                severity=r["severity"],
                exploited=bool(r["exploited"]),
                exploit_code=r["exploit_code"],
                source_action=r["source_action"],
                metadata=r["metadata"],
            )
            for r in rows
        ]

    def get_structured_summary(self, session_id: str) -> dict:
        """Get a structured summary of all assets and vulnerabilities.

        Suitable for inclusion in the world model and planner prompts.
        """
        assets = self.query_assets(session_id)
        vulns = self.query_vulnerabilities(session_id)

        ips = [a.value for a in assets if a.asset_type == "ip"]
        domains = [a.value for a in assets if a.asset_type == "domain"]
        credentials = [a.value for a in assets if a.asset_type == "credential"]

        critical = [v for v in vulns if v.severity == "critical"]
        high = [v for v in vulns if v.severity == "high"]
        exploited = [v for v in vulns if v.exploited]

        return {
            "assets": {
                "ips": ips[-20:],
                "domains": domains[-20:],
                "credentials": credentials[-10:],
                "total_assets": len(assets),
            },
            "vulnerabilities": {
                "total": len(vulns),
                "critical": [v.description[:100] for v in critical],
                "high": [v.description[:100] for v in high],
                "exploited": [v.description[:100] for v in exploited],
            },
        }

    # ------------------------------------------------------------------
    # Retrieval and world model
    # ------------------------------------------------------------------

    def _rebuild_index(self, session_id: str) -> None:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT id, summary, action_name, phase, key_findings,
                      error_summary
               FROM action_records
               WHERE session_id = ?
               ORDER BY timestamp DESC""",
            (session_id,),
        ).fetchall()
        documents = []
        for row in rows:
            parts = [row["summary"], row["action_name"]]
            try:
                findings = json.loads(row["key_findings"])
                if findings:
                    parts.append(" ".join(findings))
            except (json.JSONDecodeError, TypeError):
                pass
            documents.append(" ".join(filter(None, parts)))
        self._retriever.add_documents(documents)

    def get_context(
        self,
        current_task: str,
        session_id: str = "",
        top_k: Optional[int] = None,
        include_phase: Optional[str] = None,
    ) -> str:
        """Retrieve the most relevant past context for the current task."""
        self.initialize()
        top_k = top_k or self.top_k
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT id, summary, action_name, phase, key_findings,
                      error_summary, credentials_found, opened_ports,
                      success, timestamp
               FROM action_records
               WHERE session_id = ?
               ORDER BY timestamp DESC""",
            (session_id,),
        ).fetchall()

        if not rows:
            return "[No prior actions recorded for this session.]"

        documents = []
        for row in rows:
            parts = [row["summary"], row["action_name"]]
            try:
                findings = json.loads(row["key_findings"])
                if findings:
                    parts.append(" ".join(findings))
            except (json.JSONDecodeError, TypeError):
                pass
            documents.append(" ".join(filter(None, parts)))

        self._retriever.add_documents(documents)
        results = self._retriever.query(current_task, top_k=top_k)

        # Build the context block.
        seen = set()
        lines = ["## Relevant Past Context\n"]
        lines.append(
            f"Showing {min(top_k, len(results))} most relevant of "
            f"{len(rows)} total actions:\n"
        )

        for idx, score in results:
            if idx >= len(rows):
                continue
            row = rows[idx]
            if idx in seen:
                continue
            seen.add(idx)

            status = "\u2713" if row["success"] else "\u2717"
            lines.append(
                f"### [{idx+1}] {row['action_name']} ({row['phase']}) "
                f"[relevance: {score:.2f}] {status}"
            )
            lines.append(f"**Summary:** {row['summary']}")

            try:
                findings = json.loads(row["key_findings"])
                if findings:
                    lines.append(f"**Findings:** {', '.join(findings[:5])}")
            except (json.JSONDecodeError, TypeError):
                pass

            if row["error_summary"]:
                lines.append(f"**Error:** {row['error_summary']}")

            try:
                creds = json.loads(row["credentials_found"])
                if creds:
                    lines.append(f"**Credentials:** {', '.join(creds[:3])}")
            except (json.JSONDecodeError, TypeError):
                pass

            try:
                ports = json.loads(row["opened_ports"])
                if ports:
                    lines.append(f"**Ports:** {', '.join(map(str, ports[:10]))}")
            except (json.JSONDecodeError, TypeError):
                pass

            lines.append("")

        # Append structured assets/vulns summary.
        summary = self.get_structured_summary(session_id)
        if summary["assets"]["total_assets"] > 0 or summary["vulnerabilities"]["total"] > 0:
            lines.append("## Discovered Assets & Vulnerabilities\n")
            lines.append(json.dumps(summary, indent=2))
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # World model persistence
    # ------------------------------------------------------------------

    def save_world_model(self, key: str, value: str) -> None:
        self.initialize()
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO world_model (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()

    def load_world_model(self, key: str) -> Optional[str]:
        self.initialize()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM world_model WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def get_world_model_summary(self) -> dict:
        self.initialize()
        conn = self._get_conn()
        rows = conn.execute("SELECT key, value FROM world_model").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def _prune_if_needed(self, session_id: str) -> None:
        conn = self._get_conn()
        count = conn.execute(
            "SELECT COUNT(*) FROM action_records WHERE session_id = ?",
            (session_id,),
        ).fetchone()[0]
        if count > self.max_records:
            excess = count - self.max_records + 100
            conn.execute(
                """DELETE FROM action_records
                   WHERE id IN (
                       SELECT id FROM action_records
                       WHERE session_id = ?
                       ORDER BY timestamp ASC LIMIT ?
                   )""",
                (session_id, excess),
            )
            conn.commit()
            logger.info("Pruned %d old records for session %s", excess, session_id)

    def stats(self, session_id: str = "") -> dict:
        self.initialize()
        conn = self._get_conn()
        where = "WHERE session_id = ?" if session_id else ""
        params = (session_id,) if session_id else ()
        total = conn.execute(
            f"SELECT COUNT(*) FROM action_records {where}", params
        ).fetchone()[0]
        success = conn.execute(
            f"SELECT COUNT(*) FROM action_records {where} AND success = 1",
            params,
        ).fetchone()[0]
        phases = conn.execute(
            f"SELECT phase, COUNT(*) as cnt FROM action_records {where} GROUP BY phase",
            params,
        ).fetchall()
        asset_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE session_id = ?",
            (session_id,),
        ).fetchone()[0] if session_id else 0
        vuln_count = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE session_id = ?",
            (session_id,),
        ).fetchone()[0] if session_id else 0
        return {
            "total_actions": total,
            "successful": success,
            "failed": total - success,
            "phases": {r["phase"]: r["cnt"] for r in phases},
            "assets": asset_count,
            "vulnerabilities": vuln_count,
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
            self._initialized = False


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def build_context_augmented_prompt(
    base_prompt: str,
    current_task: str,
    context_manager: ContextManager,
    session_id: str,
    world_model_summary: str = "",
    top_k: int = DEFAULT_TOP_K,
) -> str:
    """Build a context-augmented LLM prompt."""
    parts = [base_prompt]
    if world_model_summary:
        parts.append("\n## Current World Model\n")
        parts.append(world_model_summary)
    relevant_context = context_manager.get_context(
        current_task=current_task, session_id=session_id, top_k=top_k,
    )
    parts.append(relevant_context)
    parts.append("\n## Current Task\n")
    parts.append(current_task)
    return "\n".join(parts)
