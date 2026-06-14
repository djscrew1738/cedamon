"""Lightweight graph query adapter for the heuristic engine.

The heuristic engine should not depend directly on ``graph_db`` internals.  This
module defines a small Protocol and a concrete Neo4j adapter that wraps the
project's existing graph client.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class GraphQueryAdapter(Protocol):
    """Minimal interface the heuristic engine needs from a graph client."""

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run a read-only Cypher query and return a list of record dicts."""
        ...


class Neo4jGraphAdapter:
    """Adapter wrapping graph_db.Neo4jClient (or any object with a ``driver``)."""

    def __init__(self, client: Any, user_id: str, project_id: str):
        self.client = client
        self.user_id = user_id
        self.project_id = project_id

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run Cypher with automatic user_id/project_id injection.

        Falls back gracefully if the client has no driver/session interface.
        """
        params = dict(params or {})
        params.setdefault("uid", self.user_id)
        params.setdefault("pid", self.project_id)
        try:
            driver = getattr(self.client, "driver", None)
            if driver is None:
                logger.warning("Graph client has no 'driver' attribute")
                return []
            with driver.session() as session:
                result = session.run(cypher, params)
                return [record.data() for record in result]
        except Exception as exc:
            logger.warning("Graph query failed: %s", exc)
            return []


class InMemoryGraphAdapter:
    """Fake adapter for unit tests."""

    def __init__(self, responses: dict[str, list[dict[str, Any]]] | None = None):
        self.responses = responses or {}
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.queries.append((cypher, params or {}))
        # Return the first matching response key contained in the cypher string.
        for key, value in self.responses.items():
            if key in cypher:
                return value
        return []
