"""
Cross-Engagement Memory for RedaMon XBOW Integration.

Extracts reusable tactics and rules from completed engagements so that
future engagements can pre-prioritize attack paths based on historical
success. Uses a simple JSON file for storage.

Key Features:
    - After a successful exploit, extract the tactic (e.g., "WordPress plugin
      X is vulnerable to SQLi") as a structured rule.
    - Rules carry metadata: target fingerprint, confidence, timestamp,
      success count.
    - When starting a new engagement, query rules matching the target
      fingerprint to pre-prioritize attack paths.
    - Decay mechanism: rules that haven't been validated recently lose
      confidence over time.

Usage:
    mem = CrossEngagementMemory()
    mem.record_tactic(
        tactic="WordPress plugin wp-file-manager 6.0 allows RCE",
        target_fingerprint="wordpress+php7.4",
        confidence=0.9,
    )
    # On next engagement:
    relevant = mem.query_tactics("wordpress+php8.0")
    # Returns matching rules sorted by confidence.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MEMORY_PATH = os.path.expanduser("~/.redamon/cross_engagement.json")

# Days after which a rule's confidence starts decaying.
DECAY_START_DAYS = 30

# Minimum confidence before a rule is pruned.
MIN_CONFIDENCE = 0.2


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class TacticRule:
    """A reusable tactic extracted from a successful engagement."""

    tactic: str                         # Natural language description
    target_fingerprint: str = ""        # e.g., "wordpress+php7.4+nginx"
    attack_type: str = ""               # sqli, xss, rce, cve, misconfig, etc.
    confidence: float = 0.7             # 0.0–1.0
    success_count: int = 1
    last_validated: str = ""            # ISO timestamp
    tool_used: str = ""                 # Which tool succeeded
    exploit_code_ref: str = ""          # Path to skill library template
    tags: list[str] = field(default_factory=list)

    def decay(self, current_time: float) -> "TacticRule":
        """Apply time-based confidence decay.

        Returns a new TacticRule with adjusted confidence.
        """
        if not self.last_validated:
            return self

        try:
            validated = datetime.fromisoformat(self.last_validated).timestamp()
        except (ValueError, OSError):
            return self

        age_days = (current_time - validated) / 86400
        if age_days > DECAY_START_DAYS:
            # Linear decay after DECAY_START_DAYS.
            decay = min(0.5, (age_days - DECAY_START_DAYS) / 90)
            new_conf = max(MIN_CONFIDENCE, self.confidence * (1 - decay))
            return TacticRule(
                tactic=self.tactic,
                target_fingerprint=self.target_fingerprint,
                attack_type=self.attack_type,
                confidence=round(new_conf, 3),
                success_count=self.success_count,
                last_validated=self.last_validated,
                tool_used=self.tool_used,
                exploit_code_ref=self.exploit_code_ref,
                tags=self.tags,
            )
        return self


# ---------------------------------------------------------------------------
# Cross-Engagement Memory
# ---------------------------------------------------------------------------

class CrossEngagementMemory:
    """Persistent cross-engagement tactical memory.

    Stores reusable tactics as structured rules in a JSON file. Provides
    query methods for matching tactics to new engagement targets.
    """

    def __init__(self, memory_path: str = DEFAULT_MEMORY_PATH):
        self.memory_path = Path(memory_path)
        self._rules: list[TacticRule] = []
        self._loaded = False

    def _load(self) -> None:
        """Load rules from the JSON file."""
        if self._loaded:
            return

        if self.memory_path.exists():
            try:
                with open(self.memory_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._rules = [
                    TacticRule(
                        tactic=r.get("tactic", ""),
                        target_fingerprint=r.get("target_fingerprint", ""),
                        attack_type=r.get("attack_type", ""),
                        confidence=r.get("confidence", 0.7),
                        success_count=r.get("success_count", 1),
                        last_validated=r.get("last_validated", ""),
                        tool_used=r.get("tool_used", ""),
                        exploit_code_ref=r.get("exploit_code_ref", ""),
                        tags=r.get("tags", []),
                    )
                    for r in data.get("rules", [])
                ]
                logger.info(
                    "Loaded %d rules from %s", len(self._rules), self.memory_path
                )
            except Exception as exc:
                logger.warning("Failed to load memory: %s", exc)
                self._rules = []
        else:
            self._rules = []
        self._loaded = True

    def _save(self) -> None:
        """Save rules to the JSON file."""
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {
                "rules": [
                    {
                        "tactic": r.tactic,
                        "target_fingerprint": r.target_fingerprint,
                        "attack_type": r.attack_type,
                        "confidence": r.confidence,
                        "success_count": r.success_count,
                        "last_validated": r.last_validated,
                        "tool_used": r.tool_used,
                        "exploit_code_ref": r.exploit_code_ref,
                        "tags": r.tags,
                    }
                    for r in self._rules
                ],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self.memory_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("Failed to save memory: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_tactic(
        self,
        tactic: str,
        target_fingerprint: str = "",
        attack_type: str = "",
        confidence: float = 0.7,
        tool_used: str = "",
        exploit_code_ref: str = "",
        tags: Optional[list[str]] = None,
    ) -> TacticRule:
        """Record a new tactic or update an existing one.

        If a similar tactic already exists (same tactic text), increments
        success_count and confidence rather than creating a duplicate.
        """
        self._load()

        now = datetime.now(timezone.utc).isoformat()

        # Check for existing similar tactic.
        for rule in self._rules:
            if rule.tactic.lower() == tactic.lower():
                rule.success_count += 1
                rule.confidence = min(1.0, rule.confidence + 0.1)
                rule.last_validated = now
                if tool_used:
                    rule.tool_used = tool_used
                logger.info(
                    "Updated existing tactic '%s' (count=%d, conf=%.2f)",
                    tactic[:60], rule.success_count, rule.confidence,
                )
                self._save()
                return rule

        # Create new rule.
        rule = TacticRule(
            tactic=tactic,
            target_fingerprint=target_fingerprint,
            attack_type=attack_type,
            confidence=confidence,
            success_count=1,
            last_validated=now,
            tool_used=tool_used,
            exploit_code_ref=exploit_code_ref,
            tags=tags or [],
        )
        self._rules.append(rule)
        logger.info("Recorded new tactic: %s", tactic[:60])
        self._save()
        return rule

    def query_tactics(
        self,
        target_fingerprint: str = "",
        attack_type: Optional[str] = None,
        min_confidence: float = 0.3,
        limit: int = 20,
    ) -> list[TacticRule]:
        """Query tactics matching the target fingerprint.

        Results are sorted by confidence (descending) and include decayed
        confidence values for older rules.

        Args:
            target_fingerprint: Target tech stack fingerprint to match against.
                Uses substring matching (e.g., "wordpress" matches "wordpress+php7.4").
            attack_type: Optional filter by attack type.
            min_confidence: Minimum confidence threshold.
            limit: Maximum number of results.

        Returns:
            List of matching TacticRule, sorted by confidence descending.
        """
        self._load()
        now = time.time()

        # Apply decay and filter.
        results = []
        for rule in self._rules:
            decayed = rule.decay(now)
            if decayed.confidence < min_confidence:
                continue

            # Filter by attack type.
            if attack_type and decayed.attack_type != attack_type:
                continue

            # Filter by target fingerprint (substring match).
            if target_fingerprint:
                fp_lower = target_fingerprint.lower()
                rule_fp = decayed.target_fingerprint.lower()
                # Check if any token in the query fingerprint matches.
                query_tokens = set(fp_lower.replace("+", " ").split())
                rule_tokens = set(rule_fp.replace("+", " ").split())
                if not (query_tokens & rule_tokens):
                    continue

            results.append(decayed)

        # Sort by confidence descending.
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results[:limit]

    def get_prioritized_attack_paths(
        self,
        target_fingerprint: str,
        limit: int = 5,
    ) -> list[str]:
        """Get a list of prioritized attack paths for a new engagement.

        Returns a list of tactic descriptions sorted by confidence.
        Suitable for injecting into the planner prompt.
        """
        tactics = self.query_tactics(
            target_fingerprint=target_fingerprint,
            min_confidence=0.3,
            limit=limit,
        )
        return [
            f"[conf={t.confidence:.2f}, n={t.success_count}] {t.tactic}"
            for t in tactics
        ]

    def prune_low_confidence(self) -> int:
        """Remove rules below minimum confidence. Returns count removed."""
        self._load()
        now = time.time()
        before = len(self._rules)
        self._rules = [
            r for r in self._rules
            if r.decay(now).confidence >= MIN_CONFIDENCE
        ]
        removed = before - len(self._rules)
        if removed > 0:
            logger.info("Pruned %d low-confidence rules", removed)
            self._save()
        return removed

    def stats(self) -> dict:
        """Get statistics about the memory store."""
        self._load()
        attack_types = {}
        for r in self._rules:
            at = r.attack_type or "unknown"
            attack_types[at] = attack_types.get(at, 0) + 1
        return {
            "total_rules": len(self._rules),
            "attack_types": attack_types,
            "avg_confidence": (
                sum(r.confidence for r in self._rules) / max(len(self._rules), 1)
            ),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_memory: Optional[CrossEngagementMemory] = None


def get_cross_engagement_memory(**kwargs) -> CrossEngagementMemory:
    global _default_memory
    if _default_memory is None:
        _default_memory = CrossEngagementMemory(**kwargs)
    return _default_memory
