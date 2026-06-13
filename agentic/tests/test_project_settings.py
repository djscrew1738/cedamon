"""Tests for agentic/project_settings defaults and API mapping."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from project_settings import (
    DEFAULT_AGENT_SETTINGS,
    DEFAULT_EXPLOITATION_SYSTEM_PROMPT,
    DEFAULT_INFORMATIONAL_SYSTEM_PROMPT,
    DEFAULT_POST_EXPLOITATION_SYSTEM_PROMPT,
    fetch_agent_settings,
)


class DefaultInformationalPromptTests(unittest.TestCase):
    """Sanity checks for the built-in Information Phase system prompt."""

    def test_default_is_non_empty(self):
        self.assertTrue(DEFAULT_INFORMATIONAL_SYSTEM_PROMPT)
        self.assertEqual(
            DEFAULT_AGENT_SETTINGS["INFORMATIONAL_SYSTEM_PROMPT"],
            DEFAULT_INFORMATIONAL_SYSTEM_PROMPT,
        )

    def test_default_contains_phase_rules(self):
        prompt = DEFAULT_INFORMATIONAL_SYSTEM_PROMPT.lower()
        self.assertIn("graph-first", prompt)
        self.assertIn("passive before active", prompt)
        self.assertIn("no exploitation", prompt)
        self.assertIn("exit criteria", prompt)


class DefaultExploitationPromptTests(unittest.TestCase):
    """Sanity checks for the built-in Exploitation Phase system prompt."""

    def test_default_is_non_empty(self):
        self.assertTrue(DEFAULT_EXPLOITATION_SYSTEM_PROMPT)
        self.assertEqual(
            DEFAULT_AGENT_SETTINGS["EXPL_SYSTEM_PROMPT"],
            DEFAULT_EXPLOITATION_SYSTEM_PROMPT,
        )

    def test_default_contains_phase_rules(self):
        prompt = DEFAULT_EXPLOITATION_SYSTEM_PROMPT.lower()
        self.assertIn("confirm before firing", prompt)
        self.assertIn("capture proof", prompt)
        self.assertIn("stop on success", prompt)
        self.assertIn("document and clean up", prompt)


class DefaultPostExploitationPromptTests(unittest.TestCase):
    """Sanity checks for the built-in Post-Exploitation Phase system prompt."""

    def test_default_is_non_empty(self):
        self.assertTrue(DEFAULT_POST_EXPLOITATION_SYSTEM_PROMPT)
        self.assertEqual(
            DEFAULT_AGENT_SETTINGS["POST_EXPL_SYSTEM_PROMPT"],
            DEFAULT_POST_EXPLOITATION_SYSTEM_PROMPT,
        )

    def test_default_contains_phase_rules(self):
        prompt = DEFAULT_POST_EXPLOITATION_SYSTEM_PROMPT.lower()
        self.assertIn("enumerate first", prompt)
        self.assertIn("capture proof", prompt)
        self.assertIn("minimize footprint", prompt)
        self.assertIn("know when to stop", prompt)


class FetchAgentSettingsTests(unittest.TestCase):
    """Tests for fetching project settings from the webapp API."""

    def _mock_project_response(self, project_data: dict):
        """Return a patched requests.get that yields the given project JSON."""
        mock_response = MagicMock(ok=True, status_code=200)
        mock_response.json.return_value = project_data
        mock_response.raise_for_status = MagicMock()
        return patch("requests.get", return_value=mock_response)

    def test_empty_informational_prompt_falls_back_to_default(self):
        with self._mock_project_response(
            {
                "agentInformationalSystemPrompt": "",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(
            settings["INFORMATIONAL_SYSTEM_PROMPT"],
            DEFAULT_INFORMATIONAL_SYSTEM_PROMPT,
        )

    def test_custom_informational_prompt_overrides_default(self):
        with self._mock_project_response(
            {
                "agentInformationalSystemPrompt": "CUSTOM PROMPT",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(settings["INFORMATIONAL_SYSTEM_PROMPT"], "CUSTOM PROMPT")

    def test_empty_exploitation_prompt_falls_back_to_default(self):
        with self._mock_project_response(
            {
                "agentExplSystemPrompt": "",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(
            settings["EXPL_SYSTEM_PROMPT"],
            DEFAULT_EXPLOITATION_SYSTEM_PROMPT,
        )

    def test_custom_exploitation_prompt_overrides_default(self):
        with self._mock_project_response(
            {
                "agentExplSystemPrompt": "CUSTOM EXPLOIT PROMPT",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(settings["EXPL_SYSTEM_PROMPT"], "CUSTOM EXPLOIT PROMPT")

    def test_empty_post_exploitation_prompt_falls_back_to_default(self):
        with self._mock_project_response(
            {
                "agentPostExplSystemPrompt": "",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(
            settings["POST_EXPL_SYSTEM_PROMPT"],
            DEFAULT_POST_EXPLOITATION_SYSTEM_PROMPT,
        )

    def test_custom_post_exploitation_prompt_overrides_default(self):
        with self._mock_project_response(
            {
                "agentPostExplSystemPrompt": "CUSTOM POST PROMPT",
                "agentToolPhaseMap": DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"],
            }
        ):
            settings = fetch_agent_settings("proj-123", "http://webapp")
        self.assertEqual(settings["POST_EXPL_SYSTEM_PROMPT"], "CUSTOM POST PROMPT")


if __name__ == "__main__":
    unittest.main()
