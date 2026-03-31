import json
import os
import tempfile
import pytest

import importlib.util

_state_spec = importlib.util.spec_from_file_location(
    "session_state",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session_state.py'),
)
_state_mod = importlib.util.module_from_spec(_state_spec)
_state_spec.loader.exec_module(_state_mod)

_spec = importlib.util.spec_from_file_location(
    "subagent_start",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'subagent-start.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

build_subagent_briefing = _mod.build_subagent_briefing
should_brief_agent_type = _mod.should_brief_agent_type


class TestAgentTypeFilter:
    def test_general_purpose_gets_briefing(self):
        assert should_brief_agent_type("general-purpose") is True

    def test_explore_gets_briefing(self):
        assert should_brief_agent_type("Explore") is True

    def test_statusline_setup_skipped(self):
        assert should_brief_agent_type("statusline-setup") is False

    def test_magic_docs_skipped(self):
        assert should_brief_agent_type("magic-docs") is False

    def test_none_type_gets_briefing(self):
        assert should_brief_agent_type(None) is True

    def test_unknown_type_gets_briefing(self):
        assert should_brief_agent_type("my-custom-agent") is True


class TestBriefingContent:
    def test_includes_tool_reminders(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        briefing = build_subagent_briefing(state)
        assert "Write tool" in briefing
        assert "Read tool" in briefing
        assert "Grep" in briefing or "Glob" in briefing

    def test_includes_session_rejections(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "Use script.", "a1")
        _state_mod.record_rejection(state, "node -e", "inline_exec", "Use script.", "a2")
        _state_mod.record_rejection(state, "node -e", "inline_exec", "Use script.", "a3")
        briefing = build_subagent_briefing(state)
        assert "node -e" in briefing
        assert "3" in briefing  # rejection count

    def test_empty_session_still_has_base_rules(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        briefing = build_subagent_briefing(state)
        assert "Write tool" in briefing
        assert len(briefing) > 50
