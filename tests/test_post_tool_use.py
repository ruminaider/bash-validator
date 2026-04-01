# tests/test_post_tool_use.py
import json
import os
import pytest

import importlib.util

_state_spec = importlib.util.spec_from_file_location(
    "session_state",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session_state.py'),
)
_state_mod = importlib.util.module_from_spec(_state_spec)
_state_spec.loader.exec_module(_state_mod)

_spec = importlib.util.spec_from_file_location(
    "post_tool_use",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'post-tool-use.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

resolve_prompted = _mod.resolve_prompted


class TestResolvePrompted:
    def test_signal_set_success_marks_approval(self, tmp_path):
        """When signal exists and tool succeeded, record approval."""
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        state["prompted_agents"]["a1"] = "node -e"
        resolve_prompted(state, agent_id="a1", tool_error=False)
        assert state["patterns"]["node -e"]["approvals"] == 1
        assert "a1" not in state["prompted_agents"]

    def test_signal_set_error_marks_denial(self, tmp_path):
        """When signal exists and tool errored, record denial."""
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        state["prompted_agents"]["a1"] = "node -e"
        resolve_prompted(state, agent_id="a1", tool_error=True)
        assert state["patterns"]["node -e"]["denials"] == 1
        assert "a1" not in state["prompted_agents"]

    def test_no_signal_skips_resolution(self, tmp_path):
        """When no signal for this agent, do nothing."""
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        # No signal set for agent "a2"
        resolve_prompted(state, agent_id="a2", tool_error=False)
        assert state["patterns"]["node -e"]["approvals"] == 0

    def test_cross_agent_isolation(self, tmp_path):
        """Agent B's safe command does not resolve Agent A's pending prompt."""
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        state["prompted_agents"]["a1"] = "node -e"
        # Agent B runs a safe command (no signal for B)
        resolve_prompted(state, agent_id="a2", tool_error=False)
        assert state["patterns"]["node -e"]["approvals"] == 0
        assert state["prompted_agents"]["a1"] == "node -e"  # untouched

    def test_main_agent_uses_main_key(self, tmp_path):
        """Main thread (agent_id=None) uses 'main' as key."""
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "heredoc", "heredoc", "msg", None)
        state["prompted_agents"]["main"] = "heredoc"
        resolve_prompted(state, agent_id=None, tool_error=False)
        assert state["patterns"]["heredoc"]["approvals"] == 1
        assert "main" not in state["prompted_agents"]
