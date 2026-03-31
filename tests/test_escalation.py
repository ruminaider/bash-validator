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

_guidance_spec = importlib.util.spec_from_file_location(
    "guidance_map",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'guidance_map.py'),
)
_guidance_mod = importlib.util.module_from_spec(_guidance_spec)
_guidance_spec.loader.exec_module(_guidance_mod)

# We'll test the escalation logic function directly
_validator_spec = importlib.util.spec_from_file_location(
    "bash_validator",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
)
_validator_mod = importlib.util.module_from_spec(_validator_spec)
_validator_spec.loader.exec_module(_validator_mod)

build_escalation_response = _validator_mod.build_escalation_response
extract_pattern_key = _state_mod.extract_pattern_key


class TestEscalationStructural:
    """Escalation for structural reasons (heredoc, inline_exec, etc.)."""

    def test_first_rejection_returns_ask_with_guidance(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        decision, guidance = build_escalation_response(
            state, "node -e", "inline_exec", "agent1",
            _guidance_mod.STATIC_GUIDANCE
        )
        assert decision == "ask"
        assert guidance is not None
        assert "script file" in guidance.lower() or "write" in guidance.lower()

    def test_second_rejection_returns_ask_with_escalated_guidance(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        decision, guidance = build_escalation_response(
            state, "node -e", "inline_exec", "agent1",
            _guidance_mod.STATIC_GUIDANCE
        )
        assert decision == "ask"
        assert "rejected" in guidance.lower() and "time" in guidance.lower()

    def test_third_rejection_still_asks(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        for i in range(2):
            _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", f"a{i}")
        decision, guidance = build_escalation_response(
            state, "node -e", "inline_exec", "agent1",
            _guidance_mod.STATIC_GUIDANCE
        )
        assert decision == "ask"

    def test_deny_after_three_prior_rejections(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        for i in range(3):
            _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", f"a{i}")
        decision, guidance = build_escalation_response(
            state, "node -e", "inline_exec", "agent1",
            _guidance_mod.STATIC_GUIDANCE
        )
        assert decision == "deny"
        assert "continue" in guidance.lower()


class TestEscalationSafetyGate:
    """Safety gates never escalate."""

    def test_safety_gate_always_ask_no_guidance(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        for i in range(10):
            _state_mod.record_rejection(state, "rm", "unsafe_segment", None, f"a{i}")
        decision, guidance = build_escalation_response(
            state, "rm", "unsafe_segment", "agent1",
            _guidance_mod.STATIC_GUIDANCE
        )
        assert decision == "ask"
        assert guidance is None


class TestFirstCallBriefing:
    """First Bash call from a new agent gets a proactive briefing."""

    def test_new_agent_gets_briefing(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        assert not _state_mod.is_agent_briefed(state, "agent1")

    def test_briefed_agent_does_not_get_rebriefed(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.mark_agent_briefed(state, "agent1")
        assert _state_mod.is_agent_briefed(state, "agent1")
