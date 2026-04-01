"""Integration test: full session lifecycle with adaptive intelligence.

Simulates a session where multiple agents trigger rejections, escalation
kicks in, approvals are recorded, and session state is flushed.
"""

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

_guidance_spec = importlib.util.spec_from_file_location(
    "guidance_map",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'guidance_map.py'),
)
_guidance_mod = importlib.util.module_from_spec(_guidance_spec)
_guidance_spec.loader.exec_module(_guidance_mod)

_validator_spec = importlib.util.spec_from_file_location(
    "bash_validator",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
)
_validator_mod = importlib.util.module_from_spec(_validator_spec)
_validator_spec.loader.exec_module(_validator_mod)

build_escalation_response = _validator_mod.build_escalation_response

_subagent_spec = importlib.util.spec_from_file_location(
    "subagent_start",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'subagent-start.py'),
)
_subagent_mod = importlib.util.module_from_spec(_subagent_spec)
_subagent_spec.loader.exec_module(_subagent_mod)

_compact_spec = importlib.util.spec_from_file_location(
    "pre_compact",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'pre-compact.py'),
)
_compact_mod = importlib.util.module_from_spec(_compact_spec)
_compact_spec.loader.exec_module(_compact_mod)

_post_spec = importlib.util.spec_from_file_location(
    "post_tool_use",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'post-tool-use.py'),
)
_post_mod = importlib.util.module_from_spec(_post_spec)
_post_spec.loader.exec_module(_post_mod)

_end_spec = importlib.util.spec_from_file_location(
    "session_end",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session-end.py'),
)
_end_mod = importlib.util.module_from_spec(_end_spec)
_end_spec.loader.exec_module(_end_mod)


class TestFullSessionLifecycle:
    def test_multi_agent_session(self, tmp_path):
        gmap = _guidance_mod.STATIC_GUIDANCE
        stats_path = str(tmp_path / "stats.jsonl")

        # 1. Session starts, state is empty
        state = _state_mod.load_session_state("session1", state_dir=str(tmp_path))
        assert state["patterns"] == {}

        # 2. Main agent's first Bash call: gets proactive briefing
        assert not _state_mod.is_agent_briefed(state, None)
        _state_mod.mark_agent_briefed(state, None)
        assert _state_mod.is_agent_briefed(state, None)

        # 3. Subagent A spawns, gets briefing
        briefing = _subagent_mod.build_subagent_briefing(state)
        assert "Write tool" in briefing

        # 4. Subagent A hits node -e (first rejection)
        pattern = "node -e"
        decision, guidance = build_escalation_response(
            state, pattern, "inline_exec", gmap
        )
        assert decision == "ask"
        assert guidance is not None
        _state_mod.record_rejection(state, pattern, "inline_exec", guidance, "agentA")

        # 5. User approves (signal set by PreToolUse, resolved by PostToolUse)
        state["prompted_agents"]["agentA"] = pattern
        _post_mod.resolve_prompted(state, agent_id="agentA", tool_error=False)
        assert state["patterns"][pattern]["approvals"] == 1

        # 6. Subagent A retries node -e three more times
        for i in range(3):
            _state_mod.record_rejection(state, pattern, "inline_exec", "msg", "agentA")

        # 7. Subagent B spawns, gets briefing with rejection history
        _state_mod.save_session_state("session1", state, state_dir=str(tmp_path))
        state = _state_mod.load_session_state("session1", state_dir=str(tmp_path))
        briefing = _subagent_mod.build_subagent_briefing(state)
        assert "node -e" in briefing
        assert "4" in briefing  # 4 rejections

        # 8. Subagent B tries node -e: count is 4, gets deny
        decision, guidance = build_escalation_response(
            state, pattern, "inline_exec", gmap
        )
        assert decision == "deny"
        assert "continue" in guidance.lower()

        # 9. Safety gate: rm never escalates
        for i in range(10):
            _state_mod.record_rejection(state, "rm", "unsafe_segment", None, "agentA")
        decision, guidance = build_escalation_response(
            state, "rm", "unsafe_segment", gmap
        )
        assert decision == "ask"
        assert guidance is None

        # 10. PreCompact preserves rules
        instructions = _compact_mod.build_compact_instructions(state)
        assert "Write" in instructions
        assert "node -e" in instructions

        # 11. SessionEnd flushes stats
        _end_mod.flush_session_stats(state, stats_path=stats_path)
        with open(stats_path) as f:
            line = json.loads(f.readline())
        assert line["sid"] == "session1"
        assert line["total_rejections"] > 0
        assert "node -e" in line["patterns"]
        assert "rm" in line["patterns"]
