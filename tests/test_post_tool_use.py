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

resolve_pending_rejections = _mod.resolve_pending_rejections


class TestResolveRejections:
    def test_successful_tool_marks_approval(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "git push", "unsafe_segment", None, "a1")
        resolve_pending_rejections(state, tool_error=False)
        assert state["patterns"]["git push"]["approvals"] == 1

    def test_error_tool_marks_denial(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "git push", "unsafe_segment", None, "a1")
        resolve_pending_rejections(state, tool_error=True)
        assert state["patterns"]["git push"]["denials"] == 1

    def test_no_pending_rejections_is_noop(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        resolve_pending_rejections(state, tool_error=False)
        assert state["patterns"] == {}

    def test_already_resolved_not_double_counted(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "git push", "unsafe_segment", None, "a1")
        _state_mod.record_resolution(state, "git push", approved=True)
        # rejections=1, approvals=1: no pending
        resolve_pending_rejections(state, tool_error=False)
        assert state["patterns"]["git push"]["approvals"] == 1  # unchanged

    def test_resolves_most_recent_pattern_not_oldest(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        _state_mod.record_rejection(state, "python3 -c", "inline_exec", "msg", "a1")
        # Both pending; should resolve python3 -c (most recent), not node -e
        resolve_pending_rejections(state, tool_error=False)
        assert state["patterns"]["python3 -c"]["approvals"] == 1
        assert state["patterns"]["node -e"]["approvals"] == 0
