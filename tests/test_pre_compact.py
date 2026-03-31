# tests/test_pre_compact.py
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
    "pre_compact",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'pre-compact.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

build_compact_instructions = _mod.build_compact_instructions


class TestCompactInstructions:
    def test_includes_core_rules(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        output = build_compact_instructions(state)
        assert "Write" in output
        assert "Read" in output
        assert "script file" in output.lower() or "script" in output.lower()

    def test_includes_rejected_patterns(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a2")
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a3")
        output = build_compact_instructions(state)
        assert "node -e" in output

    def test_output_is_concise(self, tmp_path):
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        output = build_compact_instructions(state)
        assert len(output) < 500  # must be concise for compaction budget
