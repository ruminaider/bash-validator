# tests/test_session_end.py
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
    "session_end",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session-end.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

flush_session_stats = _mod.flush_session_stats
rotate_rejection_log = _mod.rotate_rejection_log
STATS_LOG = _mod.STATS_LOG


class TestFlushSessionStats:
    def test_writes_stats_line(self, tmp_path):
        stats_path = str(tmp_path / "session-stats.jsonl")
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        _state_mod.record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        _state_mod.record_rejection(state, "git push", "unsafe_segment", None, "a2")
        _state_mod.record_resolution(state, "git push", approved=True)

        flush_session_stats(state, stats_path=stats_path)

        with open(stats_path) as f:
            line = json.loads(f.readline())
        assert line["sid"] == "s1"
        assert line["total_rejections"] == 2
        assert line["total_approvals"] == 1
        assert "node -e" in line["patterns"]
        assert "git push" in line["patterns"]

    def test_appends_to_existing_log(self, tmp_path):
        stats_path = str(tmp_path / "session-stats.jsonl")
        state1 = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        state2 = _state_mod.load_session_state("s2", state_dir=str(tmp_path))
        _state_mod.record_rejection(state1, "rm", "unsafe_segment", None, "a1")
        _state_mod.record_rejection(state2, "rm", "unsafe_segment", None, "a1")

        flush_session_stats(state1, stats_path=stats_path)
        flush_session_stats(state2, stats_path=stats_path)

        with open(stats_path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 2
        assert lines[0]["sid"] == "s1"
        assert lines[1]["sid"] == "s2"

    def test_empty_session_still_writes(self, tmp_path):
        stats_path = str(tmp_path / "session-stats.jsonl")
        state = _state_mod.load_session_state("empty", state_dir=str(tmp_path))
        flush_session_stats(state, stats_path=stats_path)
        with open(stats_path) as f:
            line = json.loads(f.readline())
        assert line["total_rejections"] == 0

    def test_no_auto_learning_from_approvals(self, tmp_path):
        """Approval data must NOT modify learned-rules.json."""
        stats_path = str(tmp_path / "session-stats.jsonl")
        learned_path = str(tmp_path / "learned-rules.json")
        # Create a learned-rules.json with known content
        original = {"safe_commands": [], "git_subcommands": ["add"], "docker_subcommands": []}
        with open(learned_path, "w") as f:
            json.dump(original, f)
        # Create a session with high approval rates
        state = _state_mod.load_session_state("s1", state_dir=str(tmp_path))
        for i in range(20):
            _state_mod.record_rejection(state, "chmod", "unsafe_segment", None, "a1")
            _state_mod.record_resolution(state, "chmod", approved=True)
        flush_session_stats(state, stats_path=stats_path)
        # Verify learned-rules.json was NOT modified
        with open(learned_path) as f:
            after = json.load(f)
        assert after == original


class TestLogRotation:
    def test_rotates_large_rejection_log(self, tmp_path):
        log_path = str(tmp_path / "rejections.jsonl")
        # Write 1000 entries (will exceed 1MB threshold if entries are big enough)
        with open(log_path, "w") as f:
            for i in range(1000):
                entry = {"ts": "2026-03-30", "sid": f"s{i}", "cmd": "test",
                         "tokens": ["test"] * 6, "hash": "a" * 16,
                         "reason": "unsafe_segment", "padding": "x" * 1000}
                f.write(json.dumps(entry) + "\n")
        original_size = os.path.getsize(log_path)
        assert original_size > 1_000_000  # confirm it's over 1MB
        rotate_rejection_log(log_path, max_bytes=1_000_000, keep_entries=500)
        with open(log_path) as f:
            remaining = [l for l in f if l.strip()]
        assert len(remaining) == 500

    def test_no_rotation_under_threshold(self, tmp_path):
        log_path = str(tmp_path / "rejections.jsonl")
        with open(log_path, "w") as f:
            for i in range(10):
                f.write(json.dumps({"ts": "2026-03-30", "sid": f"s{i}", "cmd": "test"}) + "\n")
        rotate_rejection_log(log_path, max_bytes=1_000_000, keep_entries=500)
        with open(log_path) as f:
            remaining = [l for l in f if l.strip()]
        assert len(remaining) == 10
