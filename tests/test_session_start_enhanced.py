# tests/test_session_start_enhanced.py
import json
import os
import time
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


class TestGuidanceMapGeneration:
    def test_session_start_generates_guidance_map(self, tmp_path):
        path = str(tmp_path / "guidance-map.json")
        _guidance_mod.generate_guidance_map(path)
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert "heredoc" in data
        assert "inline_exec" in data

    def test_guidance_map_has_null_for_safety_gates(self, tmp_path):
        path = str(tmp_path / "guidance-map.json")
        _guidance_mod.generate_guidance_map(path)
        with open(path) as f:
            data = json.load(f)
        assert data["unsafe_segment"] is None


class TestStaleSessionCleanup:
    def test_removes_old_session_files(self, tmp_path):
        # Create a "stale" session file with old mtime
        old_path = str(tmp_path / "bash-validator-session-old123.json")
        with open(old_path, "w") as f:
            json.dump({"sid": "old123"}, f)
        # Set mtime to 25 hours ago
        old_time = time.time() - (25 * 3600)
        os.utime(old_path, (old_time, old_time))

        # Create a "fresh" session file
        new_path = str(tmp_path / "bash-validator-session-new456.json")
        with open(new_path, "w") as f:
            json.dump({"sid": "new456"}, f)

        _state_mod.cleanup_stale_sessions(max_age_hours=24, state_dir=str(tmp_path))

        assert not os.path.exists(old_path)
        assert os.path.exists(new_path)

    def test_ignores_non_session_files(self, tmp_path):
        other_path = str(tmp_path / "some-other-file.json")
        with open(other_path, "w") as f:
            f.write("{}")
        old_time = time.time() - (25 * 3600)
        os.utime(other_path, (old_time, old_time))

        _state_mod.cleanup_stale_sessions(max_age_hours=24, state_dir=str(tmp_path))
        assert os.path.exists(other_path)
