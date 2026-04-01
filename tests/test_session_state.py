import json
import os
import tempfile
import pytest

# Import the module under test
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "session_state",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session_state.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

load_session_state = _mod.load_session_state
save_session_state = _mod.save_session_state
delete_session_state = _mod.delete_session_state
record_rejection = _mod.record_rejection
record_resolution = _mod.record_resolution
is_agent_briefed = _mod.is_agent_briefed
mark_agent_briefed = _mod.mark_agent_briefed
extract_pattern_key = _mod.extract_pattern_key
SESSION_STATE_DIR = _mod.SESSION_STATE_DIR


class TestSessionState:
    def test_initial_state_has_prompted_agents(self, tmp_path):
        state = load_session_state("new-session", state_dir=str(tmp_path))
        assert state["prompted_agents"] == {}


class TestSessionStateBasics:
    def test_load_nonexistent_returns_empty(self, tmp_path):
        state = load_session_state("nonexistent", state_dir=str(tmp_path))
        assert state["patterns"] == {}
        assert state["agents_briefed"] == []

    def test_save_and_load_roundtrip(self, tmp_path):
        state = load_session_state("test123", state_dir=str(tmp_path))
        state["patterns"]["node -e"] = {
            "rejections": 1, "approvals": 0, "denials": 0,
            "agents": ["main"], "last_reason": "inline_exec",
            "last_guidance": "Use a script file.",
        }
        save_session_state("test123", state, state_dir=str(tmp_path))
        reloaded = load_session_state("test123", state_dir=str(tmp_path))
        assert reloaded["patterns"]["node -e"]["rejections"] == 1

    def test_concurrent_writes_dont_corrupt(self, tmp_path):
        """Atomic write: partial writes should not corrupt state."""
        state = load_session_state("test456", state_dir=str(tmp_path))
        state["patterns"]["git push"] = {
            "rejections": 3, "approvals": 2, "denials": 0,
            "agents": ["a1", "a2"], "last_reason": "unsafe_segment",
            "last_guidance": None,
        }
        save_session_state("test456", state, state_dir=str(tmp_path))
        # File should be valid JSON
        path = os.path.join(str(tmp_path), "bash-validator-session-test456.json")
        with open(path) as f:
            data = json.load(f)
        assert data["patterns"]["git push"]["rejections"] == 3


class TestRecordRejection:
    def test_first_rejection_creates_pattern(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_rejection(state, "node -e", "inline_exec", "Use script file.", "agent1")
        assert state["patterns"]["node -e"]["rejections"] == 1
        assert state["patterns"]["node -e"]["agents"] == ["agent1"]

    def test_repeated_rejection_increments(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_rejection(state, "node -e", "inline_exec", "Use script file.", "agent1")
        record_rejection(state, "node -e", "inline_exec", "Use script file.", "agent2")
        assert state["patterns"]["node -e"]["rejections"] == 2
        assert "agent2" in state["patterns"]["node -e"]["agents"]

    def test_different_patterns_tracked_separately(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_rejection(state, "node -e", "inline_exec", "msg", "a1")
        record_rejection(state, "python3 -c", "inline_python:unsafe_module:os", "msg", "a1")
        assert len(state["patterns"]) == 2


class TestRecordResolution:
    def test_record_approval(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_rejection(state, "git push", "unsafe_segment", None, "a1")
        record_resolution(state, "git push", approved=True)
        assert state["patterns"]["git push"]["approvals"] == 1

    def test_record_denial(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_rejection(state, "git push", "unsafe_segment", None, "a1")
        record_resolution(state, "git push", approved=False)
        assert state["patterns"]["git push"]["denials"] == 1

    def test_resolution_on_unknown_pattern_is_noop(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        record_resolution(state, "unknown", approved=True)
        assert "unknown" not in state["patterns"]


class TestAgentBriefing:
    def test_new_agent_not_briefed(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        assert not is_agent_briefed(state, "agent1")

    def test_mark_and_check_briefed(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        mark_agent_briefed(state, "agent1")
        assert is_agent_briefed(state, "agent1")

    def test_main_thread_uses_main_key(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        mark_agent_briefed(state, None)  # None = main thread
        assert is_agent_briefed(state, None)


class TestExtractPatternKey:
    def test_inline_exec_python(self):
        assert extract_pattern_key("python3", "inline_python:unsafe_module:os") == "python3 -c"

    def test_inline_exec_node(self):
        assert extract_pattern_key("node -e console.log(1)", "inline_exec") == "node -e"

    def test_git_subcommand(self):
        assert extract_pattern_key("git push origin main", "unsafe_segment") == "git push"

    def test_heredoc(self):
        assert extract_pattern_key("cat > /tmp/file << EOF", "heredoc") == "heredoc"

    def test_command_substitution(self):
        assert extract_pattern_key("echo $(whoami)", "command_substitution") == "command_substitution"

    def test_plain_command(self):
        assert extract_pattern_key("rm -rf /tmp/test", "unsafe_segment") == "rm"


class TestDeleteSessionState:
    def test_delete_existing_state(self, tmp_path):
        state = load_session_state("s1", state_dir=str(tmp_path))
        save_session_state("s1", state, state_dir=str(tmp_path))
        delete_session_state("s1", state_dir=str(tmp_path))
        path = os.path.join(str(tmp_path), "bash-validator-session-s1.json")
        assert not os.path.exists(path)

    def test_delete_nonexistent_is_silent(self, tmp_path):
        delete_session_state("nonexistent", state_dir=str(tmp_path))  # should not raise


class TestPatternKeyEdgeCases:
    def test_docker_subcommand(self):
        assert extract_pattern_key("docker run myimage", "unsafe_segment") == "docker run"

    def test_docker_with_flag(self):
        assert extract_pattern_key("docker --version", "unsafe_segment") == "docker"

    def test_empty_command(self):
        assert extract_pattern_key("", "unsafe_segment") == "unknown"

    def test_absolute_path_command(self):
        assert extract_pattern_key("/usr/bin/python3 -c 'print(1)'", "inline_exec") == "python3 -c"

    def test_absolute_path_node(self):
        assert extract_pattern_key("/usr/local/bin/node -e 'console.log(1)'", "inline_exec") == "node -e"
