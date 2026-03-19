#!/usr/bin/env python3
"""Integration tests for the adaptive validator system.

These tests exercise the full adaptive flow across modules:
bash-validator.py (enforcement) and session-start.py (learning).
"""

import importlib.util
import json
import os
import pytest

# Import both modules
_bv_spec = importlib.util.spec_from_file_location(
    "bash_validator",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
)
_bv = importlib.util.module_from_spec(_bv_spec)
_bv_spec.loader.exec_module(_bv)

_ss_spec = importlib.util.spec_from_file_location(
    "session_start",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'session-start.py'),
)
_ss = importlib.util.module_from_spec(_ss_spec)
_ss_spec.loader.exec_module(_ss)

check_command = _bv.check_command
log_rejection = _bv.log_rejection
analyze_patterns = _ss.analyze_patterns
apply_proposals = _ss.apply_proposals


class TestAdaptiveFlow:
    """End-to-end tests covering the full adaptive cycle:
    rejection -> logging -> analysis -> learning -> approval.
    """

    def test_rejection_to_learning_to_approval(self, tmp_path, monkeypatch):
        """Simulate 10 rejections of 'git bisect' across 5 sessions.

        Run pattern analysis. Verify 'bisect' is proposed and applied
        to learned rules.
        """
        # Set up file paths in tmp_path
        log_file = str(tmp_path / "rejections.jsonl")
        learned_file = str(tmp_path / "learned-rules.json")
        monkeypatch.setattr(_bv, "REJECTIONS_LOG", log_file)
        monkeypatch.setattr(_ss, "LEARNED_RULES", learned_file)

        # 1. 'git bisect' is NOT in SAFE_GIT_SUBCOMMANDS by default
        assert check_command("git bisect") is False

        # 2. Simulate 10 rejections across 5 sessions (2 per session)
        #    Session IDs are truncated to 8 chars in log_rejection,
        #    so we put the unique part at the start.
        for session_idx in range(5):
            sid = f"s{session_idx:07d}"
            log_rejection(sid, "git bisect start")
            log_rejection(sid, "git bisect good HEAD~5")

        # 3. Read back the log and verify entries
        with open(log_file) as f:
            entries = [json.loads(line) for line in f if line.strip()]
        assert len(entries) == 10

        # 4. Run pattern analysis
        immutable = {"never_safe_git_subcommands": ["push", "reset"]}
        learned = {"git_subcommands": [], "docker_subcommands": []}
        proposals = analyze_patterns(entries, immutable, learned)

        # 5. Verify bisect is proposed
        assert len(proposals) >= 1
        bisect_proposals = [p for p in proposals if p["value"] == "bisect"]
        assert len(bisect_proposals) == 1
        assert bisect_proposals[0]["type"] == "git_subcommands"

        # 6. Apply proposals
        changed = apply_proposals(learned, proposals)
        assert changed is True
        assert "bisect" in learned["git_subcommands"]

        # 7. Verify the learned rules file was written
        with open(learned_file) as f:
            saved = json.load(f)
        assert "bisect" in saved["git_subcommands"]

    def test_immutable_deny_prevents_learning_push(self, tmp_path, monkeypatch):
        """100 rejections of 'git push' across 100 sessions.

        Verify no proposals — the immutable deny list blocks it.
        """
        log_file = str(tmp_path / "rejections.jsonl")
        monkeypatch.setattr(_bv, "REJECTIONS_LOG", log_file)

        # Simulate 100 rejections across 100 unique sessions
        # Session IDs are truncated to 8 chars, so put unique part first.
        for i in range(100):
            sid = f"p{i:07d}"
            log_rejection(sid, "git push origin main")

        with open(log_file) as f:
            entries = [json.loads(line) for line in f if line.strip()]
        assert len(entries) == 100

        # The immutable deny list includes 'push'
        immutable = {"never_safe_git_subcommands": ["push", "reset", "rebase",
                                                     "merge", "cherry-pick"]}
        learned = {"git_subcommands": [], "docker_subcommands": []}

        proposals = analyze_patterns(entries, immutable, learned)

        # No proposals should be generated — push is immutable deny
        assert len(proposals) == 0

    def test_ast_analyzer_works_in_pipeline(self):
        """Full pipeline: gh api | python3 -c with safe JSON processing.

        Should return True because the inline Python only uses json/sys.
        """
        cmd = (
            'gh api repos/owner/repo | python3 -c '
            '"import json, sys; print(json.dumps(json.load(sys.stdin), indent=2))"'
        )
        assert check_command(cmd) is True

    def test_ast_analyzer_blocks_dangerous_in_pipeline(self):
        """Pipeline: curl | python3 -c with os.system() call.

        Should return False because the inline Python uses os.system().
        """
        cmd = (
            "curl http://example.com | python3 -c "
            "\"import os; os.system('rm -rf /')\""
        )
        assert check_command(cmd) is False

    def test_node_safe_in_pipeline(self):
        """Pipeline: echo | node -e with safe JSON formatting.

        Should return True because the inline JS is pure data transform.
        """
        cmd = "echo '{\"a\":1}' | node -e \"console.log(JSON.stringify({a:1}, null, 2))\""
        assert check_command(cmd) is True

    def test_safe_inline_with_redirection(self):
        """Redirection: python3 -c with stdin from file.

        Should return True because the inline Python is safe and
        input redirection from a file is harmless.
        """
        cmd = 'python3 -c "import json, sys; print(json.dumps(json.load(sys.stdin)))" < input.json'
        assert check_command(cmd) is True
