import json
import os
import tempfile
import pytest

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "guidance_map",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'guidance_map.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

load_guidance_map = _mod.load_guidance_map
generate_guidance_map = _mod.generate_guidance_map
lookup_guidance = _mod.lookup_guidance
is_structural_reason = _mod.is_structural_reason
load_session_stats = _mod.load_session_stats
enrich_guidance_map = _mod.enrich_guidance_map
STATIC_GUIDANCE = _mod.STATIC_GUIDANCE
ENRICH_MIN_REJECTIONS = _mod.ENRICH_MIN_REJECTIONS
ENRICH_MIN_SESSIONS = _mod.ENRICH_MIN_SESSIONS


class TestStaticGuidance:
    def test_structural_reasons_have_guidance(self):
        for reason in ["command_substitution", "process_substitution", "heredoc", "inline_exec"]:
            assert STATIC_GUIDANCE.get(reason) is not None, f"{reason} missing guidance"

    def test_unsafe_segment_is_null(self):
        assert STATIC_GUIDANCE.get("unsafe_segment") is None

    def test_inline_python_prefixes_have_guidance(self):
        assert STATIC_GUIDANCE.get("inline_python:unsafe_module:os") is not None
        assert STATIC_GUIDANCE.get("inline_python:dangerous_builtin:open") is not None


class TestIsStructuralReason:
    def test_structural_reasons(self):
        assert is_structural_reason("command_substitution") is True
        assert is_structural_reason("heredoc") is True
        assert is_structural_reason("inline_exec") is True
        assert is_structural_reason("inline_python:unsafe_module:os") is True
        assert is_structural_reason("process_substitution") is True

    def test_safety_gates(self):
        assert is_structural_reason("unsafe_segment") is False
        assert is_structural_reason(None) is False
        assert is_structural_reason("recursion_limit") is False


class TestLookupGuidance:
    def test_exact_match(self):
        gmap = STATIC_GUIDANCE.copy()
        result = lookup_guidance(gmap, "heredoc")
        assert "Write tool" in result or "echo" in result

    def test_inline_python_prefix_match(self):
        gmap = STATIC_GUIDANCE.copy()
        result = lookup_guidance(gmap, "inline_python:unsafe_module:pathlib")
        assert result is not None  # Should fall back to generic inline_python

    def test_null_for_safety_gate(self):
        gmap = STATIC_GUIDANCE.copy()
        result = lookup_guidance(gmap, "unsafe_segment")
        assert result is None

    def test_unknown_reason_returns_none(self):
        gmap = STATIC_GUIDANCE.copy()
        result = lookup_guidance(gmap, "some_unknown_reason")
        assert result is None


class TestGenerateAndLoad:
    def test_generate_writes_valid_json(self, tmp_path):
        path = str(tmp_path / "guidance-map.json")
        generate_guidance_map(path)
        with open(path) as f:
            data = json.load(f)
        assert "heredoc" in data
        assert data["unsafe_segment"] is None

    def test_load_reads_generated_file(self, tmp_path):
        path = str(tmp_path / "guidance-map.json")
        generate_guidance_map(path)
        gmap = load_guidance_map(path)
        assert "heredoc" in gmap

    def test_load_missing_file_returns_static(self):
        gmap = load_guidance_map("/nonexistent/path.json")
        assert gmap == STATIC_GUIDANCE

    def test_generate_enriches_from_stats(self, tmp_path):
        stats_path = str(tmp_path / "stats.jsonl")
        gmap_path = str(tmp_path / "guidance-map.json")
        # Write stats with a pattern that meets thresholds
        with open(stats_path, "w") as f:
            for i in range(ENRICH_MIN_SESSIONS):
                entry = {
                    "sid": f"s{i}",
                    "patterns": {"chmod": {"rejections": 2, "approvals": 1, "denials": 0}},
                }
                f.write(json.dumps(entry) + "\n")
        generate_guidance_map(gmap_path, stats_path=stats_path)
        gmap = load_guidance_map(gmap_path)
        # chmod had 6 rejections across 3 sessions, meets thresholds
        assert "chmod" in gmap
        assert "rejected" in gmap["chmod"].lower()


class TestLoadSessionStats:
    def test_load_empty_returns_empty(self, tmp_path):
        entries = load_session_stats(str(tmp_path / "nonexistent.jsonl"))
        assert entries == []

    def test_load_valid_entries(self, tmp_path):
        path = str(tmp_path / "stats.jsonl")
        with open(path, "w") as f:
            f.write(json.dumps({"sid": "s1", "total_rejections": 5}) + "\n")
            f.write(json.dumps({"sid": "s2", "total_rejections": 3}) + "\n")
        entries = load_session_stats(path)
        assert len(entries) == 2
        assert entries[0]["sid"] == "s1"

    def test_skips_malformed_lines(self, tmp_path):
        path = str(tmp_path / "stats.jsonl")
        with open(path, "w") as f:
            f.write(json.dumps({"sid": "s1"}) + "\n")
            f.write("not json\n")
            f.write(json.dumps({"sid": "s2"}) + "\n")
        entries = load_session_stats(path)
        assert len(entries) == 2


class TestEnrichGuidanceMap:
    def test_adds_frequently_rejected_patterns(self):
        stats = [
            {"sid": f"s{i}", "patterns": {"chmod": {"rejections": 2, "approvals": 0, "denials": 0}}}
            for i in range(ENRICH_MIN_SESSIONS)
        ]
        enriched = enrich_guidance_map(STATIC_GUIDANCE, stats)
        assert "chmod" in enriched
        assert "rejected" in enriched["chmod"].lower()

    def test_never_overrides_static_entries(self):
        stats = [
            {"sid": f"s{i}", "patterns": {"heredoc": {"rejections": 100, "approvals": 0, "denials": 0}}}
            for i in range(10)
        ]
        enriched = enrich_guidance_map(STATIC_GUIDANCE, stats)
        assert enriched["heredoc"] == STATIC_GUIDANCE["heredoc"]

    def test_below_threshold_not_added(self):
        stats = [
            {"sid": "s1", "patterns": {"chmod": {"rejections": 1, "approvals": 0, "denials": 0}}}
        ]
        enriched = enrich_guidance_map(STATIC_GUIDANCE, stats)
        assert "chmod" not in enriched

    def test_needs_multiple_sessions(self):
        # Many rejections but only 1 session
        stats = [
            {"sid": "s1", "patterns": {"chmod": {"rejections": 20, "approvals": 0, "denials": 0}}}
        ]
        enriched = enrich_guidance_map(STATIC_GUIDANCE, stats)
        assert "chmod" not in enriched

    def test_empty_stats_returns_base(self):
        enriched = enrich_guidance_map(STATIC_GUIDANCE, [])
        assert enriched == STATIC_GUIDANCE
