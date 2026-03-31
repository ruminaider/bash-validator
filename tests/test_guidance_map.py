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
STATIC_GUIDANCE = _mod.STATIC_GUIDANCE


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
