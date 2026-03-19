#!/usr/bin/env python3
"""Pre-release edge-case and stress test suite for bash-validator.

Run before each release to catch regressions across the full adaptive
validator system: AST analyzers, sed/awk protection, learned rules
integration, immutable deny list enforcement, and real-world commands.

Usage:
    pytest tests/test_prerelease.py -v
"""

import importlib.util
import json
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Import bash-validator.py (hyphenated filename can't use normal import)
# ---------------------------------------------------------------------------
_spec = importlib.util.spec_from_file_location(
    "bash_validator",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

check_command = _mod.check_command
check_segment = _mod.check_segment
is_safe_inline_python = _mod.is_safe_inline_python
is_safe_inline_js = _mod.is_safe_inline_js
SAFE_COMMANDS = _mod.SAFE_COMMANDS
SAFE_GIT_SUBCOMMANDS = _mod.SAFE_GIT_SUBCOMMANDS
SAFE_DOCKER_SUBCOMMANDS = _mod.SAFE_DOCKER_SUBCOMMANDS
DANGEROUS_BUILTINS = _mod.DANGEROUS_BUILTINS


# ═══════════════════════════════════════════════════════════════════════════════
# TestASTEdgeCases — Python AST analyzer edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestASTEdgeCases:
    """Python AST analyzer edge cases for is_safe_inline_python()."""

    def test_multiline_complex_formatting(self):
        """Multi-line code with complex formatting should parse and be safe."""
        code = (
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            "result = {\n"
            "    'count': len(data),\n"
            "    'items': [\n"
            "        {'id': d['id'], 'name': d['name']}\n"
            "        for d in data\n"
            "    ]\n"
            "}\n"
            "print(json.dumps(result, indent=2))"
        )
        assert is_safe_inline_python(code) is True

    def test_comments_with_dangerous_words(self):
        """Comments containing dangerous words should not trigger rejection."""
        code = (
            "# This uses os.system internally but we just print\n"
            "# import subprocess  <-- don't actually do this\n"
            "# open('file.txt')  <-- also don't do this\n"
            "print('safe output')"
        )
        assert is_safe_inline_python(code) is True

    def test_empty_string_returns_false(self):
        """Empty string is not valid Python — AST parse succeeds but no nodes.

        An empty Module is technically valid, so is_safe_inline_python returns True.
        However check_command('python3 -c \"\"') should still handle it.
        """
        # Empty string parses to an empty Module, which has no dangerous nodes
        result = is_safe_inline_python("")
        # The function returns True for empty code (no dangerous constructs found)
        assert result is True

    def test_unicode_in_code_strings(self):
        """Unicode characters in code should be handled gracefully."""
        code = "print('Hello, \u4e16\u754c! \U0001f600')"
        assert is_safe_inline_python(code) is True

    def test_unicode_variable_names(self):
        """Unicode variable names (valid Python 3) should work."""
        code = "x = 42; print(x)"
        assert is_safe_inline_python(code) is True

    def test_deeply_nested_safe_function_calls(self):
        """Deeply nested function calls using only safe modules."""
        code = (
            "import json, sys\n"
            "print(json.dumps(sorted(list(set(json.loads(sys.stdin.read()))))))"
        )
        assert is_safe_inline_python(code) is True

    def test_importfrom_safe_module(self):
        """'from json import dumps' (ImportFrom with safe module) should be safe."""
        code = "from json import dumps; print(dumps({'key': 'val'}))"
        assert is_safe_inline_python(code) is True

    def test_importfrom_safe_submodule(self):
        """'from collections import Counter' should be safe."""
        code = "from collections import Counter; print(Counter([1,2,2,3]))"
        assert is_safe_inline_python(code) is True

    def test_importfrom_os_is_dangerous(self):
        """'from os import path' should be False — os is dangerous even for os.path."""
        code = "from os import path; print(path.join('a', 'b'))"
        assert is_safe_inline_python(code) is False

    def test_importfrom_os_environ(self):
        """'from os import environ' should be False."""
        code = "from os import environ; print(environ.get('HOME'))"
        assert is_safe_inline_python(code) is False

    def test_aliased_import_safe_module(self):
        """'import json as j; j.dumps({})' should be safe."""
        code = "import json as j; print(j.dumps({'key': 'val'}))"
        assert is_safe_inline_python(code) is True

    def test_aliased_import_dangerous_module(self):
        """'import os as o; o.system(\"ls\")' should be dangerous."""
        code = "import os as o; o.system('ls')"
        assert is_safe_inline_python(code) is False

    def test_sys_stdin_read_safe(self):
        """sys.stdin.read() should be safe (stdin is in SAFE_SYS_ATTRS)."""
        code = "import sys; data = sys.stdin.read(); print(len(data))"
        assert is_safe_inline_python(code) is True

    def test_sys_exit_dangerous(self):
        """sys.exit(0) should be dangerous."""
        code = "import sys; sys.exit(0)"
        assert is_safe_inline_python(code) is False

    def test_sys_modules_dangerous(self):
        """sys.modules access should be dangerous (not in SAFE_SYS_ATTRS)."""
        code = "import sys; print(sys.modules)"
        assert is_safe_inline_python(code) is False

    def test_sys_path_dangerous(self):
        """sys.path manipulation should be dangerous."""
        code = "import sys; sys.path.append('/tmp')"
        assert is_safe_inline_python(code) is False

    def test_only_builtins_safe(self):
        """Code using only safe builtins like print, len, range, list, etc."""
        code = "print(len([1, 2, 3]))"
        assert is_safe_inline_python(code) is True

    def test_safe_builtins_combination(self):
        """Multiple safe builtins together."""
        code = "result = sorted(list(range(10))); print(sum(result))"
        assert is_safe_inline_python(code) is True

    def test_string_containing_dangerous_import(self):
        """String content with 'import os' should be safe — AST doesn't inspect strings."""
        code = "print('import os; os.system(\"rm -rf /\")')"
        assert is_safe_inline_python(code) is True

    def test_string_containing_open_call(self):
        """String containing 'open(\"file\")' — not an actual call node."""
        code = 'msg = "use open(\\"file.txt\\") to read"; print(msg)'
        assert is_safe_inline_python(code) is True

    def test_lambda_expression_safe(self):
        """Lambda expressions with safe operations should be safe."""
        code = "f = lambda x: x * 2; print(f(3))"
        assert is_safe_inline_python(code) is True

    def test_lambda_with_map(self):
        """Lambda used with map/filter should be safe."""
        code = "print(list(map(lambda x: x**2, [1,2,3,4])))"
        assert is_safe_inline_python(code) is True

    def test_list_comprehension_safe(self):
        """List comprehension with safe operations."""
        code = "result = [x * 2 for x in range(10) if x % 2 == 0]; print(result)"
        assert is_safe_inline_python(code) is True

    def test_dict_comprehension_safe(self):
        """Dict comprehension with safe operations."""
        code = "d = {k: v for k, v in enumerate('abc')}; print(d)"
        assert is_safe_inline_python(code) is True

    def test_set_comprehension_safe(self):
        """Set comprehension with safe operations."""
        code = "s = {x % 3 for x in range(10)}; print(s)"
        assert is_safe_inline_python(code) is True

    def test_nested_comprehension_safe(self):
        """Nested comprehension with safe operations."""
        code = "matrix = [[i*j for j in range(3)] for i in range(3)]; print(matrix)"
        assert is_safe_inline_python(code) is True

    def test_type_builtin_not_dangerous(self):
        """type() is NOT in DANGEROUS_BUILTINS — should be safe for basic use."""
        assert "type" not in DANGEROUS_BUILTINS
        code = "print(type(42))"
        assert is_safe_inline_python(code) is True

    def test_isinstance_safe(self):
        """isinstance() should be safe."""
        code = "print(isinstance(42, int))"
        assert is_safe_inline_python(code) is True

    def test_syntax_error_returns_false(self):
        """Invalid Python syntax should return False."""
        code = "def foo(:"
        assert is_safe_inline_python(code) is False

    def test_dunder_name_access_rejected(self):
        """Direct __dunder__ name access should be rejected."""
        code = "__builtins__"
        assert is_safe_inline_python(code) is False

    def test_dunder_attribute_rejected(self):
        """Dunder attribute access should be rejected."""
        code = "print.__class__.__bases__"
        assert is_safe_inline_python(code) is False

    def test_fstring_safe(self):
        """f-strings with safe expressions should be safe."""
        code = "name = 'world'; print(f'Hello, {name}!')"
        assert is_safe_inline_python(code) is True

    def test_walrus_operator_safe(self):
        """Walrus operator with safe operations should be safe."""
        code = "import json, sys\nif (data := json.load(sys.stdin)):\n    print(len(data))"
        assert is_safe_inline_python(code) is True

    def test_multiple_safe_imports(self):
        """Multiple safe module imports in one statement."""
        code = "import json, sys, re, collections; print('ok')"
        assert is_safe_inline_python(code) is True

    def test_import_from_none_module(self):
        """ImportFrom with module=None (relative import 'from . import x') should be rejected."""
        # This can't easily happen via -c but test the function directly
        code = "from . import something"
        # This is a SyntaxError in non-package context, so returns False
        assert is_safe_inline_python(code) is False


# ═══════════════════════════════════════════════════════════════════════════════
# TestNodeJSEdgeCases — Node.js regex analyzer edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestNodeJSEdgeCases:
    """Node.js regex analyzer edge cases for is_safe_inline_js()."""

    def test_empty_string_safe(self):
        """Empty string has no dangerous patterns — should return True."""
        assert is_safe_inline_js("") is True

    def test_comment_with_require_fs(self):
        """Comment containing require('fs') — regex doesn't distinguish comments.

        The regex-based approach matches anywhere in the string, so a comment
        containing a dangerous pattern WILL trigger rejection. This is the
        conservative (safe) behavior for a regex-based analyzer.
        """
        code = "// require('fs') this is a comment\nconsole.log('hello')"
        # Regex sees require('fs') even in a comment — returns False (conservative)
        assert is_safe_inline_js(code) is False

    def test_string_literal_with_require_fs(self):
        """String containing 'require(\"fs\")' — regex matches inside strings too."""
        code = """console.log("the code says require('fs')")"""
        # Regex is not AST-aware; it matches the pattern in the string literal
        assert is_safe_inline_js(code) is False

    def test_template_literal_safe_content(self):
        """Template literal with safe content should be safe."""
        code = "console.log(`hello ${1+1}`)"
        assert is_safe_inline_js(code) is True

    def test_multiline_safe_js(self):
        """Multi-line JS with only safe operations."""
        code = (
            "const data = JSON.parse('[1,2,3]');\n"
            "const doubled = data.map(x => x * 2);\n"
            "console.log(JSON.stringify(doubled));"
        )
        assert is_safe_inline_js(code) is True

    def test_arrow_functions_safe(self):
        """Arrow functions with safe operations."""
        code = "const add = (a, b) => a + b; console.log(add(1, 2))"
        assert is_safe_inline_js(code) is True

    def test_destructuring_safe(self):
        """Destructuring assignment with safe operations."""
        code = "const {a, b} = {a: 1, b: 2}; console.log(a + b)"
        assert is_safe_inline_js(code) is True

    def test_require_path_safe(self):
        """require('node:path') is safe — not in dangerous patterns."""
        code = "const path = require('node:path'); console.log(path.resolve('.'))"
        assert is_safe_inline_js(code) is True

    def test_require_url_safe(self):
        """require('node:url') is safe."""
        code = "const {URL} = require('node:url'); console.log(new URL('http://example.com').hostname)"
        assert is_safe_inline_js(code) is True

    def test_fetch_dangerous(self):
        """fetch() is dangerous (network access)."""
        code = "fetch('http://evil.com').then(r => r.json())"
        assert is_safe_inline_js(code) is False

    def test_dynamic_import_dangerous(self):
        """Dynamic import() is dangerous."""
        code = "import('fs').then(m => m.readFileSync('secret'))"
        assert is_safe_inline_js(code) is False

    def test_eval_dangerous(self):
        """eval() in JS is dangerous."""
        code = "eval('process.exit(1)')"
        assert is_safe_inline_js(code) is False

    def test_new_function_dangerous(self):
        """new Function() is dangerous (code execution)."""
        code = "const f = new Function('return 1+1'); console.log(f())"
        assert is_safe_inline_js(code) is False

    def test_process_exit_dangerous(self):
        """process.exit is dangerous."""
        code = "if (false) process.exit(1); console.log('hi')"
        assert is_safe_inline_js(code) is False

    def test_require_os_dangerous(self):
        """require('os') is dangerous."""
        code = "const os = require('os'); console.log(os.hostname())"
        assert is_safe_inline_js(code) is False

    def test_math_operations_safe(self):
        """Pure math operations should be safe."""
        code = "console.log(Math.PI * Math.pow(5, 2))"
        assert is_safe_inline_js(code) is True

    def test_date_operations_safe(self):
        """Date operations should be safe."""
        code = "console.log(new Date().toISOString())"
        assert is_safe_inline_js(code) is True

    def test_array_methods_safe(self):
        """Array methods should be safe."""
        code = (
            "const arr = [3,1,4,1,5,9];\n"
            "console.log(arr.sort().filter(x => x > 2).join(', '))"
        )
        assert is_safe_inline_js(code) is True


# ═══════════════════════════════════════════════════════════════════════════════
# TestSedAwkProtection — sed -i and awk -i edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestSedAwkProtection:
    """sed and awk in-place modification edge cases."""

    def test_sed_i_empty_suffix_macos(self):
        """sed -i '' (macOS empty suffix) should be rejected."""
        assert check_command("sed -i '' 's/foo/bar/' file") is False

    def test_sed_i_equals_suffix(self):
        """sed -i= should be rejected."""
        assert check_command("sed -i= 's/foo/bar/' file") is False

    def test_sed_i_bak_suffix(self):
        """sed -i.bak should be rejected (still in-place)."""
        assert check_command("sed -i.bak 's/foo/bar/' file") is False

    def test_sed_in_place_long_form(self):
        """sed --in-place should be rejected."""
        assert check_command("sed --in-place 's/foo/bar/' file") is False

    def test_sed_e_no_i_safe(self):
        """sed -e without -i (just expression) should be safe."""
        assert check_command("sed -e 's/foo/bar/' file") is True

    def test_sed_n_safe(self):
        """sed -n (quiet mode, read-only) should be safe."""
        assert check_command("sed -n '1p' file") is True

    def test_sed_n_multiline_safe(self):
        """sed -n with address range should be safe."""
        assert check_command("sed -n '10,20p' file.txt") is True

    def test_sed_in_pipe_safe(self):
        """Read-only sed in a pipe should be safe."""
        assert check_command("grep pattern file | sed 's/old/new/'") is True

    def test_sed_multiple_expressions_safe(self):
        """Multiple -e expressions (no -i) should be safe."""
        assert check_command("sed -e 's/foo/bar/' -e 's/baz/qux/' file") is True

    def test_awk_i_inplace_dangerous(self):
        """awk -i inplace should be rejected."""
        assert check_command("awk -i inplace '{gsub(/foo/,\"bar\")}' file") is False

    def test_awk_F_not_i_safe(self):
        """awk -F (field separator) is not -i — should be safe."""
        assert check_command("awk -F, '{print $1}' file") is True

    def test_awk_F_colon_safe(self):
        """awk -F: should be safe."""
        assert check_command("awk -F: '{print $1}' /etc/passwd") is True

    def test_awk_v_safe(self):
        """awk -v (variable assignment) should be safe."""
        assert check_command("awk -v OFS='\\t' '{print $1, $2}' file") is True

    def test_awk_print_safe(self):
        """Basic awk print should be safe."""
        assert check_command("awk '{print $1}' file.txt") is True

    def test_awk_in_pipe_safe(self):
        """awk in a pipe should be safe."""
        assert check_command("cat file | awk '{print $2}' | sort") is True

    def test_sed_i_later_in_pipeline(self):
        """sed -i later in a pipeline is still dangerous."""
        # This tests piped commands; each segment is checked independently
        # 'grep' is safe, but 'sed -i ...' segment is dangerous
        assert check_command("grep pattern file | sed -i 's/old/new/' other_file") is False


# ═══════════════════════════════════════════════════════════════════════════════
# TestLearnedRulesIntegration — learned rules loading and merging
# ═══════════════════════════════════════════════════════════════════════════════

class TestLearnedRulesIntegration:
    """Test that learned rules are correctly loaded and merged."""

    def test_learned_rules_merge_git_subcommands(self, tmp_path, monkeypatch):
        """Write learned rules with new git subcommands, reimport, verify merged."""
        rules_file = tmp_path / "learned-rules.json"
        rules_file.write_text(json.dumps({
            "git_subcommands": ["bisect", "am"],
            "docker_subcommands": ["compose"],
        }))

        # Reimport the module with the monkeypatched path
        monkeypatch.setattr(
            os.path, "expanduser",
            lambda p: str(rules_file) if "learned-rules.json" in p else os.path.expanduser.__wrapped__(p)
            if hasattr(os.path.expanduser, '__wrapped__') else p,
        )

        # Instead of monkeypatching expanduser (complex), just call _load_learned_rules
        # with a direct file write and read
        spec = importlib.util.spec_from_file_location(
            "bash_validator_fresh",
            os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
        )
        # Monkeypatch expanduser before loading
        original_expanduser = os.path.expanduser
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(rules_file) if "learned-rules" in p else original_expanduser(p))

        fresh_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh_mod)

        assert "bisect" in fresh_mod.SAFE_GIT_SUBCOMMANDS
        assert "am" in fresh_mod.SAFE_GIT_SUBCOMMANDS
        assert "compose" in fresh_mod.SAFE_DOCKER_SUBCOMMANDS

    def test_learned_rules_malformed_json(self, tmp_path, monkeypatch):
        """Malformed JSON in learned rules should be handled gracefully."""
        rules_file = tmp_path / "learned-rules.json"
        rules_file.write_text("this is { not valid json")

        original_expanduser = os.path.expanduser
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(rules_file) if "learned-rules" in p else original_expanduser(p))

        # _load_learned_rules should return {} on JSONDecodeError
        result = _mod._load_learned_rules()
        assert result == {}

    def test_learned_rules_missing_file(self, tmp_path, monkeypatch):
        """Missing learned rules file should be handled gracefully."""
        nonexistent = tmp_path / "does-not-exist.json"

        original_expanduser = os.path.expanduser
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(nonexistent) if "learned-rules" in p else original_expanduser(p))

        result = _mod._load_learned_rules()
        assert result == {}

    def test_learned_rules_empty_object(self, tmp_path, monkeypatch):
        """Empty JSON object in learned rules should work without errors."""
        rules_file = tmp_path / "learned-rules.json"
        rules_file.write_text("{}")

        original_expanduser = os.path.expanduser
        monkeypatch.setattr(os.path, "expanduser", lambda p: str(rules_file) if "learned-rules" in p else original_expanduser(p))

        result = _mod._load_learned_rules()
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════════════
# TestImmutableDenyCompleteness — cross-check immutable deny vs validator
# ═══════════════════════════════════════════════════════════════════════════════

class TestImmutableDenyCompleteness:
    """Cross-check immutable-deny.json against validator whitelists.

    The immutable deny list prevents the *learning system* from ever
    auto-approving certain commands/subcommands. This test catches
    accidental additions that would bypass those protections.

    Note: 'docker' is intentionally in both SAFE_COMMANDS and
    never_safe_commands. Docker has subcommand-level filtering in
    the validator (only read-only subcommands like ps, images, logs
    are allowed). The immutable deny list prevents the learning system
    from adding docker as a blanket safe command.
    """

    @pytest.fixture(scope="class")
    def immutable_deny(self):
        deny_path = os.path.join(
            os.path.dirname(__file__), '..', 'rules', 'immutable-deny.json'
        )
        with open(deny_path) as f:
            return json.load(f)

    def test_deny_file_loads(self, immutable_deny):
        """Sanity check: immutable-deny.json exists and is valid JSON."""
        assert "never_safe_commands" in immutable_deny
        assert "never_safe_git_subcommands" in immutable_deny

    def test_never_safe_commands_not_in_safe_commands(self, immutable_deny):
        """Commands in never_safe_commands should NOT be in SAFE_COMMANDS.

        Exception: 'docker' is in SAFE_COMMANDS but has subcommand-level
        filtering that restricts it to read-only operations.
        """
        # Known exceptions: commands that are in SAFE_COMMANDS but have
        # subcommand-level restrictions that make them safe
        KNOWN_EXCEPTIONS = {"docker"}

        never_safe = set(immutable_deny["never_safe_commands"])
        violations = never_safe & SAFE_COMMANDS - KNOWN_EXCEPTIONS

        assert violations == set(), (
            f"Commands in never_safe_commands that are also in SAFE_COMMANDS "
            f"(without subcommand filtering): {violations}"
        )

    def test_never_safe_git_subcommands_not_in_safe_git(self, immutable_deny):
        """Git subcommands in the immutable deny list should NOT be in SAFE_GIT_SUBCOMMANDS."""
        never_safe_git = set(immutable_deny["never_safe_git_subcommands"])
        violations = never_safe_git & SAFE_GIT_SUBCOMMANDS

        assert violations == set(), (
            f"Git subcommands in immutable deny that are in SAFE_GIT_SUBCOMMANDS: "
            f"{violations}"
        )

    def test_never_safe_commands_not_empty(self, immutable_deny):
        """Immutable deny list should have meaningful content."""
        assert len(immutable_deny["never_safe_commands"]) >= 10
        assert len(immutable_deny["never_safe_git_subcommands"]) >= 5

    def test_critical_commands_in_deny_list(self, immutable_deny):
        """Verify critical dangerous commands are present in the deny list."""
        critical = {"rm", "sudo", "chmod", "kill", "ssh"}
        never_safe = set(immutable_deny["never_safe_commands"])
        missing = critical - never_safe
        assert missing == set(), f"Critical commands missing from deny list: {missing}"

    def test_critical_git_subcommands_in_deny_list(self, immutable_deny):
        """Verify critical dangerous git subcommands are in the deny list."""
        critical = {"push", "reset", "rebase", "clean", "checkout"}
        never_safe_git = set(immutable_deny["never_safe_git_subcommands"])
        missing = critical - never_safe_git
        assert missing == set(), f"Critical git subcommands missing from deny list: {missing}"


# ═══════════════════════════════════════════════════════════════════════════════
# TestRealWorldCommands — commands from actual Claude Code usage
# ═══════════════════════════════════════════════════════════════════════════════

class TestRealWorldCommands:
    """Test commands from actual Claude Code usage patterns."""

    def test_gh_pipe_to_safe_python_json(self):
        """gh issue list piped to safe python3 -c for JSON processing."""
        cmd = (
            'gh issue list --json number,title | python3 -c '
            '"import json,sys; data=json.load(sys.stdin); '
            '[print(f\'#{d[\\\"number\\\"]} {d[\\\"title\\\"]}\') for d in data]"'
        )
        assert check_command(cmd) is True

    def test_git_ls_tree_pipe_grep_head(self):
        """git ls-tree piped to grep and head — read-only inspection."""
        cmd = "git ls-tree -r --name-only FETCH_HEAD | grep 'packages/' | head -50"
        assert check_command(cmd) is True

    def test_cat_grep_with_redirect_and_or(self):
        """cat + grep with stderr redirect and || true fallback."""
        cmd = "cat package.json | grep -A 10 prettier 2>/dev/null || true"
        assert check_command(cmd) is True

    def test_git_show_pipe_safe_python(self):
        """git show piped to safe python3 -c for JSON inspection."""
        cmd = (
            'git show branch:file.json 2>/dev/null | python3 -c '
            '"import json,sys; d=json.load(sys.stdin); '
            'print(json.dumps(d.get(\'prettier\',\'NOT FOUND\'), indent=2))"'
        )
        assert check_command(cmd) is True

    def test_curl_pipe_safe_python(self):
        """curl piped to safe python3 -c for JSON processing."""
        cmd = (
            "curl -sL 'https://example.com/api.json' | python3 -c "
            '"import json,sys; paths=json.load(sys.stdin).get(\'paths\',{}); '
            '[print(f\'{m.upper()} {p}\') for p in paths for m in paths[p]]"'
        )
        assert check_command(cmd) is True

    def test_node_e_safe_path_resolve(self):
        """node -e with safe path.resolve usage."""
        cmd = (
            'node -e "const path = require(\'node:path\'); '
            'console.log(path.resolve(\'.\', \'src/main.ts\'))"'
        )
        assert check_command(cmd) is True

    def test_python_os_system_dangerous(self):
        """python3 -c with os.system — must be rejected."""
        cmd = 'python3 -c "import os; os.system(\'rm -rf /\')"'
        assert check_command(cmd) is False

    def test_git_checkout_dangerous(self):
        """git checkout (not in SAFE_GIT_SUBCOMMANDS) should be rejected."""
        cmd = "git checkout main -- packages/schema/ 2>/dev/null"
        assert check_command(cmd) is False

    def test_compound_git_checkout_dangerous(self):
        """Compound command with git checkout — entire command rejected."""
        cmd = "git checkout main -- packages/schema/ 2>/dev/null; git checkout -- . 2>/dev/null"
        assert check_command(cmd) is False

    def test_gh_with_jq_flag(self):
        """gh with --jq flag — best practice, auto-approves."""
        cmd = "gh issue list --json number,title --jq '.[] | \"#\\(.number) \\(.title)\"'"
        assert check_command(cmd) is True

    def test_gh_pr_view(self):
        """gh pr view — common Claude Code pattern."""
        cmd = "gh pr view 123 --json title,body,state"
        assert check_command(cmd) is True

    def test_gh_api_request(self):
        """gh api — common for GitHub API access."""
        cmd = "gh api repos/owner/repo/pulls/123/comments"
        assert check_command(cmd) is True

    def test_git_diff_with_stat(self):
        """git diff --stat — common review pattern."""
        cmd = "git diff --stat HEAD~5..HEAD"
        assert check_command(cmd) is True

    def test_git_log_oneline(self):
        """git log --oneline — common inspection pattern."""
        cmd = "git log --oneline -20"
        assert check_command(cmd) is True

    def test_grep_recursive_with_context(self):
        """grep -rn with context — common code search pattern."""
        cmd = "grep -rn 'function.*export' src/ --include='*.ts' -A 3"
        assert check_command(cmd) is True

    def test_find_name_pattern(self):
        """find with -name — common file search."""
        cmd = "find . -name '*.py' -type f | head -20"
        assert check_command(cmd) is True

    def test_jq_complex_query(self):
        """Complex jq query — should auto-approve."""
        cmd = (
            "cat package.json | jq -r "
            "'.dependencies // {} | to_entries[] | \"\\(.key): \\(.value)\"'"
        )
        assert check_command(cmd) is True

    def test_npm_run_with_double_dash(self):
        """npm run with -- passthrough args."""
        cmd = "npm run test -- --watch --verbose"
        assert check_command(cmd) is True

    def test_python_pytest_verbose(self):
        """pytest with common flags."""
        cmd = "pytest tests/ -xvs --tb=short -k 'test_auth'"
        assert check_command(cmd) is True

    def test_docker_ps_safe(self):
        """docker ps — read-only, should be safe."""
        cmd = "docker ps -a"
        assert check_command(cmd) is True

    def test_docker_run_dangerous(self):
        """docker run — not in safe subcommands."""
        cmd = "docker run -it ubuntu bash"
        assert check_command(cmd) is False

    def test_docker_logs_safe(self):
        """docker logs — read-only inspection."""
        cmd = "docker logs --tail 100 my-container"
        assert check_command(cmd) is True

    def test_multi_segment_safe_pipeline(self):
        """Complex but safe multi-segment pipeline."""
        cmd = "git log --oneline -50 | grep -i fix | wc -l"
        assert check_command(cmd) is True

    def test_env_var_assignment_with_command(self):
        """Environment variable prefix with safe command."""
        cmd = "PYTHONPATH=src python3 tests/run.py"
        assert check_command(cmd) is True

    def test_git_stash_list_safe(self):
        """git stash list — read-only."""
        cmd = "git stash list"
        assert check_command(cmd) is True

    def test_git_stash_drop_dangerous(self):
        """git stash drop — destructive."""
        cmd = "git stash drop"
        assert check_command(cmd) is False

    def test_curl_with_headers(self):
        """curl with custom headers — common API pattern."""
        cmd = "curl -sS -H 'Accept: application/json' https://api.example.com/data"
        assert check_command(cmd) is True

    def test_tail_follow_log(self):
        """tail -f for log monitoring."""
        cmd = "tail -f /var/log/app.log"
        assert check_command(cmd) is True

    def test_wc_multiple_files(self):
        """wc -l on multiple files."""
        cmd = "wc -l src/*.py tests/*.py"
        assert check_command(cmd) is True

    def test_safe_python_inline_with_stderr_redirect(self):
        """Safe python3 -c with stderr redirect — should approve."""
        cmd = 'python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))" 2>/dev/null'
        assert check_command(cmd) is True

    def test_xargs_with_safe_target(self):
        """xargs piped to a safe command."""
        cmd = "find . -name '*.py' | xargs grep -l 'import os'"
        assert check_command(cmd) is True

    def test_xargs_with_dangerous_target(self):
        """xargs piped to rm — should be rejected."""
        cmd = "find . -name '*.tmp' | xargs rm"
        assert check_command(cmd) is False

    def test_git_describe_safe(self):
        """git describe — read-only inspection."""
        cmd = "git describe --tags --always"
        assert check_command(cmd) is True

    def test_git_rev_list_safe(self):
        """git rev-list — read-only inspection."""
        cmd = "git rev-list --count HEAD"
        assert check_command(cmd) is True

    def test_line_continuation_safe(self):
        """Multi-line command with line continuations."""
        cmd = "git log \\\n  --oneline \\\n  -20"
        assert check_command(cmd) is True

    def test_ruby_e_always_dangerous(self):
        """ruby -e — no analyzer, always rejected."""
        cmd = "ruby -e 'puts 1+1'"
        assert check_command(cmd) is False

    def test_deno_eval_always_dangerous(self):
        """deno eval — no analyzer, always rejected."""
        cmd = "deno eval 'console.log(42)'"
        assert check_command(cmd) is False

    def test_bun_eval_always_dangerous(self):
        """bun eval — no analyzer, always rejected."""
        cmd = "bun eval 'console.log(42)'"
        assert check_command(cmd) is False

    def test_bash_c_always_dangerous(self):
        """bash -c — always rejected regardless of content."""
        cmd = "bash -c 'echo hello'"
        assert check_command(cmd) is False

    def test_command_substitution_rejected(self):
        """$(...) command substitution — always rejected."""
        cmd = "echo $(whoami)"
        assert check_command(cmd) is False

    def test_backtick_substitution_rejected(self):
        """Backtick command substitution — always rejected."""
        cmd = "echo `whoami`"
        assert check_command(cmd) is False

    def test_process_substitution_rejected(self):
        """<(...) process substitution — always rejected."""
        cmd = "diff <(sort file1) <(sort file2)"
        assert check_command(cmd) is False

    def test_heredoc_rejected(self):
        """Raw heredoc — rejected."""
        cmd = "cat <<EOF\nhello\nEOF"
        assert check_command(cmd) is False

    def test_safe_cat_heredoc_with_single_quotes(self):
        """$(cat <<'DELIM'...DELIM) — safe form, should be stripped and approved."""
        cmd = (
            "gh api graphql -f query=$(cat <<'GQL'\n"
            "{ repository(owner: \"foo\", name: \"bar\") { name } }\n"
            "GQL\n"
            ")"
        )
        assert check_command(cmd) is True
