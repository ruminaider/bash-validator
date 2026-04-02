#!/usr/bin/env python3
"""PreToolUse hook: validates Bash commands with allow/ask/deny permissions.

Returns hookSpecificOutput with permissionDecision:
  - "allow" for safe commands → auto-executes (bypasses all permission checks)
  - "ask"   for unsafe commands → prompts the user for approval
  - "deny"  for structural patterns rejected 3+ times → blocks without prompting

Decision: check_command() True → "allow". For unsafe commands, escalation
logic may return "ask" or "deny" based on session rejection history.
"""

import ast
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss
import guidance_map as _gm

# --- A. Whitelist ---

SAFE_COMMANDS = {
    "git",
    # JavaScript/TypeScript
    "npm", "npx", "yarn", "pnpm", "bun", "deno", "node", "tsx", "ts-node",
    "tsc", "esbuild", "vite", "webpack",
    # Python
    "python", "python3", "pip", "pip3", "uv", "poetry", "pdm", "pipx",
    "pytest", "mypy", "ruff", "black",
    # Ruby
    "ruby", "gem", "bundle", "rake",
    # Go/Rust
    "go", "cargo", "rustc",
    # Java
    "java", "javac", "mvn", "gradle",
    # Build
    "make", "cmake",
    # Testing
    "jest", "vitest", "mocha", "cypress", "playwright",
    # Code search
    "clew",
    # File utilities
    "ls", "cat", "head", "tail", "find", "grep", "rg", "fd", "wc", "file",
    "stat", "which", "type", "echo", "printf", "pwd", "tree", "du", "df",
    "diff", "date", "hostname", "uname", "basename", "dirname", "realpath",
    "readlink", "env", "printenv", "whoami", "id", "test", "sleep",
    # Navigation
    "cd",
    # File operations
    "mkdir", "touch", "ln", "cp", "mv",
    # Text processing
    "sed", "awk", "sort", "uniq", "cut", "tr", "xargs", "tee",
    # Archives
    "tar", "zip", "unzip", "gzip",
    # Data processing
    "jq", "yq", "column", "patch",
    # Package managers
    "brew",
    # CLI tools
    "gh", "claude", "claude-sync", "bd",
    # Remote (read-only safe; rsync --delete denied below)
    "rsync",
    # Containers (read-only subcommands; run/exec/rm/stop denied below)
    "docker",
    # Documentation
    "man",
    # Process info
    "lsof", "ps", "pgrep", "top",
    # Shell builtins (no-ops)
    "true", "false",
    # macOS
    "open", "pbcopy", "pbpaste", "mdfind", "locate", "defaults",
    # Terminals
    "tmux",
    # Databases (local only; psql moved to Tier 3)
    "sqlite3",
    # Search
    "fzf", "gum",
    # Binary
    "strings", "xxd", "hexdump", "base64", "openssl",
    # Network
    "curl", "wget", "tailscale", "dig", "nslookup", "ping",
}

SAFE_GIT_SUBCOMMANDS = {
    "status", "diff", "log", "show", "add", "commit", "fetch", "pull",
    "blame", "rev-parse", "ls-files", "remote", "config", "grep", "tag",
    "stash", "worktree", "checkout",
    # Read-only inspection commands
    "ls-tree", "cat-file", "describe", "shortlog", "rev-list",
    "merge-base", "name-rev", "cherry", "diff-tree", "for-each-ref",
    "show-ref", "verify-commit", "verify-tag", "count-objects",
}

# Git subcommands allowed UNLESS dangerous flags are present
GIT_DANGEROUS_FLAGS = {
    "branch": {"-d", "-D", "--delete", "-m", "-M", "--move",
               "-c", "-C", "--copy", "-f", "--force"},
    "stash":  {"drop", "clear"},
    "tag":    {"-d", "--delete", "-f", "--force"},
    "remote": {"remove", "rename", "set-url", "rm"},
    "config": {"--global", "--system", "--unset", "--unset-all",
               "--remove-section", "--rename-section"},
    "checkout": {"--", "-f", "--force", "--ours", "--theirs", "--orphan"},
    "worktree": {"add", "remove", "prune", "move", "repair", "unlock"},
}

SAFE_DOCKER_SUBCOMMANDS = {
    "inspect", "ps", "images", "logs", "stats", "top", "port",
    "version", "info", "network", "volume", "container", "image",
    "system", "context", "manifest", "trust", "history", "diff",
    "compose",
}

# docker compose sub-subcommands that are safe (read-only + standard dev workflow)
SAFE_DOCKER_COMPOSE_SUBCOMMANDS = {
    "ps", "ls", "top", "logs", "images", "config", "version",
    "up", "build", "start", "pull", "restart", "run",
    "events", "port", "alpha",
}

# --- Learned rules (auto-updated by session-start hook) ---

REJECTIONS_LOG = os.path.expanduser("~/.config/bash-validator/rejections.jsonl")


def _load_learned_rules():
    """Load auto-learned rules from user config."""
    path = os.path.expanduser("~/.config/bash-validator/learned-rules.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


_LEARNED = _load_learned_rules()

# Merge learned rules into the working sets
SAFE_GIT_SUBCOMMANDS.update(_LEARNED.get("git_subcommands", []))
SAFE_DOCKER_SUBCOMMANDS.update(_LEARNED.get("docker_subcommands", []))
# NOTE: safe_commands are NOT auto-merged — require explicit review

SAFE_DEFAULTS_SUBCOMMANDS = {
    "read", "read-type", "find", "domains", "help",
}

# --- B. Deny patterns (dangerous flags within safe commands) ---

# Interpreters that support inline code execution
INLINE_EXEC_FLAGS = {
    "node":    {"-e", "--eval", "-p", "--print"},
    "deno":    {"eval"},
    "bun":     {"eval", "-e"},
    "python":  {"-c"},
    "python3": {"-c"},
    "ruby":    {"-e", "--eval"},
}

# Commands with specific dangerous flags
DANGEROUS_CMD_FLAGS = {
    "find":  {"-delete"},
    "rsync": {"--delete", "--delete-before", "--delete-after",
              "--delete-during", "--delete-excluded",
              "--delete-delay", "--delete-missing-args",
              "--remove-source-files"},
    "sed":   {"-i", "--in-place"},
    "awk":   {"-i"},
}

# --- C. Python AST analyzer (for inline python3 -c) ---

SAFE_PYTHON_MODULES = {
    "__future__",
    "json", "csv", "sys",
    "re", "string", "textwrap", "unicodedata", "difflib", "html",
    "collections", "heapq", "bisect", "array",
    "itertools", "functools", "operator",
    "math", "cmath", "decimal", "fractions", "statistics", "random", "numbers",
    "datetime", "time", "calendar", "zoneinfo",
    "typing", "types", "abc", "dataclasses", "enum",
    "base64", "binascii", "codecs", "hashlib", "hmac",
    "ast", "tokenize", "keyword", "inspect",
    "pprint", "reprlib",
    "copy", "contextlib", "warnings", "traceback", "struct",
}

SAFE_SYS_ATTRS = {
    "stdin", "stdout", "stderr", "argv",
    "maxsize", "float_info", "int_info", "version", "version_info",
    "platform", "byteorder", "maxunicode",
}

DANGEROUS_BUILTINS = {
    "open", "exec", "eval", "compile", "__import__",
    "getattr", "setattr", "delattr",
    "globals", "locals", "vars",
    "breakpoint", "exit", "quit", "input",
}


def is_safe_inline_python(code_str):
    """Analyze a Python code string via AST to decide if it's safe.

    Returns (True, None) if safe, or (False, reason_string) if dangerous.
    The reason_string describes exactly what was flagged (e.g.,
    "dangerous_builtin:open", "unsafe_module:os", "dunder_access").
    """
    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        return False, "syntax_error"

    for node in ast.walk(tree):
        # Check dunder name access (__builtins__, __import__, etc.)
        if isinstance(node, ast.Name):
            if node.id.startswith("__") and node.id.endswith("__"):
                return False, f"dunder_name:{node.id}"

        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_module = alias.name.split('.')[0]
                if top_module not in SAFE_PYTHON_MODULES:
                    return False, f"unsafe_module:{top_module}"

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                return False, "relative_import"
            top_module = node.module.split('.')[0]
            if top_module not in SAFE_PYTHON_MODULES:
                return False, f"unsafe_module:{top_module}"

        # Check dangerous builtin calls
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in DANGEROUS_BUILTINS:
                return False, f"dangerous_builtin:{func.id}"

        # Check attribute access
        elif isinstance(node, ast.Attribute):
            # sys.exit, sys.modules, etc. — only allow safe sys attrs
            if isinstance(node.value, ast.Name) and node.value.id == "sys":
                if node.attr not in SAFE_SYS_ATTRS:
                    return False, f"unsafe_sys_attr:{node.attr}"

            # Dunder attribute access (sandbox escape patterns)
            if node.attr.startswith("__") and node.attr.endswith("__"):
                return False, f"dunder_attr:{node.attr}"

    return True, None


# --- D. Node.js regex analyzer (for inline node -e) ---

_JS_DANGEROUS_PATTERNS = [
    # File system access
    r"""\brequire\s*\(\s*['"](?:node:)?fs['"]\s*\)""",
    r"""\breadFileSync\b""",
    r"""\bwriteFileSync\b""",
    r"""\bunlinkSync\b""",
    r"""\bmkdirSync\b""",
    r"""\brmdirSync\b""",
    r"""\brmSync\b""",
    # Child process
    r"""\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)""",
    r"""\bexecSync\b""",
    r"""\bspawnSync\b""",
    r"""\bexecFileSync\b""",
    # Network
    r"""\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)""",
    r"""\brequire\s*\(\s*['"](?:node:)?net['"]\s*\)""",
    r"""\brequire\s*\(\s*['"](?:node:)?dgram['"]\s*\)""",
    r"""\bfetch\s*\(""",
    # Code execution
    r"""\beval\s*\(""",
    r"""\bnew\s+Function\s*\(""",
    r"""\brequire\s*\(\s*['"](?:node:)?vm['"]\s*\)""",
    # Process manipulation
    r"""\bprocess\.exit\b""",
    r"""\bprocess\.kill\b""",
    # OS module (system info, potentially dangerous)
    r"""\brequire\s*\(\s*['"](?:node:)?os['"]\s*\)""",
    # fs subpaths (fs/promises, etc.)
    r"""\brequire\s*\(\s*['"](?:node:)?fs/""",
    # Template literal require
    r"""\brequire\s*\(\s*`""",
    # Dynamic import() (ESM)
    r"""\bimport\s*\(""",
    # Dynamic require (variable instead of string literal)
    r"""\brequire\s*\(\s*[^'"\s)]""",
]

_JS_DANGEROUS_RE = [re.compile(p) for p in _JS_DANGEROUS_PATTERNS]


def is_safe_inline_js(code_str):
    """Check if inline Node.js code is a safe data transformation."""
    for pattern in _JS_DANGEROUS_RE:
        if pattern.search(code_str):
            return False
    return True


def output(decision, reason=None, additional_context=None):
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        payload["hookSpecificOutput"]["permissionDecisionReason"] = reason
    if additional_context:
        payload["hookSpecificOutput"]["additionalContext"] = additional_context
    print(json.dumps(payload))
    sys.exit(0)


def check_segment(segment):
    """Check if a single command segment (no unquoted operators) is safe."""
    # Internal placeholders from pre-processing are already validated
    if segment.strip() in ('"__SUBSHELL__"', '"__HEREDOC__"'):
        return True
    # Bash comments are no-ops — safe
    stripped = segment.strip()
    if stripped.startswith('#'):
        return True
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return False
    if not tokens:
        return False

    # Strip redirections
    cleaned = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if re.match(r'^[0-9]*[><]', tok) or tok in ('>&', '&>', '&>>'):
            if re.match(r'^[0-9]*[><]+\S', tok):
                continue
            skip_next = True
            continue
        cleaned.append(tok)

    if cleaned and cleaned[-1] == '&':
        cleaned = cleaned[:-1]
    if not cleaned:
        return False

    # Skip env/command prefix and VAR=val assignments
    idx = 0
    while idx < len(cleaned):
        if cleaned[idx] in ('env', 'command'):
            idx += 1
        elif '=' in cleaned[idx] and not cleaned[idx].startswith('-'):
            idx += 1
        else:
            break
    if idx >= len(cleaned):
        return False

    cmd_name = os.path.basename(cleaned[idx])
    rest = cleaned[idx + 1:]

    # Handle prefix/wrapper commands: validate the target command they wrap
    PREFIX_COMMANDS = {'time'}
    TIMEOUT_COMMANDS = {'timeout', 'gtimeout'}

    if cmd_name in PREFIX_COMMANDS:
        # 'time' takes no additional args before the command
        target_segment = ' '.join(rest)
        return check_segment(target_segment) if target_segment else True

    if cmd_name in TIMEOUT_COMMANDS:
        # timeout takes: [flags] duration command [args]
        # Skip flags (some take a separate value), then skip the duration
        TIMEOUT_VALUE_FLAGS = {'-s', '--signal', '-k', '--kill-after'}
        ti = 0
        while ti < len(rest) and rest[ti].startswith('-'):
            if rest[ti] in TIMEOUT_VALUE_FLAGS:
                ti += 2  # skip flag and its value
            else:
                ti += 1
        ti += 1  # skip duration
        if ti < len(rest):
            target_segment = ' '.join(rest[ti:])
            return check_segment(target_segment) if target_segment else True
        return True

    # --- Deny patterns (checked before allow) ---

    # Deny shell -c (bash, sh, zsh)
    if cmd_name in ('bash', 'sh', 'zsh'):
        if rest and rest[0] == '-c':
            return False

    # Inline execution flags — analyze code content if possible
    if cmd_name in INLINE_EXEC_FLAGS:
        dangerous = INLINE_EXEC_FLAGS[cmd_name]
        exec_flag = None
        code_str = None
        for i, tok in enumerate(rest):
            if tok in dangerous:
                exec_flag = tok
                # Code is the next token after the flag
                if i + 1 < len(rest):
                    code_str = rest[i + 1]
                break
            # Check for concatenated form: -c"code" or -e"code"
            for flag in dangerous:
                if tok.startswith(flag) and len(tok) > len(flag):
                    exec_flag = flag
                    code_str = tok[len(flag):]
                    break
            if exec_flag:
                break
            # Stop at first positional argument (script filename)
            if not tok.startswith('-'):
                break

        if exec_flag and code_str is not None:
            # We have inline code — analyze it for safety
            if cmd_name in ('python', 'python3'):
                safe, _detail = is_safe_inline_python(code_str)
                return safe
            elif cmd_name == 'node':
                return is_safe_inline_js(code_str)
            # Other interpreters (ruby, deno, bun) — no analyzer yet, deny
            return False
        elif exec_flag:
            # Flag present but no code string found — deny
            return False

    # Deny dangerous flags on specific commands
    if cmd_name in DANGEROUS_CMD_FLAGS:
        dangerous_flags = DANGEROUS_CMD_FLAGS[cmd_name]
        for tok in rest:
            if tok in dangerous_flags:
                return False
            # sed -i accepts optional suffix: -i.bak, -i'', -i''
            if cmd_name == "sed" and (tok.startswith("-i") or tok.startswith("--in-place")):
                return False

    # Deny find -exec with destructive targets
    if cmd_name == 'find':
        for i, tok in enumerate(rest):
            if tok in ('-exec', '-execdir') and i + 1 < len(rest):
                # Skip env/command prefixes to find the real target
                ti = i + 1
                while ti < len(rest) and rest[ti] in ('env', 'command'):
                    ti += 1
                if ti < len(rest):
                    target = os.path.basename(rest[ti])
                    if target not in SAFE_COMMANDS:
                        return False

    # Handle xargs — check the target command
    # Some flags take a separate value arg that must be skipped
    XARGS_VALUE_FLAGS = {
        '-I', '-n', '-P', '-L', '-s', '-d', '-E',
        '--max-args', '--max-procs', '--max-lines', '--max-chars',
        '--replace', '--delimiter', '--eof',
    }
    if cmd_name == 'xargs' and rest:
        xi = 0
        while xi < len(rest):
            tok = rest[xi]
            if tok in XARGS_VALUE_FLAGS:
                xi += 2  # skip flag and its value
            elif tok.startswith('-'):
                xi += 1  # skip boolean flag
            else:
                break
        if xi < len(rest):
            target = os.path.basename(rest[xi])
            if target not in SAFE_COMMANDS:
                return False
            if target == 'git' and (xi + 1) < len(rest):
                return rest[xi + 1] in SAFE_GIT_SUBCOMMANDS
        return True

    # --- Docker subcommand handling ---

    if cmd_name == 'docker':
        if not rest:
            return True  # bare 'docker' shows help
        subcmd = rest[0]
        if subcmd not in SAFE_DOCKER_SUBCOMMANDS:
            return False
        # docker compose needs sub-subcommand check
        if subcmd == 'compose':
            # Skip flags between 'compose' and the sub-subcommand
            ci = 1
            while ci < len(rest) and rest[ci].startswith('-'):
                # Skip flags that take a value (-f, -p, --project-name, etc.)
                if rest[ci] in ('-f', '--file', '-p', '--project-name',
                                '--project-directory', '--profile', '--env-file',
                                '--ansi', '--progress', '--parallel'):
                    ci += 2
                else:
                    ci += 1
            if ci >= len(rest):
                return True  # bare 'docker compose' shows help
            return rest[ci] in SAFE_DOCKER_COMPOSE_SUBCOMMANDS
        return True

    # --- macOS defaults subcommand handling ---

    if cmd_name == 'defaults':
        if not rest:
            return True  # bare 'defaults' shows usage
        subcmd = rest[0]
        return subcmd in SAFE_DEFAULTS_SUBCOMMANDS

    # --- Git subcommand handling ---

    # Git global flags that take a separate value argument
    GIT_GLOBAL_VALUE_FLAGS = {'-C', '-c', '--git-dir', '--work-tree'}
    GIT_GLOBAL_BARE_FLAGS = {
        '--no-pager', '--bare', '--no-replace-objects',
        '--literal-pathspecs', '--glob-pathspecs',
        '--noglob-pathspecs', '--no-optional-locks',
    }

    if cmd_name == 'git':
        gi = idx + 1
        while gi < len(cleaned):
            tok = cleaned[gi]
            if tok in GIT_GLOBAL_VALUE_FLAGS and (gi + 1) < len(cleaned):
                gi += 2
                continue
            if tok.startswith(('--git-dir=', '--work-tree=')):
                gi += 1
                continue
            if tok in GIT_GLOBAL_BARE_FLAGS:
                gi += 1
                continue
            break
        if gi < len(cleaned):
            subcmd = cleaned[gi]
            if subcmd in SAFE_GIT_SUBCOMMANDS:
                # Check stash sub-subcommands (drop, clear)
                if subcmd in GIT_DANGEROUS_FLAGS:
                    sub_rest = cleaned[gi + 1:]
                    if any(tok in GIT_DANGEROUS_FLAGS[subcmd] for tok in sub_rest):
                        return False
                return True
            if subcmd in GIT_DANGEROUS_FLAGS:
                sub_rest = cleaned[gi + 1:]
                return not any(tok in GIT_DANGEROUS_FLAGS[subcmd] for tok in sub_rest)
            return False
        return True

    # Internal placeholders from pre-processing are already validated
    if cmd_name in ('__SUBSHELL__', '__HEREDOC__'):
        return True

    return cmd_name in SAFE_COMMANDS


def strip_safe_cat_heredocs(cmd):
    """Replace $(cat <<'DELIM'...DELIM) with a placeholder string.

    Safe because: single-quoted delimiter prevents variable expansion,
    cat just outputs the literal text, and we verify nothing else runs
    in the subshell by requiring ) immediately after the terminator line.
    """
    start_re = re.compile(r"""\$\(\s*cat\s+<<-?\s*'([A-Za-z_]\w*)'\s*\n""")
    result = cmd
    search_from = 0

    while True:
        m = start_re.search(result, search_from)
        if not m:
            break

        delim = m.group(1)
        pos = m.end()
        replacement_end = None

        # Scan line by line for the FIRST occurrence of delimiter
        while pos < len(result):
            newline_pos = result.find('\n', pos)
            if newline_pos == -1:
                break
            line = result[pos:newline_pos]

            if line.strip() == delim:
                # Delimiter found — require ) immediately after (with optional whitespace)
                rest_text = result[newline_pos + 1:].lstrip()
                if rest_text.startswith(')'):
                    paren_idx = result.index(')', newline_pos + 1)
                    replacement_end = paren_idx + 1
                break  # stop at first delimiter match regardless

            pos = newline_pos + 1

        if replacement_end is not None:
            result = result[:m.start()] + '"__HEREDOC__"' + result[replacement_end:]
            search_from = m.start() + len('"__HEREDOC__"')
        else:
            search_from = m.end()

    return result


def strip_safe_subshells(cmd, _depth=0):
    """Replace safe (...) subshells with "__SUBSHELL__" placeholders.

    Scans left-to-right, skipping quoted strings. Ignores $(...), <(...),
    and >(...) — those are command/process substitution and stay rejected.
    Recursively validates inner content via check_command().
    """
    if _depth > 10:
        return cmd

    result = []
    i = 0
    length = len(cmd)

    while i < length:
        ch = cmd[i]

        # Skip single-quoted strings
        if ch == "'":
            j = cmd.find("'", i + 1)
            if j == -1:
                result.append(cmd[i:])
                return ''.join(result)
            result.append(cmd[i:j + 1])
            i = j + 1
            continue

        # Skip double-quoted strings
        if ch == '"':
            j = i + 1
            while j < length:
                if cmd[j] == '\\' and j + 1 < length:
                    j += 2
                    continue
                if cmd[j] == '"':
                    break
                j += 1
            result.append(cmd[i:j + 1])
            i = j + 1
            continue

        # Skip $(...), <(...), >(...)  — not plain subshells
        if ch == '(' and i > 0 and cmd[i - 1] in ('$', '<', '>'):
            result.append(ch)
            i += 1
            continue

        # Found a plain subshell opening
        if ch == '(':
            # Find matching ')' tracking depth and skipping quotes
            depth = 1
            j = i + 1
            while j < length and depth > 0:
                c = cmd[j]
                if c == "'":
                    k = cmd.find("'", j + 1)
                    if k == -1:
                        break
                    j = k + 1
                    continue
                if c == '"':
                    k = j + 1
                    while k < length:
                        if cmd[k] == '\\' and k + 1 < length:
                            k += 2
                            continue
                        if cmd[k] == '"':
                            break
                        k += 1
                    j = k + 1
                    continue
                if c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                j += 1

            # Unbalanced parens — bail, return original
            if depth != 0:
                return cmd

            inner = cmd[i + 1:j - 1]

            # Reject empty subshells
            if not inner.strip():
                return cmd

            # Recursively validate inner content
            if check_command(inner, _depth=_depth + 1):
                result.append('"__SUBSHELL__"')
            else:
                # Unsafe inner — return original command unchanged
                return cmd

            i = j
            continue

        result.append(ch)
        i += 1

    return ''.join(result)


def _contains_unquoted(cmd, pattern):
    """Check if pattern appears outside single/double quotes."""
    i = 0
    while i < len(cmd):
        if cmd[i] == "'":
            j = cmd.find("'", i + 1)
            if j == -1:
                break
            i = j + 1
        elif cmd[i] == '"':
            j = i + 1
            while j < len(cmd):
                if cmd[j] == '\\':
                    j += 2
                    continue
                if cmd[j] == '"':
                    break
                j += 1
            i = j + 1
        elif cmd[i:i + len(pattern)] == pattern:
            return True
        else:
            i += 1
    return False


def check_command(cmd, _depth=0):
    """Check if a full command string is safe."""
    safe, _ = check_command_with_reason(cmd, _depth=_depth)
    return safe


def check_command_with_reason(cmd, _depth=0):
    """Check if a full command string is safe, returning (bool, reason).

    reason is None when safe, or a string describing why the command was
    rejected (e.g., "command_substitution", "process_substitution",
    "heredoc", "unsafe_segment").
    """
    if _depth > 10:
        return False, "recursion_limit"

    # B0. Strip safe $(cat <<'DELIM'...DELIM) — multiline string literals
    cmd = strip_safe_cat_heredocs(cmd)

    # B0.5. Strip safe subshells
    cmd = strip_safe_subshells(cmd, _depth=_depth)

    # B1. Collapse line continuations (\ at end of line)
    cmd = re.sub(r'\\\n\s*', ' ', cmd)

    # B. Pre-scan: reject constructs too complex to analyze (quoting-aware)
    if _contains_unquoted(cmd, '$(') or _contains_unquoted(cmd, '`'):
        return False, "command_substitution"
    if _contains_unquoted(cmd, '<(') or _contains_unquoted(cmd, '>('):
        return False, "process_substitution"
    if _contains_unquoted(cmd, '<<'):
        return False, "heredoc"

    # C. Regex-based operator splitting (respects quoted strings)
    normalized = cmd.replace('\n', ' ; ')
    op_re = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\\.|&&|\|\||[;|]""")

    segments = []
    last_end = 0
    for m in op_re.finditer(normalized):
        if m.group() in ('&&', '||', ';', '|'):
            seg = normalized[last_end:m.start()].strip()
            if seg:
                segments.append(seg)
            last_end = m.end()
    remaining = normalized[last_end:].strip()
    if remaining:
        segments.append(remaining)
    if not segments:
        return False, "empty_command"

    for s in segments:
        if not check_segment(s):
            # Try to extract a more specific reason for inline code rejections
            reason = _get_segment_rejection_detail(s)
            return False, reason
    return True, None


def _get_segment_rejection_detail(segment):
    """Get a specific rejection reason for a failed segment.

    Attempts to identify inline code issues (dangerous builtins, unsafe
    modules) for more actionable skill guidance. Falls back to
    "unsafe_segment" for non-inline rejections.
    """
    stripped = segment.strip()
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return "unsafe_segment"
    if not tokens:
        return "unsafe_segment"

    # Find the command name (skip env/command prefixes and VAR=val)
    idx = 0
    while idx < len(tokens):
        if tokens[idx] in ('env', 'command'):
            idx += 1
        elif '=' in tokens[idx] and not tokens[idx].startswith('-'):
            idx += 1
        else:
            break
    if idx >= len(tokens):
        return "unsafe_segment"

    cmd_name = os.path.basename(tokens[idx])
    rest = tokens[idx + 1:]

    # Check for inline Python code with AST detail
    if cmd_name in ('python', 'python3') and rest:
        exec_flags = INLINE_EXEC_FLAGS.get(cmd_name, set())
        for i, tok in enumerate(rest):
            if tok in exec_flags and i + 1 < len(rest):
                _safe, detail = is_safe_inline_python(rest[i + 1])
                if detail:
                    return f"inline_python:{detail}"
                break
            if not tok.startswith('-'):
                break

    # Check for non-Python inline exec (node -e, ruby -e, deno eval, bun eval)
    if cmd_name in INLINE_EXEC_FLAGS and cmd_name not in ('python', 'python3'):
        exec_flags = INLINE_EXEC_FLAGS[cmd_name]
        for tok in rest:
            if tok in exec_flags:
                return "inline_exec"
            if not tok.startswith('-'):
                break

    # Check for shell -c (bash, sh, zsh are not in INLINE_EXEC_FLAGS)
    if cmd_name in ('bash', 'sh', 'zsh') and rest and rest[0] == '-c':
        return "inline_exec"

    return "unsafe_segment"



def log_rejection(session_id, command, reason=None):
    """Log a rejected command (tokenized) for pattern learning."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    cmd_name = os.path.basename(tokens[0]) if tokens else ""
    subcmd = tokens[1] if len(tokens) > 1 and not tokens[1].startswith("-") else None

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "sid": session_id[:8] if session_id else "?",
        "cmd": cmd_name,
        "subcmd": subcmd,
        "reason": reason,
        "tokens": tokens[:6],
        "hash": hashlib.sha256(command.encode()).hexdigest()[:16],
    }

    os.makedirs(os.path.dirname(REJECTIONS_LOG), exist_ok=True)
    with open(REJECTIONS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# --- Session-aware escalation ---

PROACTIVE_BRIEFING = "Bash validator rules: " + ". ".join(_gm.PROACTIVE_RULES) + "."


def build_escalation_response(state, pattern_key, reason, gmap):
    """Determine escalation decision and guidance for a rejection.

    Returns (decision, guidance) where:
    - decision is "ask" or "deny"
    - guidance is a string for additionalContext, or None for safety gates
    """
    if not _gm.is_structural_reason(reason):
        return "ask", None

    base_guidance = _gm.lookup_guidance(gmap, reason)
    if not base_guidance:
        return "ask", None

    count = state.get("patterns", {}).get(pattern_key, {}).get("rejections", 0)

    if count == 0:
        return "ask", base_guidance
    elif count < _gm.DENY_THRESHOLD:
        return "ask", (
            f"This pattern ({pattern_key}) has been rejected "
            f"{count} time(s) this session. {base_guidance}"
        )
    else:
        return "deny", (
            f"This pattern ({pattern_key}) has been rejected "
            f"{count} times this session and will not be approved. "
            f"{base_guidance} Please continue with your task using "
            f"the suggested alternative."
        )


def _debug_log(msg):
    try:
        with open("/tmp/bash-validator-debug.log", "a") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def main():
    # --- Parse input ---
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")
        agent_id = hook_input.get("agent_id")
        command = hook_input.get("tool_input", {}).get("command", "")
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
        _debug_log(f"[??] parse error: {e}")
        output("ask", reason="Validator could not parse hook input")
        return

    if not command:
        _debug_log(f"[{sid[:8]}] NO CMD")
        output("allow")
        return

    # --- Core safety check ---
    try:
        safe, reason = check_command_with_reason(command)
    except Exception as e:
        _debug_log(f"[{sid[:8]}] check error: {e}")
        output("ask", reason="Internal validator error")
        return

    # --- Safe command path ---
    if safe:
        try:
            state = _ss.load_session_state(sid)
            if not _ss.is_agent_briefed(state, agent_id):
                _ss.mark_agent_briefed(state, agent_id)
                _ss.save_session_state(sid, state)
                _debug_log(f"[{sid[:8]}] allow: {command[:120]}")
                output("allow", additional_context=PROACTIVE_BRIEFING)
                return
        except Exception as e:
            _debug_log(f"[{sid[:8]}] session error (safe path): {e}")
        _debug_log(f"[{sid[:8]}] allow: {command[:120]}")
        output("allow")
        return

    # --- Unsafe command path: escalation ---
    decision, guidance = "ask", None
    try:
        state = _ss.load_session_state(sid)
        pattern_key = _ss.extract_pattern_key(command, reason)
        try:
            log_rejection(sid[:8], command, reason=reason)
        except Exception:
            pass

        decision, guidance = build_escalation_response(
            state, pattern_key, reason, _gm.load_guidance_map()
        )

        _ss.record_rejection(state, pattern_key, reason, guidance, agent_id)

        agent_key = agent_id or "main"
        if decision == "deny":
            _ss.record_resolution(state, pattern_key, approved=False)
        else:
            state["prompted_agents"][agent_key] = pattern_key

        _ss.save_session_state(sid, state)
    except Exception as e:
        _debug_log(f"[{sid[:8]}] session error (escalation): {e}")

    out_reason = "Requires user approval" if decision == "ask" else guidance
    _debug_log(f"[{sid[:8]}] {decision}: {command[:120]}")
    output(decision, out_reason, guidance)


if __name__ == "__main__":
    main()
