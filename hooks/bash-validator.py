#!/usr/bin/env python3
"""PreToolUse hook: validates Bash commands with allow/ask permissions.

Returns hookSpecificOutput with permissionDecision:
  - "allow" for safe commands → auto-executes (bypasses all permission checks)
  - "ask"   for everything else → prompts the user for approval

Decision: check_command() True → "allow", otherwise → "ask".
No commands are ever hard-denied; the user always gets to decide.
"""

import json
import os
import re
import shlex
import sys

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
    # Process info
    "lsof", "ps", "pgrep", "top",
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
    "stash", "worktree",
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
    "worktree": {"add", "remove", "prune", "move", "repair", "unlock"},
}

SAFE_DOCKER_SUBCOMMANDS = {
    "inspect", "ps", "images", "logs", "stats", "top", "port",
    "version", "info", "network", "volume", "container", "image",
    "system", "context", "manifest", "trust", "history", "diff",
}

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
}


def output(decision, reason=None):
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        payload["hookSpecificOutput"]["permissionDecisionReason"] = reason
    print(json.dumps(payload))
    sys.exit(0)


def check_segment(segment):
    """Check if a single command segment (no unquoted operators) is safe."""
    # Internal placeholders from pre-processing are already validated
    if segment.strip() in ('"__SUBSHELL__"', '"__HEREDOC__"'):
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

    # --- Deny patterns (checked before allow) ---

    # Deny shell -c (bash, sh, zsh)
    if cmd_name in ('bash', 'sh', 'zsh'):
        if rest and rest[0] == '-c':
            return False

    # Deny interpreter inline execution flags (only before first positional arg)
    if cmd_name in INLINE_EXEC_FLAGS:
        dangerous = INLINE_EXEC_FLAGS[cmd_name]
        for tok in rest:
            if tok in dangerous:
                return False
            # Stop at first positional argument (script filename)
            if not tok.startswith('-'):
                break

    # Deny dangerous flags on specific commands
    if cmd_name in DANGEROUS_CMD_FLAGS:
        if any(tok in DANGEROUS_CMD_FLAGS[cmd_name] for tok in rest):
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
        return subcmd in SAFE_DOCKER_SUBCOMMANDS

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


def check_command(cmd, _depth=0):
    """Check if a full command string is safe."""
    if _depth > 10:
        return False

    # B0. Strip safe $(cat <<'DELIM'...DELIM) — multiline string literals
    cmd = strip_safe_cat_heredocs(cmd)

    # B0.5. Strip safe subshells
    cmd = strip_safe_subshells(cmd, _depth=_depth)

    # B1. Collapse line continuations (\ at end of line)
    cmd = re.sub(r'\\\n\s*', ' ', cmd)

    # B. Pre-scan: reject constructs too complex to analyze
    if re.search(r'\$\(|`', cmd):
        return False
    if re.search(r'[<>]\(', cmd):
        return False
    if '<<' in cmd:
        return False

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
        return False

    return all(check_segment(s) for s in segments)


def _is_standalone_tier3(command):
    """Check if command is a standalone Tier 3 command that should prompt.

    Returns True for single-segment commands (no compound operators) whose
    primary command is either:
    - Not in SAFE_COMMANDS (rm, docker, ssh, etc.)
    - A git command with an unknown subcommand (push, pull, reset, etc.)

    These commands should be passed through to Claude Code's permission
    system for user prompting, rather than hard-blocked by this hook.

    Commands with env/command prefixes are NOT passed through because
    they match 'Bash(env *)' in permissions.allow and would auto-allow.
    Compound commands are NOT passed through because the first segment
    may match a broad permissions.allow pattern (e.g., 'Bash(cd *)').
    """
    stripped = command.strip()
    if not stripped:
        return False

    # Reject complex constructs (could hide dangerous commands)
    if '$(' in stripped or '`' in stripped or '<<' in stripped:
        return False
    if '<(' in stripped or '>(' in stripped:
        return False

    # Reject compound commands (operators outside quotes)
    normalized = stripped.replace('\n', ' ; ')
    op_re = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\\.|&&|\|\||[;|]""")
    for m in op_re.finditer(normalized):
        if m.group() in ('&&', '||', ';', '|'):
            return False

    # Tokenize
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        return False
    if not tokens:
        return False

    # Reject env/command prefix (Bash(env *) in permissions.allow would auto-allow)
    idx = 0
    while idx < len(tokens):
        if tokens[idx] in ('env', 'command'):
            return False
        if '=' in tokens[idx] and not tokens[idx].startswith('-'):
            idx += 1
        else:
            break
    if idx >= len(tokens):
        return False

    cmd_name = os.path.basename(tokens[idx])
    rest = tokens[idx + 1:]

    # Reject shell -c patterns (should be hard-denied, not prompted)
    if cmd_name in ('bash', 'sh', 'zsh') and '-c' in rest:
        return False

    # Command NOT in SAFE_COMMANDS → Tier 3, pass through for prompting
    if cmd_name not in SAFE_COMMANDS:
        return True

    # Any standalone git command that check_command() rejected → prompt user.
    # The user can see the full command and decide; no need to hard-block.
    if cmd_name == 'git':
        return True

    return False


def main():
    debug_log = "/tmp/bash-validator-debug.log"
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")[:8]
        command = hook_input.get("tool_input", {}).get("command", "")
        if not command:
            with open(debug_log, "a") as f:
                f.write(f"[{sid}] NO CMD\n")
            output("allow")
        safe = check_command(command)
        decision = "allow" if safe else "ask"
        reason = None if safe else "Requires user approval"
        with open(debug_log, "a") as f:
            f.write(f"[{sid}] {decision}: {command[:120]}\n")
        output(decision, reason)
    except Exception as e:
        with open(debug_log, "a") as f:
            f.write(f"[??] EXCEPTION: {e}\n")
        output("allow")


if __name__ == "__main__":
    main()
