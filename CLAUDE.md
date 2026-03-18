# Bash Validator

A Claude Code plugin with two layers: a **skill** that teaches subagents to generate auto-approvable commands, and a **hook** that enforces safety at execution time. See the README for design principles and full documentation.

## Two-Layer Model

1. **Prevention** — The `validator-friendly-commands` skill (in `skills/`) activates when a subagent generates Bash commands that format JSON. It guides the subagent toward verifiable forms (`jq`, `--jq`, script files) before the command reaches the hook. Because the skill ships with the plugin, it works in every project.

2. **Enforcement** — The `bash-validator.py` hook (in `hooks/`) runs on every Bash command. It auto-approves commands whose structure is statically verifiable and prompts the user for everything else. No command is ever hard-denied.

The skill handles the common case; the hook catches everything else.

## Writing Validator-Friendly Commands

When generating Bash commands — especially in subagents — choose forms the validator can statically verify. The validator checks command *structure*, not *intent*: a safe operation expressed in an unverifiable form still triggers a prompt.

### Prefer `jq` or `--jq` over `python3 -c` for JSON formatting

This applies to formatting JSON output from CLI tools (`gh`, `curl`, `aws`, `kubectl`). Use `python3` when you genuinely need file I/O, multiple data sources, non-JSON processing, or logic that would be unreadable in jq.

```bash
# Triggers prompt (python3 -c is unverifiable)
gh issue list --json number,title | python3 -c "
import sys, json
for i in json.load(sys.stdin):
    print(f'#{i[\"number\"]} {i[\"title\"]}')
"

# Auto-approves (jq is a pure JSON processor)
gh issue list --json number,title | jq -r '.[] | "#\(.number) \(.title)"'

# Best: auto-approves, no pipe needed (gh handles jq internally)
gh issue list --json number,title --jq '.[] | "#\(.number) \(.title)"'
```

**jq null-coalescing caveat:** jq prints the literal string `"null"` for missing or null fields — it does not error. Always use `// "default"` for fields that might be absent:

```bash
# Bad: prints "null" if .author.login is missing
jq -r '.author.login'

# Good: prints "?" as fallback
jq -r '.author.login // "?"'
```

### Avoid heredocs for inline data

```bash
# Triggers prompt (<< is rejected)
cat <<'EOF' | jq -r '.title'
{"title": "test"}
EOF

# Auto-approves
echo '{"title": "test"}' | jq -r '.title'
```

### Use script files instead of interpreter `-c` flags

```bash
# Triggers prompt
python3 -c "import json; print(json.dumps({'key': 'val'}))"

# Auto-approves
python3 scripts/format_output.py
```

### Patterns that always auto-approve

- `gh` with any flags, including `--jq`
- Any safe command piped to `jq`
- `git` with safe subcommands (`status`, `diff`, `log`, `add`, `commit`, `fetch`, `pull`, `blame`, `rev-parse`, `ls-files`, `remote`, `config`, `grep`, `tag`, `stash`, `worktree`)
- Interpreter commands running script files (no `-c`, `-e`, or `--eval`)

### Patterns that always prompt

- `python3 -c`, `node -e`, `ruby -e`, `deno eval`, `bun eval`
- `bash -c`, `sh -c`, `zsh -c`
- Command substitution: `` `...` `` or `$(...)`
- Process substitution: `<(...)` or `>(...)`
- Raw heredocs: `<<`
- `find -delete` or `find -exec` targeting commands outside the whitelist
- `rsync --delete` and variants

## Architecture

Single-file validator at `hooks/bash-validator.py`. Key functions:

- `check_command(cmd)` — entry point; returns `True` (safe) or `False` (ask user)
- `check_segment(segment)` — validates a single command (no operators)
- `strip_safe_cat_heredocs(cmd)` — replaces `$(cat <<'DELIM'...DELIM)` with placeholders
- `strip_safe_subshells(cmd)` — recursively validates `(...)` groups
- `_is_standalone_tier3(cmd)` — identifies unknown commands that should pass through to Claude Code's permission system rather than be hard-blocked

## Testing

```bash
pytest tests/ -v
```

Tests are organized by tier: `TestTier1*` (safe), `TestTier2*` (flagged), `TestTier3*` (passthrough). Add new test cases to the appropriate tier class.
