# bash-validator

A Claude Code PreToolUse hook that auto-approves safe Bash commands and prompts the user for everything else.

```
safe command   →  auto-executes (no prompt)
unsafe command →  asks the user first
```

No command is ever hard-denied. The user always decides.

## Quick Start

Install as a Claude Code plugin, or add the hook directly to your settings:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "python3 path/to/bash-validator.py"
      }]
    }]
  }
}
```

The validator reads the command from stdin (Claude Code's hook input JSON), classifies it, and returns a `permissionDecision` of `"allow"` or `"ask"`.

## How It Works

The validator classifies commands into three tiers:

| Tier | Decision | Examples |
|------|----------|---------|
| **1 — Safe** | Auto-allow | `git status`, `ls -la`, `jq '.name' file.json` |
| **2 — Flagged** | Ask user | `python3 -c "..."`, `bash -c "..."`, `rm -rf /tmp/dir` |
| **3 — Unknown** | Ask user | `ssh host`, `psql`, any command not in the whitelist |

### Tier 1: Safe Commands

A curated whitelist of ~80 commands covers dev tooling, file utilities, text processing, and CLI tools. See `SAFE_COMMANDS` in `bash-validator.py` for the full list.

Some whitelisted commands carry restrictions:

- **git** — safe subcommands (`status`, `diff`, `log`, `add`, `commit`, ...) auto-approve. Dangerous flags on `branch`, `stash`, `tag`, `remote`, `config`, and `worktree` trigger a prompt.
- **docker** — read-only subcommands (`ps`, `images`, `logs`, `inspect`, ...) auto-approve. `run`, `exec`, `rm`, and `stop` trigger a prompt.
- **find** — auto-approves unless `-delete` is present or `-exec` targets a command outside the whitelist.
- **Interpreters** (`python3`, `node`, `ruby`, `deno`, `bun`) — auto-approve when running a script file. Inline execution flags (`-c`, `-e`, `--eval`) always trigger a prompt.

### Compound Commands

The validator splits pipelines (`|`), chains (`&&`, `||`), and sequences (`;`) into segments, then checks each segment independently. Every segment must pass for the command to auto-approve.

It also handles:
- **Heredocs** — `$(cat <<'DELIM'...DELIM)` patterns (safe string literals) are recognized and replaced with placeholders before analysis.
- **Subshells** — plain `(cmd1 && cmd2)` groups are recursively validated.
- **Redirections** — stripped before analysis; they don't affect safety.

Constructs the validator cannot statically analyze — command substitution (`` `...` `` or `$(...)`), process substitution (`<(...)`, `>(...)`), and raw heredocs (`<<`) — trigger a prompt.

### Tier 3: Passthrough

Standalone commands outside the whitelist (`rm`, `ssh`, `kubectl`) pass through to Claude Code's built-in permission system. The user sees the full command and decides. Compound commands containing unknown commands are not passed through, because a broad permission rule like `Bash(cd *)` could accidentally auto-approve the entire chain.

## Design Principles

### The validator checks form, not intent

The validator cannot inspect what `python3 -c "..."` does — it might format JSON or it might delete files. It can only verify that the *structure* of a command matches a known-safe pattern. This is a feature, not a limitation: static analysis of arbitrary code is an unsolvable problem, so the validator draws a clear line at what it can verify.

### Safe operations deserve safe expressions

Many commands that trigger a prompt are fundamentally safe — they just use a form the validator cannot verify. The fix belongs in the command, not the validator:

| Triggers prompt | Auto-approves | Why |
|----------------|---------------|-----|
| `gh ... \| python3 -c "import json..."` | `gh ... \| jq -r '...'` | `jq` is a pure JSON processor with no side effects |
| `gh ... \| python3 -c "..."` | `gh ... --jq '...'` | Uses `gh`'s built-in jq support; no pipe needed |
| `cat <<'EOF' \| jq ...` | `echo '...' \| jq ...` | Heredocs trigger the `<<` rejection |
| `python3 -c "format_output()"` | `python3 format_output.py` | Script files are safe; `-c` flags are not verifiable |

This principle matters most for subagents. A subagent generating `gh issue list --json number,title | python3 -c "..."` produces a command the user must manually approve — even though the operation is read-only. The same subagent generating `gh issue list --json number,title --jq '.[] | "#\(.number) \(.title)"'` produces a command that auto-approves, because every part is statically verifiable.

**Widen the validator's rules only when a class of commands is provably safe. Prefer teaching callers to express safe intent in verifiable forms.**

### Prevention over correction

The validator runs as a plugin across all projects. Subagents in any repo can generate commands that trigger prompts — and those prompts interrupt the user with long, hard-to-read command blocks they must approve or reject.

The plugin addresses this at two layers:

1. **Prevention (skill):** A bundled skill (`skills/validator-friendly-commands/`) activates whenever a subagent is about to generate a Bash command that formats JSON output. The skill teaches the subagent to choose verifiable forms (`jq`, `--jq`, script files) *before* the command is generated. Because the skill travels with the plugin, it reaches subagents in every project where the plugin is installed — no per-repo configuration needed.

2. **Enforcement (hook):** The validator hook catches anything the skill missed. When a command uses an unverifiable form, the user is prompted. This is the safety net, not the primary mechanism.

The goal: subagents generate auto-approvable commands by default, and the validator only prompts when the operation genuinely warrants human review.

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Debug Log

The validator writes decisions to `/tmp/bash-validator-debug.log`:

```
[a1b2c3d4] allow: git status
[a1b2c3d4] ask: python3 -c "import os; ..."
```

### Project Structure

```
hooks/
  bash-validator.py                        # the validator (enforcement)
  hooks.json                               # Claude Code hook registration
skills/
  validator-friendly-commands/
    SKILL.md                               # subagent guidance (prevention)
tests/
  test_bash_validator.py                   # comprehensive test suite
.claude-plugin/
  plugin.json                              # plugin manifest
  marketplace.json                         # marketplace metadata
```
