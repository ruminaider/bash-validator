# bash-validator

A Claude Code plugin that validates Bash commands before execution. It combines static analysis, inline code inspection, pattern learning, and session intelligence to auto-approve safe commands, prompt the user for risky ones, and deny structural patterns that agents repeatedly fail to correct.

```
safe command        ->  allow  (auto-executes, no prompt)
unverifiable command ->  ask    (user decides)
structural repeat   ->  deny   (after 3+ rejections in a session)
```

## Quick Start

Install as a Claude Code plugin. The plugin registers six hooks automatically:

| Hook | File | Purpose |
|------|------|---------|
| `PreToolUse:Bash` | `bash-validator.py` | Classify commands: allow, ask, or deny |
| `PostToolUse:Bash` | `post-tool-use.py` | Record approval/denial outcomes |
| `SessionStart` | `session-start.py` | Generate guidance map, apply learned rules |
| `SessionEnd` | `session-end.py` | Flush stats, rotate rejection log |
| `SubagentStart` | `subagent-start.py` | Brief subagents with validator rules |
| `PreCompact` | `pre-compact.py` | Preserve validator rules across compaction |

Or add the hooks manually to your settings (see `hooks/hooks.json` for the full configuration).

## How It Works

The validator makes three kinds of decisions:

| Decision | When | Examples |
|----------|------|---------|
| **Allow** | Command structure is statically verifiable | `git status`, `ls -la`, `jq '.name' file.json` |
| **Ask** | Command structure is unverifiable or command is outside the whitelist | `rm -rf /tmp/dir`, `ssh host`, `python3 -c "import os"` |
| **Deny** | A structural pattern was rejected 3+ times in the current session | Repeated heredocs, repeated `$(...)`  |

Deny applies only to structural reasons (heredoc, inline code, command substitution). Safety gates (destructive commands like `rm`, `git push`) always defer to the user regardless of rejection count.

### Adaptive Layers

Three adaptive layers reduce unnecessary prompts over time:

| Layer | Mechanism | What it does |
|-------|-----------|--------------|
| **1: AST Analysis** | Inline code inspection | Auto-approves safe `python3 -c` and `node -e` data transforms |
| **2: Pattern Learning** | Rejection frequency counting | Auto-learns git/docker subcommands from repeated approvals |
| **3: Skill Adaptation** | Dynamic skill guidance | Teaches subagents to avoid rejected patterns |

### Session Intelligence

Six hooks form a feedback loop across the session lifecycle:

1. **SessionStart** generates the guidance map (rejection reason to actionable advice) and cleans up stale session state files.
2. **SubagentStart** briefs every subagent that has Bash access with validator rules and session-specific warnings. Known non-Bash agent types are skipped.
3. **PreToolUse:Bash** enforces rules. On the first structural rejection, it returns `ask` with guidance in `additionalContext`. On the third rejection for the same reason, it escalates to `deny`.
4. **PostToolUse:Bash** records whether the user approved or denied via a per-agent signal in `prompted_agents`. This prevents cross-agent approval bleed.
5. **PreCompact** preserves validator rules across context compaction by injecting custom compaction instructions.
6. **SessionEnd** flushes aggregated session statistics to `~/.config/bash-validator/session-stats.jsonl` and rotates the rejection log when it exceeds 1 MB.

All hooks share per-session state through `/tmp/bash-validator-session-{sid}.json`, written atomically.

## Command Classification

### Safe Commands

A curated whitelist of ~80 commands covers dev tooling, file utilities, text processing, and CLI tools. See `SAFE_COMMANDS` in `bash-validator.py` for the full list.

Some whitelisted commands carry restrictions:

- **git**: safe subcommands (`status`, `diff`, `log`, `add`, `commit`, and others) auto-approve. Dangerous flags on `branch`, `stash`, `tag`, `remote`, `config`, and `worktree` trigger a prompt.
- **docker**: read-only subcommands (`ps`, `images`, `logs`, `inspect`, and others) auto-approve. `run`, `exec`, `rm`, and `stop` trigger a prompt.
- **find**: auto-approves unless `-delete` is present or `-exec` targets a command outside the whitelist.
- **sed**: read-only `sed` (pattern matching, substitution to stdout) auto-approves. `sed -i` and `sed --in-place` trigger a prompt because they mutate files.
- **Interpreters** (`python3`, `node`, `ruby`, `deno`, `bun`): auto-approve when running a script file. Inline execution flags (`-c`, `-e`, `--eval`) are routed to the AST analyzer (see Layer 1 below).

### Layer 1: Inline Code AST Analysis

Instead of rejecting all `python3 -c` and `node -e` commands, the validator inspects the inline code to determine if it is a safe data transformation.

**Python** uses `ast.parse()` to walk the syntax tree. Safe code must:
- Only import from a curated allowlist of ~46 modules (json, csv, sys, re, collections, itertools, math, datetime, typing, base64, hashlib, and others)
- Not call dangerous builtins (`open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`)
- Not access dangerous `sys` attributes (only `stdin`, `stdout`, `stderr`, `argv`, and a few others are allowed)
- Not use dunder attribute access (`__class__`, `__bases__`, `__builtins__`)

```bash
# Auto-approves (safe data transform: json + sys only)
python3 -c "import json, sys; print(json.dumps(json.load(sys.stdin), indent=2))"

# Prompts (file I/O)
python3 -c "open('/etc/passwd').read()"

# Prompts (subprocess)
python3 -c "import subprocess; subprocess.run(['ls'])"
```

**Node.js** uses regex pattern matching against a list of dangerous APIs (fs, child_process, net, http/https, eval, `new Function`, process.exit/kill, dynamic require/import).

```bash
# Auto-approves (pure data transform)
node -e "console.log(JSON.stringify({a: 1}, null, 2))"

# Prompts (filesystem access)
node -e "require('fs').readFileSync('/etc/passwd')"
```

**Ruby, Deno, Bun**: no analyzer yet. Inline code always prompts.

### Layer 2: Pattern Learning

Commands the validator cannot auto-approve are logged to `~/.config/bash-validator/rejections.jsonl`. At the start of each session, the SessionStart hook analyzes the log for recurring patterns.

**Learning thresholds:**
- The pattern must appear 5 or more times
- Across 3 or more distinct sessions
- At most 3 new patterns are learned per session start

**Scope:** Only git subcommands and docker subcommands can be auto-learned. The system never adds commands to `SAFE_COMMANDS`; that requires explicit code changes.

**Immutable deny list:** Commands on the deny list (`rules/immutable-deny.json`) can never be learned, regardless of frequency. This includes:
- Git subcommands: `push`, `reset`, `rebase`, `merge`, `cherry-pick`, `clean`, `checkout`, `switch`, `restore`, and others
- Top-level commands: `rm`, `sudo`, `ssh`, `kubectl`, `aws`, `psql`, `kill`, and others
- Structural deny patterns: command substitution, process substitution, heredocs, inline exec flags, `find -delete`, `rsync --delete`

**Example flow:**
1. You run `git bisect` repeatedly across several sessions
2. The validator prompts each time (bisect is not in `SAFE_GIT_SUBCOMMANDS`)
3. After 5+ occurrences across 3+ sessions, the SessionStart hook proposes learning it
4. `bisect` is added to `~/.config/bash-validator/learned-rules.json`
5. Future `git bisect` commands auto-approve

Learned rules are stored at `~/.config/bash-validator/learned-rules.json` and merged into the working sets at validator startup.

### Layer 3: Skill Adaptation

The SessionStart hook updates the bundled skill (`skills/validator-friendly-commands/SKILL.md`) with a dynamic section listing recently rejected patterns. This teaches subagents to avoid patterns that trigger prompts, for example suggesting `jq` instead of `python3 -c` for JSON formatting.

The dynamic section is injected between `<!-- DYNAMIC:START -->` and `<!-- DYNAMIC:END -->` markers and regenerated each session.

### Compound Commands

The validator splits pipelines (`|`), chains (`&&`, `||`), and sequences (`;`) into segments, then checks each segment independently. Every segment must pass for the command to auto-approve.

It also handles:
- **Heredocs**: `$(cat <<'DELIM'...DELIM)` patterns (safe string literals) are recognized and replaced with placeholders before analysis.
- **Subshells**: plain `(cmd1 && cmd2)` groups are recursively validated.
- **Redirections**: stripped before analysis; they do not affect safety.

Constructs the validator cannot statically analyze (command substitution, process substitution, raw heredocs) trigger a prompt.

### Escalation Policy

The validator distinguishes structural rejections from safety gates:

**Structural reasons** (heredoc, inline code, command substitution, process substitution) indicate the agent is using the wrong approach. The first rejection returns `ask` with actionable guidance in `additionalContext`. The third rejection for the same structural reason in the same session returns `deny`.

**Safety gates** (destructive commands, unknown commands) indicate the command is inherently risky. These always return `ask` and never escalate to `deny`, because the user should always have the final word on destructive operations.

## Writing Validator-Friendly Commands

The validator checks command *structure*, not *intent*: a safe operation expressed in an unverifiable form still triggers a prompt. Many commands that prompt are fundamentally safe; they just use a form the validator cannot verify. The fix belongs in the command, not the validator.

### Prefer `jq` or `--jq` over `python3 -c` for JSON formatting

This applies to formatting JSON output from CLI tools (`gh`, `curl`, `aws`, `kubectl`). Use `python3` when you genuinely need file I/O, multiple data sources, non-JSON processing, or logic that would be unreadable in jq.

```bash
# Triggers prompt (multiline python3 -c is hard to parse correctly)
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

**jq null-coalescing caveat:** jq prints the literal string `"null"` for missing or null fields; it does not error. Always use `// "default"` for fields that might be absent:

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
# Triggers prompt (os module is not in the safe list)
python3 -c "import os; print(os.listdir('.'))"

# Auto-approves
python3 scripts/format_output.py
```

### Quick Reference

| Triggers prompt | Auto-approves | Why |
|-----------------|---------------|-----|
| `gh ... \| python3 -c "import os; ..."` | `gh ... \| python3 -c "import json, sys; ..."` | AST verifies json+sys are safe |
| `gh ... \| python3 -c "import json..."` | `gh ... --jq '...'` | Uses `gh`'s built-in jq support |
| `cat <<'EOF' \| jq ...` | `echo '...' \| jq ...` | Heredocs trigger the `<<` rejection |
| `python3 -c "format_output()"` | `python3 format_output.py` | Script files are safe; `-c` is analyzed |
| `sed -i 's/old/new/' file` | Use the Edit tool | `sed -i` mutates files in place |

## Security Model

The adaptive system uses defense in depth: three trust layers with independent failure modes.

### Deterministic enforcement

The PreToolUse hook makes every decision using static analysis: AST parsing, regex matching, and set lookups. There is no LLM in the enforcement loop. Given the same command, the validator always produces the same result.

### Tokenized logging

Rejected commands are logged as tokenized fields (`cmd`, `subcmd`, `tokens[:6]`, `hash`), never as raw command strings. This prevents prompt injection via crafted command text from propagating into the learning system or skill guidance.

### Immutable deny list

The file `rules/immutable-deny.json` defines commands and patterns that can never be auto-approved by the learning system. This file is read-only and never modified by automation. Even if an attacker generates 1,000 `git push` rejections across 100 sessions, push will never be learned.

### Scoped learning

Auto-learning is limited to git and docker subcommands. The system cannot add new top-level commands to `SAFE_COMMANDS`. This bounds the blast radius of the learning system: even in the worst case, it can only approve additional subcommands of already-whitelisted tools.

### AST analysis boundaries

The Python AST analyzer is conservative: any import outside the allowlist, any dangerous builtin call, any dunder access, or any syntax error causes the command to prompt. The Node.js analyzer uses a deny-list of dangerous API patterns. Both default to prompting on anything they cannot verify as safe.

## Design Principles

### The validator checks form, not intent

The validator cannot inspect what arbitrary code does at runtime. It can only verify that the *structure* of a command matches a known-safe pattern. The AST analyzer extends this to inline code by verifying that the code's *imports and API calls* stay within safe boundaries, but it still checks structure, not behavior.

### Prevention over correction

The plugin addresses unnecessary prompts at two layers:

1. **Prevention (skill):** A bundled skill activates whenever a subagent generates a Bash command that formats JSON output. The skill teaches the subagent to choose verifiable forms (`jq`, `--jq`, script files) *before* the command is generated. The SubagentStart hook reinforces this by briefing subagents with session-specific warnings at spawn.

2. **Enforcement (hook):** The validator hook catches anything the skill missed. The AST analyzer (Layer 1) provides a second chance for inline code. The pattern learner (Layer 2) ensures recurring safe patterns eventually auto-approve. Escalation (Layer 3 feedback via `additionalContext`) teaches agents to correct structural mistakes within the session.

### Widen rules carefully

Widen the validator's rules only when a class of commands is provably safe. The adaptive layers follow this principle: AST analysis is deterministic and conservative, pattern learning is bounded by the immutable deny list, and skill adaptation only provides guidance (it never changes enforcement).

## Development

### Running Tests

```bash
pytest tests/ -v
```

Tests are organized across multiple files:

| File | Coverage |
|------|----------|
| `test_bash_validator.py` | Tier-based command classification |
| `test_inline_analyzer.py` | Python AST and Node.js regex analyzers |
| `test_pattern_learning.py` | Rejection logging, thresholds, deny enforcement, injection resistance |
| `test_integration.py` | End-to-end adaptive flow (rejection to learning to approval) |
| `test_escalation.py` | Escalation policy and deny threshold behavior |
| `test_guidance_map.py` | Guidance lookup, enrichment, structural reason detection |
| `test_session_state.py` | Shared state read/write, atomic operations |
| `test_post_tool_use.py` | Per-agent signal resolution |
| `test_pre_compact.py` | Compaction instruction preservation |
| `test_session_end.py` | Stats flushing, log rotation |
| `test_session_start_enhanced.py` | SessionStart hook with guidance map generation |
| `test_integration_adaptive.py` | Full session lifecycle integration |
| `test_prerelease.py` | Pre-release edge cases and security bypass attempts |

### Debug Log

The validator writes decisions to `/tmp/bash-validator-debug.log`:

```
[a1b2c3d4] allow: git status
[a1b2c3d4] ask: python3 -c "import os; ..."
```

All hooks log errors to this file before falling back to degraded behavior.

### Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| Rejection log | `~/.config/bash-validator/rejections.jsonl` | Tokenized log of prompted commands |
| Learned rules | `~/.config/bash-validator/learned-rules.json` | Auto-learned git/docker subcommands |
| Immutable deny | `rules/immutable-deny.json` (in plugin) | Commands that can never be auto-learned |
| Guidance map | `~/.config/bash-validator/guidance-map.json` | Rejection reason to guidance mapping |
| Session stats | `~/.config/bash-validator/session-stats.jsonl` | Aggregated per-session statistics |
| Session state | `/tmp/bash-validator-session-{sid}.json` | Shared state for the current session |

### Project Structure

```
hooks/
  bash-validator.py                        # PreToolUse hook (enforcement + AST analysis)
  post-tool-use.py                         # PostToolUse hook (outcome recording)
  session-start.py                         # SessionStart hook (learning + guidance map)
  session-end.py                           # SessionEnd hook (stats flush + log rotation)
  subagent-start.py                        # SubagentStart hook (subagent briefing)
  pre-compact.py                           # PreCompact hook (rule preservation)
  session_state.py                         # Shared per-session state module
  guidance_map.py                          # Rejection reason to guidance mapping
  hooks.json                               # Claude Code hook registration
skills/
  validator-friendly-commands/
    SKILL.md                               # Subagent guidance (prevention + dynamic section)
  validator-monitor/
    SKILL.md                               # Monitoring skill
rules/
  immutable-deny.json                      # Commands that can never be auto-learned
  learned-rules.json                       # Template for learned rules
scripts/
  monitor.py                              # Health check script
tests/
  test_bash_validator.py                   # Tier classification tests
  test_inline_analyzer.py                  # AST/regex analyzer tests
  test_pattern_learning.py                 # Learning system tests
  test_escalation.py                       # Escalation policy tests
  test_guidance_map.py                     # Guidance map tests
  test_session_state.py                    # Session state tests
  test_post_tool_use.py                    # PostToolUse hook tests
  test_pre_compact.py                      # PreCompact hook tests
  test_session_end.py                      # SessionEnd hook tests
  test_session_start_enhanced.py           # Enhanced SessionStart tests
  test_integration.py                      # End-to-end adaptive flow tests
  test_integration_adaptive.py             # Full session lifecycle tests
  test_prerelease.py                       # Pre-release edge case tests
.claude-plugin/
  plugin.json                              # Plugin manifest
  marketplace.json                         # Marketplace metadata
```
