# bash-validator

A Claude Code plugin that auto-approves safe Bash commands and prompts the user for everything else. It combines static analysis, inline code inspection, and pattern learning to minimize interruptions while preserving safety.

```
safe command   ->  auto-executes (no prompt)
unsafe command ->  asks the user first
```

No command is ever hard-denied. The user always decides.

## Quick Start

Install as a Claude Code plugin, or add the hooks directly to your settings:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "python3 path/to/bash-validator.py"
      }]
    }],
    "SessionStart": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "python3 path/to/session-start.py"
      }]
    }]
  }
}
```

The PreToolUse hook reads each command from stdin, classifies it, and returns `"allow"` or `"ask"`. The SessionStart hook runs once per session to analyze rejection patterns and update learned rules.

## How It Works

The validator classifies commands into three tiers:

| Tier | Decision | Examples |
|------|----------|---------|
| **1 -- Safe** | Auto-allow | `git status`, `ls -la`, `jq '.name' file.json` |
| **2 -- Flagged** | Ask user | `rm -rf /tmp/dir`, `sed -i 's/old/new/' file` |
| **3 -- Unknown** | Ask user | `ssh host`, `psql`, any command not in the whitelist |

On top of the tier system, three adaptive layers reduce unnecessary prompts over time:

| Layer | Mechanism | What it does |
|-------|-----------|--------------|
| **1 -- AST Analysis** | Inline code inspection | Auto-approves safe `python3 -c` and `node -e` data transforms |
| **2 -- Pattern Learning** | Rejection frequency counting | Auto-learns git/docker subcommands from repeated approvals |
| **3 -- Skill Adaptation** | Dynamic skill guidance | Teaches subagents to avoid rejected patterns |

### Tier 1: Safe Commands

A curated whitelist of ~80 commands covers dev tooling, file utilities, text processing, and CLI tools. See `SAFE_COMMANDS` in `bash-validator.py` for the full list.

Some whitelisted commands carry restrictions:

- **git** -- safe subcommands (`status`, `diff`, `log`, `add`, `commit`, ...) auto-approve. Dangerous flags on `branch`, `stash`, `tag`, `remote`, `config`, and `worktree` trigger a prompt.
- **docker** -- read-only subcommands (`ps`, `images`, `logs`, `inspect`, ...) auto-approve. `run`, `exec`, `rm`, and `stop` trigger a prompt.
- **find** -- auto-approves unless `-delete` is present or `-exec` targets a command outside the whitelist.
- **sed** -- read-only `sed` (pattern matching, substitution to stdout) auto-approves. `sed -i` and `sed --in-place` trigger a prompt because they mutate files.
- **Interpreters** (`python3`, `node`, `ruby`, `deno`, `bun`) -- auto-approve when running a script file. Inline execution flags (`-c`, `-e`, `--eval`) are routed to the AST analyzer (see Layer 1 below).

### Layer 1: Inline Code AST Analysis

Instead of rejecting all `python3 -c` and `node -e` commands outright, the validator inspects the inline code to determine if it is a safe data transformation.

**Python** -- uses `ast.parse()` to walk the syntax tree. Safe code must:
- Only import from a curated allowlist of ~46 modules (json, csv, sys, re, collections, itertools, math, datetime, typing, base64, hashlib, etc.)
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

**Node.js** -- uses regex pattern matching against a list of dangerous APIs (fs, child_process, net, http/https, eval, `new Function`, process.exit/kill, dynamic require/import).

```bash
# Auto-approves (pure data transform)
node -e "console.log(JSON.stringify({a: 1}, null, 2))"

# Prompts (filesystem access)
node -e "require('fs').readFileSync('/etc/passwd')"
```

**Ruby, Deno, Bun** -- no analyzer yet. Inline code always prompts.

### Layer 2: Pattern Learning

Commands the validator cannot auto-approve are logged to `~/.config/bash-validator/rejections.jsonl`. At the start of each session, the SessionStart hook analyzes the log for recurring patterns.

**Learning thresholds:**
- The pattern must appear 5 or more times
- Across 3 or more distinct sessions
- At most 3 new patterns are learned per session start

**Scope:** Only git subcommands and docker subcommands can be auto-learned. The system never adds commands to `SAFE_COMMANDS` -- that requires explicit code changes.

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

The SessionStart hook also updates the bundled skill (`skills/validator-friendly-commands/SKILL.md`) with a dynamic section listing recently rejected patterns. This teaches subagents to avoid patterns that trigger prompts -- for example, suggesting `jq` instead of `python3 -c` for JSON formatting.

The dynamic section is injected between `<!-- DYNAMIC:START -->` and `<!-- DYNAMIC:END -->` markers and is regenerated each session.

### Compound Commands

The validator splits pipelines (`|`), chains (`&&`, `||`), and sequences (`;`) into segments, then checks each segment independently. Every segment must pass for the command to auto-approve.

It also handles:
- **Heredocs** -- `$(cat <<'DELIM'...DELIM)` patterns (safe string literals) are recognized and replaced with placeholders before analysis.
- **Subshells** -- plain `(cmd1 && cmd2)` groups are recursively validated.
- **Redirections** -- stripped before analysis; they don't affect safety.

Constructs the validator cannot statically analyze -- command substitution (`` `...` `` or `$(...)`), process substitution (`<(...)`, `>(...)`), and raw heredocs (`<<`) -- trigger a prompt.

### Tier 3: Passthrough

Standalone commands outside the whitelist (`rm`, `ssh`, `kubectl`) pass through to Claude Code's built-in permission system. The user sees the full command and decides. Compound commands containing unknown commands are not passed through, because a broad permission rule like `Bash(cd *)` could accidentally auto-approve the entire chain.

## Security Model

The adaptive system is designed with defense in depth: three trust layers with independent failure modes.

### Deterministic enforcement

The PreToolUse hook makes every decision using static analysis -- AST parsing, regex matching, and set lookups. There is no LLM in the enforcement loop. Given the same command, the validator always produces the same result.

### Tokenized logging

Rejected commands are logged as tokenized fields (`cmd`, `subcmd`, `tokens[:6]`, `hash`), never as raw command strings. This prevents prompt injection via crafted command text from propagating into the learning system or skill guidance.

### Immutable deny list

The file `rules/immutable-deny.json` defines commands and patterns that can never be auto-approved by the learning system. This file is read-only and is never modified by automation. Even if an attacker generates 1,000 `git push` rejections across 100 sessions, push will never be learned.

### Scoped learning

Auto-learning is limited to git and docker subcommands. The system cannot add new top-level commands to `SAFE_COMMANDS`. This bounds the blast radius of the learning system: even in the worst case, it can only approve additional subcommands of already-whitelisted tools.

### AST analysis boundaries

The Python AST analyzer is conservative: any import outside the allowlist, any dangerous builtin call, any dunder access, or any syntax error causes the command to prompt. The Node.js analyzer uses a deny-list of dangerous API patterns. Both default to prompting on anything they cannot verify as safe.

## Design Principles

### The validator checks form, not intent

The validator cannot inspect what arbitrary code does at runtime. It can only verify that the *structure* of a command matches a known-safe pattern. The AST analyzer extends this to inline code by verifying that the code's *imports and API calls* stay within safe boundaries -- but it still checks structure, not behavior.

### Safe operations deserve safe expressions

Many commands that trigger a prompt are fundamentally safe -- they just use a form the validator cannot verify. The fix belongs in the command, not the validator:

| Triggers prompt | Auto-approves | Why |
|----------------|---------------|-----|
| `gh ... \| python3 -c "import os; ..."` | `gh ... \| python3 -c "import json, sys; ..."` | AST verifies json+sys are safe |
| `gh ... \| python3 -c "import json..."` | `gh ... --jq '...'` | Uses `gh`'s built-in jq support |
| `cat <<'EOF' \| jq ...` | `echo '...' \| jq ...` | Heredocs trigger the `<<` rejection |
| `python3 -c "format_output()"` | `python3 format_output.py` | Script files are safe; `-c` is analyzed |
| `sed -i 's/old/new/' file` | Use the Edit tool | `sed -i` mutates files in place |

### Prevention over correction

The plugin addresses unnecessary prompts at two layers:

1. **Prevention (skill):** A bundled skill activates whenever a subagent is about to generate a Bash command that formats JSON output. The skill teaches the subagent to choose verifiable forms (`jq`, `--jq`, script files) *before* the command is generated. The skill adapts over time via Layer 3, incorporating recently rejected patterns.

2. **Enforcement (hook):** The validator hook catches anything the skill missed. The AST analyzer (Layer 1) provides a second chance for inline code. The pattern learner (Layer 2) ensures recurring safe patterns eventually auto-approve.

### Widen rules carefully

Widen the validator's rules only when a class of commands is provably safe. The adaptive layers follow this principle: AST analysis is deterministic and conservative, pattern learning is bounded by the immutable deny list, and skill adaptation only provides guidance (it never changes enforcement).

## Development

### Running Tests

```bash
pytest tests/ -v
```

Tests are organized across four files:
- `test_bash_validator.py` -- tier-based command classification (Tier 1, 2, 3)
- `test_inline_analyzer.py` -- Python AST and Node.js regex analyzers, integration with `check_command()`
- `test_pattern_learning.py` -- rejection logging, pattern analysis thresholds, immutable deny enforcement, prompt injection resistance, skill adaptation
- `test_integration.py` -- end-to-end adaptive flow (rejection to learning to approval)

### Debug Log

The validator writes decisions to `/tmp/bash-validator-debug.log`:

```
[a1b2c3d4] allow: git status
[a1b2c3d4] ask: python3 -c "import os; ..."
```

### Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| Rejection log | `~/.config/bash-validator/rejections.jsonl` | Tokenized log of prompted commands |
| Learned rules | `~/.config/bash-validator/learned-rules.json` | Auto-learned git/docker subcommands |
| Immutable deny | `rules/immutable-deny.json` (in plugin) | Commands that can never be auto-learned |

### Project Structure

```
hooks/
  bash-validator.py                        # PreToolUse hook (enforcement + AST analysis)
  session-start.py                         # SessionStart hook (learning + skill adaptation)
  hooks.json                               # Claude Code hook registration
skills/
  validator-friendly-commands/
    SKILL.md                               # subagent guidance (prevention + dynamic section)
rules/
  immutable-deny.json                      # commands that can never be auto-learned
  learned-rules.json                       # template for learned rules
tests/
  test_bash_validator.py                   # tier classification tests
  test_inline_analyzer.py                  # AST/regex analyzer tests
  test_pattern_learning.py                 # learning system tests
  test_integration.py                      # end-to-end adaptive flow tests
.claude-plugin/
  plugin.json                              # plugin manifest
  marketplace.json                         # marketplace metadata
```
