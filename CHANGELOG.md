# Changelog

All notable changes to bash-validator are documented here.

## [2.3.0] - 2026-03-20

### Added

- **AST-specific rejection details** — `is_safe_inline_python` now returns exactly what was flagged (e.g., `dangerous_builtin:open`, `unsafe_module:os`, `dunder_name:__builtins__`). These details flow through the rejection log and into Layer 3 skill guidance.
- **Inline Python guidance in skill** — the `validator-friendly-commands` skill now teaches alternatives: `python3 -m py_compile` for syntax checking, `python3 -m json.tool` for JSON formatting, `git grep` instead of `for..$(...)..done` loops.
- **Detail-specific skill guidance** — Layer 3 generates targeted advice like "Inline Python using `open()` was rejected N times — use `python3 -m py_compile` for syntax checking" instead of generic "unsafe segment" messages.

## [2.2.0] - 2026-03-20

### Added

- **Rejection reason tracking** — `check_command_with_reason()` returns why a command was rejected (command_substitution, process_substitution, heredoc, unsafe_segment). Reasons are stored in the rejection log and used by Layer 3 to generate actionable skill guidance.
- Reason-based skill guidance: instead of just "for file was rejected 5 times", the skill now teaches "Commands using `$(...)` were rejected — use `git grep` instead of `for file in $(git ls-tree ...)`".

## [2.1.0] - 2026-03-20

### Fixed

- Bash comment lines (`# ...`) now auto-approve instead of triggering a prompt. Previously, `#` was tokenized as a command name not in the safe list, causing multi-line commands with comments to fail.

### Added

- `sed -i` / `--in-place` protection (moved from 2.0.0 release notes — was part of that release but worth highlighting).
- Monitoring system: `scripts/monitor.py` health check script and `/validator-monitor` skill.
- SECURITY.md with vulnerability reporting process and threat model.
- CHANGELOG.md, GitHub topics, updated repo description.

## [2.0.0] - 2026-03-19

### Added

- **Inline code AST analysis** — `python3 -c` and `node -e` commands are now analyzed for safety instead of blanket-denied. Safe data transforms (JSON processing, text manipulation) auto-approve. Dangerous operations (file I/O, network, subprocess) still prompt.
  - Python: `ast.parse()` with a 46-module safe allowlist
  - Node.js: regex pattern matching for 25 dangerous APIs
- **Pattern learning** — rejected commands are logged and analyzed at session start. Patterns appearing 5+ times across 3+ sessions are auto-learned for git and docker subcommands.
- **Immutable deny list** — `rules/immutable-deny.json` defines commands that can never be auto-approved by the learning system, regardless of frequency.
- **Skill adaptation** — the `validator-friendly-commands` skill updates dynamically based on recently rejected patterns, guiding subagents toward validator-friendly alternatives.
- **SessionStart hook** — analyzes rejection log and applies learned rules at the beginning of each session.
- **Monitoring system** — `scripts/monitor.py` runs 8 health checks; `/validator-monitor` skill for interactive monitoring.
- **sed -i protection** — `sed -i` and `--in-place` now prompt the user (prevents file mutation including self-modification of the validator).
- **Read-only git subcommands** — `ls-tree`, `cat-file`, `describe`, `shortlog`, `rev-list`, `merge-base`, `name-rev`, `cherry`, `diff-tree`, `for-each-ref`, `show-ref`, `verify-commit`, `verify-tag`, `count-objects` added to safe list.
- **Shell builtins** — `true` and `false` added to safe commands (`|| true` patterns no longer prompt).
- **Pre-release test suite** — 916 tests covering edge cases, real-world commands, and security bypass attempts.
- **ADR-001** — architecture decision record documenting the trust-layered design.

### Security

- AST analysis is deterministic and injection-proof (no LLM in the enforcement loop).
- Rejection log uses tokenized data only — raw command strings are never stored.
- `__builtins__` subscript access bypass closed (dunder check on `ast.Name` nodes).
- `require("fs/promises")` and `require("os")` Node.js bypasses closed.
- `sed -i` self-modification vector closed.

## [1.1.0] - 2026-03-18

### Added

- `validator-friendly-commands` skill for guiding subagents toward safe command patterns.
- README and CLAUDE.md documentation.

## [1.0.0] - 2026-03-17

### Added

- Initial release. PreToolUse hook with allow/ask permission model.
- Three-tier command classification: safe (auto-approve), flagged (prompt), passthrough (delegate to Claude Code).
- Safe command whitelist, git subcommand handling, docker subcommand handling.
- Heredoc stripping, subshell validation, operator splitting.
