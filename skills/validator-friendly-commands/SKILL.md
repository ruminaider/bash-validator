---
name: validator-friendly-commands
description: Use when generating Bash commands that format JSON output from CLI tools (gh, curl, aws, kubectl, etc.). Guides command construction so the bash-validator hook can auto-approve safe operations. Triggers when you would otherwise use python3 -c, node -e, ruby -e, or similar inline interpreters to format JSON in a pipe.
---

# Writing Validator-Friendly Bash Commands

A bash-validator hook runs on every Bash command in this environment. It auto-approves commands whose structure is statically verifiable and prompts the user for everything else. No command is ever hard-denied.

The validator checks command *form*, not *intent*. A safe operation expressed in an unverifiable form still triggers a prompt. Choose forms the validator can verify.

## Prefer `--jq` or `jq` over inline interpreters for JSON formatting

### Best: use the tool's built-in `--jq` flag (single command, no pipe)

```bash
# Auto-approves — single command
gh issue list --json number,title,state --jq '.[] | "#\(.number) [\(.state)] \(.title)"'
gh issue view 7 --json title,state,body --jq '"#\(.state) — \(.title)\n\n\(.body[0:2000])"'
gh pr list --json number,title,state --jq '.[] | "#\(.number) [\(.state)] \(.title)"'
```

### Good: pipe to `jq` (both commands are safe-listed)

```bash
# Auto-approves — jq is a pure JSON processor with no side effects
gh issue list --json number,title,state 2>/dev/null | jq -r '.[] | "#\(.number) [\(.state)] \(.title)"'
curl -s https://api.example.com/data | jq -r '.items[] | "\(.id): \(.name)"'
```

### Avoid: inline interpreter flags (always triggers a prompt)

```bash
# Triggers prompt — python3 -c is unverifiable (could do anything)
gh issue list --json number,title | python3 -c "
import sys, json
for i in json.load(sys.stdin):
    print(f'#{i[\"number\"]} {i[\"title\"]}')
"
```

This applies to all inline interpreter flags: `python3 -c`, `node -e`, `ruby -e`, `deno eval`, `bun eval`.

## jq null-coalescing caveat

jq prints the literal string `"null"` for missing or null fields without erroring. Always use `// "default"` for fields that might be absent:

```bash
# Bad: prints "null" if .author.login is missing
jq -r '.author.login'

# Good: prints "?" as fallback
jq -r '.author.login // "?"'
```

## Other patterns to avoid

| Triggers prompt | Auto-approves | Why |
|----------------|---------------|-----|
| `cat <<'EOF' \| jq ...` | `echo '...' \| jq ...` | Raw heredocs (`<<`) are rejected |
| `python3 -c "..."` | `python3 script.py` | Script files are safe; `-c` flags are not verifiable |
| `bash -c "cmd"` | `cmd` | Run the command directly |
| `$( subcommand )` | Split into separate Bash calls | Command substitution is rejected |

## Safe inline Python (auto-approves with AST analysis)

The validator parses `python3 -c` code via AST analysis. Inline code that only uses safe modules (json, sys, re, csv, collections, datetime, etc.) and avoids dangerous builtins auto-approves:

```bash
# Auto-approves — safe modules only, no open/exec/eval
gh api repos/owner/repo | python3 -c "import json, sys; print(json.dumps(json.load(sys.stdin), indent=2))"
```

Code that uses `open()`, `os`, `subprocess`, `exec`, `eval`, or other dangerous constructs still prompts.

## Common alternatives to dangerous inline Python

| Instead of | Use | Why |
|-----------|-----|-----|
| `python3 -c "open(f).read()..."` for syntax checking | `python3 -m py_compile file.py` | Module invocation, no `-c`, auto-approves |
| `python3 -c "import json; ..."` for JSON formatting | `jq` or `python3 -m json.tool` | Pure JSON tools, auto-approve |
| `for f in $(git ls-tree ...) ; do ... done` | `git grep -l 'pattern' branch -- '*.py'` | No command substitution, auto-approves |
| `python3 -c "import os; ..."` for file ops | `python3 script.py` | Script files auto-approve |

## When inline Python should prompt

Use `python3 -c` when you genuinely need:
- File I/O (reading/writing files during processing)
- Multiple data sources (combining JSON with non-JSON data)
- Non-JSON processing (parsing logs, text manipulation)
- Complex stateful logic that would be unreadable in jq

In these cases, the user prompt is appropriate — the validator cannot verify safety.

## jq capabilities reference

jq handles more than you might expect:
- String interpolation: `"\(.field)"`
- Truncation: `.body[0:2000]`
- Null coalescing: `.field // "default"`
- Conditional logic: `if .x then .y else .z end`
- Grouping: `group_by(.state) | map({state: .[0].state, count: length})`
- Enumeration: `to_entries[] | "\(.key + 1). \(.value)"`
- Column alignment: `(" " * ($width - (.field | tostring | length)))`
- Math: `map(.count) | add`

<!-- DYNAMIC:START -->

## Recently Rejected Patterns

The following patterns have been frequently rejected by the validator.
Use the suggested alternatives instead:

- Commands with unsafe segments were rejected 294 times. Check that all commands in the pipeline are in the safe list, inline code uses safe modules only, and no dangerous flags are present.
- Commands using `$(...)` or backticks were rejected 56 times. The validator cannot statically verify command substitution. Alternatives: decompose into separate commands, use `git grep` instead of `for file in $(git ls-tree ...) ; do ... done`, or use built-in flags like `--jq` or `--format` to avoid pipes.
- Inline Python code was rejected 29 times (reason: `syntax_error`). Write a script file instead of `python3 -c`.
- Commands using `<<` heredocs were rejected 20 times. Use `echo '...' | command` instead, or write content to a file first.
- Inline Python code was rejected 9 times (reason: `unsafe_module:mcp`). Write a script file instead of `python3 -c`.
- Commands using `<(...)` or `>(...)` were rejected 4 times. Use temporary files or pipes instead of process substitution.
- Inline Python code was rejected 4 times (reason: `unsafe_module:importlib`). Write a script file instead of `python3 -c`.
- Inline Python code was rejected 2 times (reason: `unsafe_module:starlette`). Write a script file instead of `python3 -c`.
- Inline Python code was rejected 1 times (reason: `unsafe_module:sanitized_db_mcp`). Write a script file instead of `python3 -c`.
- Inline Python code was rejected 1 times (reason: `unsafe_module:inspect`). Write a script file instead of `python3 -c`.

**Top rejected patterns:**

- `git push` was rejected 80 times - this subcommand requires user approval
- `git checkout` was rejected 59 times - this subcommand requires user approval
- `gh api` was rejected 30 times
- `node -e` was rejected 26 times - use `jq` for JSON processing or write a script file
- `python3 -c` was rejected 25 times - use `jq` for JSON processing or write a script file

<!-- DYNAMIC:END -->
