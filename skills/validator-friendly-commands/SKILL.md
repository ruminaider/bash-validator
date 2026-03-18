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

## When inline Python is the right tool

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
