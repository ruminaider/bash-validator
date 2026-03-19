---
name: validator-monitor
description: Use when monitoring the bash-validator's health, checking for issues with the adaptive learning system, auditing learned rules, analyzing rejection patterns, or troubleshooting hook behavior. Triggers on "monitor validator", "check validator health", "validator status", "audit learned rules", "rejection log analysis".
---

# Validator Health Monitor

Run the automated health check, then act on the results.

## Step 1: Run the health check

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/monitor.py
```

Parse the output. Each line is a check result in the format `PASS:`, `WARN:`, or `FAIL:` followed by a description.

## Step 2: All checks PASS

If every check returned PASS, present a concise summary and stop:

> Validator healthy. N tests passing. [rejection log stats if available]. [learned rules count if any].

Then:
- If a rejection log exists at `~/.config/bash-validator/rejections.jsonl`, highlight the top 3 most-rejected command patterns and note any learning candidates approaching thresholds.
- Ask the user if they want to dive deeper into any area.

Do not elaborate beyond this unless asked.

## Step 3: Any WARN results

List each warning with context, then provide the specific remediation:

**"Rejection log > 1MB"** — The log has grown large. Suggest rotating it:
```bash
echo "" > ~/.config/bash-validator/rejections.jsonl
```

**"SessionStart hook missing"** — The session-start hook is not registered. Read `hooks.json` in the plugin root and verify the SessionStart entry exists and points to the correct script.

**"Skill markers missing"** — The `<!-- DYNAMIC:START -->` / `<!-- DYNAMIC:END -->` markers in a SKILL.md file are missing or malformed. Check whether the file was modified outside the plugin system.

## Step 4: Any FAIL results

Failures require investigation. For each failure type:

**"File missing: <path>"** — A required plugin file does not exist. Check that the plugin is installed correctly:
```bash
ls -la ${CLAUDE_PLUGIN_ROOT}/hooks/bash-validator.py
ls -la ${CLAUDE_PLUGIN_ROOT}/rules/immutable-deny.json
```
Verify the `.claude-plugin/` manifest references the correct paths.

**"Immutable deny violation"** or **"Learned rule in deny list"** — CRITICAL. A learned rule has bypassed the immutable deny list. This must be fixed immediately:
1. Read `~/.config/bash-validator/learned-rules.json`
2. Read `${CLAUDE_PLUGIN_ROOT}/rules/immutable-deny.json`
3. Identify which learned entry appears in `never_safe_commands`, `never_safe_git_subcommands`, or violates `never_relaxable_deny_patterns`
4. Remove the violating entry from `learned-rules.json`
5. Investigate how it got there — check the session-start hook logic and the rejection log for the pattern that triggered learning

**"Live hook mismatch"** — A command is producing an unexpected allow/ask decision. Debug the logic path:
1. Read `${CLAUDE_PLUGIN_ROOT}/hooks/bash-validator.py`
2. Identify which function handles the command: `check_command()` -> `check_segment()`
3. Trace the specific token through the whitelist, deny patterns, and learned rules
4. Check if a learned rule or a recent code change altered the expected behavior

**"Test failure"** — One or more unit tests are failing. Run the full suite with output:
```bash
pytest ${CLAUDE_PLUGIN_ROOT}/tests/ -v --tb=short
```
Read the failure output, identify the broken assertion, and trace the cause in `bash-validator.py`.

## Step 5: Ongoing monitoring guidance

After resolving any issues, advise the user:
- Run this health check after each significant change to the validator or learned rules.
- Review the rejection log weekly to identify false positives — commands that are repeatedly rejected but appear safe may be candidates for adding to the validator's whitelist.
- If a pattern is repeatedly rejected and is genuinely safe, consider adding it to the appropriate tier in the validator rather than relying on user approval each time.
