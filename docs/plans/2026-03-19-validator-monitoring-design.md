# Validator Monitoring System Design

## Goal

A monitoring script (`scripts/monitor.py`) and a monitoring skill (`/validator-monitor`) that together validate the adaptive bash-validator's health — file integrity, hook registration, live decisions, rejection log trends, and learned rules safety.

## Components

### scripts/monitor.py

Standalone Python script. Exit codes: 0 = healthy, 1 = warnings, 2 = failures.

**Checks:**
1. File existence — hooks.json, bash-validator.py, session-start.py, immutable-deny.json, SKILL.md
2. Hook registration — parse hooks.json, verify PreToolUse and SessionStart present
3. Test suite — run pytest, report pass/fail
4. Immutable deny crosscheck — no immutable-deny entry in SAFE_COMMANDS or SAFE_GIT_SUBCOMMANDS (including learned)
5. Live hook validation — pipe test commands as JSON stdin to bash-validator.py, verify allow/ask
6. Rejection log analysis — total entries, unique patterns, top 10, candidates near thresholds, growth rate
7. Learned rules audit — what's learned, cross-check against immutable deny
8. Skill dynamic section — check SKILL.md markers, report if populated

**Output:** Sections with PASS/WARN/FAIL, human-readable summary, final verdict.

### skills/validator-monitor/SKILL.md

Hybrid skill:
1. Runs monitor.py
2. If all PASS → summary report
3. If any WARN/FAIL → interactive walkthrough of each issue
