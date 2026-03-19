#!/usr/bin/env python3
"""Bash Validator Health Check — standalone monitoring script.

Runs 8 checks against the bash-validator plugin and reports a structured
health summary. Exit codes: 0 = all pass, 1 = warnings, 2 = failures.

Usage:
    python3 scripts/monitor.py
"""

import importlib.util
import json
import os
import re
import subprocess
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Plugin root detection (works regardless of cwd)
# ---------------------------------------------------------------------------

PLUGIN_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)

REQUIRED_FILES = [
    "hooks/hooks.json",
    "hooks/bash-validator.py",
    "hooks/session-start.py",
    "rules/immutable-deny.json",
    "skills/validator-friendly-commands/SKILL.md",
]

REJECTIONS_LOG = os.path.expanduser("~/.config/bash-validator/rejections.jsonl")
LEARNED_RULES = os.path.expanduser("~/.config/bash-validator/learned-rules.json")

# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


class CheckResult:
    def __init__(self, status, title, lines=None):
        self.status = status  # PASS / WARN / FAIL
        self.title = title
        self.lines = lines or []

    def print(self):
        print(f"\n[{self.status}] {self.title}")
        for line in self.lines:
            print(f"  {line}")


# ---------------------------------------------------------------------------
# Check 1: File Existence
# ---------------------------------------------------------------------------

def check_file_existence():
    missing = []
    for rel in REQUIRED_FILES:
        if not os.path.isfile(os.path.join(PLUGIN_ROOT, rel)):
            missing.append(rel)

    if missing:
        return CheckResult(FAIL, "File Existence",
                           [f"Missing: {f}" for f in missing])
    return CheckResult(PASS, "File Existence",
                       [f"All {len(REQUIRED_FILES)} required files present."])


# ---------------------------------------------------------------------------
# Check 2: Hook Registration
# ---------------------------------------------------------------------------

def check_hook_registration():
    path = os.path.join(PLUGIN_ROOT, "hooks", "hooks.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return CheckResult(FAIL, "Hook Registration",
                           [f"Cannot parse hooks.json: {e}"])

    hooks = data.get("hooks", {})
    lines = []

    # PreToolUse
    pre = hooks.get("PreToolUse", [])
    has_pre = any(
        "bash-validator.py" in h.get("command", "")
        for entry in pre
        for h in entry.get("hooks", [])
    )

    # SessionStart
    ss = hooks.get("SessionStart", [])
    has_ss = any(
        "session-start.py" in h.get("command", "")
        for entry in ss
        for h in entry.get("hooks", [])
    )

    if has_pre:
        lines.append("PreToolUse: bash-validator.py")
    else:
        lines.append("PreToolUse: MISSING bash-validator.py hook")

    if has_ss:
        lines.append("SessionStart: session-start.py")
    else:
        lines.append("SessionStart: MISSING session-start.py hook")

    if not has_pre:
        return CheckResult(FAIL, "Hook Registration", lines)
    if not has_ss:
        return CheckResult(WARN, "Hook Registration", lines)
    return CheckResult(PASS, "Hook Registration", lines)


# ---------------------------------------------------------------------------
# Check 3: Test Suite
# ---------------------------------------------------------------------------

def check_test_suite():
    tests_dir = os.path.join(PLUGIN_ROOT, "tests")

    # Try multiple ways to invoke pytest:
    # 1) sys.executable -m pytest  (works if pytest is in the running Python)
    # 2) "pytest" from PATH         (works if pytest is installed elsewhere)
    attempts = [
        [sys.executable, "-m", "pytest", tests_dir, "-q", "--tb=no"],
        ["pytest", tests_dir, "-q", "--tb=no"],
    ]

    result = None
    for argv in attempts:
        try:
            r = subprocess.run(
                argv,
                capture_output=True, text=True, cwd=PLUGIN_ROOT, timeout=120,
            )
            combined = r.stdout + r.stderr
            # Check if pytest actually ran (not "No module named pytest")
            if "No module named pytest" in combined:
                continue
            if "No module named" in combined and "pytest" in combined:
                continue
            result = r
            break
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return CheckResult(FAIL, "Test Suite", ["pytest timed out after 120s"])

    if result is None:
        return CheckResult(WARN, "Test Suite",
                           ["pytest not found — install with: pip install pytest"])

    # Parse the summary line, e.g. "916 passed" or "5 failed, 911 passed"
    output_text = result.stdout + result.stderr
    passed = 0
    failed = 0
    for line in output_text.splitlines():
        line = line.strip()
        # Look for the final summary line
        if "passed" in line or "failed" in line:
            p = re.search(r"(\d+)\s+passed", line)
            f = re.search(r"(\d+)\s+failed", line)
            if p:
                passed = int(p.group(1))
            if f:
                failed = int(f.group(1))

    if result.returncode != 0 or failed > 0:
        return CheckResult(FAIL, "Test Suite",
                           [f"{passed} passed, {failed} failed"])
    if passed == 0:
        return CheckResult(WARN, "Test Suite",
                           ["No tests detected (0 passed)"])
    return CheckResult(PASS, "Test Suite",
                       [f"{passed} passed, {failed} failed"])


# ---------------------------------------------------------------------------
# Check 4: Immutable Deny Crosscheck
# ---------------------------------------------------------------------------

def check_immutable_deny_crosscheck():
    # Import bash-validator module
    spec = importlib.util.spec_from_file_location(
        "bash_validator",
        os.path.join(PLUGIN_ROOT, "hooks", "bash-validator.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Load immutable deny list
    deny_path = os.path.join(PLUGIN_ROOT, "rules", "immutable-deny.json")
    with open(deny_path) as f:
        deny = json.load(f)

    never_cmds = set(deny.get("never_safe_commands", []))
    never_git = set(deny.get("never_safe_git_subcommands", []))

    violations = []

    # Known exception: docker is in SAFE_COMMANDS for subcommand routing
    # AND in immutable deny list to prevent auto-learning. Intentional.
    KNOWN_EXCEPTIONS = {"docker"}

    for cmd in never_cmds:
        if cmd in mod.SAFE_COMMANDS and cmd not in KNOWN_EXCEPTIONS:
            violations.append(f"SAFE_COMMANDS contains denied command: {cmd}")

    for sub in never_git:
        if sub in mod.SAFE_GIT_SUBCOMMANDS:
            violations.append(
                f"SAFE_GIT_SUBCOMMANDS contains denied subcommand: {sub}")

    if violations:
        return CheckResult(FAIL, "Immutable Deny Crosscheck", violations)

    exceptions_note = (
        f" ({', '.join(sorted(KNOWN_EXCEPTIONS))}: known exception)"
        if KNOWN_EXCEPTIONS else ""
    )
    return CheckResult(PASS, "Immutable Deny Crosscheck",
                       [f"No violations found.{exceptions_note}"])


# ---------------------------------------------------------------------------
# Check 5: Live Hook Validation
# ---------------------------------------------------------------------------

def check_live_hook_validation():
    spec = importlib.util.spec_from_file_location(
        "bash_validator_live",
        os.path.join(PLUGIN_ROOT, "hooks", "bash-validator.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    allow_cases = [
        ("ls -la", True),
        ("git status", True),
        ("git ls-tree HEAD", True),
        ('python3 -c "import json, sys; print(json.dumps(json.load(sys.stdin)))"', True),
        ('node -e "console.log(1)"', True),
        ("cat file | grep pattern || true", True),
    ]

    ask_cases = [
        ("rm -rf /", False),
        ('python3 -c "import os; os.system(\\"ls\\")"', False),
        ("node -e \"require('fs').readFileSync('x')\"", False),
        ("sed -i 's/foo/bar/' file.txt", False),
        ("git push origin main", False),
    ]

    mismatches = []
    allow_correct = 0
    ask_correct = 0

    for cmd, expected in allow_cases:
        actual = mod.check_command(cmd)
        if actual == expected:
            allow_correct += 1
        else:
            mismatches.append(
                f"ALLOW expected for: {cmd!r} but got {'allow' if actual else 'ask'}")

    for cmd, expected in ask_cases:
        actual = mod.check_command(cmd)
        if actual == expected:
            ask_correct += 1
        else:
            mismatches.append(
                f"ASK expected for: {cmd!r} but got {'allow' if actual else 'ask'}")

    if mismatches:
        return CheckResult(FAIL, "Live Hook Validation",
                           [f"{allow_correct}/{len(allow_cases)} allow cases correct, "
                            f"{ask_correct}/{len(ask_cases)} ask cases correct"]
                           + mismatches)

    return CheckResult(PASS, "Live Hook Validation",
                       [f"{allow_correct}/{len(allow_cases)} allow cases correct, "
                        f"{ask_correct}/{len(ask_cases)} ask cases correct"])


# ---------------------------------------------------------------------------
# Check 6: Rejection Log Analysis
# ---------------------------------------------------------------------------

def check_rejection_log():
    if not os.path.isfile(REJECTIONS_LOG):
        return CheckResult(PASS, "Rejection Log Analysis",
                           ["No rejection log yet."])

    entries = []
    malformed = 0
    with open(REJECTIONS_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1

    if not entries and malformed == 0:
        return CheckResult(PASS, "Rejection Log Analysis",
                           ["Rejection log is empty."])

    lines = []

    # Count patterns and sessions
    pattern_counts = Counter()
    pattern_sessions = {}
    timestamps = []

    for entry in entries:
        cmd = entry.get("cmd", "")
        subcmd = entry.get("subcmd")
        sid = entry.get("sid", "?")
        ts = entry.get("ts", "")
        key = (cmd, subcmd)

        pattern_counts[key] += 1
        pattern_sessions.setdefault(key, set()).add(sid)
        if ts:
            timestamps.append(ts)

    unique_patterns = len(pattern_counts)

    # Date range
    if timestamps:
        timestamps.sort()
        oldest = timestamps[0][:10]
        newest = timestamps[-1][:10]
        period = f"{oldest} to {newest}"
    else:
        period = "unknown"

    lines.append(
        f"Entries: {len(entries)} | Patterns: {unique_patterns} | "
        f"Period: {period}"
    )

    # Top 10 patterns
    top = pattern_counts.most_common(10)
    if top:
        lines.append("Top patterns:")
        for (cmd, subcmd), count in top:
            sessions = len(pattern_sessions.get((cmd, subcmd), set()))
            label = f"{cmd} {subcmd}" if subcmd else f"{cmd} (no subcmd)"
            lines.append(f"  {label}: {count}x across {sessions} sessions")

    # Learning candidates (approaching thresholds: count >= 3, sessions >= 2
    # but not yet at 5 occurrences / 3 sessions)
    candidates = []
    for (cmd, subcmd), count in pattern_counts.most_common():
        sessions = len(pattern_sessions.get((cmd, subcmd), set()))
        if count >= 3 and sessions >= 2 and (count < 5 or sessions < 3):
            label = f"{cmd} {subcmd}" if subcmd else f"{cmd} (no subcmd)"
            candidates.append(
                f"  {label}: {count}/5 occurrences, {sessions}/3 sessions")

    if candidates:
        lines.append("Learning candidates (approaching thresholds):")
        lines.extend(candidates)

    # Log size
    log_size_bytes = os.path.getsize(REJECTIONS_LOG)
    log_size_kb = log_size_bytes / 1024
    lines.append(f"Log size: {log_size_kb:.1f} KB")

    status = PASS
    if log_size_bytes > 1_048_576:  # > 1 MB
        lines.append("WARNING: Log exceeds 1 MB — consider rotation.")
        status = WARN
    if malformed > 0:
        lines.append(f"WARNING: {malformed} malformed JSON entries found.")
        status = WARN

    return CheckResult(status, "Rejection Log Analysis", lines)


# ---------------------------------------------------------------------------
# Check 7: Learned Rules Audit
# ---------------------------------------------------------------------------

def check_learned_rules():
    if not os.path.isfile(LEARNED_RULES):
        return CheckResult(PASS, "Learned Rules Audit",
                           ["No learned rules yet."])

    try:
        with open(LEARNED_RULES) as f:
            learned = json.load(f)
    except json.JSONDecodeError as e:
        return CheckResult(FAIL, "Learned Rules Audit",
                           [f"Cannot parse learned-rules.json: {e}"])

    lines = []

    git_subs = learned.get("git_subcommands", [])
    docker_subs = learned.get("docker_subcommands", [])
    updated = learned.get("_updated", "unknown")

    if git_subs:
        lines.append(f"Learned git subcommands: {', '.join(git_subs)}")
    if docker_subs:
        lines.append(f"Learned docker subcommands: {', '.join(docker_subs)}")
    if not git_subs and not docker_subs:
        lines.append("No learned subcommands.")

    lines.append(f"Last updated: {updated}")

    # Cross-check against immutable deny
    deny_path = os.path.join(PLUGIN_ROOT, "rules", "immutable-deny.json")
    try:
        with open(deny_path) as f:
            deny = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        lines.append("WARNING: Could not load immutable-deny.json for crosscheck.")
        return CheckResult(WARN, "Learned Rules Audit", lines)

    never_git = set(deny.get("never_safe_git_subcommands", []))
    violations = []

    for sub in git_subs:
        if sub in never_git:
            violations.append(
                f"Learned git subcommand '{sub}' is in the immutable deny list!")

    # docker subcommands are not in the immutable deny list at the subcommand
    # level, but check never_safe_commands for the base command
    # (docker is a known exception — it's in SAFE_COMMANDS for routing)

    if violations:
        lines.extend(violations)
        return CheckResult(FAIL, "Learned Rules Audit", lines)

    return CheckResult(PASS, "Learned Rules Audit", lines)


# ---------------------------------------------------------------------------
# Check 8: Skill Dynamic Section
# ---------------------------------------------------------------------------

def check_skill_dynamic_section():
    skill_path = os.path.join(
        PLUGIN_ROOT, "skills", "validator-friendly-commands", "SKILL.md"
    )

    try:
        with open(skill_path) as f:
            content = f.read()
    except FileNotFoundError:
        return CheckResult(FAIL, "Skill Dynamic Section",
                           ["SKILL.md not found."])

    has_start = "<!-- DYNAMIC:START -->" in content
    has_end = "<!-- DYNAMIC:END -->" in content

    if not has_start or not has_end:
        missing = []
        if not has_start:
            missing.append("<!-- DYNAMIC:START -->")
        if not has_end:
            missing.append("<!-- DYNAMIC:END -->")
        return CheckResult(WARN, "Skill Dynamic Section",
                           [f"Missing markers: {', '.join(missing)}"])

    # Check if there's content between markers
    start_idx = content.index("<!-- DYNAMIC:START -->") + len("<!-- DYNAMIC:START -->")
    end_idx = content.index("<!-- DYNAMIC:END -->")
    between = content[start_idx:end_idx].strip()

    if between:
        return CheckResult(PASS, "Skill Dynamic Section",
                           ["Markers present. Section has content."])
    else:
        return CheckResult(PASS, "Skill Dynamic Section",
                           ["Markers present. Section is empty."])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== Bash Validator Health Check ===")

    checks = [
        check_file_existence,
        check_hook_registration,
        check_test_suite,
        check_immutable_deny_crosscheck,
        check_live_hook_validation,
        check_rejection_log,
        check_learned_rules,
        check_skill_dynamic_section,
    ]

    results = []
    for check_fn in checks:
        try:
            result = check_fn()
        except Exception as e:
            result = CheckResult(FAIL, check_fn.__name__,
                                 [f"Unexpected error: {e}"])
        results.append(result)
        result.print()

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r.status == PASS)
    warned = sum(1 for r in results if r.status == WARN)
    failed = sum(1 for r in results if r.status == FAIL)

    print()
    if failed > 0:
        verdict = "UNHEALTHY"
        exit_code = 2
    elif warned > 0:
        verdict = "DEGRADED"
        exit_code = 1
    else:
        verdict = "HEALTHY"
        exit_code = 0

    parts = []
    if passed:
        parts.append(f"{passed} passed")
    if warned:
        parts.append(f"{warned} warnings")
    if failed:
        parts.append(f"{failed} failures")

    print(f"=== Verdict: {verdict} ({', '.join(parts)}) ===")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
