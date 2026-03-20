#!/usr/bin/env python3
"""SessionStart hook: analyzes rejection log and auto-updates learned rules.

Runs at the beginning of each Claude Code session. Reads the rejection log,
identifies recurring patterns, and updates learned-rules.json within the
bounds of the immutable deny list.

Returns additionalContext with a summary of any newly learned patterns.
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT", os.path.dirname(os.path.dirname(__file__)))
REJECTIONS_LOG = os.path.expanduser("~/.config/bash-validator/rejections.jsonl")
LEARNED_RULES = os.path.expanduser("~/.config/bash-validator/learned-rules.json")
IMMUTABLE_DENY = os.path.join(PLUGIN_ROOT, "rules", "immutable-deny.json")
SKILL_PATH = os.path.join(
    PLUGIN_ROOT, "skills", "validator-friendly-commands", "SKILL.md"
)
DYNAMIC_START = "<!-- DYNAMIC:START -->"
DYNAMIC_END = "<!-- DYNAMIC:END -->"

# Thresholds for auto-learning
MIN_OCCURRENCES = 5       # Pattern must appear at least this many times
MIN_SESSIONS = 3          # Across at least this many distinct sessions
MAX_LEARN_PER_CYCLE = 3   # Learn at most this many new patterns per session start


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_rejections():
    """Load rejection log entries."""
    entries = []
    try:
        with open(REJECTIONS_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        pass
    return entries


def analyze_patterns(entries, immutable, learned):
    """Find patterns eligible for auto-learning."""
    never_commands = set(immutable.get("never_safe_commands", []))
    never_git = set(immutable.get("never_safe_git_subcommands", []))

    already_learned_cmds = set(learned.get("safe_commands", []))
    already_learned_git = set(learned.get("git_subcommands", []))
    already_learned_docker = set(learned.get("docker_subcommands", []))

    # Count (cmd, subcmd) tuples and track unique sessions
    pattern_counts = Counter()
    pattern_sessions = {}

    for entry in entries:
        cmd = entry.get("cmd", "")
        subcmd = entry.get("subcmd")
        sid = entry.get("sid", "?")
        key = (cmd, subcmd)

        pattern_counts[key] += 1
        if key not in pattern_sessions:
            pattern_sessions[key] = set()
        pattern_sessions[key].add(sid)

    proposals = []
    for (cmd, subcmd), count in pattern_counts.most_common():
        if len(proposals) >= MAX_LEARN_PER_CYCLE:
            break

        sessions = len(pattern_sessions.get((cmd, subcmd), set()))
        if count < MIN_OCCURRENCES or sessions < MIN_SESSIONS:
            continue

        # Determine what category this would go into
        if cmd == "git" and subcmd:
            if subcmd in never_git:
                continue
            if subcmd in already_learned_git:
                continue
            proposals.append({"type": "git_subcommands", "value": subcmd,
                              "count": count, "sessions": sessions})

        elif cmd == "docker" and subcmd:
            if subcmd in already_learned_docker:
                continue
            proposals.append({"type": "docker_subcommands", "value": subcmd,
                              "count": count, "sessions": sessions})

        # NOTE: We do NOT auto-add to safe_commands. That requires
        # the user to explicitly approve via a review command.

    return proposals


def apply_proposals(learned, proposals):
    """Apply approved proposals to learned rules."""
    changed = False
    for p in proposals:
        category = p["type"]
        value = p["value"]
        if value not in learned.get(category, []):
            learned.setdefault(category, []).append(value)
            changed = True

    if changed:
        learned["_updated"] = datetime.now(timezone.utc).isoformat()
        os.makedirs(os.path.dirname(LEARNED_RULES), exist_ok=True)
        with open(LEARNED_RULES, "w") as f:
            json.dump(learned, f, indent=2)

    return changed


def get_top_rejection_patterns(entries, limit=5):
    """Get the most frequently rejected command patterns."""
    pattern_counts = Counter()
    for entry in entries:
        cmd = entry.get("cmd", "")
        subcmd = entry.get("subcmd", "")
        key = f"{cmd} {subcmd}".strip() if subcmd else cmd
        pattern_counts[key] += 1
    return pattern_counts.most_common(limit)


def get_rejection_reasons(entries):
    """Count rejection reasons across all entries."""
    reason_counts = Counter()
    for entry in entries:
        reason = entry.get("reason")
        if reason:
            reason_counts[reason] += 1
    return reason_counts.most_common()


# Actionable guidance for each rejection reason.
# Reasons starting with "inline_python:" are grouped by prefix.
REASON_GUIDANCE = {
    "command_substitution": (
        "Commands using `$(...)` or backticks were rejected {count} times. "
        "The validator cannot statically verify command substitution. "
        "Alternatives: decompose into separate commands, use `git grep` "
        "instead of `for file in $(git ls-tree ...) ; do ... done`, "
        "or use built-in flags like `--jq` or `--format` to avoid pipes."
    ),
    "process_substitution": (
        "Commands using `<(...)` or `>(...)` were rejected {count} times. "
        "Use temporary files or pipes instead of process substitution."
    ),
    "heredoc": (
        "Commands using `<<` heredocs were rejected {count} times. "
        "Use `echo '...' | command` instead, or write content to a file first."
    ),
    "unsafe_segment": (
        "Commands with unsafe segments were rejected {count} times. "
        "Check that all commands in the pipeline are in the safe list, "
        "inline code uses safe modules only, and no dangerous flags are present."
    ),
}

# Guidance for inline_python:* detail reasons
INLINE_PYTHON_GUIDANCE = {
    "dangerous_builtin:open": (
        "Inline Python using `open()` was rejected {count} times. "
        "`open()` can read/write arbitrary files. Alternatives: "
        "use `python3 -m py_compile` for syntax checking, "
        "`python3 -m json.tool` for JSON formatting, "
        "or write a script file instead of `-c`."
    ),
    "dangerous_builtin:exec": (
        "Inline Python using `exec()` was rejected {count} times. "
        "`exec()` runs arbitrary code. Write a script file instead."
    ),
    "dangerous_builtin:eval": (
        "Inline Python using `eval()` was rejected {count} times. "
        "`eval()` evaluates arbitrary expressions. Write a script file instead."
    ),
    "unsafe_module:os": (
        "Inline Python importing `os` was rejected {count} times. "
        "The `os` module provides filesystem and process access. "
        "For path operations, use `python3 -c` with only safe modules "
        "(json, sys, re, collections). For file operations, write a script file."
    ),
    "unsafe_module:subprocess": (
        "Inline Python importing `subprocess` was rejected {count} times. "
        "Run commands directly in bash instead of via Python subprocess."
    ),
    "unsafe_module:shutil": (
        "Inline Python importing `shutil` was rejected {count} times. "
        "Use shell commands (`cp`, `mv`, `rm`) directly instead."
    ),
}


def _get_reason_guidance(reason, count):
    """Get guidance for a rejection reason, including inline_python details."""
    # Exact match first
    if reason in REASON_GUIDANCE:
        return REASON_GUIDANCE[reason].format(count=count)

    # inline_python:detail — check detail-specific guidance
    if reason.startswith("inline_python:"):
        detail = reason[len("inline_python:"):]
        if detail in INLINE_PYTHON_GUIDANCE:
            return INLINE_PYTHON_GUIDANCE[detail].format(count=count)
        # Generic inline python guidance for unknown details
        return (
            f"Inline Python code was rejected {count} times "
            f"(reason: `{detail}`). Write a script file instead of `python3 -c`."
        )

    return None


def update_skill_guidance(entries):
    """Update the SKILL.md dynamic section with rejection-based guidance."""
    if not entries:
        return

    top_patterns = get_top_rejection_patterns(entries)
    reason_counts = get_rejection_reasons(entries)
    if not top_patterns and not reason_counts:
        return

    lines = [
        DYNAMIC_START,
        "",
        "## Recently Rejected Patterns",
        "",
        "The following patterns have been frequently rejected by the validator.",
        "Use the suggested alternatives instead:",
        "",
    ]

    # Reason-based guidance (most actionable)
    if reason_counts:
        for reason, count in reason_counts:
            guidance = _get_reason_guidance(reason, count)
            if guidance:
                lines.append(f"- {guidance}")

        lines.append("")

    # Pattern-based guidance
    if top_patterns:
        lines.append("**Top rejected patterns:**")
        lines.append("")

    for pattern, count in top_patterns:
        parts = pattern.split()
        cmd = parts[0] if parts else ""

        if cmd in ("python3", "python") and len(parts) == 1:
            lines.append(f"- `{cmd} -c` was rejected {count} times - "
                        "use `jq` for JSON processing or write a script file")
        elif cmd == "node" and len(parts) == 1:
            lines.append(f"- `{cmd} -e` was rejected {count} times - "
                        "use `jq` for JSON processing or write a script file")
        elif cmd == "git" and len(parts) > 1:
            subcmd = parts[1]
            lines.append(f"- `git {subcmd}` was rejected {count} times - "
                        "this subcommand requires user approval")
        else:
            lines.append(f"- `{pattern}` was rejected {count} times")

    lines.extend(["", DYNAMIC_END])
    new_section = "\n".join(lines)

    try:
        with open(SKILL_PATH) as f:
            content = f.read()

        if DYNAMIC_START in content and DYNAMIC_END in content:
            start = content.index(DYNAMIC_START)
            end = content.index(DYNAMIC_END) + len(DYNAMIC_END)
            content = content[:start] + new_section + content[end:]
        else:
            content = content.rstrip() + "\n\n" + new_section + "\n"

        with open(SKILL_PATH, "w") as f:
            f.write(content)
    except (FileNotFoundError, IOError):
        pass


def main():
    try:
        raw = sys.stdin.read()
        # SessionStart may or may not pass hook_input
    except Exception:
        pass

    immutable = load_json(IMMUTABLE_DENY, {})
    learned = load_json(LEARNED_RULES, {
        "safe_commands": [], "git_subcommands": [],
        "docker_subcommands": [],
    })

    entries = load_rejections()
    if not entries:
        print(json.dumps({}))
        sys.exit(0)

    # Layer 3: Update skill guidance based on rejection patterns
    try:
        update_skill_guidance(entries)
    except Exception:
        pass

    proposals = analyze_patterns(entries, immutable, learned)
    if not proposals:
        print(json.dumps({}))
        sys.exit(0)

    changed = apply_proposals(learned, proposals)

    if changed:
        summary_lines = ["Bash validator learned new patterns:"]
        for p in proposals:
            summary_lines.append(
                f"  - {p['type']}: {p['value']} "
                f"(seen {p['count']}x across {p['sessions']} sessions)"
            )

        context = "\n".join(summary_lines)
        result = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": context,
            }
        }
        print(json.dumps(result))
    else:
        print(json.dumps({}))

    sys.exit(0)


if __name__ == "__main__":
    main()
