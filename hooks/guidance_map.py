"""Guidance map for bash-validator rejection reasons.

Maps rejection reasons to actionable guidance strings that are sent to agents
via additionalContext. Structural reasons (agent using the wrong approach)
get guidance; safety gates (destructive commands) map to None.
"""

import json
import os
from collections import Counter

GUIDANCE_MAP_PATH = os.path.expanduser("~/.config/bash-validator/guidance-map.json")
STATS_LOG = os.path.expanduser("~/.config/bash-validator/session-stats.jsonl")

# Thresholds for enriching guidance map from cross-session stats
ENRICH_MIN_REJECTIONS = 5   # Total rejections across all sessions
ENRICH_MIN_SESSIONS = 3     # Minimum distinct sessions

# Escalation deny threshold: reject with "deny" after this many prior rejections
DENY_THRESHOLD = 3

# Static base mapping. Safety gates have None values.
STATIC_GUIDANCE = {
    "command_substitution": (
        "The bash validator rejected this because it contains $(...) or backticks. "
        "Decompose into separate Bash tool calls, or use --jq / --format flags."
    ),
    "process_substitution": (
        "The bash validator rejected <(...) or >(...) process substitution. "
        "Use temporary files or pipes instead."
    ),
    "heredoc": (
        "The bash validator rejected << heredoc syntax. "
        "Use the Write tool to create files, or echo '...' | command for inline data."
    ),
    "inline_exec": (
        "Inline code execution was rejected. "
        "Write a script file with the Write tool and execute it, "
        "or limit inline code to safe modules only."
    ),
    "inline_python:unsafe_module:os": (
        "The os module is not in the safe list for inline Python. "
        "Use safe modules (json, re, sys, collections, etc.) or write a script file."
    ),
    "inline_python:unsafe_module:subprocess": (
        "The subprocess module is blocked. Use separate Bash tool calls instead."
    ),
    "inline_python:unsafe_module:importlib": (
        "The importlib module is blocked. Use explicit imports of safe modules."
    ),
    "inline_python:dangerous_builtin:open": (
        "open() is blocked in inline Python. "
        "Use the Read tool to read files, or write a script file for file operations."
    ),
    "inline_python:dangerous_builtin:exec": (
        "exec() is blocked. Write a script file instead of inline execution."
    ),
    "inline_python:dangerous_builtin:eval": (
        "eval() is blocked. Write a script file instead of inline evaluation."
    ),
    "inline_python:syntax_error": (
        "Inline Python had a syntax error and could not be analyzed. "
        "Write a script file instead of using python3 -c."
    ),
    # Safety gates: no guidance, no escalation
    "unsafe_segment": None,
    "recursion_limit": None,
    "empty_command": None,
}

# Shared proactive briefing rules (used by PreToolUse and SubagentStart)
PROACTIVE_RULES = [
    "Use Write tool (not cat >) to create files",
    "Use Read tool (not cat) to read files",
    "Use Grep tool (not grep/rg) to search file content",
    "Use Glob tool (not find/ls) to find files by pattern",
    "For complex analysis, write a script file then execute it",
    "Inline code (python3 -c, node -e) must use only safe modules",
    "Avoid heredocs (<<); use echo or the Write tool instead",
]

_STRUCTURAL_EXACT = {
    "command_substitution", "process_substitution", "heredoc", "inline_exec",
}


def is_structural_reason(reason):
    """Check if a rejection reason is structural (vs. a safety gate)."""
    if not reason:
        return False
    if reason in _STRUCTURAL_EXACT:
        return True
    return reason.startswith("inline_python:")


def lookup_guidance(gmap, reason):
    """Look up guidance for a rejection reason.

    Tries exact match first, then prefix matching for inline_python:* reasons.
    Returns None for safety gates or unknown reasons.
    """
    if not reason:
        return None

    # Exact match
    if reason in gmap:
        return gmap[reason]

    # Prefix match for inline_python:* variants
    if reason.startswith("inline_python:"):
        # Try progressively shorter prefixes
        parts = reason.split(":")
        for i in range(len(parts), 0, -1):
            prefix = ":".join(parts[:i])
            if prefix in gmap:
                return gmap[prefix]
        # Generic inline_python fallback
        return (
            "Inline Python code was rejected. "
            "Write a script file with the Write tool and execute it instead."
        )

    return None


def load_session_stats(path=None):
    """Load session stats entries from the JSONL log."""
    path = path or STATS_LOG
    entries = []
    try:
        with open(path) as f:
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


def enrich_guidance_map(base_map, stats_entries):
    """Add informational entries for frequently rejected patterns.

    Patterns with ENRICH_MIN_REJECTIONS+ rejections across
    ENRICH_MIN_SESSIONS+ sessions get an informational guidance entry.
    Never overrides existing entries in base_map.
    """
    pattern_rejections = Counter()
    pattern_sessions = {}

    for entry in stats_entries:
        patterns = entry.get("patterns", {})
        sid = entry.get("sid", "?")
        for pattern_key, counts in patterns.items():
            rejections = counts.get("rejections", 0)
            if rejections > 0:
                pattern_rejections[pattern_key] += rejections
                if pattern_key not in pattern_sessions:
                    pattern_sessions[pattern_key] = set()
                pattern_sessions[pattern_key].add(sid)

    enriched = dict(base_map)
    for pattern_key, total in pattern_rejections.most_common():
        if pattern_key in enriched:
            continue
        sessions_count = len(pattern_sessions.get(pattern_key, set()))
        if total >= ENRICH_MIN_REJECTIONS and sessions_count >= ENRICH_MIN_SESSIONS:
            enriched[pattern_key] = (
                f"This pattern has been rejected {total} times "
                f"across {sessions_count} sessions. "
                f"Consider using an alternative approach."
            )

    return enriched


def generate_guidance_map(path=None, stats_path=None):
    """Write the guidance map to disk (called by SessionStart).

    Enriches the static map with frequently rejected patterns from
    session-stats.jsonl before writing.
    """
    path = path or GUIDANCE_MAP_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)

    stats_entries = load_session_stats(stats_path)
    enriched = enrich_guidance_map(STATIC_GUIDANCE, stats_entries)

    with open(path, "w") as f:
        json.dump(enriched, f, indent=2)


def load_guidance_map(path=None):
    """Load guidance map from disk, falling back to static map."""
    path = path or GUIDANCE_MAP_PATH
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return STATIC_GUIDANCE.copy()
