"""Guidance map for bash-validator rejection reasons.

Maps rejection reasons to actionable guidance strings that are sent to agents
via additionalContext. Structural reasons (agent using the wrong approach)
get guidance; safety gates (destructive commands) map to None.
"""

import json
import os

GUIDANCE_MAP_PATH = os.path.expanduser("~/.config/bash-validator/guidance-map.json")

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

# Structural reason prefixes that trigger escalation
_STRUCTURAL_PREFIXES = (
    "command_substitution", "process_substitution", "heredoc",
    "inline_exec", "inline_python:",
)
_STRUCTURAL_EXACT = {
    "command_substitution", "process_substitution", "heredoc", "inline_exec",
}


def is_structural_reason(reason):
    """Check if a rejection reason is structural (vs. a safety gate)."""
    if not reason:
        return False
    if reason in _STRUCTURAL_EXACT:
        return True
    return any(reason.startswith(p) for p in _STRUCTURAL_PREFIXES)


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


def generate_guidance_map(path=None):
    """Write the guidance map to disk (called by SessionStart)."""
    path = path or GUIDANCE_MAP_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(STATIC_GUIDANCE, f, indent=2)


def load_guidance_map(path=None):
    """Load guidance map from disk, falling back to static map."""
    path = path or GUIDANCE_MAP_PATH
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return STATIC_GUIDANCE.copy()
