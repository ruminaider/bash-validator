"""Shared session state for bash-validator hooks.

Provides read/write access to the per-session state file that enables
communication between PreToolUse, PostToolUse, SubagentStart, PreCompact,
and SessionEnd hooks. Keyed by root session_id (shared across all agents).
"""

import json
import os
import tempfile
from datetime import datetime, timezone

SESSION_STATE_DIR = "/tmp"


def _state_path(sid, state_dir=None):
    d = state_dir or SESSION_STATE_DIR
    return os.path.join(d, f"bash-validator-session-{sid}.json")


def load_session_state(sid, state_dir=None):
    """Load session state, returning empty state if file doesn't exist."""
    path = _state_path(sid, state_dir)
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "sid": sid,
            "started": datetime.now(timezone.utc).isoformat(),
            "patterns": {},
            "agents_briefed": [],
            "last_rejected_pattern": None,
            "prompted_agents": {},
        }


def save_session_state(sid, state, state_dir=None):
    """Atomically write session state (write to temp, then rename).

    Note: This prevents partial writes but not lost updates. Two concurrent
    callers can each load, modify, and save, with the last writer winning.
    This is tolerable because escalation counts are advisory (not safety-critical)
    and hooks rarely execute concurrently for the same session.
    """
    path = _state_path(sid, state_dir)
    dir_path = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def record_rejection(state, pattern_key, reason, guidance, agent_id):
    """Record a rejection in session state."""
    agent_key = agent_id or "main"
    if pattern_key not in state["patterns"]:
        state["patterns"][pattern_key] = {
            "rejections": 0, "approvals": 0, "denials": 0,
            "agents": [], "last_reason": None, "last_guidance": None,
        }
    p = state["patterns"][pattern_key]
    p["rejections"] += 1
    p["last_reason"] = reason
    p["last_guidance"] = guidance
    if agent_key not in p["agents"]:
        p["agents"].append(agent_key)
    state["last_rejected_pattern"] = pattern_key


def record_resolution(state, pattern_key, approved):
    """Record user approval or denial for a pattern."""
    if pattern_key not in state["patterns"]:
        return
    p = state["patterns"][pattern_key]
    if approved:
        p["approvals"] += 1
    else:
        p["denials"] += 1


def is_agent_briefed(state, agent_id):
    """Check if an agent has received the proactive briefing."""
    agent_key = agent_id or "main"
    return agent_key in state["agents_briefed"]


def mark_agent_briefed(state, agent_id):
    """Mark an agent as having received the proactive briefing."""
    agent_key = agent_id or "main"
    if agent_key not in state["agents_briefed"]:
        state["agents_briefed"].append(agent_key)


def extract_pattern_key(command, reason):
    """Extract a pattern key from a command string and rejection reason.

    For structural reasons (heredoc, command_substitution, process_substitution),
    the key is the reason itself (the command shape doesn't matter).
    For inline exec, the key is "cmd -flag" (e.g., "node -e", "python3 -c").
    For git/docker, the key is "cmd subcmd".
    For everything else, the key is the base command name.
    """
    if reason in ("heredoc", "command_substitution", "process_substitution"):
        return reason

    if reason and reason.startswith("inline_python:"):
        return "python3 -c"

    if reason == "inline_exec":
        parts = command.split()
        cmd = os.path.basename(parts[0]) if parts else "unknown"
        return f"{cmd} -e" if cmd == "node" else f"{cmd} -c"

    parts = command.split()
    if not parts:
        return "unknown"
    cmd = os.path.basename(parts[0])
    if cmd == "git" and len(parts) > 1 and not parts[1].startswith("-"):
        return f"git {parts[1]}"
    if cmd == "docker" and len(parts) > 1 and not parts[1].startswith("-"):
        return f"docker {parts[1]}"
    return cmd


def delete_session_state(sid, state_dir=None):
    """Delete a session state file."""
    path = _state_path(sid, state_dir)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def cleanup_stale_sessions(max_age_hours=24, state_dir=None):
    """Delete session state files older than max_age_hours."""
    d = state_dir or SESSION_STATE_DIR
    now = datetime.now(timezone.utc).timestamp()
    prefix = "bash-validator-session-"
    for fname in os.listdir(d):
        if fname.startswith(prefix) and fname.endswith(".json"):
            path = os.path.join(d, fname)
            try:
                age = now - os.path.getmtime(path)
                if age > max_age_hours * 3600:
                    os.unlink(path)
            except OSError:
                pass
