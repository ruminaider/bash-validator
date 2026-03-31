#!/usr/bin/env python3
"""PostToolUse:Bash hook: records approval/denial outcomes in session state.

After each Bash tool call, checks if there are unresolved rejections
(rejections > approvals + denials) and resolves the most recent one
based on whether the tool succeeded or was denied.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss


def resolve_pending_rejections(state, tool_error):
    """Resolve the most recent unresolved rejection."""
    for pattern_key, data in state.get("patterns", {}).items():
        pending = data["rejections"] - data["approvals"] - data["denials"]
        if pending > 0:
            _ss.record_resolution(state, pattern_key, approved=not tool_error)
            return  # resolve one at a time (most recent)


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")

        # Check if the tool result indicates an error (user denied)
        tool_result = hook_input.get("tool_result", {})
        is_error = False
        if isinstance(tool_result, dict):
            is_error = tool_result.get("is_error", False)
        elif isinstance(tool_result, str):
            is_error = "tool use was rejected" in tool_result

        state = _ss.load_session_state(sid)
        resolve_pending_rejections(state, tool_error=is_error)
        _ss.save_session_state(sid, state)

    except Exception:
        pass

    # PostToolUse hooks should not output hookSpecificOutput for permission
    print(json.dumps({}))
    sys.exit(0)


if __name__ == "__main__":
    main()
