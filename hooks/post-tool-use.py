#!/usr/bin/env python3
"""PostToolUse:Bash hook: records approval/denial outcomes in session state.

After each Bash tool call, checks if a signal exists for the current agent
in prompted_agents and resolves the corresponding rejection based on whether
the tool succeeded or was denied.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss


def resolve_prompted(state, agent_id, tool_error):
    """Resolve the prompted agent's pending rejection via signal flag."""
    agent_key = agent_id or "main"
    prompted = state.get("prompted_agents", {})
    pattern_key = prompted.pop(agent_key, None)
    if pattern_key:
        _ss.record_resolution(state, pattern_key, approved=not tool_error)


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")
        agent_id = hook_input.get("agent_id")

        tool_result = hook_input.get("tool_result", {})
        is_error = False
        if isinstance(tool_result, dict):
            is_error = tool_result.get("is_error", False)
        elif isinstance(tool_result, str):
            is_error = "tool use was rejected" in tool_result

        state = _ss.load_session_state(sid)
        resolve_prompted(state, agent_id=agent_id, tool_error=is_error)
        _ss.save_session_state(sid, state)

    except Exception as e:
        try:
            with open("/tmp/bash-validator-debug.log", "a") as f:
                f.write(f"[post-tool-use] EXCEPTION: {e}\n")
        except OSError:
            pass

    print(json.dumps({}))
    sys.exit(0)


if __name__ == "__main__":
    main()
