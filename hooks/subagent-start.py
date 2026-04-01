#!/usr/bin/env python3
"""SubagentStart hook: injects validator briefing into subagent context.

Provides every subagent with Bash access a proactive briefing about
validator rules and session-specific rejected patterns, so they don't
start cold and repeat mistakes other agents already made.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss
import guidance_map as _gm

# Agent types that do NOT have Bash access.
# Name-based approximation: the SubagentStart hook input does not include a
# tools list, so we maintain this set of known non-Bash agent types.
_SKIP_AGENT_TYPES = {"statusline-setup", "magic-docs", "claude-code-guide"}


def should_brief_agent_type(agent_type):
    """Check if this agent type should receive a validator briefing."""
    if agent_type is None:
        return True
    return agent_type not in _SKIP_AGENT_TYPES


def build_subagent_briefing(state, gmap=None):
    """Build the briefing content from static rules + session state + guidance map."""
    if gmap is None:
        gmap = _gm.load_guidance_map()

    lines = ["Bash validator rules for this session:"]
    lines.extend(f"- {rule}" for rule in _gm.PROACTIVE_RULES)

    rejected = state.get("patterns", {})
    if rejected:
        # Sort by rejection count, show top 5
        top = sorted(rejected.items(), key=lambda x: x[1]["rejections"], reverse=True)[:5]
        structural = [
            (k, v) for k, v in top
            if v.get("last_guidance") is not None
        ]
        if structural:
            lines.append("")
            lines.append("Already rejected this session (avoid these):")
            for pattern_key, data in structural:
                count = data["rejections"]
                guidance = gmap.get(pattern_key) or data.get("last_guidance", "")
                lines.append(f"- {pattern_key}: {count}x rejected. {guidance}")

    # Cross-session warnings from enriched guidance map
    enriched_warnings = [
        (key, guidance) for key, guidance in gmap.items()
        if key not in _gm.STATIC_GUIDANCE and key not in rejected and guidance
    ]
    if enriched_warnings:
        lines.append("")
        lines.append("Frequently rejected across prior sessions:")
        for key, guidance in enriched_warnings[:5]:
            lines.append(f"- {key}: {guidance}")

    return "\n".join(lines)


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")
        agent_type = hook_input.get("agent_type")

        if not should_brief_agent_type(agent_type):
            print(json.dumps({}))
            sys.exit(0)

        state = _ss.load_session_state(sid)
        briefing = build_subagent_briefing(state)

        result = {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": briefing,
            }
        }
        print(json.dumps(result))
    except Exception:
        print(json.dumps({}))

    sys.exit(0)


if __name__ == "__main__":
    main()
