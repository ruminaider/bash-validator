#!/usr/bin/env python3
"""PreCompact hook: preserves validator rules across context compaction.

Outputs concise instructions to stdout (exit 0) that become custom
compaction instructions, telling the compaction model to preserve
bash validator rules in its summary.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss


def build_compact_instructions(state):
    """Build concise preservation instructions for the compaction model."""
    lines = [
        "Preserve these bash validator rules in your summary:",
        "1. Use Write/Read/Grep/Glob tools instead of cat/grep/find via Bash",
        "2. Inline code (python3 -c, node -e) requires safe modules only",
        "3. Write script files for complex analysis instead of heredocs",
    ]

    rejected = state.get("patterns", {})
    if rejected:
        top = sorted(rejected.items(), key=lambda x: x[1]["rejections"], reverse=True)[:3]
        patterns_str = ", ".join(
            f"{k} ({v['rejections']}x)" for k, v in top
        )
        lines.append(f"Rejected patterns this session: {patterns_str}")

    return "\n".join(lines)


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")
        state = _ss.load_session_state(sid)
        instructions = build_compact_instructions(state)
        print(instructions)
    except Exception:
        pass

    sys.exit(0)


if __name__ == "__main__":
    main()
