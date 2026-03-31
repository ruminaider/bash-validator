#!/usr/bin/env python3
"""SessionEnd hook: flushes session stats and cleans up state.

Writes aggregated session statistics to session-stats.jsonl for
long-term analysis, then removes the ephemeral session state file.
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
import session_state as _ss

STATS_LOG = os.path.expanduser("~/.config/bash-validator/session-stats.jsonl")
REJECTIONS_LOG = os.path.expanduser("~/.config/bash-validator/rejections.jsonl")


def flush_session_stats(state, stats_path=None):
    """Write aggregated session stats to the stats log."""
    path = stats_path or STATS_LOG
    os.makedirs(os.path.dirname(path), exist_ok=True)

    patterns = state.get("patterns", {})
    total_rejections = sum(p["rejections"] for p in patterns.values())
    total_approvals = sum(p["approvals"] for p in patterns.values())
    total_denials = sum(p["denials"] for p in patterns.values())

    agents = set()
    for p in patterns.values():
        agents.update(p.get("agents", []))

    # Compute session duration
    started = state.get("started")
    duration_s = None
    if started:
        try:
            start_dt = datetime.fromisoformat(started)
            duration_s = int((datetime.now(timezone.utc) - start_dt).total_seconds())
        except (ValueError, TypeError):
            pass

    entry = {
        "sid": state.get("sid", "?"),
        "ts": datetime.now(timezone.utc).isoformat(),
        "started": started,
        "duration_s": duration_s,
        "total_rejections": total_rejections,
        "total_approvals": total_approvals,
        "total_denials": total_denials,
        "patterns": {
            k: {"rejections": v["rejections"], "approvals": v["approvals"], "denials": v["denials"]}
            for k, v in patterns.items()
        },
        "agents_count": len(agents),
    }

    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def rotate_rejection_log(log_path=None, max_bytes=1_000_000, keep_entries=500):
    """Rotate the rejection log if it exceeds max_bytes.

    Keeps the last keep_entries lines. Writes atomically via temp file.
    """
    path = log_path or REJECTIONS_LOG
    try:
        if os.path.getsize(path) <= max_bytes:
            return
    except OSError:
        return

    with open(path) as f:
        lines = f.readlines()

    kept = lines[-keep_entries:]
    fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(path), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.writelines(kept)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main():
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
        sid = hook_input.get("session_id", "?")

        state = _ss.load_session_state(sid)
        flush_session_stats(state)
        _ss.delete_session_state(sid)

        # Rotate rejection log if needed
        try:
            rotate_rejection_log()
        except Exception:
            pass

    except Exception:
        pass

    print(json.dumps({}))
    sys.exit(0)


if __name__ == "__main__":
    main()
