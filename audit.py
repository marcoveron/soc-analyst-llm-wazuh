"""
Audit log of the agent's response actions.

Every decision (authorized or denied) is written as a JSON line in
response_audit.jsonl. This is the trace that demonstrates human control over
automated actions (key to defending the HITL design).
"""

import json
import os
from datetime import datetime, timezone

AUDIT_FILE = os.path.join(os.path.dirname(__file__), "response_audit.jsonl")


def log_event(**fields):
    """Append an entry to the audit log and return the recorded dict."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(), **fields}
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry
