"""The audit log: every call appends one timestamped JSON line."""

import json

import audit


def test_log_event_appends_json_lines(isolated_audit_log):
    audit.log_event(action="block_ip", ip="1.2.3.4", decision="denied")
    audit.log_event(action="block_ip", ip="1.2.3.4", decision="approved", result="ok")

    lines = isolated_audit_log.read_text().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["action"] == "block_ip"
    assert first["decision"] == "denied"
    assert "ts" in first            # auto-added UTC timestamp
