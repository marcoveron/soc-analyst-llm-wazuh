"""
The core property of the project: the Human-in-the-Loop gate.

A response (here, block_ip) must NEVER execute unless the operator explicitly
authorizes it, and every decision must be audited. We mock the authorization step
and the Wazuh Manager API so the test runs offline and asserts the gate's behaviour.
"""

import json

import response_tools
from response_tools import block_ip_tool


def _read_audit(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_deny_never_executes_and_is_audited(monkeypatch, isolated_audit_log):
    calls = {"block_ip": 0}
    monkeypatch.setattr(response_tools, "_request_authorization", lambda proposal: False)
    monkeypatch.setattr(
        response_tools.wazuh_server_api, "block_ip",
        lambda *a, **k: calls.__setitem__("block_ip", calls["block_ip"] + 1),
    )

    out = block_ip_tool.func(ip="203.0.113.5", reason="test")

    assert "DENIED" in out
    assert calls["block_ip"] == 0          # execution was never reached
    assert _read_audit(isolated_audit_log)[-1]["decision"] == "denied"


def test_approve_executes_and_is_audited(monkeypatch, isolated_audit_log):
    monkeypatch.setattr(response_tools, "_request_authorization", lambda proposal: True)
    monkeypatch.setattr(
        response_tools.wazuh_server_api, "block_ip",
        lambda ip, reason=None: {"ok": True, "dry_run": True, "detail": "simulated"},
    )

    out = block_ip_tool.func(ip="203.0.113.5", reason="test")

    assert "DRY-RUN" in out
    last = _read_audit(isolated_audit_log)[-1]
    assert last["decision"] == "approved"
    assert last["result"] == "dry_run"


def test_invalid_ip_short_circuits_before_authorization(monkeypatch):
    def boom(proposal):
        raise AssertionError("authorization must not be requested for an invalid IP")

    monkeypatch.setattr(response_tools, "_request_authorization", boom)

    out = block_ip_tool.func(ip="not-an-ip", reason="test")

    assert "Invalid IP" in out
