"""
The IP reputation heuristic (assess_ip) the agent uses before proposing a block.
AbuseIPDB is left out (no key), so only the local-evidence verdict is exercised.
"""

import intel_tools
from intel_tools import assess_ip


def _alerts(count, level):
    return [{"rule": {"level": level, "description": "x"}} for _ in range(count)]


def test_malicious_by_alert_count(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    monkeypatch.setattr(intel_tools, "get_events_by_srcip",
                        lambda ip, hours=24: _alerts(6, 5))  # >= MIN_ALERTS_MALICIOUS

    assert assess_ip("203.0.113.5")["malicious"] is True


def test_malicious_by_severity(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    monkeypatch.setattr(intel_tools, "get_events_by_srcip",
                        lambda ip, hours=24: _alerts(1, 10))  # >= MIN_LEVEL_MALICIOUS

    assert assess_ip("203.0.113.5")["malicious"] is True


def test_not_enough_evidence(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    monkeypatch.setattr(intel_tools, "get_events_by_srcip",
                        lambda ip, hours=24: _alerts(1, 5))  # below both thresholds

    assert assess_ip("203.0.113.5")["malicious"] is False


def test_invalid_ip_is_rejected():
    result = assess_ip("not-an-ip")
    assert result["valid"] is False
    assert result["malicious"] is False
