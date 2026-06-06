"""The alert-fetch tool's structured summary (built from raw indexer events)."""

import tools
from tools import get_alerts_tool

FAKE_ALERTS = [
    {"rule": {"level": 10, "description": "SSH brute force",
              "groups": ["authentication_failures"]}, "data": {"srcip": "203.0.113.5"}},
    {"rule": {"level": 5, "description": "Web 400 error",
              "groups": ["web"]}, "data": {"srcip": "203.0.113.5"}},
    {"rule": {"level": 7, "description": "Port scan",
              "groups": ["recon"]}, "data": {"srcip": "198.51.100.9"}},
]


def test_summary_counts_and_ip_tally(monkeypatch):
    monkeypatch.setattr(tools, "get_events", lambda hours=24, min_level=5: FAKE_ALERTS)

    out = get_alerts_tool.func(hours=24, min_level=5)

    assert "Found 3 alerts" in out
    assert "203.0.113.5 (x2)" in out                 # tally per source IP
    assert out.index("SSH brute force") < out.index("Web 400")  # sorted by severity desc


def test_no_alerts_message(monkeypatch):
    monkeypatch.setattr(tools, "get_events", lambda **k: [])

    assert "No alerts found" in get_alerts_tool.func()


def test_indexer_error_is_reported_not_raised(monkeypatch):
    def boom(**k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(tools, "get_events", boom)

    assert "ERROR querying" in get_alerts_tool.func()
