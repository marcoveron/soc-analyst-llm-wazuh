"""
Shared test fixtures.

These tests are designed to run OFFLINE: every external dependency (Wazuh Indexer,
Wazuh Manager API, Ollama, threat-intel HTTP APIs) is mocked in the individual tests.
Nothing here ever touches the real lab.
"""

import pytest

import audit


@pytest.fixture(autouse=True)
def isolated_audit_log(tmp_path, monkeypatch):
    """
    Redirect the audit log to a temp file for every test, so they never append to
    the real response_audit.jsonl. Returns the path so a test can read it back.
    """
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_FILE", str(log))
    return log
