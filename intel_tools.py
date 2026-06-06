"""
IP intelligence/reputation tool for the SOC agent.

check_ip_tool gathers evidence to decide whether an IP is malicious BEFORE
proposing a block. It combines two sources:

  - LOCAL evidence (Wazuh): how many alerts that IP generated and the max severity.
    Always works, even for the lab's private IPs.
  - EXTERNAL reputation (AbuseIPDB): only for PUBLIC IPs and if ABUSEIPDB_KEY is
    set in the environment. Private IPs have no applicable public reputation.
"""

import ipaddress
import os

import requests
from langchain.tools import tool

from wazuh_indexer_api import get_events_by_srcip

# Thresholds for the local verdict (simple, tunable heuristic).
MIN_ALERTS_MALICIOUS = 5     # alert count that already makes the IP suspicious
MIN_LEVEL_MALICIOUS = 10     # Wazuh rule level that already means a serious attack
ABUSE_SCORE_MALICIOUS = 50   # AbuseIPDB score (0-100) at/above which we flag it


def _abuseipdb(ip):
    """Query AbuseIPDB. Returns the 'data' dict, or None if there is no API key."""
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("data", {})


def assess_ip(ip, hours=24):
    """
    Gather evidence on a source IP and decide whether it is malicious. Shared core of
    check_ip_tool (interactive) and the monitor's autonomous triage, so the thresholds
    live in ONE place.

    Combines local Wazuh evidence (alert count + max severity for that IP) with external
    AbuseIPDB reputation (public IPs only, needs ABUSEIPDB_KEY). Returns a dict:
      valid, malicious, alert_count, max_level, top (list of (desc, n)), abuse_score,
      summary (one-line reason), lines (formatted human-readable detail).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"valid": False, "malicious": False, "ip": ip,
                "summary": f"invalid IP '{ip}'", "lines": [f"Invalid IP: '{ip}'."]}

    lines = [f"Reputation assessment for {ip}:"]

    # --- Local evidence (Wazuh) ---
    local_malicious = False
    alert_count = 0
    max_level = 0
    top = []
    try:
        alerts = get_events_by_srcip(ip, hours=hours)
    except Exception as e:  # noqa: BLE001 — report the failure, don't break the caller
        alerts = []
        lines.append(f"  [Wazuh] Could not query the indexer: {e}")

    if alerts:
        alert_count = len(alerts)
        max_level = max((a.get("rule", {}).get("level", 0) for a in alerts), default=0)
        descs = {}
        for a in alerts:
            d = a.get("rule", {}).get("description", "?")
            descs[d] = descs.get(d, 0) + 1
        top = sorted(descs.items(), key=lambda x: -x[1])[:3]
        lines.append(f"  [Wazuh] {alert_count} alerts in {hours}h, max level {max_level}.")
        for d, n in top:
            lines.append(f"          - {n}x {d}")
        local_malicious = alert_count >= MIN_ALERTS_MALICIOUS or max_level >= MIN_LEVEL_MALICIOUS
    else:
        lines.append(f"  [Wazuh] No alerts from this IP in {hours}h.")

    # --- External reputation (AbuseIPDB) ---
    ext_score = None
    if addr.is_private:
        lines.append("  [AbuseIPDB] Private IP (lab): no applicable public reputation.")
    elif not os.environ.get("ABUSEIPDB_KEY"):
        lines.append("  [AbuseIPDB] No ABUSEIPDB_KEY: external reputation not queried.")
    else:
        try:
            data = _abuseipdb(ip)
            ext_score = data.get("abuseConfidenceScore")
            lines.append(f"  [AbuseIPDB] abuse score: {ext_score}/100, "
                         f"reports: {data.get('totalReports')}, country: {data.get('countryCode')}.")
        except Exception as e:  # noqa: BLE001
            lines.append(f"  [AbuseIPDB] Error querying: {e}")

    # --- Verdict ---
    malicious = local_malicious or (ext_score is not None and ext_score >= ABUSE_SCORE_MALICIOUS)
    if top:
        summary = f"{alert_count} alerts (max level {max_level}); top: {top[0][0]}"
    elif ext_score is not None:
        summary = f"AbuseIPDB score {ext_score}/100"
    else:
        summary = "no strong local/external evidence"
    lines.append("  => Verdict: " + ("MALICIOUS — there is evidence to propose a block"
                                      if malicious else
                                      "NOT enough evidence — do not propose a block yet") + ".")

    return {"valid": True, "ip": ip, "malicious": malicious, "alert_count": alert_count,
            "max_level": max_level, "top": top, "abuse_score": ext_score,
            "summary": summary, "lines": lines}


@tool
def check_ip_tool(ip: str, hours: int = 24) -> str:
    """
    Assess whether a source IP is malicious by gathering evidence, to decide
    whether to propose a block. Combines local Wazuh evidence (alert count and
    max severity for that IP) with external AbuseIPDB reputation (only if the IP
    is public and ABUSEIPDB_KEY is set). Use it BEFORE block_ip_tool to justify
    the decision.

    Args:
        ip: the source IP to assess (data.srcip field of the alert).
        hours: look-back window to count local alerts (default 24).
    """
    return "\n".join(assess_ip(ip, hours=hours)["lines"])
