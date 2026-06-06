"""
Incident report generation for the SOC agent.

generate_report_tool builds a Markdown report combining:
  - A summary of recent Wazuh alerts (what happened).
  - The response audit trail (response_audit.jsonl): which actions were proposed,
    who authorized/denied them, and whether they were confirmed. This is the core
    of the Human-in-the-Loop design and what demonstrates human control.

The report is saved to disk and also returned as text.
"""

import json
import os
from collections import Counter
from datetime import datetime

from langchain.tools import tool

from audit import AUDIT_FILE
from wazuh_indexer_api import get_events

REPORT_DIR = os.path.dirname(__file__)


def _read_audit():
    """Read response_audit.jsonl and return the list of entries (dicts)."""
    if not os.path.exists(AUDIT_FILE):
        return []
    entries = []
    with open(AUDIT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


@tool
def generate_report_tool(hours: int = 24, min_level: int = 5) -> str:
    """
    Generate a Markdown incident report: it summarizes recent Wazuh alerts and the
    audit trail of response actions (proposed/authorized/denied blocks & unblocks,
    and whether they were confirmed). Use it when the user asks for a report,
    summary or incident write-up.

    Args:
        hours: time window for the alert summary (default 24).
        min_level: minimum rule level to consider (default 5).
    """
    now = datetime.now()
    md = [f"# Incident report — {now.strftime('%Y-%m-%d %H:%M:%S')}", ""]

    # --- Alert summary ---
    md.append("## 1. Detected alerts")
    try:
        alerts = get_events(hours=hours, min_level=min_level)
    except Exception as e:  # noqa: BLE001
        alerts = []
        md.append(f"_Could not query the indexer: {e}_")

    if alerts:
        srcips = Counter(
            a.get("data", {}).get("srcip")
            for a in alerts if a.get("data", {}).get("srcip")
        )
        descs = Counter(a.get("rule", {}).get("description", "?") for a in alerts)
        max_level = max((a.get("rule", {}).get("level", 0) for a in alerts), default=0)
        md.append(f"- Total: **{len(alerts)}** alerts (last {hours}h, level >= {min_level}).")
        md.append(f"- Max severity: **level {max_level}**.")
        if srcips:
            ips = ", ".join(f"`{ip}` (x{n})" for ip, n in srcips.most_common())
            md.append(f"- Source IPs: {ips}")
        md.append("")
        md.append("| # | Rule | Alerts |")
        md.append("|---|------|--------|")
        for i, (desc, n) in enumerate(descs.most_common(10), 1):
            md.append(f"| {i} | {desc} | {n} |")
    else:
        md.append(f"_No alerts in the last {hours}h with level >= {min_level}._")
    md.append("")

    # --- Audit trail (HITL) ---
    md.append("## 2. Response actions (Human-in-the-Loop)")
    audit = _read_audit()
    if not audit:
        md.append("_No response actions recorded._")
    else:
        md.append("| Date (UTC) | Action | IP | Decision | Result | Confirmed | Reason |")
        md.append("|------------|--------|----|----------|--------|-----------|--------|")
        for e in audit:
            verified = e.get("verified")
            verified_str = "—" if verified is None else ("yes" if verified else "no")
            md.append(
                f"| {e.get('ts', '')} | {e.get('action', '')} | {e.get('ip', '')} "
                f"| {e.get('decision', '')} | {e.get('result', '—')} | {verified_str} "
                f"| {e.get('reason', '')} |"
            )
        approved = sum(1 for e in audit if e.get("decision") == "approved")
        denied = sum(1 for e in audit if e.get("decision") == "denied")
        md.append("")
        md.append(f"_Summary: {len(audit)} decisions recorded — "
                  f"{approved} authorized, {denied} denied by the operator._")

    content = "\n".join(md)

    # --- Save to disk ---
    fname = os.path.join(REPORT_DIR, f"incident_report_{now.strftime('%Y%m%d_%H%M%S')}.md")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content + "\n")
        saved = f"\n\n(Report saved to: {fname})"
    except OSError as e:
        saved = f"\n\n(Could not save the file: {e})"

    return content + saved
