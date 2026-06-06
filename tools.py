from collections import Counter

from wazuh_indexer_api import get_events
from langchain.tools import tool

# Max number of alerts to detail (so we don't flood the model).
MAX_DETAIL = 20


@tool
def get_alerts_tool(hours: int = 24, min_level: int = 5) -> str:
    """
    Fetch recent Wazuh security alerts and summarize them in a structured way
    (level, description, source IP, groups). Use this tool when you need to see
    which attacks or suspicious events happened on the network.

    Args:
        hours: look-back time window, in hours (default 24).
        min_level: minimum Wazuh rule level to include (default 5).
    """
    try:
        alerts = get_events(hours=hours, min_level=min_level)
    except Exception as e:  # noqa: BLE001 — report the failure to the agent, don't break the loop
        return f"ERROR querying the Wazuh indexer: {e}"

    if not alerts:
        return (f"No alerts found in the last {hours}h "
                f"with level >= {min_level}.")

    # Source IP (data.srcip) tally so the agent doesn't make them up.
    srcips = Counter(
        a.get("data", {}).get("srcip")
        for a in alerts
        if a.get("data", {}).get("srcip")
    )
    if srcips:
        ips_line = "Source IPs (data.srcip): " + ", ".join(
            f"{ip} (x{n})" for ip, n in srcips.most_common()
        )
    else:
        ips_line = "Source IPs (data.srcip): none in the alerts."

    # Detail, sorted by severity descending.
    alerts_sorted = sorted(
        alerts, key=lambda a: a.get("rule", {}).get("level", 0), reverse=True
    )
    lines = []
    for a in alerts_sorted[:MAX_DETAIL]:
        rule = a.get("rule", {})
        level = rule.get("level", "?")
        desc = rule.get("description", "?")
        srcip = a.get("data", {}).get("srcip", "—")
        groups = ",".join(rule.get("groups", []))
        lines.append(f"- [level {level}] {desc} | srcip={srcip} | groups={groups}")

    extra = ""
    if len(alerts_sorted) > MAX_DETAIL:
        extra = f"\n(... and {len(alerts_sorted) - MAX_DETAIL} more alerts)"

    return (
        f"Found {len(alerts)} alerts (last {hours}h, level >= {min_level}).\n"
        f"{ips_line}\n"
        f"Detail (sorted by severity):\n" + "\n".join(lines) + extra
    )
