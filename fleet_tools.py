"""
Fleet-health tool for the SOC agent.

fleet_status_tool queries the Wazuh Manager API for the state of every agent
(active / disconnected / never_connected) plus version and last keep-alive. A SOC
analyst uses this to judge whether the telemetry is trustworthy: a disconnected
endpoint produces no alerts, so "no alerts" from it means "blind", not "safe".
Read-only — no Active Response, no human gate needed.
"""

from langchain.tools import tool

import wazuh_server_api


@tool
def fleet_status_tool() -> str:
    """
    Report the health of the Wazuh agent fleet: which endpoints are active,
    disconnected or never connected, with their version, IP and last keep-alive.
    Use it when the operator asks about agent/endpoint status, coverage, or whether
    a host is reporting — or to caveat an analysis when a relevant agent is offline.
    """
    try:
        agents = wazuh_server_api.list_agents()
    except Exception as e:  # noqa: BLE001 — report the failure instead of breaking the agent
        return f"Could not query the Manager API for agent status: {e}"

    if not agents:
        return "The Manager API returned no agents."

    # Tally by status so the agent can lead with the headline.
    tally = {}
    for a in agents:
        tally[a.get("status", "unknown")] = tally.get(a.get("status", "unknown"), 0) + 1
    headline = ", ".join(f"{n} {status}" for status, n in sorted(tally.items()))

    lines = [f"Fleet: {len(agents)} agents ({headline})."]
    for a in agents:
        lines.append(
            f"  - id {a.get('id')} '{a.get('name')}' [{a.get('status')}] "
            f"ip={a.get('ip', '?')} v{a.get('version', '?')} "
            f"last_keepalive={a.get('lastKeepAlive', '?')}"
        )
    return "\n".join(lines)
