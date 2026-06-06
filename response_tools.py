"""
Active-response tools for the agent, with Human-in-the-Loop (HITL).

block_ip_tool / unblock_ip_tool propose an action and ALWAYS ask the operator to
authorize it before executing anything. The authorization is requested via a LangGraph
`interrupt`: the agent graph PAUSES and the running front-end (terminal REPL or the
Streamlit web app) renders the proposal and resumes the graph with the human's decision.
This keeps the HITL gate identical regardless of the interface. Every decision is
recorded in the audit log (response_audit.jsonl).
"""

import ipaddress
import time

from langchain.tools import tool
from langgraph.types import interrupt

import wazuh_server_api
from audit import log_event
from wazuh_indexer_api import find_active_response_events


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _request_authorization(proposal: dict) -> bool:
    """
    Pause the agent graph and ask the human operator to authorize `proposal`.

    Uses LangGraph's `interrupt`: it suspends execution and hands `proposal` to the
    front-end, which resumes the graph with a decision string. The graph replays this
    tool from the start on resume, so everything BEFORE this call must be side-effect
    free (it is: only IP validation + building the proposal dict).

    Returns True only if the operator explicitly approved.
    """
    decision = interrupt(proposal)
    return str(decision).strip().lower() in ("y", "yes", "approve", "approved", "authorize")


def _verify_block(ip, attempts=6, delay=5):
    """
    Confirm the firewall-drop actually ran. The Manager's HTTP 200 only says the
    order was queued; here we look for the Active Response event in the indexer
    (with retries, because indexing takes a few seconds).

    Returns (confirmed: bool, event description or None).
    """
    for _ in range(attempts):
        try:
            events = find_active_response_events(ip, minutes=5)
        except Exception:  # noqa: BLE001 — if the indexer fails, treat as not confirmed
            events = []
        if events:
            return True, events[0].get("rule", {}).get("description", "Active Response event")
        time.sleep(delay)
    return False, None


@tool
def block_ip_tool(ip: str, reason: str) -> str:
    """
    Propose BLOCKING a malicious source IP on the endpoint firewall (Wazuh
    'firewall-drop' Active Response). Use it when you detect an active attack
    (brute force, port scan, etc.) with a clear source IP extracted from the
    alerts. The tool will ask for human authorization before executing anything.

    Args:
        ip: the source IP to block (data.srcip field of the alert).
        reason: short reason for the block (e.g. "SSH brute force, 47 attempts").
    """
    if not _valid_ip(ip):
        return f"Invalid IP: '{ip}'. No action taken."

    # --- Proposal to the operator (Human-in-the-Loop) ---
    authorized = _request_authorization({
        "action": "block_ip",
        "title": "🚨 PROPOSED ACTION — Block IP",
        "target": ip,
        "reason": reason,
        "command": f"{wazuh_server_api.AR_COMMAND} @ agent 'victim'",
        "dry_run": wazuh_server_api.DRY_RUN,
    })

    if not authorized:
        log_event(action="block_ip", ip=ip, reason=reason, decision="denied")
        return f"The operator DENIED the block of {ip}. No action taken."

    # --- Execution (only if the human authorized) ---
    return execute_block(ip, reason, decision="approved")


def execute_block(ip, reason, decision="approved"):
    """
    Run an ALREADY-AUTHORIZED block: fire firewall-drop, verify real execution on the
    agent, and audit the outcome. Shared by block_ip_tool (human said yes on the gate)
    and the monitor (human clicked Authorize on a queued proposal, or the auto-response
    tier approved it). `decision` is the audit label: "approved" (human) or "auto".

    Returns the human-readable result string. Does NOT prompt — the gate is the caller's.
    """
    try:
        result = wazuh_server_api.block_ip(ip, reason=reason)
    except Exception as e:  # noqa: BLE001 — we want to report any failure to the operator
        log_event(action="block_ip", ip=ip, reason=reason,
                  decision=decision, result="error", error=str(e))
        return f"Block of {ip} authorized, but execution FAILED: {e}"

    if result.get("dry_run"):
        log_event(action="block_ip", ip=ip, reason=reason, decision=decision,
                  result="dry_run", detail=result)
        return f"[DRY-RUN] {result.get('detail')}"

    if not result.get("ok"):
        log_event(action="block_ip", ip=ip, reason=reason, decision=decision,
                  result="failed", detail=result)
        return (f"⚠️ Authorized but the API returned an error "
                f"(status {result.get('status_code')}): {result.get('detail')}")

    # The API accepted the order (status 200), but that does NOT confirm the agent
    # executed it: we verify by looking for the Active Response event.
    confirmed, evidence = _verify_block(ip)
    log_event(action="block_ip", ip=ip, reason=reason, decision=decision,
              result="ok", verified=confirmed, detail=result)
    if confirmed:
        return (f"✅ IP {ip} blocked and CONFIRMED on the agent "
                f"(Active Response event: {evidence}).")
    return (f"⚠️ Block order for {ip} sent and accepted by the Manager "
            f"(status {result.get('status_code')}), but I could NOT confirm execution "
            f"on the agent (no Active Response event appeared in the indexer within the "
            f"expected time). Check active-responses.log / iptables on the victim.")


@tool
def unblock_ip_tool(ip: str, reason: str) -> str:
    """
    Propose UNBLOCKING (removing the firewall block of) an IP on the endpoint, via
    a Wazuh unblock Active Response. Use it when the operator wants to revert a
    previous block (false positive, already-remediated IP, etc.). Asks for human
    authorization before executing anything.

    Args:
        ip: the IP to unblock.
        reason: short reason for the unblock (e.g. "confirmed false positive").
    """
    if not _valid_ip(ip):
        return f"Invalid IP: '{ip}'. No action taken."

    # --- Proposal to the operator (Human-in-the-Loop) ---
    authorized = _request_authorization({
        "action": "unblock_ip",
        "title": "🔓 PROPOSED ACTION — Unblock IP",
        "target": ip,
        "reason": reason,
        "command": f"{wazuh_server_api.UNBLOCK_COMMAND} @ agent 'victim'",
        "dry_run": wazuh_server_api.DRY_RUN,
    })

    if not authorized:
        log_event(action="unblock_ip", ip=ip, reason=reason, decision="denied")
        return f"The operator DENIED the unblock of {ip}. No action taken."

    # --- Execution (only if the human authorized) ---
    try:
        result = wazuh_server_api.unblock_ip(ip, reason=reason)
    except Exception as e:  # noqa: BLE001 — report any failure to the operator
        log_event(action="unblock_ip", ip=ip, reason=reason,
                  decision="approved", result="error", error=str(e))
        return f"The operator authorized, but execution FAILED: {e}"

    if result.get("dry_run"):
        log_event(action="unblock_ip", ip=ip, reason=reason, decision="approved",
                  result="dry_run", detail=result)
        return f"[DRY-RUN] Authorized. {result.get('detail')}"

    if not result.get("ok"):
        log_event(action="unblock_ip", ip=ip, reason=reason, decision="approved",
                  result="failed", detail=result)
        return (f"⚠️ Authorized but the API returned an error "
                f"(status {result.get('status_code')}): {result.get('detail')}")

    log_event(action="unblock_ip", ip=ip, reason=reason, decision="approved",
              result="ok", detail=result)
    return (f"✅ Unblock order for {ip} sent and accepted by the Manager "
            f"(status {result.get('status_code')}). Verify with `iptables -S` on the victim "
            f"that the DROP rule is gone.")


def _run_response(action, fn, log_fields, ok_msg):
    """
    Execute an authorized active response and report+audit the outcome uniformly.

    `fn`         -> zero-arg callable that fires the AR (returns the wazuh_server_api dict).
    `log_fields` -> extra fields for the audit entry (e.g. target/reason).
    `ok_msg`     -> message to return on a real, accepted execution.
    Used by the ARs that don't need indexer verification (unlike block_ip).
    """
    try:
        result = fn()
    except Exception as e:  # noqa: BLE001 — report any failure to the operator
        log_event(action=action, decision="approved", result="error", error=str(e), **log_fields)
        return f"The operator authorized, but execution FAILED: {e}"

    if result.get("dry_run"):
        log_event(action=action, decision="approved", result="dry_run", detail=result, **log_fields)
        return f"[DRY-RUN] Authorized. {result.get('detail')}"

    if not result.get("ok"):
        log_event(action=action, decision="approved", result="failed", detail=result, **log_fields)
        return (f"⚠️ Authorized but the API returned an error "
                f"(status {result.get('status_code')}): {result.get('detail')}")

    log_event(action=action, decision="approved", result="ok", detail=result, **log_fields)
    return ok_msg(result)


@tool
def isolate_host_tool(reason: str) -> str:
    """
    Propose ISOLATING (network-quarantining) the 'victim' endpoint: an EDR-style
    containment that drops all its traffic except to the Wazuh Manager, so a
    compromised host can no longer reach attackers or pivot, while staying managed.
    Use it for a serious, host-level compromise (malware execution, C2, lateral
    movement) — stronger than blocking a single IP. Asks for human authorization first.

    Args:
        reason: short justification (e.g. "C2 beaconing confirmed on the host").
    """
    authorized = _request_authorization({
        "action": "isolate_host",
        "title": "⛔ PROPOSED ACTION — Isolate host",
        "target": "agent 'victim' (whole endpoint)",
        "reason": reason,
        "command": f"{wazuh_server_api.ISOLATE_COMMAND} @ agent 'victim'",
        "dry_run": wazuh_server_api.DRY_RUN,
    })
    if not authorized:
        log_event(action="isolate_host", reason=reason, decision="denied")
        return "The operator DENIED the host isolation. No action taken."

    return _run_response(
        "isolate_host",
        lambda: wazuh_server_api.isolate_host(reason=reason),
        {"reason": reason},
        lambda r: (f"✅ Isolation order for 'victim' sent and accepted by the Manager "
                   f"(status {r.get('status_code')}). The host should now reach only the "
                   f"Manager. Verify with `iptables -S` on the victim."),
    )


@tool
def unisolate_host_tool(reason: str) -> str:
    """
    Propose LIFTING the network isolation of the 'victim' endpoint (revert
    isolate_host_tool). Use it once the host is remediated/cleared. Asks for human
    authorization first.

    Args:
        reason: short justification (e.g. "host cleaned and validated").
    """
    authorized = _request_authorization({
        "action": "unisolate_host",
        "title": "🔓 PROPOSED ACTION — Lift host isolation",
        "target": "agent 'victim' (whole endpoint)",
        "reason": reason,
        "command": f"{wazuh_server_api.UNISOLATE_COMMAND} @ agent 'victim'",
        "dry_run": wazuh_server_api.DRY_RUN,
    })
    if not authorized:
        log_event(action="unisolate_host", reason=reason, decision="denied")
        return "The operator DENIED lifting the isolation. No action taken."

    return _run_response(
        "unisolate_host",
        lambda: wazuh_server_api.unisolate_host(reason=reason),
        {"reason": reason},
        lambda r: (f"✅ Un-isolation order for 'victim' sent and accepted by the Manager "
                   f"(status {r.get('status_code')}). Verify connectivity is restored on the victim."),
    )


@tool
def kill_process_tool(target: str, reason: str) -> str:
    """
    Propose KILLING a process on the 'victim' endpoint, by PID or by process name.
    Use it to stop an actively-running malicious process identified in the alerts
    (e.g. a miner, a reverse shell). Killing by name terminates ALL matching
    processes. Asks for human authorization first.

    Args:
        target: the PID (e.g. "4123") or process name (e.g. "xmrig") to kill.
        reason: short justification (e.g. "cryptominer xmrig running as www-data").
    """
    target = (target or "").strip()
    if not target:
        return "No process target given (need a PID or a process name). No action taken."

    authorized = _request_authorization({
        "action": "kill_process",
        "title": "💀 PROPOSED ACTION — Kill process",
        "target": f"{target} (by {'PID' if target.isdigit() else 'name'})",
        "reason": reason,
        "command": f"{wazuh_server_api.KILL_COMMAND} @ agent 'victim'",
        "dry_run": wazuh_server_api.DRY_RUN,
    })
    if not authorized:
        log_event(action="kill_process", target=target, reason=reason, decision="denied")
        return f"The operator DENIED killing process '{target}'. No action taken."

    return _run_response(
        "kill_process",
        lambda: wazuh_server_api.kill_process(target, reason=reason),
        {"target": target, "reason": reason},
        lambda r: (f"✅ Kill order for process '{target}' sent and accepted by the Manager "
                   f"(status {r.get('status_code')}). Verify on the victim with `ps`/`pgrep` "
                   f"that it is gone (and check active-responses.log)."),
    )
