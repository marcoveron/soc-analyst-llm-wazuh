#!/usr/bin/env python3
"""
Streamlit web front-end for the SOC-analyst agent.

Same agent and tools as the terminal REPL (agent.py); the difference is the
Human-in-the-Loop gate. When a response tool proposes a block/unblock it raises a
LangGraph `interrupt`, which PAUSES the agent graph. Here we render that proposal as a
card with Authorize / Deny buttons and resume the graph with the operator's decision —
so the human stays in control of every active response, exactly like on the terminal.

It also embeds the proactive Monitor (monitor.py): a background thread polls Wazuh,
triages new IPs, and surfaces block proposals in an auto-refreshing panel — same HITL
gate, just driven by detection instead of a chat prompt.

Run:
    source venv/bin/activate
    export WAZUH_USER=... WAZUH_PASS=... WAZUH_API_USER=... WAZUH_API_PASS=...
    export DRY_RUN=1          # recommended while testing
    streamlit run app.py
"""

import json
import os
import uuid
from pathlib import Path

import streamlit as st
from langgraph.types import Command

import wazuh_server_api
from agent import build_agent
from monitor import Monitor

AUDIT_FILE = Path(__file__).with_name("response_audit.jsonl")

st.set_page_config(page_title="SOC Analyst Assistant", page_icon="🛡️", layout="centered")


@st.cache_resource
def get_agent():
    """Build the agent once and reuse it across reruns (keeps the checkpointer state)."""
    return build_agent()


@st.cache_resource
def get_monitor():
    """One shared Monitor for the whole app (its thread + pending queue survive reruns)."""
    return Monitor()


def _process(result: dict) -> None:
    """
    Update UI state from an agent result. If the agent paused on a HITL gate, stash the
    proposal so the buttons render; otherwise append its final reply to the transcript.
    """
    interrupts = result.get("__interrupt__")
    if interrupts:
        st.session_state.pending = interrupts[0].value
        return
    st.session_state.pending = None
    final = result["messages"][-1].content
    if final:
        st.session_state.messages.append({"role": "assistant", "content": final})


def submit_message(prompt: str) -> None:
    st.session_state.messages.append({"role": "user", "content": prompt})
    result = agent.invoke(
        {"messages": [{"role": "user", "content": prompt}]}, st.session_state.config
    )
    _process(result)


def resume_decision(answer: str) -> None:
    result = agent.invoke(Command(resume=answer), st.session_state.config)
    _process(result)


# --- Session state -----------------------------------------------------------
agent = get_agent()
monitor = get_monitor()
if "config" not in st.session_state:
    # Unique thread per browser session -> isolated conversation + checkpoint.
    st.session_state.config = {"configurable": {"thread_id": f"web-{uuid.uuid4().hex[:8]}"}}
if "messages" not in st.session_state:
    st.session_state.messages = []   # display transcript only
if "pending" not in st.session_state:
    st.session_state.pending = None  # holds the interrupt proposal awaiting a decision


# --- Monitor proposals panel -------------------------------------------------
# The background Monitor fills monitor.pending; this fragment renders those proposals
# with the SAME Authorize/Deny gate as the chat HITL card. It auto-refreshes while the
# monitor is running (run_every) so newly-detected IPs surface without a manual reload.
@st.fragment(run_every=(2 if monitor.running else None))
def monitor_proposals_panel():
    pend = list(monitor.pending)
    if not pend:
        return
    st.subheader(f"📡 Monitor proposals ({len(pend)})")
    st.caption("Raised by the background poll loop — human still authorizes every block.")
    for p in pend:
        with st.container(border=True):
            st.markdown(f"**Block `{p['ip']}`** — {p['reason']}")
            meta = f"alerts: {p.get('alert_count', 0)} · max level: {p.get('max_level', 0)}"
            if p.get("abuse_score") is not None:
                meta += f" · AbuseIPDB: {p['abuse_score']}"
            st.caption(meta)
            if p.get("evidence"):
                with st.expander("Evidence"):
                    st.text(p["evidence"])
            col_y, col_n = st.columns(2)
            if col_y.button("✅ Authorize", key=f"mon-y-{p['id']}",
                            use_container_width=True, type="primary"):
                monitor.resolve(p["id"], True)
                st.rerun(scope="fragment")
            if col_n.button("⛔ Deny", key=f"mon-n-{p['id']}",
                            use_container_width=True):
                monitor.resolve(p["id"], False)
                st.rerun(scope="fragment")


# --- Sidebar -----------------------------------------------------------------
with st.sidebar:
    st.header("🛡️ SOC Analyst")
    st.caption("Local-LLM assistant over Wazuh — Human-in-the-Loop active response.")
    st.divider()
    st.subheader("Runtime")
    st.write(f"**Model:** `llama3.1:8b`")
    st.write(f"**Target agent:** `victim`")
    if wazuh_server_api.DRY_RUN:
        st.success("DRY-RUN: actions are simulated, no real firewall change.", icon="🧪")
    else:
        st.warning("LIVE: authorized actions WILL hit the firewall.", icon="🔥")
    st.divider()

    # --- Proactive monitoring ---
    st.subheader("📡 Monitoring")
    monitor.interval = st.number_input("Poll interval (s)", 10, 600, monitor.interval, step=10)
    monitor.min_level = st.slider("Min rule level", 1, 15, monitor.min_level)
    monitor.auto_block = st.toggle(
        "Auto-block high-confidence", value=monitor.auto_block,
        help="Supervised autonomy: block clear-cut cases without waiting for a click "
             "(audited as 'auto'). Leave off to keep every block human-gated.",
    )
    if monitor.auto_block:
        st.caption("⚠️ Auto-response tier ON — high-confidence IPs are blocked automatically.")

    if monitor.running:
        st.success("Monitor: RUNNING", icon="🟢")
        if st.button("⏹ Stop monitor", use_container_width=True):
            monitor.stop()
            st.rerun()
    else:
        st.info("Monitor: stopped", icon="⚪")
        if st.button("▶️ Start monitor", use_container_width=True, type="primary"):
            monitor.start()
            st.rerun()

    if monitor.activity:
        with st.expander("Monitor activity", expanded=False):
            for line in monitor.activity[:15]:
                st.text(line)

    st.divider()
    with st.expander("Audit log (last 5 decisions)"):
        if AUDIT_FILE.exists():
            lines = AUDIT_FILE.read_text().strip().splitlines()[-5:]
            for line in reversed(lines):
                try:
                    e = json.loads(line)
                    st.write(
                        f"`{e.get('action')}` {e.get('ip') or e.get('target') or ''} → "
                        f"**{e.get('decision')}**"
                        + (f" / {e.get('result')}" if e.get("result") else "")
                    )
                except json.JSONDecodeError:
                    continue
        else:
            st.caption("No decisions recorded yet.")

# --- Main: title + transcript ------------------------------------------------
st.title("SOC Analyst Assistant")
st.caption("Ask it to review the network, check an IP, propose a block, or generate a report.")

monitor_proposals_panel()

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

# --- Human-in-the-Loop authorization card ------------------------------------
if st.session_state.pending:
    p = st.session_state.pending
    with st.chat_message("assistant"):
        st.markdown(f"### {p.get('title', 'Proposed action')}")
        st.markdown(
            f"- **Target:** `{p.get('target')}`\n"
            f"- **Reason:** {p.get('reason')}\n"
            f"- **Command:** `{p.get('command')}`"
        )
        if p.get("dry_run"):
            st.info("DRY-RUN: simulated, no real firewall change.", icon="🧪")
        st.markdown("**Authorize this action?**")
        col_yes, col_no = st.columns(2)
        if col_yes.button("✅ Authorize", use_container_width=True, type="primary"):
            resume_decision("y")
            st.rerun()
        if col_no.button("⛔ Deny", use_container_width=True):
            resume_decision("n")
            st.rerun()

# --- Chat input (disabled while a decision is pending) -----------------------
if prompt := st.chat_input(
    "Message the SOC analyst…", disabled=st.session_state.pending is not None
):
    submit_message(prompt)
    st.rerun()
