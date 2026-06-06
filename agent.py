from langchain_ollama import ChatOllama
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from tools import get_alerts_tool
from intel_tools import check_ip_tool
from enrich_tools import enrich_indicator_tool
from fleet_tools import fleet_status_tool
from response_tools import (
    block_ip_tool,
    unblock_ip_tool,
    isolate_host_tool,
    unisolate_host_tool,
    kill_process_tool,
)
from report_tools import generate_report_tool

tools = [
    get_alerts_tool,
    check_ip_tool,
    enrich_indicator_tool,
    fleet_status_tool,
    block_ip_tool,
    unblock_ip_tool,
    isolate_host_tool,
    unisolate_host_tool,
    kill_process_tool,
    generate_report_tool,
]

# ChatOllama keeps the message structure.
# temperature=0 -> deterministic, less "creative" answers (key to avoid hallucinations).
llm = ChatOllama(model="llama3.1:8b", temperature=0)

SYSTEM_PROMPT = """You are a SOC security analyst assisting a human operator over Wazuh data.
Always answer in English.

HARD RULES (never break them):
- You may only state something if you saw it in a tool's output. Never invent alerts, IPs,
  counts or results.
- Actions are performed by CALLING the matching tool, not by describing them. If the user asks
  to block, you MUST call block_ip_tool; do not say you blocked anything if you did not call it.
- NEVER claim a block "succeeded" on your own. The real result is returned by block_ip_tool:
  repeat VERBATIM what that tool answered (authorized/denied, confirmed/not confirmed). If you
  did not call it, there is no block.
- Be specific and concise. Cite concrete data (rule level, description, data.srcip, count).
  No generic filler like "please verify it is working".

Workflow:
1. If the user asks to review the network or suspects an incident, call get_alerts_tool.
2. Summarize what it returned: the attacks (SSH brute force, scans, malware), their level and the
   source IP (data.srcip). Copy the IP VERBATIM from the output; if there is no srcip, say so and
   do not propose a block.
3. Before any block, call check_ip_tool with the IP to gather evidence. Only continue if the
   verdict is MALICIOUS; otherwise report and do not block. For extra CONTEXT on a suspicious
   IP or a file hash (geolocation, network owner, VirusTotal), call enrich_indicator_tool —
   it is context, not a verdict.
4. Choose the proportionate response and call its tool (each one asks the human for
   authorization before doing anything):
   - block_ip_tool: block a single malicious source IP on the firewall. The default first step.
   - isolate_host_tool: network-quarantine the whole endpoint. Only for a host-level compromise
     (malware execution, C2, lateral movement) — stronger and more disruptive than a block.
   - kill_process_tool: kill a specific malicious process (by PID or name) seen in the alerts.
   Pass the exact target and a short reason based on the alerts.
5. To revert: unblock_ip_tool (undo a block) or unisolate_host_tool (undo an isolation), both
   human-authorized. If the user asks for an incident report/summary, call generate_report_tool.
6. If the user asks about endpoint/agent status, coverage, or whether a host is reporting, call
   fleet_status_tool. Remember a disconnected agent means "blind", not "safe".
7. Close by reporting, in clear language, what you found, what evidence there was, and the
   tool's result (authorized/denied, confirmed/not confirmed).
"""

def build_agent(checkpointer=None):
    """
    Build the SOC-analyst agent. A checkpointer is REQUIRED for the Human-in-the-Loop
    gate: the response tools call LangGraph's `interrupt`, which can only pause/resume a
    graph that persists its state. Both front-ends (this REPL and the Streamlit web app)
    pass an InMemorySaver and drive the agent with a per-session thread_id.
    """
    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
        checkpointer=checkpointer or InMemorySaver(),
    )


def _render_proposal(proposal: dict) -> None:
    """Print a Human-in-the-Loop action proposal as a box on the terminal."""
    print("\n" + "=" * 52)
    print(f"  {proposal.get('title', 'PROPOSED ACTION')}")
    print(f"    Target  : {proposal.get('target')}")
    print(f"    Reason  : {proposal.get('reason')}")
    print(f"    Command : {proposal.get('command')}")
    if proposal.get("dry_run"):
        print("    Mode    : DRY-RUN (will not actually execute)")
    print("=" * 52)


if __name__ == "__main__":
    # The checkpointer persists the conversation per thread_id, so the agent REMEMBERS
    # prior context (e.g. the IP it already identified) without us threading history by
    # hand. The SAME mechanism powers the HITL interrupt/resume below.
    agent = build_agent()
    config = {"configurable": {"thread_id": "cli-session"}}

    while True:
        user_input = input("\nYou: ").strip()
        if not user_input:
            # Avoid firing the agent on empty input (it made it ramble).
            continue
        if user_input.lower() in ["exit", "quit"]:
            break

        result = agent.invoke({"messages": [{"role": "user", "content": user_input}]}, config)

        # The agent may pause on a Human-in-the-Loop gate (block/unblock). Each pause
        # surfaces as an `__interrupt__`: render the proposal, ask the operator, and
        # resume with their decision. Loop in case the turn proposes several actions.
        while result.get("__interrupt__"):
            _render_proposal(result["__interrupt__"][0].value)
            try:
                answer = input("Authorize? [y/N]: ").strip()
            except EOFError:
                answer = "n"
            result = agent.invoke(Command(resume=answer), config)

        print(f"\nAgent: {result['messages'][-1].content}")
