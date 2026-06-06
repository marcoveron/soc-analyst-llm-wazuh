# Local-LLM SOC Analyst — Wazuh + Human-in-the-Loop Active Response

A capstone project: a **local-LLM cybersecurity assistant** that acts as a SOC (Security
Operations Center) analyst. It pulls security alerts from a **Wazuh** SIEM, reasons over
them with a locally-hosted LLM, enriches indicators with threat intelligence, and can
**propose active responses** (blocking a malicious IP, isolating a host, killing a
process) — always gated behind explicit **human authorization (Human-in-the-Loop, HITL)**.

The LLM runs entirely on-premise via **Ollama** (`llama3.1:8b`) — no data leaves the
network — and the agent is orchestrated with **LangChain / LangGraph 1.x**.

---

## Why this design

The agent never acts autonomously on the network. Every state-changing action (a firewall
block, a host isolation, a process kill) is raised as a **proposal** that pauses the agent
graph (via a LangGraph `interrupt`) and waits for a human operator to **Authorize** or
**Deny**. Every decision is written to an append-only audit log. This makes the system a
*decision-support tool*, not an autonomous actor — the human stays in control of anything
with real-world impact.

---

## Architecture

Two paths share the same agent, tools, and HITL gate:

- **Read path** — fetch and analyze alerts.
- **Response path** — propose an action, get human approval, execute, verify, audit.

| File | Role |
|------|------|
| `agent.py` | Terminal entry point + the shared `build_agent()` factory. Defines the SOC-analyst system prompt and builds the LangChain agent (`ChatOllama`, tools, `InMemorySaver` checkpointer). The checkpointer persists conversation per `thread_id` and is what lets the HITL `interrupt` pause/resume the graph. |
| `app.py` | **Streamlit web UI.** Same agent/tools/gate; each browser session gets its own `thread_id`. Renders the chat and shows action proposals as cards with **Authorize / Deny** buttons. Sidebar shows DRY-RUN/LIVE mode and recent audit decisions. |
| `tools.py` | `get_alerts_tool` — fetches a structured summary of recent alerts (count, source-IP tally, per-alert level/description/groups). |
| `intel_tools.py` | `check_ip_tool` — hybrid IP reputation: local Wazuh evidence + optional AbuseIPDB (public IPs only). Returns a MALICIOUS / not-enough-evidence verdict. |
| `enrich_tools.py` | `enrich_indicator_tool` — adds context (not a verdict) for an IP or file hash: geolocation + network owner (ip-api.com) and VirusTotal reputation if `VT_API_KEY` is set. |
| `fleet_tools.py` | `fleet_status_tool` — read-only query of every agent's status/version/keepalive, so the agent can caveat "no alerts" from a disconnected endpoint as "blind, not safe". |
| `report_tools.py` | `generate_report_tool` — builds a Markdown incident report from the alert summary plus the audit trace. |
| `response_tools.py` | The **HITL active-response tools**: `block_ip` / `unblock_ip`, `isolate_host` / `unisolate_host`, `kill_process`. Each validates input, raises an `interrupt` for human approval, executes only on approval, verifies real execution, and audits the decision. |
| `monitor.py` | Optional proactive monitoring loop: polls Wazuh on an interval, triages new source IPs, and raises block proposals — lowering detection latency without removing the human gate. |
| `wazuh_indexer_api.py` | Client for the Wazuh **Indexer** (port 9200) — the alert read path. |
| `wazuh_server_api.py` | Client for the Wazuh **Manager/Server API** (port 55000) — JWT auth, agent-id resolution, and firing Active Response commands. Honors `DRY_RUN`. |
| `audit.py` | `log_event(...)` — appends one JSON line per decision to `response_audit.jsonl`. The trace that demonstrates human control over automated actions. |
| `lab/` | Custom Wazuh Active-Response scripts for the lab (`firewall-allow`, `isolate-host`, `unisolate-host`, `kill-process`) and setup notes (`lab/README.md`). |

**Flow:** `agent.py` → LLM tool call → either
`get_alerts_tool` → `get_events` (read), or
`block_ip_tool` → *(human approval)* → `wazuh_server_api.block_ip` + `audit.log_event` (respond).

---

## Setup

Requires Python 3.13, a running **Ollama**, and network access to a **Wazuh** deployment.

```bash
# 1. Create the virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Start Ollama locally and pull the model
ollama serve
ollama pull llama3.1:8b

# 3. Configure credentials (never commit the real values)
cp .env.example .env
#   edit .env, then load it into your shell, e.g.:
set -a; source .env; set +a
```

> **Safety:** keep `DRY_RUN=1` while testing — response tools simulate the call (no real
> firewall change) while still exercising authentication and the full HITL flow.

---

## Run

```bash
source venv/bin/activate

python agent.py            # interactive terminal REPL (type exit/quit to leave)
# OR
streamlit run app.py       # web UI — same agent + tools, HITL via Authorize/Deny buttons
# OR
python monitor.py          # optional proactive monitoring loop (terminal)
```

Both front-ends share one agent, one set of tools, and one HITL gate. The only difference
is how the human authorizes an action: a terminal `[y/N]` prompt vs. web buttons.

---

## Configuration reference

All hosts/ports and credentials are read from environment variables — see `.env.example`
for the full list. Key ones:

| Variable | Purpose | Default |
|----------|---------|---------|
| `WAZUH_USER` / `WAZUH_PASS` | Wazuh Indexer (read path) | `admin` / *(required)* |
| `WAZUH_API_USER` / `WAZUH_API_PASS` | Wazuh Manager API (response path) | `wazuh` / *(required)* |
| `DRY_RUN` | `1` = simulate responses, no real change | `0` |
| `WAZUH_AR_COMMAND` | AR command name; must match the agent's `ar.conf` | `firewall-drop120` |
| `ABUSEIPDB_KEY`, `VT_API_KEY` | Optional threat-intel enrichment | *(unset → skipped)* |

> The AR command name must match the agent's `ar.conf` **exactly** (the numeric suffix is
> the AR `<timeout>`), or the agent's `execd` rejects it. A Manager HTTP 200 only means the
> command was *queued/forwarded* — not that the endpoint executed it; that's why
> `block_ip_tool` independently verifies execution by polling the indexer.

---

## Lab environment

This project was built and tested against a self-contained Wazuh lab. Hosts/ports and the
monitored agent name are defaulted to that lab (private RFC1918 addresses) and TLS
verification is disabled for the lab's self-signed certificates. Point the environment
variables at your own deployment to run it elsewhere. See `lab/README.md` for the custom
Active-Response scripts.

---

## Notes

- No credentials are committed — both Wazuh API clients read exclusively from environment
  variables.
- The audit log (`response_audit.jsonl`) and generated incident reports are runtime
  artifacts and are not tracked in git; they are created on first run.
