#!/usr/bin/env python3
"""
Proactive monitoring loop for the SOC agent.

Instead of waiting for the operator to ask "review the network", the Monitor polls
Wazuh on an interval, triages NEW source IPs (reusing intel_tools.assess_ip), and for
malicious ones raises a block PROPOSAL. The human still authorizes every block — the loop
only lowers DETECTION latency, it does not remove the gate.

Two ways to consume it (both share poll_once + the same triage/thresholds):
  - Background mode (the Streamlit app): `start()` runs a thread that fills `pending`;
    the UI renders those proposals with Authorize/Deny and calls `resolve()`.
  - Terminal mode (`python monitor.py`): `run_terminal()` prompts y/N inline per proposal.

Optional AUTO-RESPONSE tier (off by default): if `auto_block` is on and the evidence is
high-confidence, the loop blocks immediately (audited with decision="auto") and notifies,
instead of queuing. This is supervised autonomy for clear-cut cases — keep it opt-in so the
Human-in-the-Loop remains the default.
"""

import os
import threading
import time
import uuid
from datetime import datetime, timezone

from wazuh_indexer_api import get_events
from intel_tools import assess_ip
from response_tools import execute_block
from audit import log_event


class Monitor:
    def __init__(self, interval=30, hours=1, min_level=7, lookback_hours=24,
                 retriage=600, auto_block=False, auto_min_alerts=10, auto_min_level=12,
                 auto_min_abuse=90):
        self.interval = interval            # seconds between polls
        self.hours = hours                  # window of recent alerts fetched each poll
        self.min_level = min_level          # min rule level to consider an alert
        self.lookback_hours = lookback_hours  # window assess_ip uses for evidence
        self.retriage = retriage            # don't re-triage the same IP within this many s
        self.auto_block = auto_block        # AUTO-RESPONSE tier on/off
        self.auto_min_alerts = auto_min_alerts
        self.auto_min_level = auto_min_level
        self.auto_min_abuse = auto_min_abuse

        self._actioned = set()              # IPs already proposed/blocked — never re-handle
        self._last_triage = {}              # ip -> monotonic ts of last triage
        self._lock = threading.Lock()
        self.pending = []                   # proposals awaiting a human decision (web mode)
        self.activity = []                  # recent monitor log lines (newest first)
        self._stop = threading.Event()
        self._thread = None

    # --- status / logging ---------------------------------------------------
    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def _log(self, msg):
        stamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.activity.insert(0, f"{stamp}  {msg}")
            del self.activity[40:]

    # --- core polling -------------------------------------------------------
    def _make_proposal(self, ip, a):
        return {
            "id": uuid.uuid4().hex[:8],
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ip": ip,
            "reason": a["summary"],
            "evidence": "\n".join(a["lines"]),
            "alert_count": a.get("alert_count", 0),
            "max_level": a.get("max_level", 0),
            "abuse_score": a.get("abuse_score"),
            "status": "pending",            # pending | auto-blocked | blocked | denied
            "result": None,
        }

    def _high_confidence(self, a):
        """Whether the evidence is strong enough for the auto-response tier."""
        if a.get("abuse_score") is not None and a["abuse_score"] >= self.auto_min_abuse:
            return True
        return (a.get("alert_count", 0) >= self.auto_min_alerts
                or a.get("max_level", 0) >= self.auto_min_level)

    def poll_once(self):
        """
        One polling cycle. Fetch recent alerts, triage NEW source IPs, and return the
        list of malicious proposals. Auto-block ones are already executed (status set);
        the rest come back as status="pending" for the caller to queue/prompt. Does not
        touch self.pending — queueing is the caller's job (so terminal mode can prompt).
        """
        new = []
        try:
            alerts = get_events(hours=self.hours, min_level=self.min_level)
        except Exception as e:  # noqa: BLE001 — keep the loop alive on transient errors
            self._log(f"poll error: {e}")
            return new

        now = time.monotonic()
        srcips = []
        for al in alerts:
            ip = (al.get("data") or {}).get("srcip")
            if ip and ip not in srcips:
                srcips.append(ip)

        for ip in srcips:
            with self._lock:
                if ip in self._actioned:
                    continue
                if now - self._last_triage.get(ip, 0) < self.retriage:
                    continue
                self._last_triage[ip] = now

            a = assess_ip(ip, hours=self.lookback_hours)
            if not a.get("malicious"):
                self._log(f"· {ip}: {a['summary']} — no action")
                continue

            with self._lock:
                self._actioned.add(ip)
            prop = self._make_proposal(ip, a)

            if self.auto_block and self._high_confidence(a):
                prop["result"] = execute_block(ip, f"[auto] {a['summary']}", decision="auto")
                prop["status"] = "auto-blocked"
                self._log(f"🤖 AUTO-BLOCK {ip}: {a['summary']}")
            else:
                self._log(f"⚠️ PROPOSAL {ip}: {a['summary']}")
            new.append(prop)
        return new

    # --- background (web) mode ----------------------------------------------
    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._log(f"started (every {self.interval}s, level≥{self.min_level}, "
                  f"auto_block={'ON' if self.auto_block else 'off'})")

    def _loop(self):
        while not self._stop.is_set():
            for prop in self.poll_once():
                if prop["status"] == "pending":
                    with self._lock:
                        self.pending.append(prop)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        self._log("stopped")

    def resolve(self, pid, approve):
        """Web mode: apply the operator's decision to a queued proposal."""
        with self._lock:
            prop = next((p for p in self.pending if p["id"] == pid), None)
            if prop:
                self.pending.remove(prop)
        if not prop:
            return None
        if approve:
            prop["result"] = execute_block(prop["ip"], f"[monitor] {prop['reason']}",
                                           decision="approved")
            prop["status"] = "blocked"
            self._log(f"✅ approved block {prop['ip']}")
        else:
            log_event(action="block_ip", ip=prop["ip"], reason=prop["reason"],
                      decision="denied", source="monitor")
            prop["status"] = "denied"
            self._log(f"⛔ denied block {prop['ip']}")
        return prop

    # --- terminal mode ------------------------------------------------------
    def run_terminal(self):
        print("=" * 60)
        print(f"  SOC monitor — polling every {self.interval}s, level≥{self.min_level}")
        print(f"  auto-block: {'ON' if self.auto_block else 'off'}   (Ctrl-C to stop)")
        print("=" * 60)
        try:
            while True:
                for prop in self.poll_once():
                    if prop["status"] == "auto-blocked":
                        print(f"\n🤖 AUTO-BLOCKED {prop['ip']} — {prop['reason']}")
                        print(f"   {prop['result']}")
                        continue
                    print("\n" + "=" * 52)
                    print(f"  ⚠️  PROPOSAL — Block {prop['ip']}")
                    print(f"  {prop['reason']}")
                    print("=" * 52)
                    try:
                        ans = input("Authorize block? [y/N]: ").strip().lower()
                    except EOFError:
                        ans = "n"
                    if ans in ("y", "yes"):
                        print(execute_block(prop["ip"], f"[monitor] {prop['reason']}",
                                            decision="approved"))
                    else:
                        log_event(action="block_ip", ip=prop["ip"], reason=prop["reason"],
                                  decision="denied", source="monitor")
                        print(f"Denied. {prop['ip']} not blocked.")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\nMonitor stopped.")


def _from_env():
    """Build a Monitor from MONITOR_* environment variables (terminal entry point)."""
    return Monitor(
        interval=int(os.environ.get("MONITOR_INTERVAL", "30")),
        min_level=int(os.environ.get("MONITOR_MIN_LEVEL", "7")),
        auto_block=os.environ.get("MONITOR_AUTO_BLOCK", "0") == "1",
    )


if __name__ == "__main__":
    _from_env().run_terminal()
