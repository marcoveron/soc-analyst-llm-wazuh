"""
Indicator-enrichment tool for the SOC agent.

enrich_indicator_tool adds CONTEXT to an indicator (an IP or a file hash) so the
operator can judge a block/quarantine with more than just local Wazuh counts:

  - IP: geolocation + network owner (ip-api.com, free, no key) and, if VT_API_KEY is
    set, VirusTotal reputation.
  - File hash (md5/sha1/sha256): VirusTotal reputation (needs VT_API_KEY).

It is enrichment, not a verdict — check_ip_tool still owns the malicious/no decision.
Everything external is best-effort and optional: private IPs and missing keys are
reported, never fatal.
"""

import ipaddress
import os
import re

import requests
from langchain.tools import tool

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def _geo_whois(ip):
    """Geolocation + network owner via ip-api.com (free tier, no key, HTTP)."""
    resp = requests.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,regionName,city,isp,org,as,query"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _virustotal(kind, value):
    """
    VirusTotal v3 lookup. `kind` is 'ip_addresses' or 'files'. Returns the
    last_analysis_stats dict, or None if there is no VT_API_KEY.
    """
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/{kind}/{value}",
        headers={"x-apikey": key},
        timeout=15,
    )
    resp.raise_for_status()
    attrs = resp.json().get("data", {}).get("attributes", {})
    return attrs.get("last_analysis_stats", {})


@tool
def enrich_indicator_tool(indicator: str) -> str:
    """
    Enrich an indicator with external context to support a decision. Accepts an IP
    address (returns geolocation + network owner, plus VirusTotal if VT_API_KEY is set)
    or a file hash md5/sha1/sha256 (returns VirusTotal reputation). Use it to add
    context to a suspicious IP before proposing a block, or to triage a file hash seen
    in an alert. This is context, not a block verdict.

    Args:
        indicator: an IPv4/IPv6 address or an md5/sha1/sha256 file hash.
    """
    indicator = indicator.strip()
    lines = [f"Enrichment for {indicator}:"]

    # --- File hash branch ---
    if _HASH_RE.match(indicator):
        if not os.environ.get("VT_API_KEY"):
            return lines[0] + "\n  [VirusTotal] No VT_API_KEY set: cannot look up the hash."
        try:
            stats = _virustotal("files", indicator)
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            lines.append(f"  [VirusTotal] file: {mal} malicious / {susp} suspicious / "
                         f"{harmless} harmless detections.")
            if mal >= 1:
                lines.append("  => At least one engine flags this file as malicious.")
        except Exception as e:  # noqa: BLE001
            lines.append(f"  [VirusTotal] Error querying the hash: {e}")
        return "\n".join(lines)

    # --- IP branch ---
    try:
        addr = ipaddress.ip_address(indicator)
    except ValueError:
        return (lines[0] + "\n  Not a valid IP or md5/sha1/sha256 hash. "
                "Pass an IP address or a file hash.")

    if addr.is_private:
        lines.append("  [Geo/WHOIS] Private IP (lab): no public geolocation/owner.")
    else:
        try:
            g = _geo_whois(indicator)
            if g.get("status") == "success":
                lines.append(f"  [Geo/WHOIS] {g.get('city','?')}, {g.get('regionName','?')}, "
                             f"{g.get('country','?')} | owner: {g.get('org') or g.get('isp','?')} "
                             f"({g.get('as','?')}).")
            else:
                lines.append(f"  [Geo/WHOIS] lookup failed: {g.get('message','?')}.")
        except Exception as e:  # noqa: BLE001
            lines.append(f"  [Geo/WHOIS] Error querying: {e}")

    if addr.is_private:
        lines.append("  [VirusTotal] Private IP: not applicable.")
    elif not os.environ.get("VT_API_KEY"):
        lines.append("  [VirusTotal] No VT_API_KEY set: external reputation not queried.")
    else:
        try:
            stats = _virustotal("ip_addresses", indicator)
            lines.append(f"  [VirusTotal] ip: {stats.get('malicious',0)} malicious / "
                         f"{stats.get('suspicious',0)} suspicious detections.")
        except Exception as e:  # noqa: BLE001
            lines.append(f"  [VirusTotal] Error querying: {e}")

    return "\n".join(lines)
