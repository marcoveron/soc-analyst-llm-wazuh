import requests
import os
from requests.auth import HTTPBasicAuth

# Lab indexer (read path). TLS unverified, like the rest of the project.
WAZUH_INDEXER_URL = "https://192.168.100.79:9200"
SEARCH_ENDPOINT = "/wazuh-alerts*/_search"

requests.packages.urllib3.disable_warnings()


def _post_search(payload):
    """Run a search against the Indexer and return the list of _source dicts."""
    username = os.environ.get("WAZUH_USER", "admin")
    password = os.environ.get("WAZUH_PASS")
    url = WAZUH_INDEXER_URL + SEARCH_ENDPOINT
    response = requests.post(
        url,
        auth=HTTPBasicAuth(username, password),
        json=payload,
        verify=False,
        params={"pretty": "true"},
        timeout=15,
    )
    response.raise_for_status()
    hits = response.json()["hits"]["hits"]
    return [hit["_source"] for hit in hits]


def get_events(hours=1, min_level=5):
    """Recent alerts from the 'victim' agent (main read path)."""
    payload = {
      "size": 100,
      "sort": [{"@timestamp": {"order": "desc"}}],
      "_source": ["timestamp", "rule.description", "rule.level", "agent.name", "data.srcip", "rule.groups", "full_log"],
      "query": {
        "bool": {
          "must": [
            {"match": {"agent.name": "victim"}},
            {"range": {"rule.level": {"gte": min_level}}},
            {"range": {"@timestamp": {"gte": "now-" + str(hours) + "h"}}}
          ],
          "must_not": [
            {"match": {"rule.groups": "sca"}},
            {"match": {"rule.groups": "dpkg"}},
            {"match": {"rule.groups": "systemd"}}]
        }
      }
    }
    return _post_search(payload)


def get_events_by_srcip(srcip, hours=24, min_level=1):
    """
    Fetch alerts whose data.srcip == srcip within the given window. Used as LOCAL
    evidence to assess whether an IP is malicious (check_ip_tool).
    """
    payload = {
      "size": 200,
      "sort": [{"@timestamp": {"order": "desc"}}],
      "_source": ["timestamp", "rule.description", "rule.level", "rule.groups", "data.srcip", "full_log"],
      "query": {
        "bool": {
          "must": [
            {"match": {"data.srcip": srcip}},
            {"range": {"rule.level": {"gte": min_level}}},
            {"range": {"@timestamp": {"gte": "now-" + str(hours) + "h"}}}
          ]
        }
      }
    }
    return _post_search(payload)


def find_active_response_events(srcip, minutes=5):
    """
    Find recent Active Response events that mention the IP. Used to CONFIRM that
    firewall-drop ran (which the Manager's HTTP 200 does not guarantee). firewall-drop
    leaves a line in active-responses.log that logcollector ships and that ends up
    indexed with the 'active_response' group.
    """
    payload = {
      "size": 20,
      "sort": [{"@timestamp": {"order": "desc"}}],
      "_source": ["timestamp", "rule.description", "rule.level", "rule.groups", "full_log"],
      "query": {
        "bool": {
          "must": [
            {"match": {"rule.groups": "active_response"}},
            {"match_phrase": {"full_log": srcip}},
            {"range": {"@timestamp": {"gte": "now-" + str(minutes) + "m"}}}
          ]
        }
      }
    }
    return _post_search(payload)
