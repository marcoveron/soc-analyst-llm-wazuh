# Lab setup: custom Active Response scripts

The agent ships four custom Active Responses beyond the stock `firewall-drop`:

| Script           | Tool                              | ar.conf name (timeout `no`) |
|------------------|-----------------------------------|-----------------------------|
| `firewall-allow` | `unblock_ip_tool`                 | `firewall-allow0`           |
| `isolate-host`   | `isolate_host_tool`               | `isolate-host0`             |
| `unisolate-host` | `unisolate_host_tool`             | `unisolate-host0`           |
| `kill-process`   | `kill_process_tool`               | `kill-process0`             |

Each one is: (1) a script copied to the VICTIM's `active-response/bin/`, and (2) a
`<command>` + `<active-response>` pair declared on the MANAGER with `<timeout>no</timeout>`
(so the ar.conf name gets the `0` suffix the agent's tool expects). Pattern is identical
for all of them — `firewall-allow` below is the worked example; the rest follow it.

## `firewall-allow` (unblock)

Wazuh has no clean API "delete" for `firewall-drop` (it only self-removes when its
`<timeout>` expires). To support `unblock_ip_tool`, add a custom Active Response that
runs `iptables -D`. Do this once in the lab.

## 1. Install the script on the VICTIM agent (192.168.100.77)

```bash
sudo cp firewall-allow /var/ossec/active-response/bin/firewall-allow
sudo chown root:wazuh /var/ossec/active-response/bin/firewall-allow
sudo chmod 750 /var/ossec/active-response/bin/firewall-allow
```

## 2. Declare the AR on the MANAGER (monitor, 192.168.100.79)

Edit `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<command>
  <name>firewall-allow</name>
  <executable>firewall-allow</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>firewall-allow</command>
  <location>local</location>
  <timeout>no</timeout>
</active-response>
```

`<timeout>no</timeout>` makes the ar.conf entry `firewall-allow0`, which matches the
default `WAZUH_AR_UNBLOCK_COMMAND` in `wazuh_server_api.py`.

Then restart the Manager:

```bash
sudo systemctl restart wazuh-manager
```

## 3. Verify the agent received it

On the VICTIM, the distributed ar.conf should now include the unblock command:

```bash
sudo cat /var/ossec/etc/shared/ar.conf   # expect a line: firewall-allow0 - firewall-allow - 0
```

## 4. Test

Block an IP, then unblock it from the agent, and check on the victim:

```bash
sudo tail -n 10 /var/ossec/logs/active-responses.log
sudo iptables -S INPUT | grep <ip>      # the DROP rule should be gone
```

---

# `isolate-host` / `unisolate-host` (endpoint quarantine)

EDR-style containment: drop all the endpoint's traffic except the Wazuh Manager, so a
compromised host stays managed (and can be un-isolated remotely) but can't reach
attackers. `isolate-host` keeps loopback + established + the Manager IP and sets the
default policies to DROP; `unisolate-host` restores ACCEPT and removes the isolation
rules. Both tag their rules with the `WAZUH_ISOLATION` iptables comment.

> The Manager IP defaults to `192.168.100.79`; override on the victim with
> `WAZUH_MANAGER_IP` if your lab differs. **Recovery note:** if isolation locks you out
> of SSH, the un-isolation AR still reaches the agent (Manager traffic is allowed), or
> use the VM console.

## 1. Install both scripts on the VICTIM

```bash
for s in isolate-host unisolate-host; do
  sudo cp "$s" /var/ossec/active-response/bin/"$s"
  sudo chown root:wazuh /var/ossec/active-response/bin/"$s"
  sudo chmod 750 /var/ossec/active-response/bin/"$s"
done
```

## 2. Declare them on the MANAGER (`/var/ossec/etc/ossec.conf`)

```xml
<command>
  <name>isolate-host</name>
  <executable>isolate-host</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
  <command>isolate-host</command>
  <location>local</location>
  <timeout>no</timeout>
</active-response>

<command>
  <name>unisolate-host</name>
  <executable>unisolate-host</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
  <command>unisolate-host</command>
  <location>local</location>
  <timeout>no</timeout>
</active-response>
```

Restart the Manager (`sudo systemctl restart wazuh-manager`); the victim's `ar.conf`
should then list `isolate-host0` and `unisolate-host0`.

---

# `kill-process` (terminate a process)

Kills a process on the endpoint by PID or name. The target comes from the AR
`arguments` field (`kill_process_tool` passes the PID/name there). Numeric → `kill -9`
by PID; otherwise → `pkill -9 -x` by exact name. Needs `python3` on the victim (used to
parse the AR JSON).

## 1. Install on the VICTIM

```bash
sudo cp kill-process /var/ossec/active-response/bin/kill-process
sudo chown root:wazuh /var/ossec/active-response/bin/kill-process
sudo chmod 750 /var/ossec/active-response/bin/kill-process
```

## 2. Declare on the MANAGER

```xml
<command>
  <name>kill-process</name>
  <executable>kill-process</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<active-response>
  <command>kill-process</command>
  <location>local</location>
  <timeout>no</timeout>
</active-response>
```

Restart the Manager; the victim's `ar.conf` should list `kill-process0`.

## 3. Test the script standalone (no API needed)

```bash
sleep 600 &                       # a throwaway target process
echo '{"command":"add","parameters":{"extra_args":["'"$!"'"]}}' \
  | sudo /var/ossec/active-response/bin/kill-process
sudo tail -n 3 /var/ossec/logs/active-responses.log   # "killed PID ..."
```
