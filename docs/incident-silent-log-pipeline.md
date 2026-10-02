# Incident: the router's logs went silent for 7.5 hours, and nothing noticed

**Date:** 2026-10-01/02 · **Impact:** loss of router telemetry (firewall and DHCP events) for about 7.5 hours · **Detected by:** a user-visible symptom, not by any alert · **Status:** mitigated; detection gap closed; root-cause fix under observation

## Summary

pfSense stopped forwarding its firewall and DHCP logs to the monitoring server at 23:47 UTC. Nothing alerted. The problem only surfaced hours later, when every device outside the main LAN (phone, console, access point, gaming PC) showed as **offline** in the SOC dashboard while they were clearly online.

## Timeline (UTC)

| Time | Event |
|---|---|
| 23:47 | Last syslog message received from pfSense. Router telemetry stops. |
| ~02:47 | Devices in other zones start flipping to "offline". The dashboard learns about those zones only from DHCP events, and marks a device offline 3 h after its last event. |
| 07:09 | Investigation starts after "my phone and Xbox are online but show offline". |
| 07:14 | Receiver side checked and ruled out (see below). |
| 07:19 | pfSense remote logging restarted; messages flow again immediately. |
| 07:30 | pfSense's device list connected over key-only SSH, removing the dependency on DHCP events for online status. |

## Investigation: work from the receiver back to the sender

```text
$ curl -s localhost:8088/api/state  →  pfsense.lastLog = 2026-10-01 23:47 UTC   (when it stopped)
$ ss -ulnp | grep 5140              →  listener up (python3, sentinel-agent)   (receiver OK)
$ ufw status | grep 5140            →  5140/udp ALLOW 10.20.1.1                (host firewall OK)
$ tcpdump -ni <iface> udp port 5140 →  0 packets in 90 s                       (nothing arriving)
```

`tcpdump` sees packets **before** the host firewall does. Zero packets at the interface therefore means the sender stopped, not that the receiver dropped them. pfSense's remote-logging settings were all still correct (enabled, right server and port, firewall and DHCP events ticked). Toggling remote logging off and on, which restarts its syslog daemon, restored the flow within seconds:

```text
07:18:21 IP 10.20.1.1.514 > 10.20.1.10.5140: SYSLOG local0.info, length: 141
```

Root cause on the router side is unconfirmed (no config change around 23:47). The working theory is a stalled syslog daemon.

**Recurrence:** about an hour after the fix, the feed died again, unnoticed for another ~13 hours. The dashboard did show "No events since 4 h ago", but only to someone who opened that tab. The common factor was **Source Address = LAN**, which binds pfSense's syslog daemon to the LAN interface's address. If that interface or the filter reloads (package updates, Suricata or pfBlockerNG restarts), the daemon can lose its socket and never recover. The source address was changed to **Default (any)**, and the feed resumed immediately. Whether that's the permanent fix is being verified over the following days; the new silence alert means a third failure can't go unnoticed.

## Why it matters

Losing telemetry with no alert is exactly what an attacker tries to arrange. MITRE ATT&CK lists it as **T1562.006, Impair Defenses: Indicator Blocking**. Here the cause was benign, but for 7.5 hours the SIEM would have missed port scans stopped at the router, new devices joining any VLAN, and DHCP activity. The dashboard kept showing **"Threat: Low"** the whole time, which was true only because it couldn't see.

## Fixes

| Done | Change |
|---|---|
| ✅ | Restarted pfSense remote logging; verified with `tcpdump` and the dashboard's "events in the last hour". |
| ✅ | Connected pfSense's device list over key-only SSH, so online status in every zone comes from the router's ARP table every 5 minutes, independent of syslog. Trade-off documented: the monitoring server now holds an admin key to the router. |
| ✅ | Added troubleshooting for this failure to the dashboard's README. |
| ✅ | **Gap closed:** the dashboard now raises a high-severity **"pfSense logs stopped arriving"** alert (T1562.006) after 30 minutes of silence, posts it to Discord, and closes it automatically when logs resume. It only watches a feed that has worked before, and waits 30 minutes after a restart, so it doesn't false-alarm. |

## Lessons

- **Silence isn't safety.** A quiet dashboard can mean nothing is happening, or that you've gone blind. Every log source needs a "last seen" check that alerts.
- **Debug the pipeline end to end, receiver first.** Each check above ruled out one hop, and `tcpdump` settled it in 90 seconds.
- **Don't let presence depend on a single feed.** Online status relied entirely on DHCP log events, so one stalled daemon cascaded into "everything offline". A second, independent source (the router's ARP table) removes that coupling.
