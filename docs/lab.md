# Isolated lab target and log pipeline

This lab gives the SIEM real web-application telemetry to work with, without putting anything vulnerable on the home network.

## Containment

| Layer | Control |
|---|---|
| Network | Kali box on the **Lab VLAN (10.20.40.0/24)**, which pfSense blocks from every other zone |
| Firewall exception | **One** pass rule: Kali `/32` → Wazuh server `/32`, TCP **1514–1515** (agent traffic only). Verified with `nc -zv` |
| Application | DVWA published on **`127.0.0.1:8080`** only; its MariaDB has **no published port** (reachable only on a private Docker network). Verified with `ss -tlnp` |
| Agent | Wazuh agent **pinned to the manager's version** and held (`apt-mark hold`), because Kali's rolling updates would otherwise outrun the 4.14.8 manager |

## Build notes

- **DVWA needs its own database.** The `digininja/dvwa` image ships without one and fails with `mysqli_sql_exception: Connection refused`. The fix is a separate MariaDB container on a user-defined network (`dvwa-net`) and `DB_SERVER=dvwa-db`.
- **DVWA logs only to Docker's console output.** The web server's logs are symlinked to stdout, which the agent can't read. Mounting a host folder over `/var/log/apache2` makes the web server write real files, and the agent tails `access.log` and `error.log` with `log_format apache`.

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/dvwa/access.log</location>
</localfile>
```

## Baseline before any testing

| Metric | Value |
|---|---|
| SCA (CIS Distribution Independent Linux v2.0.0) | 45 % (83 pass / 99 fail) |
| Vulnerabilities | 1 medium |

## Pipeline verification

Before treating silence as meaningful, I proved the path works with a harmless request for a page that doesn't exist:

```text
GET /does-not-exist → 404 → /var/log/dvwa/access.log → agent → manager → indexer
Rule 31101 "Web server 400 error code" (level 5), decoder web-accesslog,
data.url /does-not-exist, PCI DSS 6.5/11.4, NIST SA.11/SI.4
```

## Gaps documented

1. **The source IP is always the Docker gateway.** Every request arrives through `docker-proxy`, so every web alert shows `srcip 172.18.0.1` instead of the real client. That breaks per-source correlation and blocking. Fixes for a multi-host setup: `--network host`, or a reverse proxy that passes `X-Forwarded-For` along with a log format that records it.
2. **Status-code-blind failed logins.** Repeated failed logins to the app produced **no alert**, because the app answers a wrong password with a normal `200 OK` page. Wazuh's stock web rules key on error responses (4xx/5xx), so failed authentication that looks like success is invisible to them. Because the pipeline had just been verified with the 404 test, I could show this was a detection gap rather than a broken pipeline.

## Noise found on the new agent

**Observed:** bursts of about 5 USB attach/detach events (rules 81101/81102, level 3) every few minutes on the Kali agent.

**Investigation:** the kernel log showed the whole tree behind one hub re-enumerating together. A USB KVM switch controller (ASIX AX68004) sat behind a Genesys hub, with a keyboard and a wireless mouse receiver behind it. The device numbers kept climbing, which means repeated reconnects. No storage device was involved (`lsblk` showed only the internal NVMe drive). The bursts lined up with me switching the shared keyboard and mouse between my PC and the lab box.

**Decision:** explained and benign, but **not tuned**. The events are level 3, already below the level-7 threshold that sends alerts to Sentinel, so nothing pages. A USB storage attach on a lab host is security-relevant (T1052, T1091) and must keep alerting, and a tuning rule scoped to the KVM's port would also hide a USB stick plugged into that hub. Not every noisy rule needs an exception. Sometimes the right fix is knowing why it's noisy and filtering the view.
