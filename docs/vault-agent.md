# Monitoring the password vault without opening a door

The password manager (Vaultwarden) runs on a dedicated Raspberry Pi 5 in its own firewall zone, reachable only over Tailscale from personal devices. The network design is in [Desk-Pi-Rack](https://github.com/KevinTechLabs/Desk-Pi-Rack/blob/main/network/vault.md). This write-up covers bringing that Pi into the SIEM: getting visibility into the most valuable box on the network **without giving the SIEM a way to control it**.

**Result:** agent online with active response disabled, file-integrity monitoring on the vault's critical files, and CIS score raised **42 % → 61 %** on a single-purpose ARM board. A validation test also caught a server that could still reach the vault.

## Design constraints

| Concern | Decision |
|---|---|
| The SIEM server is a bigger target than the vault (Docker, dashboards, more software) | The agent may only send data **out**. Wazuh **active response is disabled** on this agent, so a compromised manager can't run commands on the vault |
| The vault zone can't start connections to any internal network | One pfSense pass rule, scoped as narrowly as the Kali lab exception: vault `/32` → Wazuh server `/32`, TCP **1514–1515** |
| The Wazuh server can't start connections into the vault zone | Unchanged. The agent connects out and the manager replies over that session |
| Remote-control agents (NexusLab, Portainer) | Not installed on this Pi |

## Agent setup

1. **pfSense, VAULT tab.** Pass rule TCP 1514–1515 to the Wazuh server, placed **above** the "block all internal networks" rule. Until the rule existed, the agent log showed `Requesting a key from server` with no reply and the enrollment port test failed.
2. **Install** the arm64 agent at or below the manager's version, with `WAZUH_MANAGER` and `WAZUH_AGENT_NAME=vault`.
3. **Lock it down** in `ossec.conf`:

```xml
<active-response>
  <disabled>yes</disabled>
</active-response>
```

4. **Watch the files that matter** in real time:

```xml
<syscheck>
  <directories realtime="yes" check_all="yes">/home/<user>/vaultwarden/compose.yml</directories>
  <directories realtime="yes" check_all="yes">/home/<user>/vaultwarden/data/rsa_key.pem</directories>
  <directories realtime="yes" check_all="yes">/home/<user>/.ssh</directories>
  <directories realtime="yes" check_all="yes">/usr/local/bin/vw-backup.sh</directories>
  <directories realtime="yes" check_all="yes">/var/spool/cron/crontabs</directories>
</syscheck>
```

The vault database itself is **not** watched. It changes every time a password is used, so watching it would only generate noise. The compose file, signing key, SSH keys, backup script and crontab should almost never change. A change to any of them is worth an alert.

### Verification

| Check | Result |
|---|---|
| Agent log | `Valid key received`, then `Connected to the server (…:1514/tcp)` |
| Dashboard | Agent `vault` (007) **Active** |
| FIM test | `touch /usr/local/bin/vw-backup.sh` → rule **550 "Integrity checksum changed"** (level 7) |
| Active-response lock | Agent log shows `active response queue (disabled)` whenever the manager pushes a command. This is expected, and it proves the lock works |

## Validation finding: a server could still reach the vault

The Tailscale policy grants personal (untagged) devices access to everything, and grants servers (`tag:server`) access only to each other. The vault relies on every server being tagged.

While testing the agent, `tailscale status` on the vault showed two machines still owned by a user instead of a tag: **nexus-ai** (an AI server) and an old **Kali** install. That made both of them count as "personal" devices, so both could reach the vault.

| Test from nexus-ai | Result | Meaning |
|---|---|---|
| `curl -m5 -k https://<vault Tailscale IP>` before tagging | `TLS connect error … tlsv1 alert internal error` | **Reachable.** The TCP connection got through, and only the TLS handshake failed because the request used an IP instead of the hostname |
| Same command after tagging `tag:server` | `Connection timed out after 5002 milliseconds` | Blocked by the Tailscale policy |

**Lesson:** a TLS error is not a block. Any reply at all means the network path is open. Only a timeout proves the policy is working. A tag-based policy also fails *open* for any machine someone forgets to tag, so after adding a device, check the Machines list for anything that isn't tagged.

## CIS hardening (CIS Debian Linux 13 Benchmark)

Same method as the [SIEM server](hardening.md): back up, change, validate syntax, test from a **second** SSH session before closing the first, then rescan. Vaultwarden health (`docker ps`), Tailscale and a phone sync were checked after every batch.

| Step | Changes | Score |
|---|---|---|
| Baseline (after `/tmp` and `/dev/shm` moved to `tmpfs` with `nosuid,nodev,noexec`) | 207 checks: 78 pass / 106 fail / 23 N/A | **42 %** |
| Batches 1–4 | avahi and bluetooth masked; login banners; cron permissions; root password locked; `login.defs` defaults; SSH drop-in (banner, keepalives, `DisableForwarding`, `LoginGraceTime`, `MaxAuthTries 4`, `MaxStartups`, ETM MACs); sudo log file and timeout validated with `visudo -cf`; `su` restricted to an empty group; auditd, AppArmor and pwquality installed; 31 audit rules written for arm64 | **60 %** (114 / 76 / 17) |
| Follow-up | auditd `keep_logs`, PAM `nullok` removed, pwquality PAM profile | **61 %** (116 / 74 / 17) |

### ARM-specific gotcha

The audit-rule checks keep failing even though `auditctl -l` shows 31 rules loaded. The CIS rule text uses older system-call names such as `open`, `chmod` and `rename`. **64-bit ARM (aarch64) doesn't have those calls at all**, only the `*at` versions (`openat`, `fchmodat`, `renameat2`). Rules written for this hardware are correct but can never match the check text. This is the same class of problem as the [benchmark defects](hardening.md#benchmark-and-tooling-defects-found) found on the SIEM server.

### Accepted risks

| Control | Why accepted |
|---|---|
| Separate partitions for `/home`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit` | Needs a reinstall; little value on a single-user, single-container Pi |
| nftables and iptables sections, "ufw not in use" | CIS has three mutually exclusive firewall sections, so some always fail. ufw is used on the host, and pfSense is the main firewall |
| Bootloader / GRUB | The Pi doesn't use GRUB |
| chrony | Time is kept by systemd-timesyncd |
| rsyslog, journal-remote | Logs already reach the SIEM through the agent |
| faillock, pwhistory, password expiry | Login is by SSH key only. These would only lock the owner out of `sudo` or the local console |
| AIDE | Wazuh file-integrity monitoring already covers the files that matter |
| Halt or single-user mode when the audit disk fills | It would take the password manager offline. The drive is 2 TB |

### Open items

A few batch-1 controls (banner file permissions, the root lock check, `login.defs` values, the sudo timeout) still report as failed after being applied. The next step is to read each check's SCA rule text against the live files, as was done for the SIEM server, before deciding whether each one is a real gap or a benchmark defect.
