# Hardening the SIEM server against CIS

The SIEM is the most valuable box on the network, so I hardened it first and measured the work with Wazuh's own Security Configuration Assessment (SCA).

**Result: 47 % → 67 % (103 → 64 failed checks) in 6 batches, with zero lockouts and one planned reboot.**

## Problem 0: the benchmark never ran

Configuration Assessment showed **"No scans available"** for the server, even though SCA was enabled.

- **Root cause** (found in the agent's `ossec.log`): Wazuh ships only `cis_ubuntu22-04.yml`. Its requirements block checks `/etc/os-release` for "Ubuntu 22.04", so on 26.04 the policy was **silently skipped** in 0 seconds on every run.
- **Fix:** a custom policy, `cis_ubuntu26-04_custom.yml`, copied from 22.04 with a new policy ID and version requirement, referenced from `<sca><policies>` in the agent config.
- **Debugging along the way:**
  - The first attempt reused the policy ID, so it was ignored.
  - The next one hit duplicate check IDs, because check IDs must be unique across *every* loaded policy and the stock 22.04 policy still loads. I shifted all 207 check IDs by +900000.
- **Caveat:** the benchmark targets 22.04. Most controls (SSH, PAM, permissions, sysctl, auditd) carry over, but a few misreport. Those are listed under benchmark defects below.

## Batches

Each batch followed the same pattern: back up, change, validate syntax, test from a **second** session before closing the first, then rescan.

| # | Changes | Score |
|---|---|---|
| Baseline | 207 checks: 93 pass / 103 fail / 11 N/A | **47 %** |
| 1 | Permissions on cron, `sshd_config` and `opasswd`; removed telnet, ldap-utils and ftp; disabled avahi, cups, bluetooth and apport; login banners | 55 % |
| 2 | auditd plus 27 CIS audit rules, `keep_logs`, audit tool permissions; `audit.log` shipped to Wazuh | 59 % |
| 3 | SSH drop-in `sshd_config.d/00-cis.conf`: no root login, `AllowUsers`, MaxAuthTries 4, MaxStartups, LoginGraceTime, keepalives, banner, ETM MACs. Validated with `sshd -t` | 63 % |
| 4 | PAM: pwquality (minlen 14, 4 classes, dictcheck), faillock (deny 5, unlock after 900 s), pwhistory (remember 24). Applied via `pam-auth-update` profiles, with a root shell kept open as a safety net | 65 % |
| 5 | AIDE file integrity (daily check), local-only postfix for its reports, AppArmor utilities; GRUB `apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192`; **planned reboot** | 65 % (2 new findings caused by the new packages) |
| 6 | Targeted fixes after reading each check's actual SCA rule: smtp listener disabled, memtest GRUB entries removed, CIS-style `aidecheck.timer`, audit tools covered by AIDE, `opasswd` permissions | **67 %** |

Post-reboot health check: kernel command line correct, AppArmor loaded (237 profiles), audit backlog 8192, and all agents and services back, including the 3 Wazuh containers.

## Ubuntu 26.04 gotchas worth knowing

- **sudo-rs** replaces sudo and rejects `Defaults logfile=` (`visudo: unknown setting`). I reverted immediately and kept `timestamp_timeout=15`. Always run `visudo -c`.
- **Socket-activated sshd** (`ssh.socket`): "ssh.service is not active, cannot reload" is expected. Each new connection reads the config, so test with a fresh session.
- Removing `ftp` pulls in `ftp-ssl`, because `ubuntu-standard` depends on an FTP client. Check 712 was accepted as a risk.

## Accepted risks (documented, not fixed)

| Control | Why accepted |
|---|---|
| Separate partitions and mount options (21 checks) | Needs a reinstall |
| Bootloader password | Physical-access threat model; it would block unattended reboots |
| Root password | Ubuntu locks root by design |
| Forced password expiry | NIST SP 800-63B advises against it |
| timesyncd | chrony is used instead |
| nginx / X / GDM present | Needed by Sentinel and the desktop |
| iptables/nftables alternatives | ufw plus Docker manage the firewall |
| auditd `-e 2` (immutable), `admin_space_left_action=halt` | A full disk would halt the SIEM itself |

## Benchmark and tooling defects found

These checks **fail even though the setting is applied**. I verified each one against the live system and the check's SCA rule text:

| Check | Defect |
|---|---|
| 593 | The rule `not f:/etc/default/grub -> !r:audit_backlog_limit` fails on any normal GRUB file. The live value is 8192 (`auditctl -s`) |
| 598 | Expects `auid!=unset\|4294967295`, but audit 4.x prints `auid!=-1` |
| 601 | File-rule paths (`/etc/security/nsswitch.conf`) contradict the live-rule paths (`/etc/nsswitch.conf`) |
| 604 | Expects `/etc/apparmor/` with a trailing slash; `auditctl -l` prints it without one |
| 610–612 | Run `stat` on `/sbin/autrace`, which audit 4.x removed, so they can never pass |
| 656, 659 | sudo-rs has no logfile support, and the check anchors on `^timestamp_timeout` (invalid sudoers syntax). The setting is applied |
| 730, 731 | Require the dictcheck/enforcing lines inside `common-password`, which would break PAM. The settings are applied in `pwquality.conf` |

**Remaining 64 failures** = partitioning (21) + the accepted risks above + the defects above.
