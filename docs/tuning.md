# Alert tuning: evidence before exceptions

Each finding follows the same steps: **observe, then investigate, verify, decide, scope the rule, and re-check.** An exception is written only when the evidence proves the activity benign, and it is scoped tightly enough that a malicious lookalike still alerts at the original severity.

---

## Finding 1: Rule 92910 flood, "Explorer process was accessed … possible process injection"

**Observed:** about **1,700 level-12 alerts in under 24 h**, all from the Windows agent (Sysmon Event ID 10, ProcessAccess).

**Investigation**
- Source: `C:\Users\<user>\AppData\Roaming\Spotify\Spotify.exe` → target `C:\Windows\Explorer.EXE`
- `GrantedAccess: 0x40`, which is `PROCESS_DUP_HANDLE` only. It has none of the rights normally used for injection (`VM_WRITE 0x20`, `VM_OPERATION 0x8`, `CREATE_THREAD 0x2`).
- **Correction (found during a later review):** my first write-up said this handle "cannot inject". That's wrong. Microsoft's documentation warns that a process holding `PROCESS_DUP_HANDLE` on another process can duplicate that process's own pseudo-handle and get a **full-access** handle. So 0x40 is not harmless by itself, and the tuning can't rest on the access mask alone.
- The CallTrace runs through `shcore.dll` → `explorerframe.dll`, the Windows shell's file-dialog components.
- Authenticode signature **Valid**, signer `CN=Spotify AB` (DigiCert G4 code-signing CA).

**Decision:** benign. It is Spotify's file dialog duplicating a handle. The case rests on the **combination**: the signed binary, its exact install path, the shell file-dialog call trace, a steady volume matching normal use, and the mask.

**Residual risk (accepted, documented):** the path is under the user's `AppData`, which the user can write to, and Sysmon access events don't carry a signature. A look-alike `Spotify.exe` dropped there by malware would match the rule. Two things limit this: the event is downgraded to level 3, not dropped, so it's still searchable; and process creation of that path is logged separately with hashes (Sysmon event 1). Requiring the file-dialog call trace in the rule would raise the bar further.

**Rule 100100:** a child of 92910 at level 3. It matches **only** Spotify's exact path **and** access mask `^0x40$`, so any other process, or Spotify with a different mask, still alerts at level 12.

**Verification:** level-12 alerts from this source stopped at the moment of deployment, and the events now land as level 3 under rule 100100.

## Finding 2: Checking the tuning left no blind spot

About 11 minutes after deployment, rule 92910 fired at level 12 for a *different* process, which shows the exception was correctly narrow:
- `OneDrive.exe` → Explorer, `GrantedAccess 0x101411` (SYNCHRONIZE | QUERY_LIMITED_INFORMATION | QUERY_INFORMATION | VM_READ | TERMINATE): read-only, with no write, operation or thread rights.
- Call trace via `FileSyncClient.dll` (sync-status overlays). Signature Valid, `CN=Microsoft Corporation`.
- **Decision:** benign, but **no exception was written**. It fired once, and I tune only on recurrence.

## Finding 3: Rule 92213, critical (level 15), "Executable file dropped in folder commonly used by malware"

**Observed:** 2 hits, at the same minutes I opened PowerShell to verify the signatures for Findings 1–2.

**Investigation**
- Sysmon Event ID 11 (FileCreate) by `powershell.exe`, target `…\AppData\Local\Temp\__PSScriptPolicyTest_<8>.<3>.ps1`.
- PowerShell writes and deletes this file on every start to test AppLocker and execution policy. Public Sigma rules exclude the same artifact. The file was already gone (`Test-Path` False).

**Lesson:** *my own investigation generated the critical alert.* Correlate alert times with analyst activity before escalating.

**Rule 100101:** a child of 92213 at level 3. It requires **both** a PowerShell binary (Windows PowerShell, ISE, or PowerShell 7) **and** the exact `__PSScriptPolicyTest_[a-z0-9]{8}.[a-z0-9]{3}.ps1` name in the user's Temp folder. Any other executable drop still alerts at level 15.

**Verification:** reopening PowerShell produced the event at level 3 under rule 100101, with no level-15 alert.

## Finding 4: Boot-time burst on the Windows agent

**Agent queue flooding:** after the PC was off overnight, the agent reported its queue 90 % full and then flooded, losing events. I raised `client_buffer` (queue 50,000, 1,000 events/s) through a **centralized `agent.conf`** (group `default`, `os=Windows`), so the change is managed from the server.

**Rule 92043, "Netsh used to add firewall rule" (level 10, T1562.004):**
- The command line adds an inbound allow rule named `Tailscale-In`. The parent is `C:\Program Files\Tailscale\tailscaled.exe` running as SYSTEM.
- Tailscale re-creates its own firewall rule on every service start, so this fires twice per boot and is benign.
- **Rule 100102:** a child of 92043 at level 3. It requires the parent to be `tailscaled.exe` **and** the command line to name `Tailscale-In`. Any other netsh firewall change still alerts at level 10.

**Rule 60110, "User account changed" (Event 4738, level 8, T1098):**
- The subject is the computer account (SYSTEM) updating the local user's attributes during sign-in and Microsoft-account sync.
- **Left untuned on purpose.** It's low volume, and a 4738 by a *user* subject would be meaningful.

---

## Results

| | Before | After |
|---|---|---|
| Level-12 alerts/day from Finding 1 | ~1,700 | 0 (logged at level 3) |
| Level-15 alerts from Finding 3 | 2 per PowerShell launch | 0 (logged at level 3) |
| Level-10 alerts from Finding 4 | 2 per boot | 0 (logged at level 3) |
| Events lost to agent queue overflow at boot | yes | none observed |

The tuned events are **downgraded, not dropped**. They stay searchable, and [`scripts/wazuh-alert-summary.py`](../scripts/wazuh-alert-summary.py) reports how often each tuning rule still matches.

## Vulnerability reduction (same period)

| | Total | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| Before | 13,664 | 1,201 | 5,133 | 979 | 254 |
| After | 10,297 | 745 | 3,929 | 832 | 232 |

Most of the drop came from old kernels (7.0.0-31) still installed next to the running one. The vulnerability feed matched CVEs against every installed kernel package. Purging them (about 345 MB and 319 MB on the two Ubuntu hosts) and applying pending security updates cut **25 % of all findings and 38 % of critical ones**.

---

## Finding 5: Three-day review with the alert-summary script

**12,887 alerts in 3 days:** 4,943 low / 2,312 medium / 5,627 high / 5 critical. The script ([`scripts/wazuh-alert-summary.py`](../scripts/wazuh-alert-summary.py)) ranks rule+agent pairs by volume and separately lists *every* alert at level 10 or above, so rare high-severity rules can't hide below the noise.

Two bugs I fixed in my own tooling along the way, both worth knowing:
- An OpenSearch aggregation bug (`multi_terms` combined with `top_hits` throws "this.scorer is null" on some shards) made the first report say **0 alerts**. OpenSearch returned HTTP 200 with half the shards failed. The script now fails loudly on any shard failure, because a silently empty SIEM report is worse than an error.
- Indexed alerts nest decoded fields under `data.` (`data.win.eventdata.image`), while rules refer to them without the prefix (`win.eventdata.image`).

### 5a: Critical cluster: app auto-updates (triaged, not tuned)
Within 6 minutes on the Windows host: rule 92213 (level 15) ×5, rule 92041 "Base64-like registry value" ×4, and rule 92058 "Application Compatibility Database launched" ×1. The drill-down showed:
- Spotify (Chromium-based) unpacking four `.js` files into Temp
- `BraveUpdate.exe` dropping a `brave_installer-delta-x64.exe`
- Discord updating 1.0.9259 → 1.0.9260 and re-registering its `discord://` handler with `reg.exe` (the "Base64-like" values)
- `sdbinst.exe -m -bg` run by `svchost` (Windows updating its compatibility database)

**Decision:** benign. **Not tuned**: these are rare and only fire when apps update. The existing PowerShell rule (100101) correctly did *not* match these files, so they reached me at full severity, which is how it should work.

### 5b: OneDrive, 5,591 level-12 alerts (Finding 2 recurred, so now tuned)
- `OneDrive.exe` → `Explorer.EXE`, access `0x40` (5,617 of the 5,626 events of rule 92910 had that mask). The rest were Discord (28) and MSI Center (7, mask `0x1410`, read-only); both are low volume and left alone.
- Every OneDrive call trace runs `ntdll → KERNELBASE → shcore → windows.storage → FileSyncClient / SyncEngine`, which is OneDrive's sync engine updating overlay icons through the shell storage API.
- **Rule 100103** requires all three: the OneDrive path, mask exactly `0x40`, **and** that call trace. Because of the `0x40` correction in Finding 1, the call trace is the main evidence, not the mask.

### 5c: "Device enables promiscuous mode", 1,716 level-10 alerts on the SIEM server: **my own SOC tool**
- Rule 80710 (auditd `ANOM_PROMISCUOUS`) on `enp1s0`, at exactly **24 per hour** (one on and one off every 5 minutes) for 3 days, from a background service (auid unset).
- Sentinel's discovery loop runs `arp-scan` every 300 s. Running `arp-scan` by hand produced the same pair of records:
  - turning it **on** is `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP)`
  - turning it **off** is the `close()` on the socket
  - both carry `exe="/usr/sbin/arp-scan"`
- The hex `proctitle` in Sentinel's own events decodes to Sentinel's exact scan command line.
- Wazuh's decoder didn't put `exe` into its own field, but it **is** in the full log. So **rule 100104** matches `comm="arp-scan" exe="/usr/sbin/arp-scan"` plus `dev=enp1s0`.
- **Why not just downgrade 80710?** A rule that ignored every promiscuous-mode event from a background service would also hide a real packet sniffer running as root (T1040). Scoping to the binary keeps that detection.
- **Residual risk:** root could replace `/usr/sbin/arp-scan` with a sniffer. AIDE and Wazuh FIM both watch `/usr/sbin`, so a swapped binary raises its own alert.
- **Lesson:** monitoring tools generate security telemetry too. The SOC dashboard was the single largest source of level-10 alerts on its own host.

| Source | Before (3 days) | After |
|---|---|---|
| OneDrive → Explorer (92910, level 12) | 5,591 | level 3 under rule 100103 |
| Sentinel arp-scan (80710, level 10) | 1,716 | level 3 under rule 100104 |
