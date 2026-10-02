# Alert tuning: evidence before exceptions

Each finding follows the same steps: **observe, then investigate, verify, decide, scope the rule, and re-check.** An exception is written only when the evidence proves the activity benign, and it is scoped tightly enough that a malicious lookalike still alerts at the original severity.

---

## Finding 1: Rule 92910 flood, "Explorer process was accessed … possible process injection"

**Observed:** about **1,700 level-12 alerts in under 24 h**, all from the Windows agent (Sysmon Event ID 10, ProcessAccess).

**Investigation**
- Source: `C:\Users\<user>\AppData\Roaming\Spotify\Spotify.exe` → target `C:\Windows\Explorer.EXE`
- `GrantedAccess: 0x40`, which is `PROCESS_DUP_HANDLE` only. Injection needs `VM_WRITE (0x20)`, `VM_OPERATION (0x8)` or `CREATE_THREAD (0x2)`, so this handle cannot inject.
- The CallTrace runs through `shcore.dll` → `explorerframe.dll`, the Windows shell's file-dialog components.
- Authenticode signature **Valid**, signer `CN=Spotify AB` (DigiCert G4 code-signing CA).

**Decision:** benign. It is Spotify's file dialog duplicating a handle.

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

**Rule 100101:** a child of 92213 at level 3. It requires **both** the PowerShell binary path **and** the exact `__PSScriptPolicyTest_[a-z0-9]{8}.[a-z0-9]{3}.ps1` name in the user's Temp folder. Any other executable drop still alerts at level 15.

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
