# 🔍 SOC Investigation: Windows Threat Detection 3 – C2, Persistence & Malware Analysis

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-C2%20%7C%20Persistence%20%7C%20Malware%20Detection-007ACC?style=flat)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()
[![Tools](https://img.shields.io/badge/Tools-Sysmon%20%7C%20Security%20Logs%20%7C%20Task%20Scheduler%20%7C%20Registry%20Editor-blue?style=flat)]()

Final room in the Windows threat detection series. This investigation covers what happens when attackers decide to **stay** — Command and Control establishment, four distinct persistence mechanisms, and live malware analysis. Investigated using Sysmon telemetry, Windows Security logs, Task Scheduler, and Registry Editor across five practical scenarios.

**Attack phases investigated:**
> C2 Setup → Backdoor Account Creation → Service Persistence → Scheduled Task Persistence → Startup Folder & Run Key Persistence

---

## 📌 Investigation Summary

| Field | Detail |
|-------|--------|
| **Target Host** | THM-DFIR-VM-3 |
| **Scenario 1** | C2 malware hidden in `AppData\Roaming\update.exe` — C2: `route.m365officesync.workers[.]dev` |
| **Scenario 2** | RDP brute-force (6 failures) → backdoor account `support` created → added to Administrators |
| **Scenario 3** | Service persistence — `nessie.exe` as `Data Protection Service` (Event ID 4697) |
| **Scenario 4** | Scheduled task persistence — `troy.exe` as `AmazonSync` task (Event ID 4698) |
| **Scenario 5** | Startup folder persistence (`odin.cmd`) + Run key persistence (`kitten.exe` — key: `Basket`) |
| **Evidence Sources** | Sysmon EVTX, Security EVTX, Task Scheduler, Registry Editor |
| **Flags Recovered** | `THM{c2_is_on_schedule!}` (Troy), `THM{persisting_in_basket!}` (Kitten) |
| **Outcome** | Full C2 + persistence chain uncovered — 4 persistence mechanisms identified and analysed |

---

## 🎯 Key Findings

| # | Finding | Evidence Source |
|---|---------|----------------|
| 1 | Suspicious archive `URGENT!.zip` downloaded via Chrome — initial delivery vector | Sysmon Event ID 15 |
| 2 | C2 malware hidden at `C:\Users\Administrator\AppData\Roaming\update.exe` | Sysmon Event ID 11 |
| 3 | C2 domain: `route.m365officesync.workers[.]dev` — masquerading as Microsoft | Sysmon Event ID 22 |
| 4 | RDP brute-force — **6 failed logins** to Administrator before success | Security Event ID 4625 |
| 5 | Backdoor account `support` created post-breach | Security Event ID 4720 |
| 6 | `support` added to Administrators group | Security Event ID 4732 |
| 7 | Service persistence — `nessie.exe` registered as `Data Protection Service` | Security Event ID 4697 |
| 8 | Scheduled task `AmazonSync` persisting `troy.exe` — triggered at system startup | Task Scheduler + Event ID 4698 |
| 9 | Startup folder persistence — `odin.cmd` in `\Programs\Startup\` | File system + Sysmon Event ID 11 |
| 10 | Run key persistence — `kitten.exe` in `HKCU\...\CurrentVersion\Run` as `Basket` | Registry Editor + Sysmon Event ID 13 |

---

## 🔎 Investigation Walkthrough

### Phase 1 — Command & Control: Archive Download, C2 Deployment & Callback

**Log File**: `Task 2\Sysmon.evtx`
**Archive Downloaded**: `URGENT!.zip`
**C2 Malware**: `C:\Users\Administrator\AppData\Roaming\update.exe`
**C2 Domain**: `route.m365officesync.workers[.]dev`

Sysmon Event ID 15 (File Stream Created) captured `URGENT!.zip` being downloaded via Chrome — the initial delivery vector. The archive was designed to create urgency, pressuring the user to open it immediately. Once extracted, the phishing content deployed a C2 malware binary, which was deliberately hidden in `AppData\Roaming\` under the innocuous name `update.exe` — designed to blend with legitimate Windows update processes.

Sysmon Event ID 11 confirmed the file creation at `C:\Users\Administrator\AppData\Roaming\update.exe` by `powershell.exe` (PID 3140) — confirming script-based deployment. Sysmon Event ID 22 captured the C2 callback DNS query to `route.m365officesync.workers[.]dev` — a domain crafted to impersonate Microsoft Office 365 services, increasing the chance of bypassing DNS-based filtering.

**Key indicator**: Executable written to `AppData\Roaming\` by PowerShell, followed immediately by a DNS query to a Microsoft-lookalike domain — high-confidence C2 deployment signature.

#### 📸 Screenshot 1 — Sysmon Event ID 15: `URGENT!.zip` Downloaded via Chrome
<img width="1366" height="728" alt="URGENT zip download" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/1_sysmon_urgent_zip_download.png" />

*Sysmon Event ID 15 — Image: chrome.exe, TargetFilename: C:\Users\Administrator\Downloads\URGENT!.zip — phishing archive delivery confirmed*

#### 📸 Screenshot 2 — Sysmon Event ID 11: C2 Malware Hidden at `AppData\Roaming\update.exe`
<img width="1366" height="728" alt="C2 malware hidden" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/2_sysmon_c2_malware_appdata.png" />

*Sysmon Event ID 11 — Image: powershell.exe, TargetFilename: C:\Users\Administrator\AppData\Roaming\update.exe — C2 binary hidden in AppData*

#### 📸 Screenshot 3 — Sysmon Event ID 22: C2 Callback to `route.m365officesync.workers.dev`
<img width="1366" height="728" alt="C2 DNS callback" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/3_sysmon_c2_dns_callback.png" />

*Sysmon Event ID 22 — QueryName: route.m365officesync.workers.dev — Microsoft-lookalike C2 domain confirmed*

---

### Phase 2 — Persistence via Backdoor Account: RDP Brute-Force & User Creation

**Log File**: `Task 3\Security.evtx`
**Failed Logins**: 6 (Event ID 4625)
**Backdoor Account**: `support`
**Group Added To**: Administrators

Security log analysis revealed 6 Event ID 4625 failures against the Administrator account — a targeted brute-force rather than a broad spray. The attacker succeeded and immediately created a backdoor account named `support` — a deliberately generic name designed to appear as a legitimate IT support account.

Event ID 4720 logged the creation of `support` at 7/2/2025 9:01:38 PM. The account name follows a pattern of blending with expected system accounts — `support`, `backup`, `admin` — making it harder to spot during casual user reviews.

**Key indicator**: Account creation (4720) immediately following a successful login that was preceded by multiple 4625 failures from the same source — confirms attacker-created backdoor account.

#### 📸 Screenshot 4 — Security Event ID 4625: 6 Failed Login Attempts to Administrator
<img width="1366" height="728" alt="RDP brute force 4625" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/4_security_brute_force_4625.png" />

*Security Event ID 4625 — 6 failed logon attempts to Administrator — targeted brute-force confirmed before successful login*

#### 📸 Screenshot 5 — Security Event ID 4720: Backdoor Account `support` Created
<img width="1366" height="728" alt="Backdoor account support" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/5_security_backdoor_account_support.png" />

*Security Event ID 4720 — New Account: support — backdoor account created immediately post-compromise at 9:01:38 PM*

---

### Phase 3 — Persistence via Windows Service: `nessie.exe` as `Data Protection Service`

**Log File**: `Task 4\Security (All Time).evtx`
**Service Name**: `Data Protection Service`
**Binary Path**: `C:\Windows\Help\nessie.exe`
**Event ID**: 4697 (Security System Extension)
**Service Start Type**: Automatic (runs on every reboot)

Security Event ID 4697 confirmed a new Windows service registered to run `nessie.exe` from `C:\Windows\Help\` — a legitimate-looking directory chosen to avoid suspicion. The service name `Data Protection Service` was deliberately crafted to sound like a genuine Windows security service.

The service was configured with `LocalSystem` account privileges — the highest available service account — giving `nessie.exe` unrestricted access to the system on every reboot, with no user interaction required.

**Key indicator**: New service (Event ID 4697) with binary path in an unusual directory (`\Windows\Help\`), running as LocalSystem — any new service outside `Program Files` or `Windows\System32` warrants immediate investigation.

#### 📸 Screenshot 6 — Security Event ID 4697: `Data Protection Service` Persisting `nessie.exe`
<img width="1366" height="728" alt="Service persistence nessie" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/6_security_service_persistence_nessie.png" />

*Security Event ID 4697 — Service Name: Data Protection Service, Service File Name: C:\Windows\Help\nessie.exe, Account: LocalSystem — service persistence confirmed*

---

### Phase 4 — Persistence via Scheduled Task: `troy.exe` as `AmazonSync`

**Log File**: `Task 4\` (Task Scheduler + Security Event ID 4698)
**Task Name**: `AmazonSync`
**Binary**: `C:\Program Files\Common Files\troy.exe -d`
**Trigger**: At system startup
**Flag**: `THM{c2_is_on_schedule!}`

Task Scheduler analysis revealed `AmazonSync` — a task named to impersonate a legitimate Amazon synchronisation service. The task action was configured to run `troy.exe` with the `-d` flag (daemon mode) from `C:\Program Files\Common Files\` — a location that appears legitimate to casual inspection.

Running `troy.exe` directly revealed the flag `THM{c2_is_on_schedule!}` and exposed the parent process context — `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule` — the standard parent for scheduled tasks, demonstrating how task-based persistence blends with legitimate Windows scheduling behaviour.

**Key indicator**: Scheduled task (Event ID 4698) with binary in `Common Files` or unusual paths, triggered at startup — especially tasks named to resemble vendor software (`AmazonSync`, `MicrosoftUpdate`, `GoogleSync`).

#### 📸 Screenshot 7 — Task Scheduler: `AmazonSync` Persisting `troy.exe` at Startup
<img width="1366" height="728" alt="Scheduled task AmazonSync" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/7_task_scheduler_amazonsync_troy.png" />

*Task Scheduler — AmazonSync task, Action: C:\Program Files\Common Files\troy.exe -d, Trigger: At system startup — scheduled task persistence confirmed*

#### 📸 Screenshot 8 — `troy.exe` Executed: Flag `THM{c2_is_on_schedule!}` Recovered
<img width="1366" height="728" alt="Troy malware flag" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/8_troy_malware_flag.png" />

*troy.exe output — parent: svchost.exe -k netsvcs -p -s Schedule — confirms scheduled task execution — flag: THM{c2_is_on_schedule!}*

---

### Phase 5 — Persistence via Startup Folder & Run Key

**Log File**: `Task 5\`

#### 5a — Startup Folder: `odin.cmd`
**File**: `odin.cmd`
**Path**: `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
**Last Line Output**: `Done doing bad stuff!`

The Startup folder contained `odin.cmd` — a PowerShell-based script designed to execute on every user login via explorer.exe. Inspecting the source code in Notepad revealed a multi-step malicious routine producing output before ending with `Done doing bad stuff!` — confirming active execution.

**Key indicator**: Any file in `\Programs\Startup\` that is not a known application shortcut — especially scripts (`.cmd`, `.bat`, `.ps1`) — should be treated as suspicious and investigated immediately.

#### 5b — Run Key: `kitten.exe` as `Basket`
**Binary**: `C:\Users\Public\kitten.exe`
**Registry Key**: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
**Value Name**: `Basket`
**Flag**: `THM{persisting_in_basket!}`

Registry Editor revealed a Run key entry named `Basket` pointing to `C:\Users\Public\kitten.exe` — a non-standard executable in a world-writable directory. Run key entries execute automatically on every user login, giving `kitten.exe` guaranteed persistence without requiring administrative privileges.

Running `kitten.exe` revealed the flag `THM{persisting_in_basket!}` and confirmed the Run key value name `Basket` as the persistence identifier.

**Key indicator**: New entries in `HKCU\...\CurrentVersion\Run` pointing to executables in `\Public\`, `\Temp\`, or `\AppData\` — Sysmon Event ID 13 captures these registry writes in real time.

#### 📸 Screenshot 9 — Startup Folder: `odin.cmd` Found + Source Code Revealed
<img width="1366" height="728" alt="Startup folder odin.cmd" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/9_startup_folder_odin_cmd.png" />

*Startup folder — odin.cmd present with PowerShell payload — last output line: "Done doing bad stuff!" confirmed*

#### 📸 Screenshot 10 — Registry Run Key: `kitten.exe` as `Basket` — Flag Recovered
<img width="1366" height="728" alt="Run key kitten Basket" src="https://github.com/ugbomakyrian5-web/windows-threat-detection-3/blob/main/screenshots/10_registry_run_key_kitten_basket.png" />

*Registry Editor — HKCU\...\CurrentVersion\Run, Value: Basket = C:\Users\Public\kitten.exe — Run key persistence confirmed — flag: THM{persisting_in_basket!}*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|----|----------|
| Command & Control | Application Layer Protocol | T1071 | C2 callback to `route.m365officesync.workers.dev` |
| Defense Evasion | Masquerading | T1036 | `update.exe`, `Data Protection Service`, `AmazonSync` — all named to blend in |
| Persistence | Create Account | T1136 | Backdoor account `support` — Event ID 4720 |
| Privilege Escalation | Account Manipulation | T1098 | `support` added to Administrators — Event ID 4732 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | `nessie.exe` as `Data Protection Service` — Event ID 4697 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | `troy.exe` as `AmazonSync` — Event ID 4698 |
| Persistence | Boot or Logon Autostart: Startup Folder | T1547.001 | `odin.cmd` in Startup folder — Sysmon Event ID 11 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | `kitten.exe` as `Basket` in HKCU Run key — Sysmon Event ID 13 |

---

## 🛡 Containment & Hardening Recommendations

### Immediate Response
- **Block `route.m365officesync.workers[.]dev`** at DNS and firewall immediately
- **Delete `C:\Users\Administrator\AppData\Roaming\update.exe`** — C2 binary confirmed
- **Disable and delete `support` account** — backdoor account confirmed
- **Remove `Data Protection Service`** — `sc delete "Data Protection Service"`
- **Delete `AmazonSync` scheduled task** — `schtasks /delete /tn AmazonSync /f`
- **Remove `odin.cmd`** from Startup folder
- **Delete `Basket` Run key entry** — `reg delete HKCU\...\Run /v Basket /f`

### Detection Rules (SIEM)

C2 binary dropped to AppData by PowerShell
Alert: Sysmon Event ID 11 — Image contains powershell.exe
AND TargetFilename contains \AppData\Roaming\ AND .exe extension

Microsoft-lookalike C2 domain
Alert: Sysmon Event ID 22 — QueryName contains "microsoft" OR "office365"
OR "windows" AND domain NOT in approved list

Backdoor account creation post-brute-force
Alert: Security Event ID 4720 within 10 minutes of 3+ Event ID 4625
from same source IP

Malicious Windows service
Alert: Security Event ID 4697 — ServiceFileName NOT starting with
C:\Windows\System32\ OR C:\Program Files\

Suspicious scheduled task
Alert: Security Event ID 4698 — TaskContent contains path outside
Program Files or Windows — especially \Public, \AppData, \Temp\

Startup folder persistence
Alert: Sysmon Event ID 11 — TargetFilename contains
\Start Menu\Programs\Startup\ AND Image NOT in known-good list

Run key modification
Alert: Sysmon Event ID 13 — TargetObject contains
\CurrentVersion\Run AND Details contains \Public\ OR \AppData\ OR \Temp\

### Hardening
- **Audit all services and scheduled tasks weekly** — flag any not in approved baseline
- **Monitor `AppData\Roaming\` for executable drops** — no legitimate software installs there
- **Restrict Run key write access** via Group Policy where possible
- **Enable Security Event ID 4697 and 4698 alerting** in SIEM — many environments miss these
- **Block `workers.dev` wildcard domain** — commonly abused for C2 infrastructure

---

## 📌 Investigator Notes

> Persistence is where attackers reveal their patience — and their tradecraft.
>
> Every persistence method in this investigation was designed to blend in:
> `update.exe` — looks like a Windows update process
> `Data Protection Service` — sounds like a legitimate security service
> `AmazonSync` — impersonates vendor software
> `support` account — blends with IT helpdesk accounts
> `Basket` Run key — generic enough to be overlooked
>
> The lesson: persistence detection cannot rely on name-based filtering alone.
> It requires baselining — knowing what services, tasks, accounts, and Run keys
> are expected on a system and flagging anything that deviates from that baseline.
>
> Every attacker leaves a trail. The question is whether you baseline before they arrive.

---

## 📌 Persistence Mechanisms Reference

| Method | Event ID | Where to Look |
|--------|----------|---------------|
| Backdoor account | 4720 + 4732 | Security log |
| Windows service | 4697 | Security log |
| Scheduled task | 4698 | Security log |
| Startup folder | Sysmon 11 | `\Programs\Startup\` |
| Run key | Sysmon 13 | `HKCU\...\CurrentVersion\Run` |

---

## 📌 Skills Demonstrated

- C2 infrastructure detection — archive delivery, binary hiding, domain masquerading
- Backdoor account investigation — brute-force correlation + 4720/4732 analysis
- Windows service persistence detection — Event ID 4697 analysis
- Scheduled task persistence detection — Task Scheduler + Event ID 4698 analysis
- Startup folder and Run key persistence identification
- Live malware execution and flag extraction
- MITRE ATT&CK mapping across C2 and persistence phases
- Structured, SOC-grade incident documentation

---

**Completed**: May 2026

Full portfolio of SOC investigations available at [github.com/ugbomakyrian5-web](https://github.com/ugbomakyrian5-web)

Feel free to fork, star, or reach out. Open to feedback and collaboration!

MIT License – see the [LICENSE](LICENSE) file for details.
