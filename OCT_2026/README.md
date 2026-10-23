# App Control for Business (WDAC) — Multi-Policy STIG Guide (Scripts + Wizard, No GPO)

> [!NOTE]
> This guide takes a Windows 11 Privileged Access Workstation (PAW) from **"no custom App Control policy"** to an **enforced, multiple-policy-format base policy** that allows every application the PAW needs and blocks everything else. It closes DISA PAW STIG **V-243450** and **V-243451** (`Win32_DeviceGuard` = **`2 / 2`**). Run it end to end with the **App Control Policy Wizard** (three GUI steps) and the **scripts** in `scripts\` (PowerShell 7) or `scripts\pwsh_5.1\` (Windows PowerShell 5.1). No agent, GPO, or code-signing PKI is required.

> [!IMPORTANT]
> **Managed Installer (Option 13) is ON in this guide.** Software deployed by **MECM** (Microsoft Configuration Manager) or **Intune** is trusted automatically once that tool is set up as a *managed installer*. The option has **no effect until the managed installer is configured** on the device. See **[2. Managed Installer (MECM / Intune)](#2-managed-installer-mecm--intune)**.

---

## Contents

1. [Overview](#1-overview)
2. [Managed Installer (MECM / Intune)](#2-managed-installer-mecm--intune)
3. [Plan Your Run](#3-plan-your-run)
4. [Scripts at a Glance — Run Order](#4-scripts-at-a-glance--run-order)
5. [Phase 1 — Prepare (Step 0)](#5-phase-1--prepare-step-0)
6. [Phase 2 — Baseline Audit Policy (Steps 1 – 2)](#6-phase-2--baseline-audit-policy-steps-1--2)
7. [Phase 3 — Capture What Your Apps Need (Steps 3 – 4)](#7-phase-3--capture-what-your-apps-need-steps-3--4)
8. [Phase 4 — Merge and Screen (Step 5)](#8-phase-4--merge-and-screen-step-5)
9. [Phase 5 — Enforce (Steps 6 – 7)](#9-phase-5--enforce-steps-6--7)
10. [Phase 6 — Verify (Step 8)](#10-phase-6--verify-step-8)
11. [Rollback and Fix-Forward](#11-rollback-and-fix-forward)
12. [Troubleshooting and Lessons Learned](#12-troubleshooting-and-lessons-learned)
- [Appendix A — Script Parameter Reference](#appendix-a--script-parameter-reference)
- [Appendix B — PowerShell 7 vs Windows PowerShell 5.1](#appendix-b--powershell-7-vs-windows-powershell-51)
- [Appendix C — Agent Handover and Audit Log Protocol](#appendix-c--agent-handover-and-audit-log-protocol)

---

## 1. Overview

### 1.1 The Two STIG Findings This Guide Closes

| STIG ID | Vulnerability ID | What it checks (`Win32_DeviceGuard`) | Passing value |
|---|---|---|:---:|
| **V-243450** | `WPAW-00-001050` (CAT II) | `CodeIntegrityPolicyEnforcementStatus` — kernel-mode code integrity | **`2`** |
| **V-243451** | `WPAW-00-001060` (CAT II) | `UsermodeCodeIntegrityPolicyEnforcementStatus` — user-mode code integrity (UMCI) | **`2`** |

`0` = not configured · `1` = audit mode · `2` = enforced. The values are recorded at every stage, so you can prove that **your** policy is what moves the PAW to `2 / 2`.

> [!NOTE]
> **The starting values are not always `0 / 0`.** Newer Windows 11 builds load Microsoft platform policies out of the box. Smart App Control in *Evaluation* runs audit-mode UMCI, and the vulnerable-driver blocklist enforces kernel mode, so the PAW can start at **`2 / 1`**. That is fine: record what you see in Step 0 and finish at `2 / 2`.

### 1.2 Environment and Scope

| Item | Value (lab example — substitute your own) |
|---|---|
| Target | `WIN11-PAW-WDAC` — Windows 11 Enterprise (Hyper-V VM); host `RYZEN-BEE` |
| Account | `lorenzo@skynet-home.local` (or local admin `.\lorenzo` before domain join) |
| Tools | App Control Policy Wizard + PowerShell 7 (`pwsh`) **or** Windows PowerShell 5.1 + `CiTool.exe`. Requires Windows 11 22H2+ or Server 2025. |
| Policy architecture | **Multiple Policy Format** (`{PolicyID}.cip` in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`), **Allow Supplemental Policies** on |
| Deployment | Unsigned policy, live updates with `CiTool.exe --update-policy` (no reboot needed to apply) |
| Software distribution | **MECM** and/or **Intune** as managed installer (Option 13) |
| Approved apps | Everything the PAW needs. The guide is application-agnostic: the audit log tells the Wizard what to allow. |
| Block-test app *(optional)* | One installed app you deliberately leave out and never launch during the audit (the lab used Firefox). It must be blocked once enforced. |
| Working folders | `C:\WDAC\{Source,Compiled,Events,Logs}` on the PAW; scripts in `C:\WDAC-Scripts\` |
| Reference repo | [dcodev1702/STIG-WDAC-WIN11-25H2](https://github.com/dcodev1702/STIG-WDAC-WIN11-25H2/blob/main/README.md) |

### 1.3 How the Workflow Fits Together

```text
 Phase 1  Prepare        Step 0    pre-flight: folders, transcript, baseline STIG, CI log size, managed-installer readiness
 Phase 2  Baseline       Step 1    [Wizard] Base-Audit.xml (Allow Microsoft, Audit Mode, both block lists)
                         Step 1.1  validate + fix the Wizard output (options, block lists, optional WSL)
                         Step 2    stamp v1, compile, deploy live                          STIG UMCI -> 1
 Phase 3  Capture        Step 3    reboot, run EVERY app you need                          (3076 events)
                         Step 4    export .evtx -> [Wizard] Events-Allow.xml -> sanitize
 Phase 4  Merge/screen   Step 5    merge v2, deploy, reboot, re-run apps, expect 0 new 3076
 Phase 5  Enforce        Step 6    [Wizard] Audit Mode OFF in Base-Enforce.xml
                         Step 7    gate, stamp v3, compile, deploy                          STIG -> 2 / 2
 Phase 6  Verify         Step 8    STIG check, .cip layout, positive test, block test (3077)
```

Each audit stage repeats Steps 4 – 5 until the screening is clean. Every script stops with a `STOP:` message on any failure, so a bad file never reaches `CiTool.exe`.

### 1.4 The Golden Rules

1. **Deploy the baseline audit policy *before* capturing events.** The Wizard only writes XML. Windows logs no Event `3076` until a compiled `.cip` is loaded.
2. **One `PolicyID` GUID for every revision.** Never use `-ResetPolicyID`. Each stage keeps the GUID and raises `VersionEx`, so Windows replaces the policy in place instead of stacking a second one.
3. **Merge only — never deploy `Events-Allow.xml` on its own.** Two active base policies *intersect* (a file must pass both). Merge `Base-Audit.xml` (first) + `Events-Allow.xml` (second) into one base policy.
4. **Watch `Merge-CIPolicy` option unioning.** The merge keeps the first file's ID, name, and version but **unions the `<Option>` tags** of both files. Script 4 removes any option that leaks in.
5. **Time-box the events.** Old `3076` events stay in the log forever. Export only `3076` (audit block) and `3089` (signature details, needed for Publisher rules) since the audit window started.
6. **One deliberate reboot per test round.** Deployments apply live (`Option 16` + `CiTool.exe`). The reboots in Steps 3, 5, and 8 exist so services, startup items, and updaters load fresh under the policy.
7. **Sanitize event-derived rules before merging.** The Wizard can emit rules the compiler rejects (for example `invalid file rule with ID "ID_FILEATTRIB_…"`). Step 4.3 repairs or removes them, and Steps 5 and 7 re-check.

### 1.5 Version and ID Progression

| Stage | XML file | Friendly name | Policy ID label | `VersionEx` (example: all stages on 2026-10-23) | Mode | Expected STIG (KMCI / UMCI) |
|---|---|---|---|---|---|:---:|
| Pre-flight | — | *(Microsoft platform policies only)* | — | — | — | `0 / 0` *or* `2 / 1` |
| Baseline audit | `Base-Audit.xml` | `PAW-WDAC-Audit-Baseline` | `PAW-AUDIT-BASE-v1` | `2026.10.23.1` | Audit | `1 / 1` *or* `2 / 1` |
| Merged audit | `Base-Audit-Merged.xml` | `PAW-WDAC-Audit-Merged` | `PAW-AUDIT-MERGED-v2` | `2026.10.23.2` | Audit | `1 / 1` *or* `2 / 1` |
| **Enforced** | `Base-Enforce.xml` | `PAW-WDAC-Enforced` | `PAW-ENFORCED-v3` | `2026.10.23.3` | **Enforce** | **`2 / 2`** |
| *Fix-forward (optional)* | `Base-Audit-Merged.xml` | `PAW-WDAC-Audit-Merged` | `PAW-AUDIT-MERGED-v2` | next version (§11 Option A) | Audit | `1 / 1` *or* `2 / 1` |

**Versions are date-based: `YYYY.MM.DD.N`.** The date is the local date the script runs, and the counter **N** restarts at **1** each day. Administrators can read from the version when a policy was built. Scripts 1, 4 and 6 choose the version with `scripts\WDAC-Version.ps1`. A stage run on a later day gets that day's date: a baseline on 10-23 and an enforce on 10-24 give `2026.10.23.1` → `2026.10.24.1`.

> [!IMPORTANT]
> Windows replaces the active policy only when the new `VersionEx` is **higher** than the one loaded. It compares the four parts in order, so the date outranks the counter. A new version is **never lower than the highest version already known** for the policy: the active one in CiTool, the previous stage's XML, and the archived `PAW-WDAC-*_v<version>.cip` files. If a clock is wrong or a later-dated version already exists, the scripts continue after that version instead of going backwards. Each part is a number, so 9 October shows as `2026.10.9.1` (no leading zeros).

### 1.6 Policy Rule Options — What Changes Between Audit and Enforce

Going from audit to enforced turns **one** option off — **`Enabled:Audit Mode`** — and changes nothing else.

**Options that stay ENABLED (audit → enforced)**

| Option | Rule # | Wizard toggle | Why |
|---|:---:|---|---|
| `Enabled:UMCI` | 0 | User Mode Code Integrity | Makes **V-243451** report `2` |
| `Required:WHQL` | 2 | Require WHQL | Kernel drivers must be WHQL-signed |
| `Enabled:Unsigned System Integrity Policy` | 6 | Unsigned System Integrity Policy | `.cip` is unsigned — no PKI needed |
| `Enabled:Advanced Boot Options Menu` | 9 | Advanced Boot Options Menu | F8 recovery menu stays available |
| `Enabled:Boot Audit On Failure` | 10 | Boot Audit on Failure | A failing boot-critical driver is audited instead of blocking boot |
| `Disabled:Script Enforcement` | 11 | Disable Script Enforcement | PowerShell stays in `FullLanguage` (the option is *present*; "Disabled" is part of its name) |
| **`Enabled:Managed Installer`** | **13** | **Managed Installer** | **Trusts files installed by MECM / Intune** — see [section 2](#2-managed-installer-mecm--intune) |
| `Enabled:Update Policy No Reboot` | 16 | Update Policy without Rebooting | Live updates with `CiTool.exe` |
| `Enabled:Allow Supplemental Policies` | 17 | Allow Supplemental Policies | Keeps the multiple-policy model working |
| *Template extras* — e.g. `Enabled:Inherit Default Policy` (5, reserved) | | *(from the Allow Microsoft template)* | Anything already enabled in the screened audit policy also stays |

**The one option turned OFF**

| Option | Rule # | Audit stages (Steps 2 – 5) | Enforced (Step 7) |
|---|:---:|:---:|:---:|
| `Enabled:Audit Mode` | 3 | ✅ ON — logs `3076` instead of blocking | ❌ OFF — blocks; STIG `2 / 2` |

**Options that stay OFF (never enabled)**

| Option | Rule # | Why |
|---|:---:|---|
| `Enabled:Intelligent Security Graph Authorization` | 14 | The PAW does not rely on cloud reputation |
| `Enabled:Invalidate EAs on Reboot` | 15 | Only applies to ISG extended attributes |
| `Disabled:Runtime FilePath Rule Protection` | 18 | Keep it **absent**: runtime protection then stays ON, so FilePath rules only work on admin-writable folders |
| `Enabled:Dynamic Code Security` | 19 | No audit mode — would enforce immediately on .NET dynamic code |
| `Enabled:Revoked Expired As Unsigned` | 20 | Kept off per the STIG guide |

> [!TIP]
> You never have to edit options by hand. `0_1_validate_base_policy.ps1` (Step 1.1) checks and fixes the Wizard output. Script 4 re-asserts the ON list and strips the OFF list after the merge. Script 6 refuses to compile if anything other than Audit Mode was switched off, and prints the exact list of options that stay enabled.

---

## 2. Managed Installer (MECM / Intune)

> [!IMPORTANT]
> **Option 13 (`Enabled:Managed Installer`) is ON in every stage of this guide** because this environment distributes software with **MECM**, and can also use **Intune**. Turning the option on in the App Control policy is only **half** of the feature. Until a managed installer is designated on the device through an **AppLocker `ManagedInstaller` rule collection**, the option is present but **inert**.

### 2.1 How It Works

- An AppLocker `ManagedInstaller` rule names the installer binaries you trust (for example the MECM client or the Intune Management Extension).
- When one of them runs, Windows tags every file it, and its child processes, write to disk with an *origin claim* extended attribute: `$KERNEL.SMARTLOCKER.ORIGINCLAIM`.
- With Option 13 in the policy, App Control allows a tagged file to run **without a per-app rule**, unless a deny rule matches it.
- So MECM- or Intune-deployed software keeps working under the enforced policy **without** re-running the audit → merge cycle for every package.

### 2.2 Configure MECM as the Managed Installer

MECM configures itself as a managed installer **automatically only when you deploy one of its built-in App Control policies**. This guide deploys a **custom** policy with `CiTool.exe`, so pick one of these options:

| Option | How | Notes |
|---|---|---|
| **A — client install property** *(recommended)* | Install or repair the client with **`CCMSetup.exe MANAGEDINSTALLER=1`** (add it to your client push / task-sequence command line) | Sets `ccmsetup.exe` and `client.msi` as managed installers |
| **B — built-in audit policy alongside** | MECM console → **Assets and Compliance → Endpoint Protection → App Control for Business → Create Application Control Policy** → mode **Audit Only** → deploy to the PAW collection | An *audit-only* base policy never blocks, so it does not intersect with your enforced custom policy. MECM still configures itself as managed installer. |

> [!NOTE]
> The MECM client binaries are Microsoft-signed, so the *Allow Microsoft* template already lets the client itself run. The managed-installer setting is what extends that trust to the software MECM **installs**.

### 2.3 Configure Intune as the Managed Installer (optional)

1. **Intune admin center → Endpoint security → App Control for Business → Managed installer** tab → **Create**.
2. Set **Enable Intune Managed Extension as Managed Installer** = **Enabled**, assign it to the PAW device group, and create. Delivery can take up to ~30 minutes.
3. If MECM is already the managed installer, Intune's AppLocker policy **merges** with it. Intune can't designate MECM; set that up from MECM (2.2).

> [!CAUTION]
> When Intune merges its managed-installer AppLocker policy into an **existing** AppLocker policy, any rule collection set to **NotConfigured with an empty rule set** becomes *enforced with one dummy rule* and can block sign-in or boot. Remove empty `NotConfigured` collections from your existing AppLocker policy first.

### 2.4 Verify the Managed Installer

`0_pre-flight.ps1` reports all of this for you (section 9 of its output). To check by hand:

```powershell
# AppLocker ManagedInstaller rule collection present in the effective policy
([xml](Get-AppLockerPolicy -Effective -Xml)).AppLockerPolicy.RuleCollection | Where-Object Type -eq 'ManagedInstaller'
# Both AppLocker components must be RUNNING (if not: appidtel.exe start -mionly)
sc.exe query appidsvc; sc.exe query AppLockerFltr
# A file installed by the managed installer carries the origin claim
fsutil.exe file queryEA 'C:\Program Files\<App>\<app>.exe'    # look for $KERNEL.SMARTLOCKER.ORIGINCLAIM
```

> [!WARNING]
> - **Only files written *while* the managed installer runs are tagged.** Apps installed before MECM or Intune became the managed installer have no origin claim, and must be allowed by the audit capture (Steps 3 – 5) like any other app.
> - **Don't rely on the managed installer for boot-critical binaries, services, or drivers.** The origin check may not be available early in boot. Give those explicit Publisher, file, or hash rules.
> - Managed-installer trust is based on **how a file arrived**, not on who signed it. Anything your MECM/Intune admins deploy will run.

---

## 3. Plan Your Run

### 3.1 Decide What Runs and What Doesn't

| Decide | Lab example | Where it matters |
|---|---|---|
| **Approved apps** — every app, tool, extension, and updater the PAW needs | PowerShell 7, VS Code (+ extensions), Azure CLI, WinDirStat, WSL Ubuntu 26.04 | Install **before** Step 2; run them in Steps 3 and 5 |
| **Block-test app** *(optional)* — installed, never launched during the audit | Firefox (left installed on purpose) | `-ExcludedAppPattern`; launched only in Step 8.4 |
| **WSL needed?** | Yes | `0_1_validate_base_policy.ps1 -AllowWSL` |
| **Admin-only folders to allow wholesale** *(optional)* | `C:\Program Files\Microsoft SDKs\Azure\CLI2\*` (az CLI loads different native modules per command and per upgrade) | `-AdditionalFolderRules` on script 4 |
| **Managed installer** | MECM (+ Intune) | [Section 2](#2-managed-installer-mecm--intune) |

### 3.2 Prerequisites Checklist

- ✅ Windows 11 22H2+ (or Server 2025) with `CiTool.exe`; no legacy `SiPolicy.p7b`.
- ✅ **App Control Policy Wizard** installed (2.8+).
- ✅ An **elevated** PowerShell 7 or Windows PowerShell 5.1 session.
- ✅ Scripts copied to the PAW: `C:\WDAC-Scripts\` (PS7) and `C:\WDAC-Scripts\pwsh_5.1\` (5.1).
- ✅ Every approved app **installed and first-run setup completed** (for example, a WSL distro's first-launch user creation).
- ✅ A VM checkpoint / backup to roll back to (Step 0.1).

> [!TIP]
> If the copied scripts are blocked (Mark of the Web), unblock them once with `Get-ChildItem C:\WDAC-Scripts -Recurse | Unblock-File`. Alternatively, run `Set-ExecutionPolicy -Scope Process Bypass` in the elevated window.

### 3.3 Parameters You May Set

All parameters **default to empty or off**, so the scripts run unchanged on a PAW that has none of the lab's apps. A folder that doesn't exist is skipped with a warning, and an empty pattern skips its check.

| Parameter | Scripts | Lab value | Purpose |
|---|---|---|---|
| `-ExcludedAppPattern` | 0, 0_1, 4, 6 | `'Mozilla\|Firefox'` | Regex for the block-test app. Script 0 lists its background tasks/services; scripts 4 and 6 **stop** if it appears in the policy. |
| `-AllowWSL` | 0_1 | set | Removes the 6 WSL deny rules from the recommended block list |
| `-AdditionalFolderRules` | 4 | `'C:\Program Files\Microsoft SDKs\Azure\CLI2\*'` | FilePath allow rules for admin-writable-only folders |
| `-CILogSizeMB` | 0 | `100` (default) | Minimum CodeIntegrity log size |

Full list: [Appendix A](#appendix-a--script-parameter-reference).

---

## 4. Scripts at a Glance — Run Order

Run in this order from `C:\WDAC-Scripts\` (PS7) or `C:\WDAC-Scripts\pwsh_5.1\` (5.1), always **elevated**.

| # | Step | Script / action | What it does | Success looks like |
|:---:|---|---|---|---|
| 1 | 0.3 – 0.4 | `0_pre-flight.ps1` | Folders, transcript, ConfigCI, baseline STIG, Smart App Control state, CI log ≥ 100 MB, managed-installer readiness, block-test app background components | No `STOP:`; baseline recorded |
| 2 | 1 | 🖱️ **Wizard** | Creates `C:\WDAC\Source\Base-Audit.xml` | File exists |
| 3 | **1.1** | **`0_1_validate_base_policy.ps1`** | Validates and fixes the Wizard output (format, options incl. 13, block lists, `-AllowWSL`), with a compile test | `PASSED` |
| 4 | 2 | `1_compile_and_deploy.ps1` | Stamps v1, compiles, deploys, writes `AuditRoundStart.txt` | `OperationResult 0` |
| 5 | 2 | `2_audit_policy_activation.ps1` | STIG, CiTool inventory, Event `3099` | UMCI `1`; 3099 present |
| 6 | 3 | 🔄 **Reboot**, run every app | Generates `3076` events | Apps ran |
| 7 | 4.1 | `3_capture_ciaudit_events.ps1` (+ `Export-CIEventEvidence.ps1`) | Previews and exports `PAW-Audit-3076.evtx`; evidence CSV/MD | Export count = live count |
| 8 | 4.2 | 🖱️ **Wizard** | `.evtx` → `C:\WDAC\Source\Events-Allow.xml` | File exists |
| 9 | 4.3 | `3_1_validate_winevent_rules.ps1` | Sanitizes event rules (compile + merge test) | `PASSED` |
| 10 | 5 | `4_merge_audit_base_and_events_policies.ps1` | Merges, cleans options, stamps v2, deploys, writes `ScreenStart.txt` | `OperationResult 0` |
| 11 | 5 | 🔄 **Reboot**, run every app again | Screening | Apps ran |
| 12 | 5 | `5_audit_merged_events.ps1` | Counts new `3076`; prepares `Base-Enforce.xml` | `0` new events (or `-AcceptRemaining`) |
| 13 | 6 | 🖱️ **Wizard** | Audit Mode **OFF** in `Base-Enforce.xml` | Saved |
| 14 | 7 | `6_enforce_policy.ps1` | Gate (only Audit Mode off), stamps v3, compiles, deploys | `PRE-DEPLOYMENT CHECK PASSED`; `OperationResult 0` |
| 15 | 8.1 | `7_DISA_STIG_CHECK.ps1` | V-243450 / V-243451 | **`2 / 2` PASS** |
| 16 | 8.2 | `8_validate_multipolicy_layout.ps1` | `.cip` layout, CiTool, Event `3099` | `IsEnforced` / `IsAuthorized` `True` |
| 17 | 8.3 – 8.4 | 🔄 **Reboot**; `Get-Blocked_CI_Events.ps1` / `Export-CIEventEvidence.ps1 -EventId 3077` | Positive test + block test | Approved apps work; block-test app logged as `3077` |
| 18 | 8.5 *(optional)* | `New-WDACRunReport.ps1` | One self-contained HTML report of the whole run (STIG history, policies, FilePath verdicts, managed installer, every 3076/3077) | Report written to `C:\WDAC\Logs\` |

**Quick start (copy, set `$Block`, and run line by line):**

```powershell
Set-Location C:\WDAC-Scripts                 # Windows PowerShell 5.1: C:\WDAC-Scripts\pwsh_5.1
$Block = ''                                  # regex for your block-test app, e.g. 'Mozilla|Firefox'; '' = none

.\0_pre-flight.ps1 -ExcludedAppPattern $Block
#   >>> Step 1: Wizard -> C:\WDAC\Source\Base-Audit.xml
.\0_1_validate_base_policy.ps1 -ExcludedAppPattern $Block          # add -AllowWSL if WSL must keep working
.\1_compile_and_deploy.ps1
.\2_audit_policy_activation.ps1
#   >>> Step 3: reboot, run every app you need
.\3_capture_ciaudit_events.ps1
.\Export-CIEventEvidence.ps1 -EvtxPath 'C:\WDAC\Events\PAW-Audit-3076.evtx'
#   >>> Step 4.2: Wizard -> C:\WDAC\Source\Events-Allow.xml
.\3_1_validate_winevent_rules.ps1
.\4_merge_audit_base_and_events_policies.ps1 -ExcludedAppPattern $Block   # optional: -AdditionalFolderRules 'C:\Program Files\<App>\*'
#   >>> Step 5: reboot, run every app again
.\5_audit_merged_events.ps1
#   >>> Step 6: Wizard -> Audit Mode OFF in Base-Enforce.xml
.\6_enforce_policy.ps1 -ExcludedAppPattern $Block
.\7_DISA_STIG_CHECK.ps1
.\8_validate_multipolicy_layout.ps1
#   >>> Step 8.3 / 8.4: reboot, test approved apps, launch the block-test app
.\Export-CIEventEvidence.ps1 -EventId 3077 -StartTime (Get-Date).AddMinutes(-30)
.\New-WDACRunReport.ps1 -BlockTestPattern $Block              # optional: -NotesMarkdown 'C:\WDAC\Logs\My-Run-Notes.md'
```

> [!TIP]
> **Looping:** if the screening (row 12) shows new `3076` events for an app you need, repeat rows **7 → 12** (export → Wizard → sanitize → merge → screen) before Step 6.

---

## 5. Phase 1 — Prepare (Step 0)

### Step 0.1 — Take a Safety Checkpoint (Hyper-V host)

```powershell
# Elevated pwsh on the Hyper-V host
Checkpoint-VM -Name 'WIN11-PAW-WDAC' -SnapshotName 'Pre-WDAC-Manual-Walkthrough'
Get-VMCheckpoint -VMName 'WIN11-PAW-WDAC' | Select-Object Name, CreationTime
```

> [!TIP]
> On physical hardware, take a full backup or make sure you can reach the PAW's recovery options (F8 / Advanced Boot Options stays enabled through Option 9).

### Step 0.2 — Persistent PowerShell Direct Session *(optional)*

PowerShell Direct works over the VMBus even when the guest firewall blocks WinRM. Keep the session open; don't run `Remove-PSSession`.

```powershell
# Elevated pwsh on the Hyper-V host
$Cred = Get-Credential -UserName 'lorenzo@skynet-home.local' -Message 'Enter PAW Administrator Password'
$PAWSession = New-PSSession -VMName 'WIN11-PAW-WDAC' -Credential $Cred -Name 'PAW-WDAC-Session'
Copy-Item -ToSession $PAWSession -Path '<path>\scripts' -Destination 'C:\WDAC-Scripts' -Recurse
```

Run every command below **on the PAW**: inside `Enter-PSSession -Session $PAWSession`, or in an elevated window on its desktop next to the Wizard.

### Steps 0.3 – 0.4 — Pre-Flight (`0_pre-flight.ps1`)

```powershell
.\0_pre-flight.ps1 -ExcludedAppPattern $Block
```

| Section | What it does | Expect |
|---|---|---|
| 1 – 4 | Admin check; creates `C:\WDAC\{Source,Compiled,Events,Logs}`; starts a transcript in `C:\WDAC\Logs\`; loads ConfigCI; confirms `CiTool.exe` | No `STOP:` |
| 5 | Baseline STIG + Smart App Control state | `0 / 0`, or `2 / 1` on builds with platform policies |
| 6 – 7 | `SiPolicy.p7b` check; CiTool inventory | `False`; only `IsSystemPolicy = True` policies |
| 8 | Raises the CodeIntegrity log to ≥ `-CILogSizeMB` (100 MB) | "raised" or "no change needed" |
| 9 | **Managed-installer readiness**: MECM `CcmExec`, Intune IME, AppLocker `ManagedInstaller`, `AppIDSvc`, `AppLockerFltr` | Configured, or a yellow reminder pointing to [section 2](#2-managed-installer-mecm--intune) |
| 10 | Scheduled tasks and services of the block-test app | A list (or `0 / 0` if the app isn't installed) |

> [!WARNING]
> **Install every approved app now, and finish each first-run setup now**, before Step 2 starts the audit window. One-time installer noise otherwise ends up in your rules. **Don't launch the block-test app** at any point before Step 8.4.

> [!NOTE]
> The Windows default CodeIntegrity log is **1 MB (~200 events)** and circular. A single audit round can overwrite its own earlier events before Step 4.1 exports them, which is why section 8 raises it.

---

## 6. Phase 2 — Baseline Audit Policy (Steps 1 – 2)

### Step 1 — App Control Policy Wizard: Create `Base-Audit.xml`

1. Launch the **App Control Policy Wizard** → **Policy Creator** → **Base Policy**.
2. Keep **Multiple Policy Format** (default) → choose **Allow Microsoft Mode**.
3. **Policy Name:** `PAW-WDAC-Audit-Baseline` · **File Path:** `C:\WDAC\Source\Base-Audit.xml` → **Next**.
4. On **Policy Rules**, click **+ Advanced Options** and set:

| Wizard rule option | Setting | Why |
|---|:---:|---|
| Audit Mode | ✅ ON | Log `3076` without blocking while the allow list is built |
| User Mode Code Integrity (UMCI) | ✅ ON | Required for **V-243451** |
| Allow Supplemental Policies | ✅ ON | Multiple-policy model and future supplemental policies |
| Disable Script Enforcement | ✅ ON | Keeps PowerShell in `FullLanguage` |
| Unsigned System Integrity Policy | ✅ ON | Deploy `.cip` without a code-signing certificate |
| Update Policy without Rebooting | ✅ ON | Live updates with `CiTool.exe` |
| Advanced Boot Options Menu | ✅ ON | F8 recovery menu |
| Require WHQL | ✅ ON | WHQL-signed kernel drivers (STIG) |
| Boot Audit on Failure *(Advanced)* | ✅ ON | Failing boot-critical driver → audit instead of BSOD |
| **Managed Installer** | ✅ **ON** | **Trust software deployed by MECM / Intune** ([section 2](#2-managed-installer-mecm--intune)) |
| Intelligent Security Graph (ISG) | ❌ OFF | No cloud reputation on a PAW |
| Dynamic Code Security *(Advanced)* | ❌ OFF | No audit mode; enforces immediately |
| Treat Revoked as Unsigned *(Advanced)* | ❌ OFF | Off per the STIG guide |
| Disable Runtime FilePath Rule Protection *(Advanced)* | ❌ OFF | Keeps runtime protection **ON** |
| Invalidate EAs on Reboot *(Advanced)* | ❌ OFF | ISG only |
| Hypervisor-protected Code Integrity (HVCI) | ❌ OFF | Configured at the OS/VBS level, not in this XML |

5. **Next** → on **File Rules**, check **both**:
   - ✅ **Merge with Recommended User Mode Block Rules** (known bypass tools / LOLBins)
   - ✅ **Merge with Recommended Kernel Mode Block Rules** (vulnerable drivers)
6. **Next** to build. The Wizard may also compile a `.cip` next to the XML; it isn't used (Step 2 compiles its own).

> [!WARNING]
> **The Recommended User Mode Block Rules deny WSL.** They contain 6 deny rules covering every version of `bash.exe`, `lxrun.exe`, `LxssManager.dll`, `wsl.exe`, `wslconfig.exe`, and `wslhost.exe`. A deny **always beats an allow**, so WSL would be blocked once enforced no matter what the audit captures. If the PAW needs WSL, run Step 1.1 with **`-AllowWSL`**. Linux code *inside* WSL isn't governed by App Control, which is why Microsoft blocks WSL on locked-down devices. Allowing it is a deliberate trade-off.

### Step 1.1 — Validate the Wizard Output (`0_1_validate_base_policy.ps1`)

```powershell
.\0_1_validate_base_policy.ps1 -ExcludedAppPattern $Block              # add -AllowWSL if WSL must work
.\0_1_validate_base_policy.ps1 -ReportOnly                             # preview only; change nothing
```

| Check | Result |
|---|---|
| `PolicyType = Base Policy` and `PolicyID = BasePolicyID` (Multiple Policy Format) | `FAIL` → `STOP:` (recreate in the Wizard) |
| The 10 required options (0, 2, 3, 6, 9, 10, 11, **13**, 16, 17) | Missing → `FIX` (turned ON) |
| The 5 forbidden options (14, 15, 18, 19, 20) | Present → `FIX` (turned OFF) |
| Both recommended block lists merged | `WARN` if a scenario has no deny rules |
| 6 WSL deny rules | `WARN`, or `FIX` (removed) with `-AllowWSL` |
| `-ExcludedAppPattern` already matches the base policy | `WARN` (scripts 4/6 would stop on a false positive) |

Before changing anything it saves `Base-Audit.wizard-original-<timestamp>.xml`, then proves the result with a real compile. If that compile fails, the original is restored. It never calls `CiTool.exe`. Findings go to `C:\WDAC\Logs\Base-Audit-Validate-<timestamp>.csv`.

### Step 2 — Stamp, Compile, and Deploy the Baseline (`1_compile_and_deploy.ps1`, `2_audit_policy_activation.ps1`)

```powershell
.\1_compile_and_deploy.ps1
.\2_audit_policy_activation.ps1
```

**Script 1:**
1. Stamps `PAW-WDAC-Audit-Baseline` / `PAW-AUDIT-BASE-v1` / the next date-based version (e.g. `2026.10.23.1`, printed as *"Policy version …"*), with no `-ResetPolicyID`.
2. Saves the GUID to `C:\WDAC\Source\PolicyGuid.txt`.
3. Compiles `C:\WDAC\Compiled\{PolicyID}.cip` and keeps an archive copy.
4. Deploys with `CiTool.exe --update-policy`.
5. Writes the **audit window start** to `C:\WDAC\Events\AuditRoundStart.txt`. If an older start file exists, it's kept as `AuditRoundStart.previous-<timestamp>.txt`.

**Verify the script 1 output:** `PolicyType` = `Base Policy`, `PolicyID` = `BasePolicyID`, and `RuleOptions` includes `Enabled:Audit Mode`, `Enabled:UMCI`, `Enabled:Managed Installer`, `Enabled:Allow Supplemental Policies`, `Enabled:Boot Audit On Failure`, `Disabled:Script Enforcement`, `Enabled:Update Policy No Reboot`, and `Enabled:Unsigned System Integrity Policy`.

**Script 2:** UMCI = `1` (KMCI `1`, or still `2` if platform policies enforced it already); CiTool shows `PAW-WDAC-Audit-Baseline` at the version script 1 printed, with `IsAuthorized True`; Event **3099** *"Refreshed and activated Code Integrity policy … PAW-WDAC-Audit-Baseline"*. The 3099 query retries for ~10 s, because the event can land a moment after script 1 finishes.

> [!NOTE]
> In CiTool output, `IsEnforced = True` means *the policy is active*, not that it is in enforce mode. The mode is what `Win32_DeviceGuard` reports.

---

## 7. Phase 3 — Capture What Your Apps Need (Steps 3 – 4)

### Step 3 — 🔄 Reboot, Then Run Every Application You Need

1. **Reboot** the PAW. `AuditRoundStart.txt` survives the reboot. Re-open an elevated window afterwards, and re-create `$PAWSession` if you use it.
2. **Run everything the PAW must keep doing**: every app, admin tool, CLI, editor and its extensions, browser and plug-ins, and **update checks**. Open real files and use the features that load extra DLLs or helpers.
3. **Wait a few minutes** so services, scheduled tasks, sync agents, and updaters run too.
4. 🚫 **Don't launch the block-test app.** An app that never runs logs no `3076`, gets zero rules, and is blocked in Step 8.

> [!WARNING]
> **Background components of the block-test app still run.** A browser's scheduled updater or default-browser agent can log `3076` events without anyone opening the browser. Step 0 lists them (`-ExcludedAppPattern`). **Don't add those rows in Step 4.2.** Scripts 4 and 6 stop if the pattern reaches the policy anyway.

> [!TIP]
> Microsoft-signed software (Windows, PowerShell 7, VS Code, WSL, the MECM client) is already allowed by the *Allow Microsoft* template and usually logs **no** `3076`. That's expected, not a capture failure.

### Step 4.1 — Export Time-Boxed Events (`3_capture_ciaudit_events.ps1`)

```powershell
.\3_capture_ciaudit_events.ps1
.\Export-CIEventEvidence.ps1 -EvtxPath 'C:\WDAC\Events\PAW-Audit-3076.evtx'     # audit-trail CSV + Markdown
```

Script 3:
1. Previews the unique files behind every `3076` since `AuditRoundStart.txt`.
2. Exports **only `3076` + `3089`** from that window to `C:\WDAC\Events\PAW-Audit-3076.evtx`.
3. Reads the export back and compares its `3076` count with the live log.

The evidence script writes **every event** (time, record ID, file, process, signer/issuer, signing levels, hashes, policy) to `C:\WDAC\Logs\CI-Evidence-3076-<timestamp>.csv/.md`.

> [!NOTE]
> Each `3076` should come with at least one `3089` (signature details, joined by ActivityId). A `3089` whose publisher is `Unknown` means the file is **unsigned**, so it can only get a **Hash** rule.

### Step 4.2 — App Control Policy Wizard: Convert Events to `Events-Allow.xml`

1. Wizard → **Policy Editor** → **Convert Event Logs to a Policy** → **Parse Log File(s)** → `C:\WDAC\Events\PAW-Audit-3076.evtx` → **Next**.
2. For each row you want to allow, choose the **Rule Type** and click **Add Allow Rule**:

| File | Rule type |
|---|---|
| Signed, from a publisher you trust (survives updates) | **Publisher** |
| Signed, and you want it tighter | **FilePublisher** (only if the file has version info) |
| Unsigned (publisher `Unknown`) | **Hash** |
| The block-test app or its updater | 🚫 **Don't add** |
| A row you don't recognize | Don't add — investigate first |

3. **Next** → save as **`C:\WDAC\Source\Events-Allow.xml`**.

> [!NOTE]
> **Check where the Wizard actually saved it.** It can write the converted policy to **`%USERPROFILE%\Documents\EventLogPolicy_<timestamp>.xml`** instead; the timestamp in the name is **UTC**. The final screen lists the real output location. If so, copy the newest one into place by hand:
> ```powershell
> Get-ChildItem "$env:USERPROFILE\Documents\EventLogPolicy_*.xml" | Sort-Object LastWriteTime | Select-Object -Last 1 |
>     Copy-Item -Destination 'C:\WDAC\Source\Events-Allow.xml'
> ```
> The file is typed as a *Supplemental Policy* whose `BasePolicyID` is your base. That's expected: the Step 5 merge keeps the base's type, GUID, and name. Ignore any `.cip` the Wizard lists next to it.

> [!CAUTION]
> Never compile or deploy `Events-Allow.xml` on its own. Two base policies intersect, and this one would block Windows. It is only an input for the merge in Step 5. **Sanitize it first (Step 4.3).**

> [!TIP]
> - **Hash rules break on every update** of that file. For an app that installs hundreds of files into an **admin-writable-only** folder (for example `C:\Program Files\<App>\`), add a FilePath rule in Step 5 with `-AdditionalFolderRules`.
> - Unsigned files in **user-writable** folders (for example VS Code extensions under `%USERPROFILE%\.vscode`) can't use FilePath rules. Re-capture them after the extension updates.

### Step 4.3 — Sanitize the Event-Derived Rules (`3_1_validate_winevent_rules.ps1`)

```powershell
.\3_1_validate_winevent_rules.ps1                          # sanitize in place (a timestamped backup is kept)
.\3_1_validate_winevent_rules.ps1 -ReportOnly              # preview; change nothing
.\3_1_validate_winevent_rules.ps1 -AllowPublisherFallback  # see the warning in Appendix A first
```

It checks every rule against what `Merge-CIPolicy` / `ConvertFrom-CIPolicy` accept. It repairs what is safe to repair, removes what can't be compiled, and proves the result with a real compile **and** a merge-and-compile with `Base-Audit.xml` in a temporary folder. Only then does it update `Events-Allow.xml`. It never calls `CiTool.exe`.

| Check | Result |
|---|---|
| Rule with no identifying attribute (`FileAttrib` without `FileName`/`InternalName`/`FileDescription`/`ProductName`/`PackageFamilyName`/`Hash`/`FilePath`) | **Removed** — the `invalid file rule with ID …` error |
| Empty attribute values (`Hash=""`) — compile alone but break the merge | Stripped; rule re-evaluated |
| Hash not hex, not 40/64 characters, or combined with other attributes | **Removed** |
| Invalid `MinimumFileVersion` / `MaximumFileVersion` (3-part versions are fixed) | **Removed** / **Fixed** |
| Duplicate IDs; IDs not matching the schema pattern | Duplicate removed; ID renamed (references follow) |
| Signer with no/invalid `CertRoot`, empty publisher/issuer, missing `CertEKU` | Signer **removed** (an empty publisher must never widen trust) |
| Signer whose every `FileAttrib` was invalid | **Removed** (or kept with `-AllowPublisherFallback`) |
| Dangling or duplicate references; unknown/duplicate options | **Removed** |
| Unreferenced rules; remaining schema complaints | **Warning** |

Findings are tagged `FIXED` / `REMOVED` / `WARN` and saved to `C:\WDAC\Logs\Events-Allow-Sanitize-<timestamp>.csv`. On `PASSED`, go to Step 5. If a rule you need was removed, re-add that file in the Wizard as **Publisher** or **Hash** and re-run.

---

## 8. Phase 4 — Merge and Screen (Step 5)

### Step 5 — Merge, Deploy, Screen (`4_merge_audit_base_and_events_policies.ps1`, `5_audit_merged_events.ps1`)

```powershell
.\4_merge_audit_base_and_events_policies.ps1 -ExcludedAppPattern $Block
#   optional: -AdditionalFolderRules 'C:\Program Files\<App>\*', 'C:\Program Files\<Other>\*'
```

**Script 4:**
1. Merges `Base-Audit.xml` (**first**) + `Events-Allow.xml` (**second**) → `Base-Audit-Merged.xml`.
2. Adds FilePath rules for `-AdditionalFolderRules`, skipping, with a warning, any folder that doesn't exist or that standard users can write to.
3. Re-asserts the ON options (0, 2, 3, 6, 9, 10, 11, **13**, 16, 17) and strips the OFF options (14, 15, 18, 19, 20).
4. Stamps `PAW-WDAC-Audit-Merged` / `PAW-AUDIT-MERGED-v2` / the next date-based version, higher than the baseline (e.g. `2026.10.23.2`).
5. **Gate:** no uncompilable `FileAttrib`, same GUID, Audit Mode / Supplemental / Boot Audit ON, block-test app absent.
6. Compiles, deploys, writes `C:\WDAC\Events\ScreenStart.txt`, and shows the STIG values and CiTool inventory.

Check its output: `MatchesBaseline`, `AuditModeOn`, `SupplementalOn`, and `BootAuditOn` = `True`; `ExcludedAppInPolicy` = `False`.

**Then 🔄 reboot, run every app again** (the same set as Step 3, including update checks), wait a few minutes, and screen:

```powershell
.\5_audit_merged_events.ps1                    # count new 3076; when clean, prepare Base-Enforce.xml
.\5_audit_merged_events.ps1 -AcceptRemaining   # every remaining event is for an app you intend to block
.\5_audit_merged_events.ps1 -Overwrite         # replace an existing, different Base-Enforce.xml without asking
```

| Result | Meaning / next step |
|---|---|
| ✅ `New 3076 events since screening started: 0` + `Base-Enforce.xml prepared` | Allow list complete → Step 6 |
| ⚠️ `NOT ready to enforce: N new 3076 event(s)` | Nothing copied. Inspect them with the `Export-CIEventEvidence.ps1 -StartTime …` command it prints. For apps you need, loop Steps 4 → 5. If **every** event is for the block-test app (or its updater), re-run with `-AcceptRemaining`. |

If a different `Base-Enforce.xml` already exists, script 5 **never overwrites it silently**. It asks (default: a timestamped `Base-Enforce_<yyyyMMdd-HHmmss>.xml`), and chooses the timestamped copy automatically in non-interactive sessions.

---

## 9. Phase 5 — Enforce (Steps 6 – 7)

### Step 6 — App Control Policy Wizard: Switch Audit → Enforce

1. Wizard → **Policy Editor** → **Edit Policy XML File** → `C:\WDAC\Source\Base-Enforce.xml` (or the newest `Base-Enforce_<timestamp>.xml` script 5 named) → **Next**.
   - **Policy Name / Policy ID:** leave them unchanged. They are only friendly labels. Script 6 stamps `PAW-WDAC-Enforced` / `PAW-ENFORCED-v3` / the next date-based version, and the `PolicyID` GUID, which must stay the same, isn't editable on this screen.
   - **New Save Location:** leave it blank. The Wizard then saves next to the original in `C:\WDAC\Source\`, often as `Base-Enforce_v10.0.0.0.xml`, and may already raise `VersionEx`. Both are fine.
2. On **Policy Rules** (**+ Advanced Options**):
   - ❌ **Audit Mode → OFF**: the **only** toggle you change.
   - Leave everything else exactly as it is. Verify that these stay ✅ ON: **Managed Installer**, Boot Audit on Failure, UMCI, Allow Supplemental Policies, Disable Script Enforcement, Unsigned System Integrity Policy, Update Policy without Rebooting, Advanced Boot Options Menu, Require WHQL.
3. **Next** past **File Rules** without re-checking the block-list boxes (those rules are already in the XML) → **Next** to save. A version-suffixed file name (e.g. `Base-Enforce_v10.0.0.0.xml`) is fine; script 6 uses the newest `Base-Enforce*.xml`.

> [!NOTE]
> Script 6 also deletes Audit Mode itself and stops if any *other* screened option went missing. This Wizard pass is a visual review, not a hard dependency.

### Step 7 — Gate, Stamp, Compile, and Enforce (`6_enforce_policy.ps1`)

```powershell
.\6_enforce_policy.ps1 -ExcludedAppPattern $Block
```

1. Uses the newest `Base-Enforce*.xml` and compares it with the **screened** `Base-Audit-Merged.xml`.
2. Ensures options 0, 2, 6, 9, 10, 11, **13**, 16, 17 are ON and 3, 14, 15, 18, 19, 20 are OFF.
3. Stamps `PAW-WDAC-Enforced` / `PAW-ENFORCED-v3` / the next date-based version, higher than the screened audit policy (e.g. `2026.10.23.3`).
4. **Gate:** no bad `FileAttrib`; same GUID; `PolicyID = BasePolicyID`; **Audit Mode is the only option turned off**; UMCI, Boot Audit, and Supplemental ON; block-test app absent.
5. Compiles, records the `.cip` SHA-256, and deploys live.

Expected output when the gate passes:

```text
PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!
Audit Mode is the ONLY option turned off. Options that stay ENABLED in the enforced policy:
  Disabled:Script Enforcement
  Enabled:Advanced Boot Options Menu
  Enabled:Allow Supplemental Policies
  Enabled:Boot Audit On Failure
  Enabled:Inherit Default Policy
  Enabled:Managed Installer
  Enabled:UMCI
  Enabled:Unsigned System Integrity Policy
  Enabled:Update Policy No Reboot
  Required:WHQL
```

`OnlyAuditModeTurnedOff : True` with an empty `OtherOptionsTurnedOff` is the proof. If the script stops with *"these screened options are missing from Base-Enforce.xml"*, nothing was compiled or deployed. Turn those options back ON in the Wizard (Step 6) and re-run. If they are options this guide requires OFF, re-run script 4 and re-screen.

---

## 10. Phase 6 — Verify (Step 8)

### 8.1 — Official DISA STIG Check (`7_DISA_STIG_CHECK.ps1`)

```powershell
.\7_DISA_STIG_CHECK.ps1
```

```text
V-243450 (CodeIntegrityPolicyEnforcementStatus)         : 2 [PASS - NOT A FINDING]
V-243451 (UsermodeCodeIntegrityPolicyEnforcementStatus) : 2 [PASS - NOT A FINDING]
```

### 8.2 — Multi-Policy Layout, CiTool Inventory, Event 3099 (`8_validate_multipolicy_layout.ps1`)

Expect `{PolicyID}.cip` in `CiPolicies\Active\`, `SiPolicy.p7b` = `False`, and CiTool `PAW-WDAC-Enforced` at the version script 6 printed, with `IsEnforced` / `IsAuthorized` `True`. Event 3099 should show the activation.

### 8.3 — 🔄 Positive Test: Everything You Need Still Works

1. **Reboot**, then run every approved app (the Step 3 set, including update checks).
2. `$ExecutionContext.SessionState.LanguageMode` → `FullLanguage`.
3. Check for unexpected blocks:

```powershell
.\Export-CIEventEvidence.ps1 -EventId 3077 -StartTime (Get-Date).AddMinutes(-30)
```

Anything you need that shows up as `3077` → [section 11](#11-rollback-and-fix-forward) (fix-forward).

### 8.4 — 🚫 Negative Test: Prove Enforcement With the Block-Test App

Launch the block-test app (double-click it, or `& 'C:\Path\To\App.exe'`). Expected:
- The app does not start. Toast: *"Your organization used App Control for Business to block this app."*
- PowerShell: *"An Application Control policy has blocked this file."*
- Event **3077**: `.\Get-Blocked_CI_Events.ps1`, or the evidence command above for a CSV with hashes and signer.

### 8.5 — Run Report *(optional)* (`New-WDACRunReport.ps1`)

```powershell
.\New-WDACRunReport.ps1 -BlockTestPattern $Block      # add -NotesMarkdown <file> to append your own run notes
```

The report is **one self-contained HTML file**: inline CSS, no scripts, no external resources, light/dark aware and printable. It's written to `C:\WDAC\Logs\WDAC-Run-Report-<timestamp>.html`, and collects:

| Section | Content |
|---|---|
| STIG values | Current `Win32_DeviceGuard`, plus every reading found in the `C:\WDAC\Logs` transcripts (the stage-by-stage progression) |
| Policies | Active custom policies (CiTool); each XML stage (Audit Mode, Managed Installer, counts, options, SHA-256); every compiled `.cip` |
| FilePath rules | Every FilePath rule, with whether Windows will **honor** it: admin-only ✅, user-writable ❌, or runtime check disabled in that policy ⚠️ |
| Managed installer | MECM client, Intune IME, AppLocker `ManagedInstaller` collection, AppIDSvc, AppLockerFltr |
| Script findings | Latest `0_1_validate_base_policy` and `3_1_validate_winevent_rules` CSVs |
| Events | Every audit `3076` (from the exported `.evtx`), screening `3076`, and enforced `3077`. Rows matching `-BlockTestPattern` are marked *expected*; everything else is flagged for review. |
| Artifacts | `C:\WDAC\Source` / `Events` file inventory with SHA-256, and the log list |

> [!TIP]
> Keep the evidence files (`C:\WDAC\Logs\CI-Evidence-*.csv/.md`, the run report, transcripts, and `C:\WDAC\Compiled\*.cip` hashes) as your STIG audit package.

---

## 11. Rollback and Fix-Forward

The policy is unsigned and has `Enabled:Update Policy No Reboot`, so every option below applies live.

### Option A — Fix-Forward: Back to Audit Mode Without Removing the Policy

Stamp `Base-Audit-Merged.xml` with the next date-based version, which is always above the enforced one, and apply it. Then capture the new app (Steps 3 – 5) and enforce again; script 6 picks an even higher version.

```powershell
Set-Location C:\WDAC-Scripts                                  # the folder that holds WDAC-Version.ps1
. .\WDAC-Version.ps1
$RollbackXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuid  = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()
$CipFile     = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
$Known       = @(Get-WdacActivePolicyVersion $PolicyGuid) + @(Get-WdacVersionsFromArchive -Name 'PAW-WDAC-Audit-Baseline', 'PAW-WDAC-Audit-Merged', 'PAW-WDAC-Enforced')
$Version     = (Get-WdacNextVersion -Known $Known).Versions[0]   # e.g. 2026.10.24.1
Set-CIPolicyVersion -FilePath $RollbackXml -Version $Version -ErrorAction Stop
ConvertFrom-CIPolicy -XmlFilePath $RollbackXml -BinaryFilePath $CipFile -ErrorAction Stop
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
```

### Option B — Remove the Custom Policy

```powershell
$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()
& "$env:SystemRoot\System32\CiTool.exe" --remove-policy $PolicyGuid -json
```

### Option C — Restore the Hyper-V Checkpoint (host)

```powershell
Restore-VMCheckpoint -VMName 'WIN11-PAW-WDAC' -Name 'Pre-WDAC-Manual-Walkthrough' -Confirm:$false
```

> [!NOTE]
> To remove the **managed installer** itself, clear the managed-installer AppLocker policy from the device (and disable the Intune managed-installer policy, if used).

---

## 12. Troubleshooting and Lessons Learned

| Symptom | Cause | Fix |
|---|---|---|
| Baseline reads `2 / 1`, not `0 / 0` | Microsoft platform policies (Smart App Control *Evaluation*, driver blocklist) are already active | Expected. Record it; the target is still `2 / 2`. |
| Fewer `3076` events than expected, or early ones missing | CodeIntegrity log is 1 MB and circular | Script 0 raises it to 100 MB; re-run the audit round |
| WSL works in audit but would be blocked when enforced (or `3076` for `wsl.exe` keeps appearing in screening) | Recommended User Mode Block Rules **deny** WSL; deny beats allow | `0_1_validate_base_policy.ps1 -AllowWSL`, then redeploy from Step 2 |
| `3076` events for the block-test app although it was never opened | Its scheduled updater or agent ran | Don't add those rows; `-AcceptRemaining` in Step 5 once every remaining event is for that app |
| Script 2 shows no Event 3099 | Event not flushed yet | Script 2 retries ~10 s; re-run it |
| `There is invalid file rule with ID "ID_FILEATTRIB_…"` | Wizard FilePublisher rule for a file with no version info | Step 4.3 (`3_1_validate_winevent_rules.ps1`); re-add as Publisher or Hash |
| An app breaks after its update (e.g. a CLI with many native modules) | Hash rules no longer match | `-AdditionalFolderRules` for its admin-only folder, or re-capture |
| FilePath rule has no effect | Folder is user-writable; runtime FilePath protection ignores it | Script 4 now skips it with a warning; use Publisher/Hash rules |
| MECM/Intune-deployed app blocked | Managed installer not configured, or the app was installed before it was | [Section 2](#2-managed-installer-mecm--intune); check the origin claim with `fsutil file queryEA` |
| PowerShell in `ConstrainedLanguage` | Script enforcement on | Keep Option 11 (`Disabled:Script Enforcement`) |
| `Merge-CIPolicy` added `Dynamic Code Security` / ISG | Option unioning from the event policy | Script 4 strips the OFF list automatically |
| VS Code extension stops working after it auto-updates | Unsigned native module in a user-writable folder had a Hash rule | Re-capture (Steps 3 – 5) or add a supplemental policy |

---

## Appendix A — Script Parameter Reference

| Script | Parameters (default) |
|---|---|
| `0_pre-flight.ps1` | `-CILogSizeMB` (`100`) · `-ExcludedAppPattern` (`''`) |
| `0_1_validate_base_policy.ps1` | `-BaseXml` (`C:\WDAC\Source\Base-Audit.xml`) · `-AllowWSL` · `-ExcludedAppPattern` (`''`) · `-ReportOnly` |
| `1_compile_and_deploy.ps1` | — |
| `2_audit_policy_activation.ps1` | — |
| `3_capture_ciaudit_events.ps1` | — |
| `3_1_validate_winevent_rules.ps1` | `-EventsXml` (`C:\WDAC\Source\Events-Allow.xml`) · `-BaseXml` (`C:\WDAC\Source\Base-Audit.xml`) · `-ReportOnly` · `-AllowPublisherFallback` ⚠️ trusts **every** file from a publisher whose file rules were all invalid — use only deliberately |
| `4_merge_audit_base_and_events_policies.ps1` | `-AdditionalFolderRules` (`@()`) · `-ExcludedAppPattern` (`''`) |
| `5_audit_merged_events.ps1` | `-AcceptRemaining` · `-Overwrite` |
| `6_enforce_policy.ps1` | `-ExcludedAppPattern` (`''`) |
| `7_DISA_STIG_CHECK.ps1` | — |
| `8_validate_multipolicy_layout.ps1` | — |
| `Get-Blocked_CI_Events.ps1` | — (last 15 min of `3077`) |
| `Export-CIEventEvidence.ps1` | `-EvtxPath` · `-StartTime` (default: `AuditRoundStart.txt`) · `-EventId` (`3076` \| `3077`) · `-OutCsv` / `-OutMd` (default: `C:\WDAC\Logs\CI-Evidence-<id>-<timestamp>.*`) |
| `New-WDACRunReport.ps1` | `-OutHtml` (default: `C:\WDAC\Logs\WDAC-Run-Report-<timestamp>.html`) · `-Title` · `-BlockTestPattern` (`''`) · `-NotesMarkdown` · `-EnforcedSince` (default: time the enforced `.cip` archive was written) |

Files the scripts produce:

| Path | Written by | Purpose |
|---|---|---|
| `C:\WDAC\Source\Base-Audit.xml` / `.wizard-original-*.xml` | Wizard / 0_1 | Baseline (and its pre-fix backup) |
| `C:\WDAC\Source\PolicyGuid.txt` | 1 | The one GUID for every revision |
| `C:\WDAC\Source\Events-Allow.xml` / `.original-*.xml` | Wizard / 3_1 | Event rules (and pre-sanitize backup) |
| `C:\WDAC\Source\Base-Audit-Merged.xml` | 4 | Screened audit policy (reference for script 6) |
| `C:\WDAC\Source\Base-Enforce*.xml` | 5 / Wizard / 6 | Enforced policy source |
| `C:\WDAC\Compiled\{GUID}.cip` + `PAW-WDAC-*_v*.cip` | 1, 4, 6 | Active binary + archive per version |
| `C:\WDAC\Events\AuditRoundStart.txt`, `ScreenStart.txt` | 1, 4 | Audit / screening window starts |
| `C:\WDAC\Events\PAW-Audit-3076.evtx` | 3 | Time-boxed `3076` + `3089` export for the Wizard |
| `C:\WDAC\Logs\*` | all | Transcripts, validation/sanitize CSVs, evidence CSV/MD |

## Appendix B — PowerShell 7 vs Windows PowerShell 5.1

Both editions have the same file names and behavior. The 5.1 copies in `scripts\pwsh_5.1\` differ only by:
1. `Import-Module ConfigCI` **without** `-UseWindowsPowerShell`.
2. Calling `New-CIPolicyRule` / `Merge-CIPolicy` directly instead of through a nested `powershell.exe`.
3. Loading XML with `XmlDocument.Load()`, because 5.1's `Get-Content` assumes ANSI for BOM-less UTF-8.
4. ASCII-only text.
5. A `#Requires -PSEdition Desktop` guard on the scripts that use ConfigCI.

`Export-CIEventEvidence.ps1`, `New-WDACRunReport.ps1` and `WDAC-Version.ps1` (the date-based version helper, dot-sourced by scripts 1, 4 and 6) need no ConfigCI and are identical in both folders. `WDAC-Version.ps1` is also identical to the copy in `C:\WDAC\GPO\scripts\`.

## Appendix C — Agent Handover and Audit Log Protocol

When an agent takes over (or for the follow-on **Multi-Policy GPO Deployment Guide**):

1. **Persistent session:** connect with `New-PSSession -VMName 'WIN11-PAW-WDAC' -Credential (Get-Credential 'lorenzo@skynet-home.local')` and never remove it. An agent running *on* the PAW instead must stop before each reboot and resume from its log.
2. **Complete audit trail:** keep a transcript (`C:\WDAC\Logs\Agent-Transcript-<timestamp>.log`) plus an append-only Markdown log of every command, its timestamp and reason, before/after policy versions and hashes, and the `Win32_DeviceGuard` / CiTool results.
3. **No unapproved reboots or destructive actions:** never reboot, reset `PolicyID` GUIDs, or overwrite authored XML files without explicit confirmation.
4. **GPO follow-on:** the built-in *Deploy App Control for Business* GPO setting only supports legacy single-policy `SiPolicy.p7b`. The follow-on guide deploys the validated `C:\WDAC\Compiled\{PolicyID}.cip` (and any supplemental `.cip`) with a **Group Policy startup or scheduled script + `CiTool.exe --update-policy`** from a UNC share on `skynet-home.local`.
