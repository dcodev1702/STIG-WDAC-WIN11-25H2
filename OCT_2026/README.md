# App Control for Business (WDAC) on `WIN11-PAW-WDAC` — Simplified Manual Multi-Policy Guide (No GPO)

> **Environment & Scope**
> - **Target VM:** `WIN11-PAW-WDAC` (Windows 11 Enterprise 25H2 on Hyper-V)
> - **Account:** `lorenzo@skynet-home.local` (or local admin `.\lorenzo` if testing before domain join)
> - **Deployment Method:** **100% Manual** using **App Control Policy Wizard** + **PowerShell 7 (`pwsh`)** *or* **Windows PowerShell 5.1** + **`CiTool.exe`** (**No GPO** in this guide)
> - **Scripts:** Every step in this guide has a ready-to-run script — PowerShell 7 versions in `scripts\`, Windows PowerShell 5.1 versions in `scripts\pwsh_5.1\`. See **[Scripts at a Glance — Run Order](#scripts-at-a-glance--run-order)** for the exact order, and the note in §0.3 for the only differences between the two editions
> - **Policy Architecture:** **Multiple-Policy Format** (`{PolicyID}.cip` in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`) with **Allow Supplemental Policies** enabled
> - **Approved Apps to Keep Working:** **Every application your PAW needs.** The guide is application-agnostic: after a reboot you simply run everything you need and the audit log tells the Wizard what to allow
> - **Block-Test App (optional):** Any application you deliberately leave out and never launch during the audit window — it must be blocked once the policy is enforced
> - **Target End State:** `CodeIntegrityPolicyEnforcementStatus = 2` **and** `UsermodeCodeIntegrityPolicyEnforcementStatus = 2` (resolves DISA PAW STIG **V-243450** & **V-243451**)
> - **Reference Repo:** [dcodev1702/STIG-WDAC-WIN11-25H2](https://github.com/dcodev1702/STIG-WDAC-WIN11-25H2/blob/main/README.md)

---

## Table of Contents

> **Quick reference:** [Scripts at a Glance — Run Order](#scripts-at-a-glance--run-order) lists every script, in the order you run it, with the matching guide step. [Policy Rule Options — What Changes Between Audit and Enforce](#policy-rule-options--what-changes-between-audit-and-enforce) lists which options stay enabled, which one is turned off (Audit Mode only), and which stay off.

1. [How This Workflow Fits Together (And Why Each Rule Exists)](#1-how-this-workflow-fits-together-and-why-each-rule-exists)
2. [Step 0 — Checkpoint, Persistent `pwsh 7` Session, and `0 / 0` Pre-Flight Check](#2-step-0--checkpoint-persistent-pwsh-7-session-and-0--0-pre-flight-check)
3. [Step 1 — Use the Wizard to Establish the Baseline Policy (Audit Mode)](#3-step-1--use-the-wizard-to-establish-the-baseline-policy-audit-mode)
4. [Step 2 — Use PowerShell 7 to Stamp, Compile, and Deploy the Baseline Audit Policy (`0 / 0` → `1 / 1`)](#4-step-2--use-powershell-7-to-stamp-compile-and-deploy-the-baseline-audit-policy-0--0--1--1)
5. [Step 3 — Reboot and Run Every Application You Need to Generate `3076` Audit Events](#5-step-3--reboot-and-run-every-application-you-need-to-generate-3076-audit-events)
6. [Step 4 — Export Time-Boxed Events, Capture `3076` Events as New Rules, and Sanitize Them](#6-step-4--export-time-boxed-events-capture-3076-events-as-new-rules-and-sanitize-them)
7. [Step 5 — Use PowerShell 7 to Merge Baseline + Events, Keep in Audit Mode, and Screen (`1 / 1`)](#7-step-5--use-powershell-7-to-merge-baseline--events-keep-in-audit-mode-and-screen-1--1)
8. [Step 6 — Use the Wizard to Keep Boot Audit Enabled and Switch from Audit to Enforce](#8-step-6--use-the-wizard-to-keep-boot-audit-enabled-and-switch-from-audit-to-enforce)
9. [Step 7 — Use PowerShell 7 to Bump Version, Verify Multi-Policy Suitability, and Apply (`1 / 1` → `2 / 2`)](#9-step-7--use-powershell-7-to-bump-version-verify-multi-policy-suitability-and-apply-1--1--2--2)
10. [Step 8 — Validate STIG Compliance (`2` and `2`) and Prove Enforcement with a Block Test](#10-step-8--validate-stig-compliance-2-and-2-and-prove-enforcement-with-a-block-test)
11. [Quick Rollback / Fix-Forward Reference](#11-quick-rollback--fix-forward-reference)
12. [Agent Handover & Audit Log Protocol (For Follow-On Automation / GPO Phase)](#12-agent-handover--audit-log-protocol-for-follow-on-automation--gpo-phase)

---

## Scripts at a Glance — Run Order

Run these **in this order**. Use the **PowerShell 7** copy from `scripts\` *or* the **Windows PowerShell 5.1** copy from `scripts\pwsh_5.1\` (same file names, same behavior). Always use an **elevated** session on `WIN11-PAW-WDAC`. Every script stops with a `STOP:` message on any failure, so a failed step can never feed a bad file to the next one.

| Order | Guide Step | Script / Action | What It Does | Success Looks Like |
|:---:|---|---|---|---|
| **1** | Step 0.3 – 0.4 | `0_pre-flight.ps1` | Admin check, creates `C:\WDAC\{Source,Compiled,Events,Logs}`, starts the transcript, loads `ConfigCI`, records the `0 / 0` STIG baseline | STIG `0 / 0`; only Microsoft platform policies listed |
| **2** | Step 1 | *Manual — App Control Policy Wizard* | Creates `C:\WDAC\Source\Base-Audit.xml` (Allow Microsoft, **Audit Mode**) | `Base-Audit.xml` exists |
| **3** | Step 2 | `1_compile_and_deploy.ps1` | Stamps **`PAW-AUDIT-BASE-v1` / `2026.10.21.1`**, saves `PolicyGuid.txt`, compiles, deploys with `CiTool.exe`, and **records the audit window start** (`AuditRoundStart.txt`) | `OperationResult` `0`; `AuditRoundStart.txt` written |
| **4** | Step 2 (verify) | `2_audit_policy_activation.ps1` | Confirms the baseline is loaded and authorized | STIG `1 / 1`; Event `3099` |
| **5** | Step 3 | *Manual — **reboot**, then run **every application you need*** | Generates the `3076` audit events (the window start is already recorded by row 3) | Applications ran under the audit policy |
| **6** | Step 4.1 | `3_capture_ciaudit_events.ps1` | Previews `3076` events and exports a time-boxed `PAW-Audit-3076.evtx` | `.evtx` created |
| **7** | Step 4.2 | *Manual — App Control Policy Wizard* | Converts the `.evtx` into allow rules → `C:\WDAC\Source\Events-Allow.xml` | `Events-Allow.xml` exists |
| **8** | **Step 4.3** | **`3_1_validate_winevent_rules.ps1`** | **Sanitizes every rule in `Events-Allow.xml` so it compiles, merges, and is accepted by `CiTool.exe`** (proves it with a real compile + merge test before saving) | `PASSED` message; original backed up if anything changed |
| **9** | Step 5 | `4_merge_audit_base_and_events_policies.ps1` | Merges Base + Events, cleans options, stamps **`PAW-AUDIT-MERGED-v2` / `2026.10.21.2`**, compiles, deploys, and **records the screening window start** (`ScreenStart.txt`) | `OperationResult` `0`; STIG `1 / 1`; `ScreenStart.txt` written |
| **10** | Step 5 (screen) | *Manual — **reboot**, then run **every application you need** again* | Re-exercises everything under the merged audit policy (the window start is already recorded by row 9) | Applications ran under the merged policy |
| **11** | Step 5 (screen) | `5_audit_merged_events.ps1` | Counts new `3076` events since the screening started and, **when clean, prepares `Base-Enforce.xml`** (a copy of the screened `Base-Audit-Merged.xml`). If a different `Base-Enforce.xml` already exists it **asks before overwriting** (default: a timestamped copy) | `0` new events and `Base-Enforce.xml` prepared (otherwise repeat Steps 4 – 5) |
| **12** | Step 6 | *Manual — App Control Policy Wizard* | Open the `Base-Enforce.xml` that script 5 prepared, turn **Audit Mode OFF** (keep Boot Audit ON), and save | Audit Mode off in the saved `Base-Enforce*.xml` |
| **13** | Step 7 | `6_enforce_policy.ps1` | Pre-deployment gate (including proof that **Audit Mode is the only option turned off**, plus a list of the options that stay enabled), stamps **`PAW-ENFORCED-v3` / `2026.10.21.3`**, compiles, deploys | `PRE-DEPLOYMENT CHECK PASSED`; `OperationResult` `0` |
| **14** | Step 8.1 | `7_DISA_STIG_CHECK.ps1` | Runs the DISA STIG check (`V-243450` / `V-243451`) | STIG `2 / 2` — **PASS** |
| **15** | Step 8.2 | `8_validate_multipolicy_layout.ps1` | Verifies the `.cip` layout, `CiTool` inventory, and Event `3099` | `IsEnforced` / `IsAuthorized` = `True` |
| **16** | Step 8.4 *(optional)* | `Get-Blocked_CI_Events.ps1` | Lists enforced-block Event `3077` records | Your unapproved app is listed |

> **Looping:** if the screening in row 11 shows new `3076` events for an application you need, repeat rows **6 → 11** (export → Wizard → **sanitize (row 8)** → merge → screen) before moving on to Step 6.
> **Copying the scripts to the PAW:** from the Hyper-V host, `Copy-Item -ToSession $PAWSession -Path '<path>\scripts' -Destination 'C:\WDAC-Scripts' -Recurse` (uses the session from Step 0.2), then run them from `C:\WDAC-Scripts\` (PowerShell 7) or `C:\WDAC-Scripts\pwsh_5.1\` (Windows PowerShell 5.1).

---

## 1. How This Workflow Fits Together (And Why Each Rule Exists)

### The Two DISA STIG Findings We Are Closing

| STIG ID | Vulnerability ID | What It Checks | Passing Value |
|---|---|---|---|
| **V-243450** | `WPAW-00-001050` (CAT II) | `CodeIntegrityPolicyEnforcementStatus` (Kernel-mode CI) | **`2`** (Enforced) |
| **V-243451** | `WPAW-00-001060` (CAT II) | `UsermodeCodeIntegrityPolicyEnforcementStatus` (User-mode CI / UMCI) | **`2`** (Enforced) |

In `Win32_DeviceGuard`, **`0`** = Not Configured, **`1`** = Audit Mode, and **`2`** = Enforced. By checking these values at every stage (**`0 / 0` → `1 / 1` → `2 / 2`**), we prove beyond doubt that **our policy** is what transitions the PAW into STIG compliance.

### The Seven Golden Rules of This Multi-Policy Workflow

1. **Deploy the Baseline Audit Policy *Before* Capturing Events (Step 2):**
   The Wizard only writes an `.xml` file to disk. Windows will not log any Event ID `3076` ("would have been blocked") telemetry until that baseline policy is compiled into a `.cip` binary and loaded with `CiTool.exe`.
2. **One `PolicyID` GUID Across All Revisions (Never Use `-ResetPolicyID`):**
   In the Multiple-Policy Format, the Wizard assigns a unique `PolicyID` GUID when creating `Base-Audit.xml`. Every subsequent stage (Merged Audit and Enforced) **must keep that exact same `PolicyID` GUID** with a higher version number so Windows updates the existing policy in place rather than stacking a second policy alongside it.
3. **Merge Only — Never Deploy `Events-Allow.xml` on Its Own:**
   If two separate **Base Policies** are active at the same time, Windows **intersects** them (an app must be allowed by *both* policies to run). Deploying an event-derived policy by itself would block Windows itself! Instead, we **merge** `Base-Audit.xml` (listed **first**) + `Events-Allow.xml` (listed **second**) into one updated base policy.
4. **Watch Out for `Merge-CIPolicy` Rule-Option Unioning:**
   When `Merge-CIPolicy` merges two XML files, it keeps the first file's `PolicyID` GUID, name, and version, **but it combines (unions) the `<Option>` tags from both files**. Because the Wizard's event-conversion output includes extra default options (like `Enabled:Dynamic Code Security`), Step 5 includes an explicit PowerShell cleanup so unwanted options never leak into your merged policy.
5. **Time-Boxed `.evtx` Exports (`3076` + `3089`):**
   Old `3076` events stay in Event Viewer forever. Exporting a time-filtered `.evtx` containing only `EventID=3076` (audit block) and `EventID=3089` (the paired Authenticode signature record that the Wizard needs to build Publisher rules) since `$AuditRoundStart` keeps your rules clean.
6. **No Reboots Required to Deploy a Policy — One Deliberate Reboot per Test Round:**
   Because we enable **Update Policy without Rebooting** (`Option 16`) and deploy unsigned policies via `CiTool.exe --update-policy`, every policy deployment and update in this guide takes effect **live without rebooting**. The *only* reboots in this guide are the deliberate ones in Step 3 and Step 5: restarting the PAW before you run your applications guarantees that startup components, services, and updaters all load fresh under the active audit policy, so every binary you depend on is logged (or proven clean).
7. **Sanitize the Event-Derived Rules Before You Merge (Why `ConvertFrom-CIPolicy` / `Merge-CIPolicy` Can Fail):**
   The Wizard can write rules the ConfigCI compiler rejects — for example a `<FileAttrib>` with no `FileName`, `InternalName`, `FileDescription`, `ProductName`, `PackageFamilyName`, `Hash`, or `FilePath` (typically a **FilePublisher** rule for a file with no version resource). The error looks like `There is invalid file rule with ID "ID_FILEATTRIB_A_3_1"`. Some defects are worse: an *empty* `Hash` compiles on its own but breaks the **merge** later. **Step 4.3** (`3_1_validate_winevent_rules.ps1`) finds and repairs or removes every such rule *before* the merge, and Steps 5 and 7 re-check as a safety net.

### Version & ID Progression Plan

| Stage | XML File | Friendly Name (`-PolicyName`) | Policy ID Label (`-PolicyId`) | `VersionEx` | Mode | Expected STIG Status |
|---|---|---|---|---|---|---|
| **Pre-Flight** | *(None)* | *(Only MS platform policies)* | — | — | None | **`0` / `0`** |
| **Baseline Audit** | `Base-Audit.xml` | `PAW-WDAC-Audit-Baseline` | `PAW-AUDIT-BASE-v1` | `2026.10.21.1` | Audit | **`1` / `1`** |
| **Merged Audit** | `Base-Audit-Merged.xml` | `PAW-WDAC-Audit-Merged` | `PAW-AUDIT-MERGED-v2` | `2026.10.21.2` | Audit | **`1` / `1`** |
| **Enforced** | `Base-Enforce.xml` | `PAW-WDAC-Enforced` | `PAW-ENFORCED-v3` | `2026.10.21.3` | **Enforce** | **`2` / `2`** |
| *Fix-Forward (optional)* | `Base-Audit-Merged.xml` | `PAW-WDAC-Audit-Merged` | `PAW-AUDIT-MERGED-v2` | `2026.10.21.4` | Audit | **`1` / `1`** |

> The `VersionEx` always increases by one at each stage (`.1` → `.2` → `.3`, and `.4` for an optional fix-forward), and the label (`v1`, `v2`, `v3`) matches the stage. Windows only replaces the active policy in place when the new `VersionEx` is **higher** than the one already loaded.

### Policy Rule Options — What Changes Between Audit and Enforce

**The rule:** going from the audit policy to the enforced policy turns **one** option off — **`Enabled:Audit Mode`** — and changes **nothing else**. Every other option in the screened audit policy stays exactly as it is.

**1. Options that stay ENABLED (audit → enforced)**

| Option | Rule # | Wizard toggle (Step 1) | Why it stays enabled |
|---|:---:|---|---|
| `Enabled:UMCI` | 0 | User Mode Code Integrity (UMCI) | User-mode code integrity — this is what makes **V-243451** report `2` |
| `Required:WHQL` | 2 | Require WHQL | Kernel drivers must be WHQL-signed |
| `Enabled:Unsigned System Integrity Policy` | 6 | Unsigned System Integrity Policy | The `.cip` is unsigned — no code-signing certificate is required |
| `Enabled:Advanced Boot Options Menu` | 9 | Advanced Boot Options Menu | The F8 pre-boot recovery menu stays available |
| `Enabled:Boot Audit On Failure` | 10 | Boot Audit on Failure | A boot-critical driver that fails validation is audited instead of blocking boot |
| `Disabled:Script Enforcement` | 11 | Disable Script Enforcement | Script enforcement stays **off** (PowerShell stays in `FullLanguage`). The option is *present* (ON) — "Disabled" is part of its name |
| `Enabled:Update Policy No Reboot` | 16 | Update Policy without Rebooting | Later updates apply live with `CiTool.exe` |
| `Enabled:Allow Supplemental Policies` | 17 | Allow Supplemental Policies | Keeps the multiple-policy (supplemental) model working |
| *Template extras*, e.g. `Required:Enforce Store Applications` (12) and `Enabled:Inherit Default Policy` (5, reserved — no effect) | | *(carried by the Allow Microsoft template, not a toggle you set)* | Anything else already enabled in your screened audit policy also stays. A policy built from the Windows *Allow Microsoft* template carries these two |

**2. The one option turned OFF**

| Option | Rule # | Wizard toggle | Audit stages (Steps 2 – 5) | Enforced (Step 7) |
|---|:---:|---|---|---|
| `Enabled:Audit Mode` | 3 | Audit Mode | ✅ **ON** — logs `3076` instead of blocking | ❌ **OFF** — blocks; STIG `2 / 2` |

**3. Options that stay OFF (never enabled in this guide)**

| Option | Rule # | Wizard toggle (Step 1) | Why it stays off |
|---|:---:|---|---|
| `Enabled:Managed Installer` | 13 | Managed Installer | MECM / Intune Managed Installer is not used |
| `Enabled:Intelligent Security Graph Authorization` | 14 | Intelligent Security Graph (ISG) | The PAW does not rely on internet cloud reputation |
| `Enabled:Invalidate EAs on Reboot` | 15 | Invalidate EAs on Reboot | Only applies to ISG extended attributes |
| `Disabled:Runtime FilePath Rule Protection` | 18 | Disable Runtime FilePath Rule Protection | Keep it **absent**: its absence keeps runtime protection **ON**, so FilePath rules only work on admin-writable folders |
| `Enabled:Dynamic Code Security` | 19 | Dynamic Code Security | Has no audit mode — it would enforce immediately on .NET dynamic assemblies |
| `Enabled:Revoked Expired As Unsigned` | 20 | Treat Revoked as Unsigned | Kept off per the STIG guide |

**How the workflow guarantees this**

- **Step 1 (Wizard):** you set the toggles exactly as in the Wizard table in Step 1.
- **Step 5 (`4_merge_audit_base_and_events_policies.ps1`):** re-ensures the required options are ON and removes the six OFF options if the Wizard's event policy leaked any of them in.
- **Step 7 (`6_enforce_policy.ps1`):** compares the enforced policy with the **screened** `Base-Audit-Merged.xml`. If any option other than `Enabled:Audit Mode` was enabled there and is missing now, it **stops before compiling** and names the option. When it passes, it prints the exact list of options that stay enabled (an example is in Step 7).
- The list printed by script 6 is authoritative for your machine; it can differ from table 1 only by template extras.

---

## 2. Step 0 — Checkpoint, Persistent `pwsh 7` Session, and `0 / 0` Pre-Flight Check

### 0.1 Take a Safety Checkpoint on the Hyper-V Host

**What this does:** Creates a fresh point-in-time snapshot of `WIN11-PAW-WDAC` right before we create or load any WDAC policy (in addition to your existing `FULLY UPDATED - NON DC JOINED - NO WDAC POLICY` checkpoint).
**Why we need it:** Gives you an instant one-command rollback if you ever want to re-run the lab from a clean slate.

Run this in an **elevated PowerShell 7 (`pwsh`)** window on your **Hyper-V Host (`RYZEN-BEE`)**:

```powershell
# Run on Hyper-V Host (Elevated pwsh 7)
Checkpoint-VM -Name 'WIN11-PAW-WDAC' -SnapshotName 'Pre-WDAC-Manual-Walkthrough'
Get-VMCheckpoint -VMName 'WIN11-PAW-WDAC' | Select-Object Name, CreationTime
```

### 0.2 Connect to `WIN11-PAW-WDAC` via PowerShell 7 (And Do Not Remove the Session)

**What this does:** Opens a persistent, elevated PowerShell 7 session into `WIN11-PAW-WDAC` over the Hyper-V VMBus (**PowerShell Direct**) using the Windows credential dialog (`Get-Credential`), and enters it interactively.
**Why we need it:** PowerShell Direct works even when the guest firewall blocks WinRM/SSH. Keeping `$PAWSession` in memory (and never running `Remove-PSSession`) lets you hop in and out or copy files (`Copy-Item -ToSession $PAWSession` / `-FromSession $PAWSession`) throughout the entire exercise.

```powershell
# Run on Hyper-V Host (Elevated pwsh 7)
# Note: If WIN11-PAW-WDAC is not yet joined to skynet-home.local, either run .\Join-SkynetDomain.ps1 first
# or enter .\lorenzo in the credential dialog.
$Cred = Get-Credential -UserName 'lorenzo@skynet-home.local' -Message 'Enter PAW Administrator Password'
$PAWSession = New-PSSession -VMName 'WIN11-PAW-WDAC' -Credential $Cred -Name 'PAW-WDAC-Session'

# Verify the session is Open (DO NOT run Remove-PSSession!)
Get-PSSession -Name 'PAW-WDAC-Session'
```

> **Where to run the commands below:**
> Since you will also be clicking through the **App Control Policy Wizard GUI** on `WIN11-PAW-WDAC`, you can either:
> - Run the PowerShell commands inside your interactive remote session (`Enter-PSSession -Session $PAWSession`), **or**
> - Open an **elevated PowerShell 7 (`pwsh` — Run as Administrator)** window directly on the `WIN11-PAW-WDAC` desktop right next to the Wizard GUI.
> Either way, the commands below execute on `WIN11-PAW-WDAC` against `C:\WDAC\`.

### 0.3 Create Working Folders, Start Audit Transcript, and Load `ConfigCI`

**What this does:**
1. Creates `C:\WDAC\Source`, `C:\WDAC\Compiled`, `C:\WDAC\Events`, and `C:\WDAC\Logs` on `WIN11-PAW-WDAC`.
2. Starts a full PowerShell transcript (`Start-Transcript`) so every command you run and every output returned is saved for your audit trail.
3. Loads the Windows `ConfigCI` module (into PowerShell 7 with `-UseWindowsPowerShell`, or natively in Windows PowerShell 5.1).

**Why we need it:** `ConfigCI` (`New-CIPolicy`, `Merge-CIPolicy`, `Set-CIPolicyIdInfo`, `Set-CIPolicyVersion`, `Set-RuleOption`, `ConvertFrom-CIPolicy`) is a Windows PowerShell 5.1 system module. Passing `-UseWindowsPowerShell` loads it seamlessly into PowerShell 7 via the built-in compatibility session; Windows PowerShell 5.1 loads it natively.

> **PowerShell 7 or Windows PowerShell 5.1 — your choice.** All commands in this guide are available in both editions:
> - **PowerShell 7 (`pwsh`)** → use the scripts in `scripts\`.
> - **Windows PowerShell 5.1 (console or ISE)** → use the scripts in `scripts\pwsh_5.1\`. They differ only by (1) `Import-Module ConfigCI` *without* `-UseWindowsPowerShell`, (2) calling `New-CIPolicyRule`/`Merge-CIPolicy` directly instead of through a nested `powershell.exe`, (3) loading XML with `XmlDocument.Load()` (5.1's `Get-Content` assumes ANSI for BOM-less UTF-8), (4) ASCII-only text, and (5) a `#Requires -PSEdition Desktop` guard on the scripts that use `ConfigCI`.
> - Always start the session **elevated** (*Run as administrator*). Every script stops with a clear `STOP:` message instead of continuing after an error, so a failed compile can never reach `CiTool.exe`.

Run on **`WIN11-PAW-WDAC`** (elevated `pwsh 7`; for 5.1 use `scripts\pwsh_5.1\0_pre-flight.ps1`):

```powershell
# 1. Verify this PowerShell 7 session is running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'STOP: Open PowerShell 7 with "Run as Administrator".' }

# 2. Create the clean directory structure
$Folders = @(
    'C:\WDAC\Source',
    'C:\WDAC\Compiled',
    'C:\WDAC\Events',
    'C:\WDAC\Logs'
)
New-Item -Path $Folders -ItemType Directory -Force -ErrorAction Stop | Out-Null

# 3. Start an audit log transcript of all commands and outputs
Start-Transcript -Path "C:\WDAC\Logs\WDAC-Manual-Run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

# 4. Import ConfigCI into PowerShell 7 and confirm CiTool.exe exists (Windows 11 22H2+ / Server 2025)
#    (Windows PowerShell 5.1: use  Import-Module ConfigCI -WarningAction SilentlyContinue -ErrorAction Stop)
Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop
Get-Command -Module ConfigCI
if (-not (Test-Path -LiteralPath "$env:SystemRoot\System32\CiTool.exe")) { throw 'STOP: CiTool.exe was not found. Multiple-policy deployment requires Windows 11 22H2 or later.' }
```

### 0.4 Run the Stage 0 STIG Check (`0 / 0` Baseline) & Install Everything You Need

**What this does:** Records the "Before" state of `Win32_DeviceGuard` and lists currently active policies in `CiTool.exe` before we enable WDAC.
**Why we need it:**
- Confirms both STIG values start at **`0` (Not Configured)** and no stray `SiPolicy.p7b` or custom `.cip` policy is already active.
- **Install every application you need on the PAW *now*, before Audit Mode is turned on.** Installers and first-run setup routines would otherwise pollute the `3076` audit log with one-time noise. **Do not launch any application you intend to keep blocked.**

```powershell
# 5. Stage 0 STIG Check - Expect BOTH values to be 0 (Not Configured)
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 6. Confirm no legacy single-policy SiPolicy.p7b exists (Expect: False)
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"

# 7. List existing policies in CiTool - Expect ONLY built-in Microsoft Platform policies (IsSystemPolicy = true)
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Select-Object PolicyID, FriendlyName, IsSystemPolicy, IsEnforced, IsAuthorized |
    Format-Table -AutoSize
```

---

## 3. Step 1 — Use the Wizard to Establish the Baseline Policy (Audit Mode)

**What this does:** Uses the **App Control Policy Wizard** GUI to build a **Multiple-Policy Format** base policy from the **Allow Microsoft** template in **Audit Mode**, including Microsoft's Recommended User Mode and Kernel Mode Block Rules.
**Why we need it:** Starting from *Allow Microsoft* in Audit Mode trusts Windows and Microsoft-signed binaries (including PowerShell 7 and `CiTool.exe`) while logging Event ID `3076` for everything else (any third-party, non-Microsoft-signed, or unsigned application you run) without blocking anything yet.

### Step-by-Step in the App Control Policy Wizard GUI

1. Launch the **App Control Policy Wizard** on `WIN11-PAW-WDAC`.
2. Click **Policy Creator** -> select **Base Policy**.
3. Ensure **Multiple Policy Format (Windows 10 1903+)** is selected (this is the default radio button—do **not** select Single Policy Format).
4. Select **Allow Microsoft Mode** as the base template.
5. Under **Policy Name** and **File Path**:
   - **Policy Name:** `PAW-WDAC-Audit-Baseline`
   - **File Path:** Click **Browse** and save to **`C:\WDAC\Source\Base-Audit.xml`**
   - Click **Next**.
6. On the **Policy Rules** screen, click **+ Advanced Options** at the bottom so all toggles are visible, and set them exactly as follows:

| Wizard Rule Option | Setting | Why We Set It This Way |
|---|---|---|
| **Audit Mode** | ✅ **ON** | Logs `3076` events without blocking apps while we build our allowlist. |
| **User Mode Code Integrity (UMCI)** | ✅ **ON** | Required to enforce user-mode apps and satisfy STIG **V-243451** (`WPAW-00-001060`). |
| **Allow Supplemental Policies** | ✅ **ON** | Required so this base policy supports the **multi-policy method** and future supplemental policies. |
| **Disable Script Enforcement** | ✅ **ON** | Lab exception from the guide: keeps interactive PowerShell in `FullLanguage` mode instead of dropping into `ConstrainedLanguage` mode. |
| **Unsigned System Integrity Policy** | ✅ **ON** | Allows deploying `.cip` files without requiring a PKI code-signing certificate. |
| **Update Policy without Rebooting** | ✅ **ON** | Allows `CiTool.exe --update-policy` to apply changes live without rebooting. |
| **Advanced Boot Options Menu** | ✅ **ON** | Enables the F8 pre-boot recovery menu if a boot issue ever occurs. |
| **Require WHQL** | ✅ **ON** | Requires kernel drivers to be WHQL-signed per the STIG guide. |
| **Boot Audit on Failure** *(under Advanced Options)* | ✅ **ON** | Safety net: if a boot-critical driver fails validation, Windows boots in Audit Mode instead of BSODing. |
| **Intelligent Security Graph (ISG)** | ❌ **OFF** | PAW does not rely on internet cloud reputation. |
| **Managed Installer** | ❌ **OFF** | MECM / Intune Managed Installer is not used in this workflow. |
| **Dynamic Code Security** *(Advanced)* | ❌ **OFF** | Has no audit mode; enforces immediately on .NET dynamic assemblies and can break admin tools. |
| **Treat Revoked as Unsigned** *(Advanced)* | ❌ **OFF** | Keep off per the STIG guide. |
| **Disable Runtime FilePath Rule Protection** *(Advanced)* | ❌ **OFF** | **Keep OFF!** Leaving this toggle OFF keeps runtime protection **ON** (ensuring FilePath rules only work on admin-writable folders like `C:\Program Files`). |
| **Invalidate EAs on Reboot** *(Advanced)* | ❌ **OFF** | Only applies to ISG extended attributes. |
| **Hypervisor-protected Code Integrity (HVCI)** | ❌ **OFF** | Configured at the OS/VBS level rather than inside this policy XML. |

> **What happens to each of these at enforcement?** Only **Audit Mode** is turned off (Step 7). Every other ✅ option stays on and every ❌ option stays off — see [Policy Rule Options — What Changes Between Audit and Enforce](#policy-rule-options--what-changes-between-audit-and-enforce) for the full list with rule numbers and reasons.

7. Click **Next** to reach the **File Rules** screen.
8. At the bottom of the **File Rules** screen, check **both** boxes:
   - ✅ **Merge with Recommended User Mode Block Rules** *(blocks known Microsoft-signed bypass tools / LOLBins)*
   - ✅ **Merge with Recommended Kernel Mode Block Rules** *(blocks known vulnerable kernel drivers)*
9. Click **Next** to build the policy.
   - *(Note: In Wizard v2.8+, the Wizard may also compile a `.cip` file in the same folder automatically. We will compile our own versioned `.cip` into `C:\WDAC\Compiled\` in Step 2).*

---

## 4. Step 2 — Use PowerShell 7 to Stamp, Compile, and Deploy the Baseline Audit Policy (`0 / 0` → `1 / 1`)

**What this does:**
1. Inspects `C:\WDAC\Source\Base-Audit.xml` to verify all required rule options are present and records the `PolicyID` GUID.
2. Stamps a clear `PolicyId` (`PAW-AUDIT-BASE-v1`), `PolicyName` (`PAW-WDAC-Audit-Baseline`), and `VersionEx` (`2026.10.21.1`) into the XML.
3. Compiles `Base-Audit.xml` into `C:\WDAC\Compiled\{PolicyID}.cip`.
4. Loads the policy live into Windows using `CiTool.exe --update-policy` and verifies the STIG status moves from **`0 / 0`** to **`1 / 1` (Audit Mode)**.
5. **Records the start of the audit window** (`C:\WDAC\Events\AuditRoundStart.txt`) the moment the policy is successfully loaded. This is the timestamp Step 4.1 uses to export *only* the `3076` events from this round. If the file already exists, the old value is kept as `AuditRoundStart.previous-<timestamp>.txt` and a warning is shown, so re-running this script can never silently lose an earlier window.
**Why we need it:** Windows cannot log `3076` events until an audit policy is actually active on the system!

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC` (or run `scripts\1_compile_and_deploy.ps1` / `scripts\pwsh_5.1\1_compile_and_deploy.ps1`):

```powershell
if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }

$BaseXml = 'C:\WDAC\Source\Base-Audit.xml'
if (-not (Test-Path -LiteralPath $BaseXml)) { throw "STOP: $BaseXml not found. Create it with the App Control Policy Wizard first (Step 1)." }

# 1. Stamp helpful Name, ID label, and VersionEx (NEVER use -ResetPolicyID!)
Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'PAW-WDAC-Audit-Baseline' -PolicyId 'PAW-AUDIT-BASE-v1' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $BaseXml -Version '2026.10.21.1' -ErrorAction Stop

# 2. Read the PolicyID GUID and verify rule options in the XML
[xml]$BaseDoc = Get-Content -LiteralPath $BaseXml
$PolicyGuid   = $BaseDoc.SiPolicy.PolicyID
if (-not $PolicyGuid) { throw 'STOP: No PolicyID found. Base-Audit.xml must be created in Multiple Policy Format.' }
$PolicyGuid | Set-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt'

[pscustomobject]@{
    PolicyType   = $BaseDoc.SiPolicy.PolicyType
    PolicyID     = $BaseDoc.SiPolicy.PolicyID
    BasePolicyID = $BaseDoc.SiPolicy.BasePolicyID
    VersionEx    = $BaseDoc.SiPolicy.VersionEx
    RuleOptions  = ($BaseDoc.SiPolicy.Rules.Rule.Option -join ', ')
} | Format-List
```

**Verify in the output above:**
- `PolicyType` is `Base Policy`
- `PolicyID` and `BasePolicyID` are **identical GUIDs** (proving Multiple-Policy Format)
- `RuleOptions` includes `Enabled:Audit Mode`, `Enabled:UMCI`, `Enabled:Allow Supplemental Policies`, `Enabled:Boot Audit On Failure`, `Disabled:Script Enforcement`, `Enabled:Update Policy No Reboot`, and `Enabled:Unsigned System Integrity Policy`.

Now compile and deploy the baseline audit policy. If the compile or `CiTool.exe` reports a failure, the script stops with a `STOP:` message and the policy is **not** applied:

```powershell
# 3. Compile Base-Audit.xml to C:\WDAC\Compiled\{PolicyID}.cip
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $BaseXml -BinaryFilePath $CipFile -ErrorAction Stop
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }

# Save an archive copy of v2026.10.21.1 for our audit trail
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip' -Force -ErrorAction Stop

# 4. Deploy the Baseline Audit Policy live with CiTool.exe (no reboot required)
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }

# 5. Start the audit window: every Event ID 3076 from now on belongs to this round (3_capture_ciaudit_events.ps1 reads this file)
$AuditStartFile = 'C:\WDAC\Events\AuditRoundStart.txt'
New-Item -Path (Split-Path -Parent $AuditStartFile) -ItemType Directory -Force | Out-Null
if (Test-Path -LiteralPath $AuditStartFile) {
    $PreviousFile = Join-Path (Split-Path -Parent $AuditStartFile) "AuditRoundStart.previous-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    Copy-Item -LiteralPath $AuditStartFile -Destination $PreviousFile -ErrorAction Stop
    Write-Warning "An earlier audit window start existed and was replaced. The old value was kept as $PreviousFile"
}
$AuditRoundStart = Get-Date
$AuditRoundStart.ToString('o') | Set-Content -LiteralPath $AuditStartFile -ErrorAction Stop
Write-Host "Audit window started at $($AuditRoundStart.ToString('o')). Reboot now, then run every application you need (Step 3)." -ForegroundColor Green
```

### Verify Stage 1 Activation (`0 / 0` → `1 / 1` and Event ID `3099`)

> Script: `scripts\2_audit_policy_activation.ps1` (PowerShell 7) or `scripts\pwsh_5.1\2_audit_policy_activation.ps1` (Windows PowerShell 5.1).

```powershell
# 1. Stage 1 STIG Check - Expect BOTH values to now be 1 (Audit Mode)!
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 2. Verify CiTool shows PAW-WDAC-Audit-Baseline loaded and authorized
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, BasePolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

# 3. Confirm Event ID 3099 (Policy Loaded) in the CodeIntegrity Operational log
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3099
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List
```

---

## 5. Step 3 — Reboot and Run Every Application You Need to Generate `3076` Audit Events

**What this does:** **Reboots the PAW** and then has you run **every application and workflow you need to keep working** on it. The start of this audit window was already recorded by Step 2 (`AuditRoundStart.txt`).
**Why we need it:** Code Integrity only logs Event ID `3076` when a binary is actually loaded into memory. Rebooting *after* the audit policy is active forces every startup component, service, scheduled task, and updater to load under the audit policy, and `AuditRoundStart.txt` (recorded when the policy was loaded, so before the reboot) lets us export *only* the events generated during this controlled window (including the boot itself).

### 3.1 The Audit Window Start Is Recorded Automatically

`1_compile_and_deploy.ps1` wrote `C:\WDAC\Events\AuditRoundStart.txt` right after it loaded the baseline audit policy, so there is nothing to run here. Confirm it exists:

```powershell
Get-Content -LiteralPath 'C:\WDAC\Events\AuditRoundStart.txt'
```

> **Optional — restart the window manually.** If you want a fresh start (for example, you launched something you did *not* want captured after Step 2 and before rebooting), re-mark it just before you reboot:
> ```powershell
> $AuditRoundStart = Get-Date
> $AuditRoundStart.ToString('o') | Set-Content -LiteralPath 'C:\WDAC\Events\AuditRoundStart.txt'
> ```

### 3.2 Reboot, Then Run Everything You Need

1. **Reboot `WIN11-PAW-WDAC` now** (Start menu -> Restart, or `Restart-Computer`).
   - `AuditRoundStart.txt` is saved on disk, so it survives the reboot.
   - A reboot ends your PowerShell session, transcript, and any PowerShell Direct session (`$PAWSession`). After signing back in, open a new **elevated** PowerShell window (and re-create `$PAWSession` from the Hyper-V host if you use it). `ConfigCI` is re-imported automatically by the Step 2, 5, and 7 code/scripts.
2. **Sign in and run all of the applications and workflows you need** — every line-of-business app, admin tool, command-line tool, editor, browser, plug-in/extension, installer, and **update mechanism** (check for updates) that this PAW must keep running. Open real files, run real commands, and use each feature that loads extra DLLs, drivers, or helper executables.
3. **Give background activity a few minutes to run** (services, scheduled tasks, sync agents, updaters).
4. **🚫 Do NOT launch anything you want to stay blocked.** An application that never runs during the audit window generates no `3076` events and therefore receives **zero** allow rules — that is exactly what makes it blockable in Step 8.

---

## 6. Step 4 — Export Time-Boxed Events, Capture `3076` Events as New Rules, and Sanitize Them

### 4.1 Preview `3076` Events and Export a Time-Boxed `.evtx` File (PowerShell)

> Script: `scripts\3_capture_ciaudit_events.ps1` (PowerShell 7) or `scripts\pwsh_5.1\3_capture_ciaudit_events.ps1` (Windows PowerShell 5.1).

**What this does:**
1. Queries `Microsoft-Windows-CodeIntegrity/Operational` for all Event ID `3076` ("would have been blocked") records created since `$AuditRoundStart` and displays the unique file paths.
2. Uses `wevtutil epl` to export a clean `.evtx` file (`C:\WDAC\Events\PAW-Audit-3076.evtx`) containing **only Event IDs `3076` and `3089`** created since `$AuditRoundStart`.

**Why we need it:**
- Event ID `3076` records the file that would have been blocked; Event ID `3089` records the file's Authenticode signature chain. The Wizard needs **both `3076` and `3089`** in the `.evtx` file to create `Publisher` / `FilePublisher` rules.
- Time-boxing to `$AuditRoundStart` prevents stale historical events from sneaking into your policy.

```powershell
$AuditStartFile = 'C:\WDAC\Events\AuditRoundStart.txt'
if (-not (Test-Path -LiteralPath $AuditStartFile)) { throw "STOP: $AuditStartFile not found. Run 1_compile_and_deploy.ps1 first (it records the start of the audit window)." }
$AuditRoundStart = [datetime]::Parse((Get-Content -LiteralPath $AuditStartFile -Raw).Trim())

# 1. Preview unique files that generated Event ID 3076 during our test window
$Events3076 = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $AuditRoundStart
} -ErrorAction SilentlyContinue)

if ($Events3076.Count -eq 0) { throw "STOP: No Event ID 3076 found since $AuditRoundStart. Confirm the audit policy is active (script 2), you are elevated, and you ran your applications after the audit window started." }

$Events3076 | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $File = ($Xml.Event.EventData.Data | Where-Object Name -in 'FileNameBuffer', 'FileName', 'File Name').'#text'
    [pscustomobject]@{
        TimeCreated = $_.TimeCreated
        FilePath    = $File
    }
} | Group-Object FilePath | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

# 2. Export ONLY 3076 + 3089 events since $AuditRoundStart to C:\WDAC\Events\PAW-Audit-3076.evtx
$StartUtc = $AuditRoundStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$EvtxPath = 'C:\WDAC\Events\PAW-Audit-3076.evtx'

& wevtutil.exe epl 'Microsoft-Windows-CodeIntegrity/Operational' $EvtxPath "/q:*[System[(EventID=3076 or EventID=3089) and TimeCreated[@SystemTime>='$StartUtc']]]" /ow:true
if ($LASTEXITCODE -ne 0) { throw "STOP: wevtutil.exe failed to export events (exit code $LASTEXITCODE). Run this from an elevated session." }
Get-Item -LiteralPath $EvtxPath -ErrorAction Stop | Select-Object FullName, Length, LastWriteTime
```

### 4.2 Convert the `.evtx` Events into a Policy in the Wizard GUI

**What this does:** Parses `C:\WDAC\Events\PAW-Audit-3076.evtx` in the App Control Policy Wizard and builds `C:\WDAC\Source\Events-Allow.xml` containing allow rules for the applications you ran.
**Why we need it:** Converts the real-world telemetry from Step 3 into structured XML allow rules ready to be merged into our baseline.

1. Open the **App Control Policy Wizard** -> click **Policy Editor**.
2. Select **Convert Event Logs to a Policy**.
3. Under **Parse Event Log evtx Files to Policy**, click **Parse Log File(s)** and select:
   - **`C:\WDAC\Events\PAW-Audit-3076.evtx`**
4. Once the notification confirms parsing succeeded, click **Next** to open the **Configure Event Log Rules** table.
5. For each application you want to allow, select its row, choose the **Rule Type**, and click **Add Allow Rule** (the row will show *"Added to policy"*):
   - **Signed binaries:** choose **Publisher** (trusts the signer) — or **FilePublisher** (signer + file name/version) if you want a tighter rule.
   - **Unsigned binaries:** choose **Hash**.
   - **Rows you do not recognize or do not want allowed:** leave them alone (do **not** add them), and investigate them before enforcing.
   - **Folders full of binaries:** if an application ships hundreds of files in an **admin-writable-only** folder (for example under `C:\Program Files\...`), you can allow the folder once with a `FilePath` rule in Step 5 (`$AdditionalFolderRules`) instead of adding every file individually.
   - ⚠️ **Prefer Publisher or Hash over FilePublisher for files that have no version information** (some DLLs or plug-in modules). A FilePublisher rule built from a file with no name/version metadata becomes an empty `FileAttrib` that **cannot be compiled** (`There is invalid file rule with ID "ID_FILEATTRIB_..."`). **Step 4.3 repairs or removes such rules for you**, but a Publisher or Hash rule keeps the application allowed.
6. Click **Next** and save the output XML as:
   - **`C:\WDAC\Source\Events-Allow.xml`**

> ⚠️ **Important:** Do **not** compile or deploy `Events-Allow.xml` by itself! It is only an input file for the merge in Step 5. **Run Step 4.3 on it first.**

### 4.3 Sanitize the Event-Derived Rules (`3_1_validate_winevent_rules.ps1`)

**What this does:** Opens `C:\WDAC\Source\Events-Allow.xml` *right after the Wizard writes it* and checks **every rule** against what `Merge-CIPolicy` / `ConvertFrom-CIPolicy` (and therefore `CiTool.exe`) will accept. It repairs what can be repaired safely, removes what cannot, and then **proves** the result by running a real compile of `Events-Allow.xml` and a real merge-and-compile with `Base-Audit.xml` in a temporary folder. Only if both pass does it update `Events-Allow.xml` (after saving a timestamped backup).
**Why we need it:** The Wizard can emit rules that the compiler rejects — for example `There is invalid file rule with ID "ID_FILEATTRIB_A_3_1"` — and a few defects (such as an empty `Hash`) compile alone but break the merge. Catching them here means Step 5 never fails halfway.

> **Safe by design:** the script **never** calls `CiTool.exe` and never applies a policy. It changes `Events-Allow.xml` only after the compile + merge test passes; if the test still fails, the file is left **untouched** and the script stops with a `STOP:` message.

Run it in your elevated session (PowerShell 7 from `scripts\`, or Windows PowerShell 5.1 from `scripts\pwsh_5.1\`):

```powershell
.\3_1_validate_winevent_rules.ps1                          # sanitize Events-Allow.xml in place (a backup is kept)
.\3_1_validate_winevent_rules.ps1 -ReportOnly              # preview the findings; change nothing
.\3_1_validate_winevent_rules.ps1 -AllowPublisherFallback  # see the warning below before using this
```

| Parameter | Default | Purpose |
|---|---|---|
| `-EventsXml` | `C:\WDAC\Source\Events-Allow.xml` | The Wizard-generated rules to sanitize |
| `-BaseXml` | `C:\WDAC\Source\Base-Audit.xml` | Used only for the merge test (the merge test is skipped, with a warning, if it is missing) |
| `-ReportOnly` | off | Show what would change and run the compile + merge test, but do not modify any file |
| `-AllowPublisherFallback` | off | If **every** `FileAttrib` restriction of a signer is invalid, keep the signer as a whole-publisher rule instead of removing it. This trusts **all** files from that publisher, so use it only deliberately |

**What it checks, and what it does about it**

| Check | Result |
|---|---|
| Rule has no identifying attribute (`FileAttrib` with none of `FileName`, `InternalName`, `FileDescription`, `ProductName`, `PackageFamilyName`, `Hash`, `FilePath`; `Allow`/`Deny` with no `Hash`, `FilePath`, or `FileName`) | **Removed** — this is the `invalid file rule with ID …` error |
| Empty attribute values (e.g. `Hash=""`, `FileName=""`) — compile alone, **break the merge** | Empty attribute **stripped**; the rule is then re-evaluated and removed if nothing valid is left |
| `Hash` that is not hexadecimal, or is not SHA-1 (40) / SHA-256 (64) characters long | **Removed** |
| `Hash` combined with other file attributes | **Removed** |
| `MinimumFileVersion` / `MaximumFileVersion` not a valid `a.b.c.d` (each part 0 – 65535), or Min greater than Max | **Removed** (a 3-part version such as `10.0.1` is **fixed** to `10.0.1.0`) |
| Duplicate rule IDs or duplicate signer IDs | Later duplicate **removed** (first kept) |
| IDs that do not match the schema pattern (`ID_ALLOW_…`, `ID_DENY_…`, `ID_FILEATTRIB_…`, `ID_SIGNER_…`) | **Renamed**, and every reference to them is updated |
| Signer with no `CertRoot`, a non-hex/empty `CertRoot`, an empty `CertPublisher`/`CertIssuer`, or a missing `CertEKU` | Signer **removed** (an empty publisher must never widen trust) |
| Signer without a `Name` | **Fixed** (set to the signer ID) |
| Signer whose **every** `FileAttrib` rule was invalid | Signer **removed** so it does not silently become a *whole-publisher* rule (or kept, with a warning, with `-AllowPublisherFallback`) |
| References to rules/signers that do not exist (`FileAttribRef`, `FileRuleRef`, `AllowedSigner`, `CiSigner`, …) and duplicate references | Dangling reference **removed**; duplicates **removed** |
| Unknown or duplicate policy options | Unknown option **removed**; duplicate **removed** |
| Hash case / stray whitespace | **Normalized** (upper-case hashes, trimmed values) |
| Valid rules that nothing references (they have no effect) | **Warning** only |
| Anything the Windows policy schema (`cipolicy.xsd`) still rejects | **Warning** — and the compile + merge test then decides whether it is fatal |

**Reading the output**

- Each finding is tagged `FIXED`, `REMOVED`, or `WARN` and is also saved as a CSV in `C:\WDAC\Logs\Events-Allow-Sanitize-<timestamp>.csv` for your audit trail.
- `PASSED: … No changes were needed.` — the file was already clean and was **not modified**.
- `PASSED: … was sanitized … Original saved as …Events-Allow.original-<timestamp>.xml` — proceed to Step 5.
- If rules were **removed** that you still need (for example, an application's `FilePublisher` rule), re-add those files in the Wizard as **Publisher** or **Hash** rules (Step 4.2), save `Events-Allow.xml` again, and re-run this step.
- `STOP: … still fails Merge-CIPolicy/ConvertFrom-CIPolicy after sanitizing` — the file was **not** modified. Read the red message and the findings table, fix the rule in the Wizard, and re-run.

---

## 7. Step 5 — Use PowerShell 7 to Merge Baseline + Events, Keep in Audit Mode, and Screen (`1 / 1`)

**What this does:**
1. Merges `Base-Audit.xml` (**FIRST**) and `Events-Allow.xml` (**SECOND**) into `C:\WDAC\Source\Base-Audit-Merged.xml`.
2. *(Optional)* Adds a folder-scoped `FilePath` allow rule for each admin-protected folder you list in `$AdditionalFolderRules` (empty by default).
3. Cleans up any unwanted rule options (such as `Dynamic Code Security` or `Revoked Expired As Unsigned`) that `Merge-CIPolicy` unioned from the Wizard's event policy XML, while guaranteeing **Audit Mode** (`Option 3`), **Boot Audit on Failure** (`Option 10`), **Allow Supplemental Policies** (`Option 17`), and **Disable Script Enforcement** (`Option 11`) stay enabled.
4. Stamps a helpful ID (`PAW-AUDIT-MERGED-v2`), Name (`PAW-WDAC-Audit-Merged`), and bumped Version (`2026.10.21.2`) while keeping the **exact same `PolicyID` GUID**.
5. **Verifies the merged XML before compiling** — no uncompilable `FileAttrib` rules, same `PolicyID` GUID, Audit Mode still ON, and (optionally) that an application listed in `$ExcludedAppPattern` has no rules.
6. Compiles and deploys the merged audit policy live via `CiTool.exe`.
7. **Records the start of the screening window** (`C:\WDAC\Events\ScreenStart.txt`) right after the policy is loaded, so that — after you reboot and re-run your applications — Step 5's screening can confirm **zero** new `3076` events.

**Why we need it:** Merging into `Base-Audit.xml` (with `Base-Audit.xml` listed first) preserves our base `PolicyID` GUID and Microsoft allow/deny rules while adding the new application allow rules. Screening in Audit Mode proves our rules are complete *before* we switch to Enforce Mode.

> **Prerequisite:** run **Step 4.3** (`3_1_validate_winevent_rules.ps1`) on `Events-Allow.xml` first, so this merge only ever sees rules the compiler accepts.

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC` (or run `scripts\4_merge_audit_base_and_events_policies.ps1` / `scripts\pwsh_5.1\4_merge_audit_base_and_events_policies.ps1`):

```powershell
if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }

$BaseXml        = 'C:\WDAC\Source\Base-Audit.xml'
$EventsXml      = 'C:\WDAC\Source\Events-Allow.xml'
$MergedXml      = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuidFile = 'C:\WDAC\Source\PolicyGuid.txt'

# Optional: admin-writable-only folders to allow with a FilePath rule, e.g. 'C:\Program Files\MyApp\*' (leave empty if not needed)
$AdditionalFolderRules = @()
# Optional: regex for an application that must NOT be allowed by this policy, e.g. 'MyBlockedApp' (leave empty to skip the check)
$ExcludedAppPattern = ''

foreach ($RequiredFile in $BaseXml, $EventsXml, $PolicyGuidFile) {
    if (-not (Test-Path -LiteralPath $RequiredFile)) { throw "STOP: Required file not found: $RequiredFile" }
}
$PolicyGuid = (Get-Content -LiteralPath $PolicyGuidFile -Raw).Trim()

# 1. Merge Base-Audit.xml (FIRST!) and Events-Allow.xml (SECOND)
try { Merge-CIPolicy -PolicyPaths $BaseXml, $EventsXml -OutputFilePath $MergedXml -ErrorAction Stop | Out-Null }
catch { throw "STOP: Merge-CIPolicy failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (Step 4.3), then re-run this script." }

# 2. Optional: add FilePath allow rules for the admin-protected folders listed in $AdditionalFolderRules
#    (Runs New-CIPolicyRule in Windows PowerShell 5.1 so Rule objects serialize cleanly into Merge-CIPolicy)
foreach ($Folder in $AdditionalFolderRules) {
    if (-not (Test-Path -LiteralPath (Split-Path $Folder -Parent))) {
        Write-Warning "Skipping FilePath rule - folder not found: $Folder"
        continue
    }
    Write-Host "Adding admin-protected FilePath rule: $Folder" -ForegroundColor Cyan
    powershell.exe -NoProfile -Command "
        `$ErrorActionPreference = 'Stop'
        Import-Module ConfigCI
        `$Rule = New-CIPolicyRule -FilePathRule '$Folder'
        Merge-CIPolicy -PolicyPaths '$MergedXml' -Rules `$Rule -OutputFilePath '$MergedXml.tmp' | Out-Null
        Move-Item -LiteralPath '$MergedXml.tmp' -Destination '$MergedXml' -Force
    "
    if ($LASTEXITCODE -ne 0) { throw "STOP: Failed to add the FilePath rule for $Folder" }
}

# 3. Clean up any extra rule options unioned from Events-Allow.xml and ensure Audit options remain set
#    Ensure REQUIRED options are ON:
#      0 = Enabled:UMCI
#      2 = Required:WHQL
#      3 = Enabled:Audit Mode
#      6 = Enabled:Unsigned System Integrity Policy
#      9 = Enabled:Advanced Boot Options Menu
#     10 = Enabled:Boot Audit On Failure
#     11 = Disabled:Script Enforcement
#     16 = Enabled:Update Policy No Reboot
#     17 = Enabled:Allow Supplemental Policies
foreach ($OptOn in @(0, 2, 3, 6, 9, 10, 11, 16, 17)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOn -ErrorAction Stop
}
#    Ensure UNWANTED options (often leaked by Wizard event policies) are OFF:
#     13 = Enabled:Managed Installer
#     14 = Enabled:Intelligent Security Graph Authorization
#     15 = Enabled:Invalidate EAs on Reboot
#     18 = Disabled:Runtime FilePath Rule Protection (deleting Option 18 keeps Runtime Protection ON!)
#     19 = Enabled:Dynamic Code Security
#     20 = Enabled:Revoked Expired As Unsigned
foreach ($OptOff in @(13, 14, 15, 18, 19, 20)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOff -Delete -ErrorAction Stop
}

# 4. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.2) - DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $MergedXml -PolicyName 'PAW-WDAC-Audit-Merged' -PolicyId 'PAW-AUDIT-MERGED-v2' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $MergedXml -Version '2026.10.21.2' -ErrorAction Stop

# 5. Verify the merged policy BEFORE compiling
[xml]$MergedDoc = Get-Content -LiteralPath $MergedXml

#    5a. ConvertFrom-CIPolicy rejects any FileAttrib rule that has no name/hash/path attribute (typically a Wizard FilePublisher
#        rule for a file without version info) with: "There is invalid file rule with ID ID_FILEATTRIB_..."
$BadAttribs = @($MergedDoc.SiPolicy.FileRules.FileAttrib | Where-Object {
    -not ($_.HasAttribute('FileName') -or $_.HasAttribute('InternalName') -or $_.HasAttribute('FileDescription') -or
          $_.HasAttribute('ProductName') -or $_.HasAttribute('PackageFamilyName') -or $_.HasAttribute('Hash') -or $_.HasAttribute('FilePath'))
})
if ($BadAttribs.Count -gt 0) {
    foreach ($Bad in $BadAttribs) {
        $Signers = @($MergedDoc.SiPolicy.Signers.Signer | Where-Object { $_.FileAttribRef.RuleID -contains $Bad.ID } | ForEach-Object { "$($_.Name) [$($_.ID)]" })
        Write-Host "Invalid FileAttrib rule: $($Bad.ID)  (used by signer: $($Signers -join ', '))" -ForegroundColor Red
        Write-Host "    $($Bad.OuterXml)" -ForegroundColor DarkYellow
    }
    throw "STOP: $($BadAttribs.Count) FileAttrib rule(s) above cannot be compiled. Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (or re-add those files as Publisher or Hash rules in the Wizard), then re-run this script."
}

#    5b. PolicyID GUID is unchanged, Audit Mode is still ON, and the optional excluded application is not present
$HasExcludedApp = $false
if ($ExcludedAppPattern) { $HasExcludedApp = (Get-Content -LiteralPath $MergedXml -Raw) -match $ExcludedAppPattern }
$Opts = $MergedDoc.SiPolicy.Rules.Rule.Option

$Check = [pscustomobject]@{
    PolicyName          = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel       = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyID_GUID       = $MergedDoc.SiPolicy.PolicyID
    MatchesBaseline     = ($MergedDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    VersionEx           = $MergedDoc.SiPolicy.VersionEx
    AuditModeOn         = ($Opts -contains 'Enabled:Audit Mode')
    SupplementalOn      = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    BootAuditOn         = ($Opts -contains 'Enabled:Boot Audit On Failure')
    ExcludedAppInPolicy = $HasExcludedApp
}
$Check | Format-List

if (-not ($Check.MatchesBaseline -and $Check.AuditModeOn -and $Check.SupplementalOn -and $Check.BootAuditOn -and -not $Check.ExcludedAppInPolicy)) {
    throw 'STOP: Merged policy verification failed! Review the values above (MatchesBaseline/AuditModeOn/SupplementalOn/BootAuditOn must be True; ExcludedAppInPolicy must be False).'
}
```

**Check the output above:**
- `MatchesBaseline` **must be `True`**
- `AuditModeOn`, `SupplementalOn`, and `BootAuditOn` **must all be `True`**
- `ExcludedAppInPolicy` **must be `False`** (it is always `False` when `$ExcludedAppPattern` is empty)
- If the script stops with **`Invalid FileAttrib rule: ID_FILEATTRIB_...`**, nothing has been compiled or deployed. The message names the rule and the signer that uses it. This should not happen if you ran **Step 4.3**; run `3_1_validate_winevent_rules.ps1` on `Events-Allow.xml` (or re-add that file as a **Publisher** or **Hash** rule in the Wizard, Step 4.2) and re-run this step.

Now compile and deploy the merged audit policy:

```powershell
# 6. Compile Base-Audit-Merged.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
try { ConvertFrom-CIPolicy -XmlFilePath $MergedXml -BinaryFilePath $CipFile -ErrorAction Stop }
catch { throw "STOP: Compiling $MergedXml failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (Step 4.3), then re-run this script. Nothing was deployed." }
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Merged_v2026.10.21.2.cip' -Force -ErrorAction Stop

# 7. Apply the updated Merged Audit Policy live with CiTool.exe
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }

# 8. Start the screening window: every Event ID 3076 from now on is a gap in the merged rules (5_audit_merged_events.ps1 reads this file)
$ScreenStartFile = 'C:\WDAC\Events\ScreenStart.txt'
New-Item -Path (Split-Path -Parent $ScreenStartFile) -ItemType Directory -Force | Out-Null
$ScreenStart = Get-Date
$ScreenStart.ToString('o') | Set-Content -LiteralPath $ScreenStartFile -ErrorAction Stop

# 9. Confirm STIG status is still 1 / 1 (Audit Mode) and FriendlyName updated to PAW-WDAC-Audit-Merged
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

Write-Host "Screening window started at $($ScreenStart.ToString('o')). Reboot now, run every application you need, then run 5_audit_merged_events.ps1." -ForegroundColor Yellow
```

### Screen the Merged Audit Policy (Reboot, Re-Run Everything, Verify `0` New `3076` Events)

**What this does:** The merge script already saved the start of the screening window (`C:\WDAC\Events\ScreenStart.txt`) the moment the merged policy was loaded. You now **reboot the PAW**, run **every application you need** again, and check whether any new `3076` events appear.
**Why we need it:** Because old `3076` events remain in Event Viewer permanently, filtering for events after `ScreenStart.txt` proves whether our merged rules completely cover everything you run. Keeping the start time in a file lets it survive the reboot.

> **Optional — restart the screening window manually.** If you want a fresh start just before you reboot, re-mark it:
> ```powershell
> $ScreenStart = Get-Date
> $ScreenStart.ToString('o') | Set-Content -LiteralPath 'C:\WDAC\Events\ScreenStart.txt'
> ```

**Reboot `WIN11-PAW-WDAC`**, sign in, open a new **elevated** PowerShell window, and **run all of the applications and workflows you need** (the same set you ran in Step 3, including update checks). Give background services and scheduled tasks a few minutes, then run the screening script — `scripts\5_audit_merged_events.ps1` (PowerShell 7) or `scripts\pwsh_5.1\5_audit_merged_events.ps1` (Windows PowerShell 5.1). It reads `ScreenStart.txt` for you:

```powershell
.\5_audit_merged_events.ps1                    # count new 3076 events; if the screening is clean, prepare Base-Enforce.xml for Step 6
.\5_audit_merged_events.ps1 -AcceptRemaining   # the remaining events are all for applications you intend to keep blocked
.\5_audit_merged_events.ps1 -Overwrite         # replace an existing Base-Enforce.xml instead of being asked
```

**What the script does**

1. Counts every new Event ID `3076` since `ScreenStart.txt` and lists them.
2. **If there are none** (or you pass `-AcceptRemaining`), it **prepares `C:\WDAC\Source\Base-Enforce.xml`** as a copy of the screened `Base-Audit-Merged.xml`. This replaces the old hand-typed copy command, so the only manual step left before enforcing is the Wizard (Step 6).
3. **If `Base-Enforce.xml` already exists and differs** (for example it was prepared from an older merge, or you already edited it in the Wizard), it **never overwrites silently**. In an interactive window it asks you to choose:
   - **Timestamped copy** *(default)* — keeps the existing file and writes `Base-Enforce_<yyyyMMdd-HHmmss>.xml` next to it.
   - **Overwrite** — replaces `Base-Enforce.xml`.
   - **Cancel** — changes nothing.

   When there is no interactive console (a scheduled task, `-NonInteractive`, redirected input) it chooses the timestamped copy automatically; `-Overwrite` is how you say "replace it" up front.
4. If the file is already identical, it says so and changes nothing.

| Parameter | Purpose |
|---|---|
| `-AcceptRemaining` | Prepare `Base-Enforce.xml` even though `3076` events remain — use it only after you have confirmed every one is for an application you **intend** to keep blocked |
| `-Overwrite` | Replace an existing, different `Base-Enforce.xml` without asking (otherwise you are asked, and a timestamped copy is the default) |

**Reading the result**

- **`New 3076 events since screening started: 0`** and **`Base-Enforce.xml prepared …`** — your allowlist is complete. Proceed to **Step 6**.
- **`NOT ready to enforce: N new 3076 event(s)`** — nothing was copied. If any event is for an application you need, export and convert those remaining events in the Wizard (Step 4), **sanitize them (Step 4.3)**, merge (Step 5), bump the version, reboot, and re-screen. Events for anything you *intend* to stay blocked are expected: leave them out and re-run with `-AcceptRemaining`.

---

## 8. Step 6 — Use the Wizard to Keep Boot Audit Enabled and Switch from Audit to Enforce

**What this does:** Opens the `Base-Enforce.xml` that `5_audit_merged_events.ps1` prepared (a copy of the screened `Base-Audit-Merged.xml`) in the **App Control Policy Wizard**, confirms **Boot Audit on Failure** remains **ON**, and turns **Audit Mode OFF**. This is the one step that needs your hands, because the Wizard is a GUI.
**Why we need it:**
- Working on a copy (`Base-Enforce.xml`) preserves your known-good `Base-Audit-Merged.xml` file for instant rollback.
- Turning **Audit Mode OFF** deletes `<Option>Enabled:Audit Mode</Option>` from the XML, switching the policy from Audit (`1`) to Enforced (`2`).
- Keeping **Boot Audit on Failure ON** ensures that if a boot-critical kernel driver ever fails validation during a future reboot, Windows falls back to audit mode rather than failing to boot.

### 6.1 `Base-Enforce.xml` Is Prepared Automatically (Script 5)

When the screening was clean, `5_audit_merged_events.ps1` already copied the screened `Base-Audit-Merged.xml` to `C:\WDAC\Source\Base-Enforce.xml`, so there is no copy command to type. Confirm which file to open:

```powershell
Get-ChildItem -Path 'C:\WDAC\Source' -Filter 'Base-Enforce*.xml' | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime
```

- If script 5 reported `Base-Enforce.xml prepared …`, open **`Base-Enforce.xml`**.
- If it reported that it wrote **`Base-Enforce_<timestamp>.xml`** (because a different `Base-Enforce.xml` already existed and you chose — or defaulted to — a timestamped copy), open **that** file in the Wizard instead. Step 7 (`6_enforce_policy.ps1`) automatically uses the **newest** `Base-Enforce*.xml`.

> **Manual fallback.** If you ever need to create it by hand: `Copy-Item -LiteralPath 'C:\WDAC\Source\Base-Audit-Merged.xml' -Destination 'C:\WDAC\Source\Base-Enforce.xml'`

### 6.2 Switch from Audit to Enforce in the Wizard GUI

1. Open the **App Control Policy Wizard** -> click **Policy Editor**.
2. Select **Edit Policy XML File** -> click **Browse** and select:
   - **`C:\WDAC\Source\Base-Enforce.xml`** *(or the newer `Base-Enforce_<timestamp>.xml` if script 5 told you it wrote one — see 6.1)*
   - Click **Next**.
3. On the **Policy Rules** screen, click **+ Advanced Options** so you can see both columns:
   - **Turn OFF — this is the ONLY toggle you change:**
     - ❌ **Audit Mode** -> toggle to **OFF (Disabled)** *(this puts the policy into Enforce Mode!)*
   - **Leave every other toggle exactly as it is** (these are the ones to verify remain enabled — see [Policy Rule Options](#policy-rule-options--what-changes-between-audit-and-enforce); any other option already in the policy, such as the *Allow Microsoft* template extras, must also be left alone):
     - ✅ **Boot Audit on Failure** *(under Advanced Options)* -> **ON**
     - ✅ **User Mode Code Integrity (UMCI)** -> **ON**
     - ✅ **Allow Supplemental Policies** -> **ON**
     - ✅ **Disable Script Enforcement** -> **ON**
     - ✅ **Unsigned System Integrity Policy** -> **ON**
     - ✅ **Update Policy without Rebooting** -> **ON**
     - ✅ **Advanced Boot Options Menu** -> **ON**
     - ✅ **Require WHQL** -> **ON**
4. Click **Next** to reach the **File Rules** screen (leave your existing allow and block rules untouched—do not re-check the blocklist merge boxes, as those rules are already inside the XML).
5. Click **Next** to save the updated `Base-Enforce.xml`.
   - *(Note: Depending on your Wizard version, it may save in-place as `Base-Enforce.xml` or append a version suffix like `Base-Enforce_v10.0.0.0.xml`. Step 7 checks for that automatically!)*

> **Step 7 double-checks this.** `6_enforce_policy.ps1` compares the policy you saved with the screened `Base-Audit-Merged.xml` and **stops before compiling** if any option other than Audit Mode was switched off. Because script 6 also turns Audit Mode off itself, this Wizard pass is a visual review — it is not required for the policy to enforce correctly.

---

## 9. Step 7 — Use PowerShell 7 to Bump Version, Verify Multi-Policy Suitability, and Apply (`1 / 1` → `2 / 2`)

**What this does:**
1. Stamps `Base-Enforce.xml` with a helpful name (`PAW-WDAC-Enforced`), ID (`PAW-ENFORCED-v3`), and bumped version (`2026.10.21.3`) while keeping the **exact same `PolicyID` GUID**.
2. Runs a pre-deployment gate to verify that the policy compiles and is suitable for the **multi-policy method** (no uncompilable `FileAttrib` rules, `PolicyID == BasePolicyID`, `Allow Supplemental Policies = ON`, `Boot Audit on Failure = ON`, `UMCI = ON`, `Audit Mode = OFF`, and — optionally — no rules for the application in `$ExcludedAppPattern`). It also **proves Audit Mode is the only option turned off** by comparing every option against the screened `Base-Audit-Merged.xml`, and lists the options that stay enabled (see the example output after the script and **[Policy Rule Options](#policy-rule-options--what-changes-between-audit-and-enforce)** in Section 1).
3. Compiles `Base-Enforce.xml` into `C:\WDAC\Compiled\{PolicyID}.cip` and applies it live with `CiTool.exe --update-policy` (stopping before deployment if anything fails).

**Why we need it:** Because the enforced policy has the **same `PolicyID` GUID** and a **higher version (`2026.10.21.3` > `2026.10.21.2`)**, `CiTool.exe --update-policy` seamlessly upgrades the active policy in place from Audit Mode to Enforce Mode without a reboot and without creating duplicate policies.

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC` (or run `scripts\6_enforce_policy.ps1` / `scripts\pwsh_5.1\6_enforce_policy.ps1`):

```powershell
if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }

$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw -ErrorAction Stop).Trim()

# Optional: regex for an application that must NOT be allowed by this policy, e.g. 'MyBlockedApp' (leave empty to skip the check)
$ExcludedAppPattern = ''

# If the Wizard wrote a version-suffixed file (e.g., Base-Enforce_v*.xml), normalize it to Base-Enforce.xml
$LatestEnforceXml = Get-ChildItem -Path 'C:\WDAC\Source' -Filter 'Base-Enforce*.xml' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $LatestEnforceXml) { throw 'STOP: No Base-Enforce*.xml found in C:\WDAC\Source. Run 5_audit_merged_events.ps1 first (it prepares Base-Enforce.xml once the screening is clean), then open it in the Wizard (Step 6).' }
$EnforceXml = 'C:\WDAC\Source\Base-Enforce.xml'
if ($LatestEnforceXml.FullName -ne $EnforceXml) {
    Copy-Item -LiteralPath $LatestEnforceXml.FullName -Destination $EnforceXml -Force -ErrorAction Stop
}

# The screened audit policy is the reference: enforcing must turn Audit Mode off and nothing else
$AuditXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
if (-not (Test-Path -LiteralPath $AuditXml)) { throw "STOP: $AuditXml not found. It is the reference that proves Audit Mode is the only option being turned off. Run 4_merge_audit_base_and_events_policies.ps1 first." }
[xml]$AuditDoc = Get-Content -LiteralPath $AuditXml
$AuditOptions = @($AuditDoc.SiPolicy.Rules.Rule.Option)

# 1. Guarantee Enforce Mode options (Audit Mode OFF, Boot Audit ON, Supplemental ON, UMCI ON, Script Enforcement Disabled)
foreach ($OptOn in @(0, 2, 6, 9, 10, 11, 16, 17)) {
    Set-RuleOption -FilePath $EnforceXml -Option $OptOn -ErrorAction Stop
}
foreach ($OptOff in @(3, 13, 14, 15, 18, 19, 20)) {
    # Option 3 = Enabled:Audit Mode -> Deleting Option 3 guarantees ENFORCE MODE!
    Set-RuleOption -FilePath $EnforceXml -Option $OptOff -Delete -ErrorAction Stop
}

# 2. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.3) - DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $EnforceXml -PolicyName 'PAW-WDAC-Enforced' -PolicyId 'PAW-ENFORCED-v3' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $EnforceXml -Version '2026.10.21.3' -ErrorAction Stop

# 3. Verify Multi-Policy Suitability & Enforce Readiness before compiling
[xml]$EnfDoc = Get-Content -LiteralPath $EnforceXml

#    3a. ConvertFrom-CIPolicy rejects any FileAttrib rule that has no name/hash/path attribute (typically a Wizard FilePublisher
#        rule for a file without version info) with: "There is invalid file rule with ID ID_FILEATTRIB_..."
$BadAttribs = @($EnfDoc.SiPolicy.FileRules.FileAttrib | Where-Object {
    -not ($_.HasAttribute('FileName') -or $_.HasAttribute('InternalName') -or $_.HasAttribute('FileDescription') -or
          $_.HasAttribute('ProductName') -or $_.HasAttribute('PackageFamilyName') -or $_.HasAttribute('Hash') -or $_.HasAttribute('FilePath'))
})
if ($BadAttribs.Count -gt 0) {
    foreach ($Bad in $BadAttribs) {
        $Signers = @($EnfDoc.SiPolicy.Signers.Signer | Where-Object { $_.FileAttribRef.RuleID -contains $Bad.ID } | ForEach-Object { "$($_.Name) [$($_.ID)]" })
        Write-Host "Invalid FileAttrib rule: $($Bad.ID)  (used by signer: $($Signers -join ', '))" -ForegroundColor Red
        Write-Host "    $($Bad.OuterXml)" -ForegroundColor DarkYellow
    }
    throw "STOP: $($BadAttribs.Count) FileAttrib rule(s) above cannot be compiled. Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml, re-run script 4, then repeat Step 6."
}

#    3b. Multi-policy format, enforce-mode options, and the optional excluded application
$Opts = @($EnfDoc.SiPolicy.Rules.Rule.Option)
#    Audit Mode must be the ONLY option that was enabled in the screened audit policy and is not enabled now
$OtherOptionsTurnedOff = @($AuditOptions | Where-Object { $_ -ne 'Enabled:Audit Mode' -and $Opts -notcontains $_ })
$OptionsAdded = @($Opts | Where-Object { $AuditOptions -notcontains $_ })
$HasExcludedApp = $false
if ($ExcludedAppPattern) { $HasExcludedApp = (Get-Content -LiteralPath $EnforceXml -Raw) -match $ExcludedAppPattern }
$Check = [pscustomobject]@{
    PolicyName              = ($EnfDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel           = ($EnfDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyType              = $EnfDoc.SiPolicy.PolicyType
    PolicyID_GUID           = $EnfDoc.SiPolicy.PolicyID
    BasePolicyID_GUID       = $EnfDoc.SiPolicy.BasePolicyID
    SameGuidAsAudit         = ($EnfDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    MultiPolicyFormatValid  = ($EnfDoc.SiPolicy.PolicyID -eq $EnfDoc.SiPolicy.BasePolicyID -and [bool]$EnfDoc.SiPolicy.PolicyID)
    VersionEx               = $EnfDoc.SiPolicy.VersionEx
    AuditModeRemoved        = ($Opts -notcontains 'Enabled:Audit Mode')
    OnlyAuditModeTurnedOff  = ($OtherOptionsTurnedOff.Count -eq 0)
    OtherOptionsTurnedOff   = ($OtherOptionsTurnedOff -join ', ')
    OptionsAdded            = ($OptionsAdded -join ', ')
    UMCI_Enabled            = ($Opts -contains 'Enabled:UMCI')
    BootAuditEnabled        = ($Opts -contains 'Enabled:Boot Audit On Failure')
    AllowSupplemental       = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    ScriptEnforceDisabled   = ($Opts -contains 'Disabled:Script Enforcement')
    UpdateNoRebootEnabled   = ($Opts -contains 'Enabled:Update Policy No Reboot')
    ExcludedAppInPolicy     = $HasExcludedApp
}
$Check | Format-List

if (-not $Check.OnlyAuditModeTurnedOff) {
    Write-Host "Audit Mode must be the only option turned off, but these screened options are missing from Base-Enforce.xml: $($OtherOptionsTurnedOff -join ', ')" -ForegroundColor Red
    Write-Host 'Switch them back ON in the Wizard. If they are options this guide requires OFF (Managed Installer, ISG, Invalidate EAs, Runtime FilePath Rule Protection, Dynamic Code Security, Revoked Expired As Unsigned), re-run script 4 to clean the audit policy and re-screen.' -ForegroundColor Red
}
if (-not ($Check.SameGuidAsAudit -and $Check.MultiPolicyFormatValid -and $Check.AuditModeRemoved -and $Check.OnlyAuditModeTurnedOff -and $Check.UMCI_Enabled -and $Check.BootAuditEnabled -and $Check.AllowSupplemental -and -not $Check.ExcludedAppInPolicy)) {
    throw 'STOP: Pre-deployment verification failed! Review the False property above before applying.'
}
Write-Host 'PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!' -ForegroundColor Green
Write-Host 'Audit Mode is the ONLY option turned off. Options that stay ENABLED in the enforced policy:' -ForegroundColor Green
$Opts | Sort-Object | ForEach-Object { Write-Host "  $_" }
```

Now compile and apply the enforced policy live:

```powershell
# 4. Compile Base-Enforce.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
try { ConvertFrom-CIPolicy -XmlFilePath $EnforceXml -BinaryFilePath $CipFile -ErrorAction Stop }
catch { throw "STOP: Compiling $EnforceXml failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml, re-run script 4, then repeat Step 6. Nothing was deployed." }
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Enforced_v2026.10.21.3.cip' -Force -ErrorAction Stop

# Record SHA256 hash of the enforced .cip binary for your audit evidence
Get-FileHash -LiteralPath $CipFile -Algorithm SHA256 | Format-List

# 5. Apply the Enforced Policy live with CiTool.exe (no reboot required)
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }
```

### Reading Script 6's Option Output (Audit Mode Is the Only Option Turned Off)

When the gate passes, script 6 prints the exact list of options that stay enabled in the enforced policy. For a policy built from the Windows *Allow Microsoft* template it looks like this (your list may differ only by template extras — anything already enabled in your screened audit policy stays):

```text
PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!
Audit Mode is the ONLY option turned off. Options that stay ENABLED in the enforced policy:
  Disabled:Script Enforcement
  Enabled:Advanced Boot Options Menu
  Enabled:Allow Supplemental Policies
  Enabled:Boot Audit On Failure
  Enabled:Inherit Default Policy
  Enabled:UMCI
  Enabled:Unsigned System Integrity Policy
  Enabled:Update Policy No Reboot
  Required:Enforce Store Applications
  Required:WHQL
```

- In the check table above it, **`OnlyAuditModeTurnedOff : True`** and **`OtherOptionsTurnedOff`** (empty) are your proof that nothing but Audit Mode was switched off.
- If the script instead prints **`Audit Mode must be the only option turned off, but these screened options are missing from Base-Enforce.xml: …`** and stops, nothing was compiled or deployed. Switch the named option(s) back **ON** in the Wizard (Step 6.2) and re-run. If the named options are ones this guide requires **OFF** (Managed Installer, ISG, Invalidate EAs, Runtime FilePath Rule Protection, Dynamic Code Security, Revoked Expired As Unsigned), the *screened* policy itself contains them: re-run script 4, which removes them, re-screen, and try again.
- The full list of what stays enabled, what is turned off, and what stays off — with the reason for each — is in **[Policy Rule Options — What Changes Between Audit and Enforce](#policy-rule-options--what-changes-between-audit-and-enforce)** (Section 1).

---

## 10. Step 8 — Validate STIG Compliance (`2` and `2`) and Prove Enforcement with a Block Test

### 8.1 Run the Official DISA STIG Check (`V-243450` & `V-243451`)

> Script: `scripts\7_DISA_STIG_CHECK.ps1` (PowerShell 7) or `scripts\pwsh_5.1\7_DISA_STIG_CHECK.ps1` (Windows PowerShell 5.1).

**What this does:** Runs the exact elevated WMI/CIM query from the STIG repository (`Win32_DeviceGuard`) and checks that **both** `CodeIntegrityPolicyEnforcementStatus` and `UsermodeCodeIntegrityPolicyEnforcementStatus` return **`2`**.
**Why we need it:** A value of `2` for both properties is the definitive STIG requirement proving that both Kernel-Mode Code Integrity (**V-243450**) and User-Mode Code Integrity (**V-243451**) are actively **Enforced** on `WIN11-PAW-WDAC`.

```powershell
# Official DISA STIG Check (must be run in an elevated PowerShell session)
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'Run the STIG check in an elevated PowerShell session (Run as administrator).' }

$DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
if (-not $DG) { throw 'Win32_DeviceGuard returned no data on this system.' }
$DG | Format-List *codeintegrity*

Write-Host "V-243450 (CodeIntegrityPolicyEnforcementStatus)         : $($DG.CodeIntegrityPolicyEnforcementStatus) $(if ($DG.CodeIntegrityPolicyEnforcementStatus -eq 2) { '[PASS - NOT A FINDING]' } else { '[OPEN FINDING]' })" -ForegroundColor $(if ($DG.CodeIntegrityPolicyEnforcementStatus -eq 2) { 'Green' } else { 'Red' })
Write-Host "V-243451 (UsermodeCodeIntegrityPolicyEnforcementStatus) : $($DG.UsermodeCodeIntegrityPolicyEnforcementStatus) $(if ($DG.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) { '[PASS - NOT A FINDING]' } else { '[OPEN FINDING]' })" -ForegroundColor $(if ($DG.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) { 'Green' } else { 'Red' })
```

**Expected Output:**
```text
CodeIntegrityPolicyEnforcementStatus         : 2
UsermodeCodeIntegrityPolicyEnforcementStatus : 2
```

### 8.2 Verify Multi-Policy Disk Layout, `CiTool` Inventory, and Event ID `3099`

> Script: `scripts\8_validate_multipolicy_layout.ps1` (PowerShell 7) or `scripts\pwsh_5.1\8_validate_multipolicy_layout.ps1` (Windows PowerShell 5.1).

```powershell
# 1. Confirm the active multi-policy binary exists under CiPolicies\Active\{PolicyID}.cip (and no legacy SiPolicy.p7b exists)
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.cip' -ErrorAction Stop |
    Select-Object Name, Length, LastWriteTime
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"   # Expect: False

# 2. Confirm CiTool reports PAW-WDAC-Enforced (v2026.10.21.3) with IsEnforced = True and IsAuthorized = True
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, BasePolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

# 3. Confirm Event ID 3099 logged the activation of PAW-WDAC-Enforced
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3099
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List
```

### 8.3 Positive Test — Reboot and Confirm Everything You Need Still Works

1. **Reboot `WIN11-PAW-WDAC`** so everything starts fresh under the enforced policy.
2. **Run all of the applications and workflows you need** (the same set you exercised in Step 3, including update checks). Each one must launch and work normally.
3. **PowerShell Language Mode:** Verify your interactive PowerShell session is still in `FullLanguage`:
   ```powershell
   $ExecutionContext.SessionState.LanguageMode   # Expect: FullLanguage
   ```
4. **Check for unexpected blocks** (Event ID `3077`). Anything you need that appears here must be added back through the Fix-Forward procedure in Section 11:
   ```powershell
   Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3077; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction SilentlyContinue |
       Select-Object TimeCreated, Message | Format-List
   ```

### 8.4 Negative Test — Launch an Unapproved Application to Prove Enforcement (`Event ID 3077`)

**What this does:** Attempts to launch an application you **intentionally left out** of the policy (one that was never run during the audit window) and queries `Microsoft-Windows-CodeIntegrity/Operational` for **Event ID `3077`**.
**Why we need it:** Proves that enforcement is actively blocking unapproved user-mode executables in real time.

1. Double-click an unapproved application on the desktop/Start Menu, or launch it from PowerShell (substitute your own path):
   ```powershell
   & 'C:\Path\To\UnapprovedApp.exe'
   ```
2. **Expected Result on Screen:**
   - Windows immediately blocks the application from starting.
   - On the desktop, Windows displays the toast notification:
     > *"Your organization used App Control for Business to block this app"*
   - In PowerShell, launching it fails immediately with:
     > *"An Application Control policy has blocked this file"*
3. **Confirm Event ID `3077` (Enforced Block Event) in the Event Log** (or run `scripts\Get-Blocked_CI_Events.ps1`):
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
       Id        = 3077
       StartTime = (Get-Date).AddMinutes(-15)
   } -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List
   ```

---

## 11. Quick Rollback / Fix-Forward Reference

Because our policy is unsigned and has `Enabled:Update Policy No Reboot`, you have three fast ways to recover or adjust rules at any time:

### Option A — Fix-Forward in Place (Switch Back to Audit Mode Without Removing the Policy)
If you ever want to put the PAW back into Audit Mode to capture another application, just bump the version of `Base-Audit-Merged.xml` higher than the enforced version (e.g., `2026.10.21.4`) and apply it with `CiTool.exe`:

```powershell
$RollbackXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuid  = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()
$CipFile     = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"

Set-CIPolicyVersion -FilePath $RollbackXml -Version '2026.10.21.4' -ErrorAction Stop
ConvertFrom-CIPolicy -XmlFilePath $RollbackXml -BinaryFilePath $CipFile -ErrorAction Stop
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
```

### Option B — Remove the Custom Policy Completely with `CiTool.exe`
```powershell
$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()
& "$env:SystemRoot\System32\CiTool.exe" --remove-policy $PolicyGuid -json
```

### Option C — Restore the Hyper-V Checkpoint (From the Host)
```powershell
Restore-VMCheckpoint -VMName 'WIN11-PAW-WDAC' -Name 'Pre-WDAC-Manual-Walkthrough' -Confirm:$false
```

---

## 12. Agent Handover & Audit Log Protocol (For Follow-On Automation / GPO Phase)

When you have finished stepping through this manual guide and tell me to take over (or when we move to the follow-on **Multi-Policy GPO Deployment Guide**), I will follow these strict rules:

1. **Persistent Session via Direct Credential Dialog:**
   - Connect to `WIN11-PAW-WDAC` using PowerShell 7 (`New-PSSession -VMName 'WIN11-PAW-WDAC' -Credential (Get-Credential 'lorenzo@skynet-home.local')`) and keep the session open without removing it.
2. **Complete Command & Action Audit Log:**
   - Maintain both a PowerShell session transcript (`C:\WDAC\Logs\Agent-Transcript-<timestamp>.log`) and a structured append-only audit log (`C:\WDAC\Logs\Agent-Audit-Log.md`) recording every command run, its timestamp, why it was executed, the before/after policy version/hash, and the resulting `Win32_DeviceGuard` / `CiTool` output.
3. **No Unapproved Reboots or Destructive Actions:**
   - Never reboot `WIN11-PAW-WDAC`, reset `PolicyID` GUIDs, or overwrite your authored XML files without your explicit confirmation.
4. **Ready for the Multi-Policy GPO Follow-On:**
   - Because the built-in *Deploy App Control for Business* GPO setting only supports legacy single-policy `SiPolicy.p7b` files, our next guide will take your validated `C:\WDAC\Compiled\{PolicyID}.cip` multi-policy binary (and any future supplemental `.cip` policies) and deploy them via a **Group Policy Startup/Scheduled Script + `CiTool.exe --update-policy`** from a domain UNC share on `skynet-home.local`.
