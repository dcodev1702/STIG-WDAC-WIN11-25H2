# App Control for Business (WDAC) — Policy Rebase: New Baseline Without the Recommended Block Rules (No GPO)

> [!NOTE]
> Use this runbook to replace the App Control base policy on a PAW with a **new baseline** that you build from scratch in the App Control Policy Wizard.
> - **Both "Merge with Recommended … Block Rules" boxes stay unchecked.**
> - The new baseline is deployed **locally** with the scripts from [README.md](README.md). No GPO is involved.
> - Next you rebuild the allow list with the normal audit cycle, and you enforce when you're ready.
>
> It works whether the device is in Audit or Enforce today, and whether a GPO or the README delivered its current policy.

> [!IMPORTANT]
> **What you must do, and why**
> - **If a WDAC GPO manages the device, take the device out of the GPO's scope first.** Otherwise the GPO keeps managing the policy and can redeploy or replace your local baseline.
> - **Choose a route before you start** ([§2](#2-choose-a-route)):
>   - **Route A (new GUID), recommended.** Every step is in Microsoft's documentation.
>   - **Route B (keep the GUID).** It has fewer steps, but one of them is a direct XML edit that no documentation describes.
> - **Never merge the old `Base-Enforce.xml` or `Base-Audit-Merged.xml` into the new baseline.** Both contain the block rules you are removing, so a merge brings them back. Capture your applications again instead.
> - **Run every application again during the audit window.** The new baseline trusts only Microsoft-signed code and software from the managed installer (MECM / Intune). Every allow rule from earlier rounds is gone.

---

## Contents

1. [Overview](#1-overview)
2. [Choose a Route](#2-choose-a-route)
3. [Before You Start](#3-before-you-start)
4. [Steps](#4-steps)
5. [Rollback](#5-rollback)
6. [Troubleshooting](#6-troubleshooting)
7. [How Each Step Is Documented](#7-how-each-step-is-documented)
8. [Sources](#8-sources)

---

## 1. Overview

![WDAC policy rebase on one PAW in three phases. Prepare (steps 0 to 2) takes a checkpoint and backup, moves the device out of the WDAC GPO's scope and builds a new Allow Microsoft baseline in the Wizard with both Recommended Block Rules boxes unchecked. Swap (steps 3 to 7, in Audit) validates the baseline and replaces the old base policy: Route A keeps the new GUID, removes the old policy with CiTool and re-creates its supplemental policies, with every step documented; Route B writes the old GUID into the new XML, an undocumented edit, and replaces the policy in place. Rebuild and enforce (steps 8 and 9) captures every application again, merges and screens without -BaseXml, then enforces and verifies V-243450 and V-243451 at 2 (ENFORCING). The panel compares the routes and lists guardrails: leave GPO scope first, the trade-off of the unchecked boxes, reading the mode from the user-mode value, and rollback](images/WDAC-Policy-Rebase.png)

<sub>Source: [`images/WDAC-Policy-Rebase.svg`](images/WDAC-Policy-Rebase.svg) · 1600 × 1776. The SVG is generated from `images/WDAC-Policy-Rebase.spec.json`, and the PNG is rendered from the SVG at 2x. To change the diagram, edit the spec, regenerate the SVG, re-render the PNG, and keep all three files.</sub>

### 1.1 What Changes

| | Before the rebase | After the rebase |
|---|---|---|
| Base policy | The existing reference policy (README Steps 1–7, or the GPO guide's package) | A new **Allow Microsoft** baseline from the Wizard |
| Recommended **User Mode** Block Rules | Merged | **Not merged** |
| Recommended **Kernel Mode** Block Rules | Merged | **Not merged** |
| Delivery | GPO or local | **Local**: `CiTool.exe` through the README scripts |
| Allow rules for your applications | From earlier audit rounds | **Captured again** in a new audit round |

README Golden Rule 2 applies again from Step 6 on: every later revision of the new baseline keeps its GUID and raises `VersionEx`.

### 1.2 Check the Current State

On the device, in an elevated window. These commands only read:

```powershell
Set-Location C:\WDAC-Scripts                       # Windows PowerShell 5.1: C:\WDAC-Scripts\pwsh_5.1
.\7_DISA_STIG_CHECK.ps1                            # V-243450 / V-243451 with their meaning, and the active organization policy
gpresult /scope computer /r | Select-String AppControl
Get-ScheduledTask -TaskName 'WDAC-GPO-Deploy-*' -ErrorAction SilentlyContinue
```

How to read the output:

- **`Win32_DeviceGuard` values:** `0 (OFF)`, `1 (AUDIT)`, `2 (ENFORCING)`. The **user-mode value (V-243451)** tells you the mode of your policy. The kernel-mode value often reads `2 (ENFORCING)` because of Windows' built-in policies, even while your policy is in Audit.
- **CiTool `IsEnforced = True`** means the policy is **active**, not that it is in enforce mode.
- **A GPO manages the device** if you see an *AppControl* GPO in `gpresult` or a `WDAC-GPO-Deploy-*` task. In that case, do Step 1.

> [!NOTE]
> **Lab example:** WIN11-PAW-WDAC on 2026-10-27.
> - **STIG values:** `2 (ENFORCING) / 1 (AUDIT)`. The device was in **Audit**, not Enforce.
> - **Active policy:** `PAW-WDAC-GPO-Audit` v2026.10.24.11 `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}`.
> - **Delivered by:** the GPO *JMSC-WDAC-PAWS - AppControl Audit*.
> - **Supplemental policy:** one, `PAW-WDAC-Supp-ClaudeCode`.

### 1.3 What Leaving the Two Boxes Unchecked Gives Up

| Wizard box | What it adds when checked | When left unchecked |
|---|---|---|
| Merge with Recommended **User Mode** Block Rules | Deny rules for Microsoft-signed applications that can bypass App Control, for example `msbuild.exe`, `mshta.exe`, `cdb.exe`, `windbg.exe`, `wmic.exe`, `cscript.exe`, `wscript.exe`, `wsl.exe` and `bash.exe` | The **Allow Microsoft** template allows them, because they are Microsoft-signed. WSL is no longer denied, so `-AllowWSL` isn't needed. |
| Merge with Recommended **Kernel Mode** Block Rules | A copy of Microsoft's vulnerable-driver blocklist inside your policy | Windows still enforces its **own** vulnerable-driver blocklist, which has been on by default since the Windows 11 2022 update. Microsoft notes that the list it publishes is usually more complete than the copy built into Windows. |

Before you rely on the built-in driver blocklist, confirm it's on. It's also shown in **Windows Security → Device security → Core isolation**.

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable   # 1 = on
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object FriendlyName -eq 'Microsoft Windows Driver Policy' | Select-Object FriendlyName, VersionString, IsEnforced
```

Lab: `VulnerableDriverBlocklistEnable = 1`, and the *Microsoft Windows Driver Policy* is active.

---

## 2. Choose a Route

The Wizard gives every new base policy a **new, random `PolicyID` GUID**. The two routes differ in what happens to the current policy.

| | **Route A — New GUID** *(recommended)* | **Route B — Keep the GUID** |
|---|---|---|
| How it works | Keep the Wizard's GUID. Remove the old base policy with `CiTool`, then re-create its supplemental policies for the new base. | Write the old GUID into the new Wizard XML. `CiTool` then replaces the old policy in place. |
| Documented? | **Yes, every step** ([§7](#7-how-each-step-is-documented)) | **No.** No cmdlet or Wizard option sets a GUID you choose, so Step 3 is a direct XML edit. |
| Route-only steps | Step 5 (remove the old policy), Step 7 (re-create supplementals) | Step 3 (stamp the GUID) |
| Supplemental policies | Re-created with new IDs that point at the new base | Stay attached, unchanged |
| `C:\WDAC\Source\PolicyGuid.txt` | Script 1 writes the new GUID | Unchanged |

Under both routes, the new baseline is in **Audit** from Step 6 until Step 9. Your policy blocks nothing during that time, which is what lets the audit round see every application.

---

## 3. Before You Start

### 3.1 Prerequisites

- **Session:** an elevated PowerShell 7 or Windows PowerShell 5.1 window on the device.
- **Scripts:** in `C:\WDAC-Scripts\` (PowerShell 7) or `C:\WDAC-Scripts\pwsh_5.1\` (5.1). They are the same set as `scripts\` next to this file.
- **Wizard:** App Control Policy Wizard 2.8 or later.
- **Step 1 only:**
  - permission to move the computer object in Active Directory;
  - the AD PowerShell module (RSAT) on an admin machine.
- **Rollback:** a VM checkpoint or a full backup (Step 0).
- **Route A:** the **source XML of every supplemental policy** of the current base. Step 7 re-creates the supplementals from those files. Lab: `C:\WDAC\Source\Supp-ClaudeCode.xml`.
- **Unsigned policies only.** This guide's policies are unsigned (option 6 `Enabled:Unsigned System Integrity Policy`). A **signed** base policy needs Microsoft's signed-replacement procedure instead (see [§8](#8-sources)).

### 3.2 Values You Set

| Value | Lab value | Used in |
|---|---|---|
| `$Block`, a regex for the block-test application (`''` = none) | `'Mozilla\|Firefox'` | Steps 4, 8, 9 |
| Admin-only folders to allow wholesale | `'C:\Program Files\Git\*'`, `'C:\Program Files\Microsoft SDKs\Azure\CLI2\*'` | Step 8 (`-AdditionalFolderRules`) |
| An OU outside the WDAC GPOs' scope | *(your choice)* | Step 1 |
| Each supplemental policy's XML and name | `C:\WDAC\Source\Supp-ClaudeCode.xml` / `PAW-WDAC-Supp-ClaudeCode` | Step 7 (Route A) |

---

## 4. Steps

Run each step on the device, elevated, from `C:\WDAC-Scripts`, unless the step says otherwise. Scripts 1, 4 and 6 print a yellow summary and ask `Continue? [Y/N]` before they deploy anything.

| Step | Route A | Route B | What it does |
|:---:|:---:|:---:|---|
| 0 | ✅ | ✅ | Safety net |
| 1 | ✅ | ✅ | Take the device out of GPO scope |
| 2 | ✅ | ✅ | Wizard: new baseline, both boxes unchecked |
| 3 | — | ✅ | Stamp the old GUID into the new baseline |
| 4 | ✅ | ✅ | Validate the Wizard output |
| 5 | ✅ | — | Remove the old base policy and its supplementals |
| 6 | ✅ | ✅ | Deploy the new baseline in Audit |
| 7 | ✅ | — | Re-create the supplemental policies |
| 8 | ✅ | ✅ | Rebuild the allow list (audit cycle) |
| 9 | ✅ | ✅ | Enforce and verify, when you decide |

### Step 0 — Safety Net

```powershell
# Hyper-V host, elevated
Checkpoint-VM -Name '<VM name>' -SnapshotName "Pre-Rebase-$(Get-Date -Format 'yyyyMMdd')"
```

```powershell
# Device, elevated: back up the working files and record the current policy GUID
$Backup = "C:\WDAC\Backups\Rebase-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $Backup | Out-Null
Copy-Item -LiteralPath 'C:\WDAC\Source', 'C:\WDAC\Events' -Destination $Backup -Recurse
Copy-Item -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Destination (Join-Path $Backup 'OldPolicyGuid.txt')
$Backup
```

Steps 3, 5 and 7 read `OldPolicyGuid.txt` from the newest `C:\WDAC\Backups\Rebase-*` folder. On physical hardware, take a full backup instead of the checkpoint. The F8 recovery menu stays available through option 9.

### Step 1 — Take the Device Out of GPO Scope

Skip this step if §1.2 showed no WDAC GPO.

Microsoft says: *"Before removing any policy, you must first disable the method used to deploy it (such as Group Policy or MDM). Otherwise, the policy may redeploy to the computer."* The GPO guide's endpoint script deploys its package to every device in the OU. What happens if the device stays in scope depends on the route:

| Route | If the device stays in the OU |
|---|---|
| A | The GPO puts the old base policy back next to your new one. Two active base policies **intersect**: a file has to pass both. |
| B | The next package published to the OU replaces your baseline. |

```powershell
# Admin machine with the AD module (RSAT)
Get-ADComputer '<device name>' | Move-ADObject -TargetPath 'OU=<OU without the WDAC GPOs>,DC=<domain>,DC=<tld>'
```

```powershell
# Device
gpupdate /target:computer /force
gpresult /scope computer /r | Select-String AppControl                        # expect: no output
Get-ScheduledTask -TaskName 'WDAC-GPO-Deploy-*' -ErrorAction SilentlyContinue  # expect: no output
```

- **The task:** Group Policy Preferences removes the `WDAC-GPO-Deploy-*` task, because the GPO guide creates it with "remove when no longer applied". If the task is still there, the move hasn't reached the device's domain controller yet. Wait, then run `gpupdate` again.
- **The policy stays on the device.** A GPO never removes a `.cip` ([GPO README §10.3](../GPO/README.md#103-add-or-remove-devices)). Step 5 (Route A) or Step 6 (Route B) replaces it.
- **Pick the target OU with care:** it must still give the device every *other* GPO it needs.
- **Don't disable or delete the WDAC GPOs.** Other devices in the OU still use them.

### Step 2 — App Control Policy Wizard: New Baseline, Both Boxes Unchecked

Follow [README Step 1](README.md#6-phase-2--baseline-audit-policy-steps-1--2), with one difference on the File Rules screen:

1. **Launch the Wizard:** **Policy Creator** → **Base Policy** → **Multiple Policy Format** → **Allow Microsoft Mode**.
2. **Name and file:**
   - **Policy Name:** `PAW-WDAC-Audit-Baseline`
   - **File Path:** `C:\WDAC\Source\Base-Audit.xml`
   
   Replace the existing file; Step 0 backed it up.
3. **Policy Rules (+ Advanced Options):** use exactly the README Step 1 table. Audit Mode, UMCI and Managed Installer are ON, and so on.
4. **File Rules:** leave **both** boxes **unchecked**:
   - ☐ **Merge with Recommended User Mode Block Rules**
   - ☐ **Merge with Recommended Kernel Mode Block Rules**
5. **Build:** click **Next**. Ignore any `.cip` the Wizard writes next to the XML; script 1 compiles its own.

### Step 3 — Route B Only: Stamp the Old GUID Into the New Baseline

> [!WARNING]
> **This step is not documented by Microsoft or the README.**
> - **No cmdlet sets a GUID you choose.** `Set-CIPolicyIdInfo -ResetPolicyID` only creates a random GUID, and `-PolicyId` sets the text label, not the GUID.
> - **Microsoft recommends the Wizard or the ConfigCI cmdlets** over editing the XML for policy changes.
> - **What was tested (2026-10-27):** the snippet works in PowerShell 7.6.9 and Windows PowerShell 5.1, and the result compiles.
>
> If you need documented steps only, use Route A.

```powershell
$Backup  = (Get-ChildItem 'C:\WDAC\Backups' -Directory -Filter 'Rebase-*' | Sort-Object Name | Select-Object -Last 1).FullName
$OldGuid = (Get-Content -LiteralPath (Join-Path $Backup 'OldPolicyGuid.txt') -Raw).Trim()
if ($OldGuid -notmatch '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') { throw "STOP: '$OldGuid' in $Backup\OldPolicyGuid.txt is not a {GUID}. Check the Step 0 backup." }
$Xml = 'C:\WDAC\Source\Base-Audit.xml'
$Doc = New-Object System.Xml.XmlDocument; $Doc.PreserveWhitespace = $true; $Doc.Load($Xml)
"Wizard GUID: $($Doc.SiPolicy.PolicyID) -> $OldGuid"
$Doc.SiPolicy.PolicyID = $OldGuid; $Doc.SiPolicy.BasePolicyID = $OldGuid
$Doc.Save($Xml)
```

Step 4 then validates the file and compiles it as a test.

### Step 4 — Validate the Wizard Output

```powershell
$Block = ''            # regex for your block-test application; lab: 'Mozilla|Firefox'
.\0_1_validate_base_policy.ps1 -ExcludedAppPattern $Block
```

| Check | Expected | Meaning |
|---|---|---|
| Multiple Policy Format | `OK` | `PolicyID` = `BasePolicyID`. On Route B this is the old GUID. |
| Recommended User Mode Block Rules | **`WARN`** *"no deny rules in scenario 12"* | Proves the user-mode box was unchecked |
| Recommended Kernel Mode Block Rules | **`WARN`** *"no deny rules in scenario 131"* | Proves the kernel-mode box was unchecked |
| WSL deny rules | `OK` *"none present"* | `-AllowWSL` isn't needed |

The script must end with `PASSED`. Before it changes any rule option, it saves `Base-Audit.wizard-original-<timestamp>.xml`. It never calls `CiTool.exe` ([README Step 1.1](README.md#6-phase-2--baseline-audit-policy-steps-1--2)).

### Step 5 — Route A Only: Remove the Old Base Policy and Its Supplementals

Do this **before** Step 6, for two reasons:
- Script 1 overwrites `PolicyGuid.txt` with the new GUID.
- The old policy's events stay out of the new audit window.

```powershell
$Backup   = (Get-ChildItem 'C:\WDAC\Backups' -Directory -Filter 'Rebase-*' | Sort-Object Name | Select-Object -Last 1).FullName
$OldGuid  = (Get-Content -LiteralPath (Join-Path $Backup 'OldPolicyGuid.txt') -Raw).Trim()
$CiTool   = "$env:SystemRoot\System32\CiTool.exe"
$Policies = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies)
$Supps    = @($Policies | Where-Object { $_.BasePolicyID -eq $OldGuid.Trim('{}').ToLower() -and $_.PolicyID -ne $_.BasePolicyID })
$Supps | Select-Object FriendlyName, PolicyID, VersionString | Export-Csv -LiteralPath (Join-Path $Backup 'OldSupplementals.csv') -NoTypeInformation
$Supps | Select-Object FriendlyName, PolicyID, VersionString      # Step 7 re-creates each of these
& $CiTool --remove-policy $OldGuid -json
foreach ($S in $Supps) { & $CiTool --remove-policy "{$($S.PolicyID)}" -json }
```

- **Expect `OperationResult 0`** for each removal.
- **No restart needed** on Windows 11 2024 update and later; Microsoft says unsigned policies are removed without one there. On earlier builds, restart.
- **Check:** `.\7_DISA_STIG_CHECK.ps1` no longer lists the old policy. If the device was in Enforce, nothing is blocked from now on.

### Step 6 — Deploy the New Baseline in Audit

```powershell
.\1_compile_and_deploy.ps1          # answer Y
.\2_audit_policy_activation.ps1
```

**Script 1:**
- It prints *"Policy version YYYY.MM.DD.N"*. The version is above every version known for this GUID: the active policy, the archives in `C:\WDAC\Compiled`, and the GPO packages built on this device.
- `CiTool` returns `OperationResult 0`.
- It writes `PolicyGuid.txt`: the new GUID on Route A, the old GUID again on Route B.
- It starts the audit window. The previous start time is kept as `AuditRoundStart.previous-<timestamp>.txt`.
- **On Route B,** this is the moment the old policy is replaced in place. If it was enforced, the device switches to Audit now.

**Script 2:**
- `PAW-WDAC-Audit-Baseline` is active at that version, with `IsAuthorized True`.
- User mode (V-243451) reads `1 (AUDIT)`.
- Event **3099** is logged.
- **On Route B,** the supplemental policies are still listed against the same base.

### Step 7 — Route A Only: Re-create the Supplemental Policies for the New Base

Microsoft documents this in *Enforce App Control policies*: make a copy of each supplemental policy with a **new `PolicyID`** that points at the new base, then compile and deploy it. Do this **before** Step 8. Otherwise the files the supplemental allows appear as `3076` events and end up in the base policy.

Repeat the block for each policy listed in `OldSupplementals.csv`. The original XML is in the Step 0 backup.

```powershell
if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue }   # Windows PowerShell 5.1: Import-Module ConfigCI
. .\WDAC-Version.ps1
$NewGuid  = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()   # written by script 1 in Step 6
$SuppXml  = 'C:\WDAC\Source\<Supplemental>.xml'          # lab: C:\WDAC\Source\Supp-ClaudeCode.xml
$SuppName = '<supplemental policy name>'                 # lab: PAW-WDAC-Supp-ClaudeCode
Set-CIPolicyIdInfo -FilePath $SuppXml -PolicyName $SuppName -SupplementsBasePolicyID $NewGuid -ResetPolicyID | Out-Null
$Version  = (Get-WdacNextVersion).Versions[0]
Set-CIPolicyVersion -FilePath $SuppXml -Version $Version
$SuppDoc  = New-Object System.Xml.XmlDocument; $SuppDoc.Load($SuppXml)
$SuppGuid = $SuppDoc.SiPolicy.PolicyID
$Cip      = Join-Path 'C:\WDAC\Compiled' "$SuppGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $SuppXml -BinaryFilePath $Cip | Out-Null
Copy-Item -LiteralPath $Cip -Destination "C:\WDAC\Compiled\$($SuppName)_v$Version.cip"
Copy-Item -LiteralPath $SuppXml -Destination "C:\WDAC\Compiled\$($SuppName)_v$Version.xml"
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $Cip -json
```

- **Expect `OperationResult 0`.**
- **Check:** `.\8_validate_multipolicy_layout.ps1` lists the supplemental, with `BasePolicyID` = the new base GUID.
- **What was tested (2026-10-27):** these commands, on a copy of the lab supplemental, in PowerShell 7.6.9 and Windows PowerShell 5.1. The policy type stayed *Supplemental Policy*, it got a new `PolicyID` and the target `BasePolicyID`, and it compiled.

### Step 8 — Rebuild the Allow List (README Steps 3 – 5)

```powershell
$Block = ''                         # same value as Step 4; lab: 'Mozilla|Firefox'
#   >>> Reboot, then run every application the device needs (README Step 3)
.\3_capture_ciaudit_events.ps1
.\Export-CIEventEvidence.ps1 -EvtxPath 'C:\WDAC\Events\PAW-Audit-3076.evtx'
#   >>> Wizard: .evtx -> C:\WDAC\Source\Events-Allow.xml (README Step 4.2)
.\3_1_validate_winevent_rules.ps1
.\4_merge_audit_base_and_events_policies.ps1 -ExcludedAppPattern $Block   # add -AdditionalFolderRules '<admin-only folder>\*' if you use them
#   >>> Reboot, run every application again (README Step 5)
.\5_audit_merged_events.ps1
```

- **Don't pass `-BaseXml`.** The default, `C:\WDAC\Source\Base-Audit.xml`, is the new baseline. README §11 Option D passes `-BaseXml Base-Enforce.xml` to extend the **old** reference policy; here that would merge the block rules back in.
- **Loop until the screening is clean:** repeat export → Wizard → sanitize → merge → screen until script 5 reports `0` new `3076` events.
- **Rule types in the Wizard:** add FilePublisher or Publisher rules for signed files. Leave out rows in admin-only folders that a folder rule will cover.
- **Lab folder rules:** `-AdditionalFolderRules 'C:\Program Files\Git\*', 'C:\Program Files\Microsoft SDKs\Azure\CLI2\*'`. Script 4 skips a folder that doesn't exist, with a warning.

Full detail: [README §7 – §8](README.md#7-phase-3--capture-what-your-apps-need-steps-3--4).

### Step 9 — Enforce and Verify (When You Decide)

```powershell
#   >>> Wizard: newest C:\WDAC\Source\Base-Enforce*.xml, Audit Mode OFF and nothing else (README Step 6)
.\6_enforce_policy.ps1 -ExcludedAppPattern $Block
.\7_DISA_STIG_CHECK.ps1             # expect 2 (ENFORCING) / 2 (ENFORCING)
.\8_validate_multipolicy_layout.ps1
#   >>> Reboot, test every approved application, launch the block-test application (README Steps 8.3 - 8.4)
.\New-WDACRunReport.ps1 -BlockTestPattern $Block     # optional
```

Full detail: [README §9 – §10](README.md#9-phase-5--enforce-steps-6--7).

---

## 5. Rollback

| Situation | What to do |
|---|---|
| Anything went wrong (fastest) | Restore the Step 0 checkpoint ([README §11 Option C](README.md#11-rollback-and-fix-forward)). |
| New baseline enforced, but you need Audit again | [README §11 Option A](README.md#11-rollback-and-fix-forward): it stamps `Base-Audit-Merged.xml` above the enforced version and applies it. |
| Return the device to GPO management, **Route A** | 1. Remove the new base and its re-created supplementals: `CiTool --remove-policy <GUID>` ([README §11 Option B](README.md#11-rollback-and-fix-forward)).<br>2. Restore `C:\WDAC\Source` from the Step 0 backup, so `PolicyGuid.txt` names the GPO policy again.<br>3. Move the computer back into the OU and run `gpupdate /target:computer /force`.<br><br>The GPO then deploys its package, because that GUID is no longer active on the device. |
| Return the device to GPO management, **Route B** | Move the computer back into the OU. **The GPO won't replace your baseline** while the baseline has the higher version: the endpoint script never downgrades ([GPO README §10.2](../GPO/README.md#102-demote-enforce--audit)). Publish a new package pair ([GPO README §10.1](../GPO/README.md#10-ongoing-operations)), or restore the checkpoint. |

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `0_1` reports `WARN` *"no deny rules in scenario 12 / 131"* | Both boxes were unchecked | Expected in this runbook |
| Script 4 stops: *"… is not base policy … from PolicyGuid.txt"* | `Base-Audit.xml` and `PolicyGuid.txt` name different GUIDs. Either Step 6 didn't run after the Wizard, or on Route B Step 3 was skipped or ran after Step 6. | Route B: run Step 3. Then run Step 6. |
| The `WDAC-GPO-Deploy-*` task is still present, or the old policy comes back | The device is still in GPO scope | Step 1: wait for AD replication, then run `gpupdate` again |
| The old policy is still listed after Step 5 | The removal didn't complete | Read the CiTool output. On builds before the Windows 11 2024 update, restart. |
| Script 2 reports user mode `2 (ENFORCING)` after Step 6 | Another enforced base policy is still active (Route A: old base not removed) | Step 5 |
| `3076` events for `msbuild.exe`, `wsl.exe` and similar during Step 8 | The new baseline allows these, so the old base (with its deny rules) is still active | Step 5 |
| An application the supplemental allowed shows up as `3076` (Route A) | The supplemental wasn't re-created before the audit run | Step 7, then repeat the audit round |

---

## 7. How Each Step Is Documented

| Step | Your guides | Microsoft Learn |
|:---:|---|---|
| 0 | [README Step 0.1](README.md#5-phase-1--prepare-step-0) (checkpoint). README §11 Option D step 2 (back up `Source` and `Events`). The `Rebase-<timestamp>` folder and `OldPolicyGuid.txt` are this runbook's own. | — |
| 1 | [GPO README §10.3](../GPO/README.md#103-add-or-remove-devices) | *Remove App Control policies*: disable the deployment method first |
| 2 | README Step 1, **except** the two boxes: the README checks both | *Wizard: create a base policy* |
| 3 (B) | **Not documented** | **Not documented.** `Set-CIPolicyIdInfo` can't set a GUID you choose. |
| 4 | README Step 1.1. The script reports `WARN`, not `STOP`, when a block list is missing. | — |
| 5 (A) | [README §11 Option B](README.md#11-rollback-and-fix-forward) | *Remove App Control policies*: `CiTool -rp`; no restart for unsigned policies from the Windows 11 2024 update |
| 6 | README Step 2 | — |
| 7 (A) | — | *Enforce App Control policies*: copies of the supplemental policies, made with `Set-CIPolicyIdInfo -SupplementsBasePolicyID … -ResetPolicyID` |
| 8 | README Steps 3 – 5. The "don't merge the old reference policy" rule follows from §1.3. | *Use audit events to create rules*; *Merge App Control policies* |
| 9 | README Steps 6 – 8 | *Enforce App Control policies* |

What Microsoft documents about replacing a policy **in place**, which is how Route B works:

- **Same PolicyId, equal or higher version:** *"The replacement policy must have the same PolicyId as the one it's replacing and a version that's equal to or greater than the existing policy."* Source: *Remove App Control policies*. The article states this for replacing a **signed** base policy.
- **Skipping the ID reset:** *"If you prefer to replace the audit policy in-place, you can skip this step"* (the `-ResetPolicyID` step). Source: *Enforce App Control policies*.
- **Supplementals:** *"If you didn't reset the enforcement base policy's PolicyID, you can skip this procedure"* (copying the supplemental policies). Same article.
- **Direct XML edits:** Microsoft *"recommends all additional changes to policy rules or signing files to be made using the Windows Defender App Control Wizard or Configurable Code Integrity Cmdlets in PowerShell"*, rather than by editing the policy XML. Source: *Essential Eight application control*.

---

## 8. Sources

**Microsoft Learn**
- [Remove App Control for Business policies](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies)
- [Enforce App Control for Business policies](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/enforce-appcontrol-policies)
- [Set-CIPolicyIdInfo](https://learn.microsoft.com/powershell/module/configci/set-cipolicyidinfo)
- [Use multiple App Control for Business policies](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)
- [Applications that can bypass App Control and how to block them](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) (the user-mode block list)
- [Microsoft recommended driver block rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) (the kernel-mode block list and the built-in blocklist)
- [Editing existing base and supplemental App Control policies with the Wizard](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard-editing-policy)
- [Essential Eight application control](https://learn.microsoft.com/compliance/anz/e8-app-control)

**This repository**
- [README.md](README.md): the multi-policy STIG guide (scripts + Wizard, no GPO)
- [../GPO/README.md](../GPO/README.md): the multi-policy GPO deployment guide
