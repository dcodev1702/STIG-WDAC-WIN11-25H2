# App Control for Business (WDAC) on `WIN11-PAW-WDAC` — Simplified Manual Multi-Policy Guide (No GPO)

> **Environment & Scope**
> - **Target VM:** `WIN11-PAW-WDAC` (Windows 11 Enterprise 25H2 on Hyper-V)
> - **Account:** `lorenzo@skynet-home.local` (or local admin `.\lorenzo` if testing before domain join)
> - **Deployment Method:** **100% Manual** using **App Control Policy Wizard** + **PowerShell 7 (`pwsh`)** + **`CiTool.exe`** (**No GPO** in this guide)
> - **Policy Architecture:** **Multiple-Policy Format** (`{PolicyID}.cip` in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`) with **Allow Supplemental Policies** enabled
> - **Approved Apps to Keep Working:** **WinDirStat**, **Azure CLI (`az`)**, **VS Code (including updates)**
> - **Deliberately Excluded App (Proof of Enforcement):** **Mozilla Firefox** (must be blocked when enforced!)
> - **Target End State:** `CodeIntegrityPolicyEnforcementStatus = 2` **and** `UsermodeCodeIntegrityPolicyEnforcementStatus = 2` (resolves DISA PAW STIG **V-243450** & **V-243451**)
> - **Reference Repo:** [dcodev1702/STIG-WDAC-WIN11-25H2](https://github.com/dcodev1702/STIG-WDAC-WIN11-25H2/blob/main/README.md)

---

## Table of Contents

1. [How This Workflow Fits Together (And Why Each Rule Exists)](#1-how-this-workflow-fits-together-and-why-each-rule-exists)
2. [Step 0 — Checkpoint, Persistent `pwsh 7` Session, and `0 / 0` Pre-Flight Check](#2-step-0--checkpoint-persistent-pwsh-7-session-and-0--0-pre-flight-check)
3. [Step 1 — Use the Wizard to Establish the Baseline Policy (Audit Mode)](#3-step-1--use-the-wizard-to-establish-the-baseline-policy-audit-mode)
4. [Step 2 — Use PowerShell 7 to Stamp, Compile, and Deploy the Baseline Audit Policy (`0 / 0` → `1 / 1`)](#4-step-2--use-powershell-7-to-stamp-compile-and-deploy-the-baseline-audit-policy-0--0--1--1)
5. [Step 3 — Exercise Approved Apps to Generate `3076` Audit Events (Leave Out Firefox!)](#5-step-3--exercise-approved-apps-to-generate-3076-audit-events-leave-out-firefox)
6. [Step 4 — Export Time-Boxed Events & Use the Wizard to Capture `3076` Events as New Rules](#6-step-4--export-time-boxed-events--use-the-wizard-to-capture-3076-events-as-new-rules)
7. [Step 5 — Use PowerShell 7 to Merge Baseline + Events, Keep in Audit Mode, and Screen (`1 / 1`)](#7-step-5--use-powershell-7-to-merge-baseline--events-keep-in-audit-mode-and-screen-1--1)
8. [Step 6 — Use the Wizard to Keep Boot Audit Enabled and Switch from Audit to Enforce](#8-step-6--use-the-wizard-to-keep-boot-audit-enabled-and-switch-from-audit-to-enforce)
9. [Step 7 — Use PowerShell 7 to Bump Version, Verify Multi-Policy Suitability, and Apply (`1 / 1` → `2 / 2`)](#9-step-7--use-powershell-7-to-bump-version-verify-multi-policy-suitability-and-apply-1--1--2--2)
10. [Step 8 — Validate STIG Compliance (`2` and `2`) and Prove Enforcement by Blocking Firefox](#10-step-8--validate-stig-compliance-2-and-2-and-prove-enforcement-by-blocking-firefox)
11. [Quick Rollback / Fix-Forward Reference](#11-quick-rollback--fix-forward-reference)
12. [Agent Handover & Audit Log Protocol (For Follow-On Automation / GPO Phase)](#12-agent-handover--audit-log-protocol-for-follow-on-automation--gpo-phase)

---

## 1. How This Workflow Fits Together (And Why Each Rule Exists)

### The Two DISA STIG Findings We Are Closing

| STIG ID | Vulnerability ID | What It Checks | Passing Value |
|---|---|---|---|
| **V-243450** | `WPAW-00-001050` (CAT II) | `CodeIntegrityPolicyEnforcementStatus` (Kernel-mode CI) | **`2`** (Enforced) |
| **V-243451** | `WPAW-00-001060` (CAT II) | `UsermodeCodeIntegrityPolicyEnforcementStatus` (User-mode CI / UMCI) | **`2`** (Enforced) |

In `Win32_DeviceGuard`, **`0`** = Not Configured, **`1`** = Audit Mode, and **`2`** = Enforced. By checking these values at every stage (**`0 / 0` → `1 / 1` → `2 / 2`**), we prove beyond doubt that **our policy** is what transitions the PAW into STIG compliance.

### The Six Golden Rules of This Multi-Policy Workflow

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
6. **No Reboots Required:**
   Because we enable **Update Policy without Rebooting** (`Option 16`) and deploy unsigned policies via `CiTool.exe --update-policy`, every policy deployment and update in this guide takes effect **live without rebooting**.

### Version & ID Progression Plan

| Stage | XML File | Friendly Name (`-PolicyName`) | Policy ID Label (`-PolicyId`) | `VersionEx` | Mode | Expected STIG Status |
|---|---|---|---|---|---|---|
| **Pre-Flight** | *(None)* | *(Only MS platform policies)* | — | — | None | **`0` / `0`** |
| **Baseline Audit** | `Base-Audit.xml` | `PAW-WDAC-Audit-Baseline` | `PAW-AUDIT-BASE-v1` | `2026.10.21.1` | Audit | **`1` / `1`** |
| **Merged Audit** | `Base-Audit-Merged.xml` | `PAW-WDAC-Audit-Merged` | `PAW-AUDIT-MERGED-v2` | `2026.10.21.2` | Audit | **`1` / `1`** |
| **Enforced** | `Base-Enforce.xml` | `PAW-WDAC-Enforced` | `PAW-ENFORCED-v3` | `2026.10.21.3` | **Enforce** | **`2` / `2`** |

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
3. Loads the Windows `ConfigCI` module into PowerShell 7 using `-UseWindowsPowerShell`.

**Why we need it:** `ConfigCI` (`New-CIPolicy`, `Merge-CIPolicy`, `Set-CIPolicyIdInfo`, `Set-CIPolicyVersion`, `Set-RuleOption`, `ConvertFrom-CIPolicy`) is a Windows PowerShell 5.1 system module. Passing `-UseWindowsPowerShell` loads it seamlessly into PowerShell 7 via the built-in compatibility session.

Run on **`WIN11-PAW-WDAC`** (elevated `pwsh 7`):

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
New-Item -Path $Folders -ItemType Directory -Force | Out-Null

# 3. Start an audit log transcript of all commands and outputs
Start-Transcript -Path "C:\WDAC\Logs\WDAC-Manual-Run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

# 4. Import ConfigCI into PowerShell 7
Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue
Get-Command -Module ConfigCI
```

### 0.4 Run the Stage 0 STIG Check (`0 / 0` Baseline) & Confirm App Installations

**What this does:** Records the "Before" state of `Win32_DeviceGuard`, lists currently active policies in `CiTool.exe`, and verifies that **WinDirStat**, **Azure CLI (`az`)**, **VS Code**, and **Firefox** are installed on the PAW before we enable WDAC.
**Why we need it:**
- Confirms both STIG values start at **`0` (Not Configured)** and no stray `SiPolicy.p7b` or custom `.cip` policy is already active.
- Installing **Firefox** *now* (before Audit Mode is turned on) ensures its installer does not pollute our `3076` audit log later. (**Do not launch Firefox after installing it!**)

```powershell
# 1. Stage 0 STIG Check — Expect BOTH values to be 0 (Not Configured)
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 2. Confirm no legacy single-policy SiPolicy.p7b exists (Expect: False)
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"

# 3. List existing policies in CiTool — Expect ONLY built-in Microsoft Platform policies (IsSystemPolicy = true)
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Select-Object PolicyID, FriendlyName, IsSystemPolicy, IsEnforced, IsAuthorized |
    Format-Table -AutoSize

# 4. Verify our 3 Approved Apps + 1 Proof-of-Block App (Firefox) are installed on the PAW
[pscustomobject]@{
    WinDirStat = (Get-ChildItem "$env:ProgramFiles\WinDirStat\WinDirStat.exe", "${env:ProgramFiles(x86)}\WinDirStat\WinDirStat.exe" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    AzureCLI   = (Get-Command az.cmd -ErrorAction SilentlyContinue).Source
    VSCode     = (@("$env:ProgramFiles\Microsoft VS Code\Code.exe", "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1)
    Firefox    = (@("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1)
} | Format-List
```

> **Note on Firefox Background Tasks:** If Firefox is installed, disable its background scheduled tasks now so it doesn't silently run in the background during Step 3 and generate `3076` events:
> ```powershell
> Get-ScheduledTask | Where-Object { $_.TaskName -match 'Firefox|Mozilla' } | Disable-ScheduledTask
> ```

---

## 3. Step 1 — Use the Wizard to Establish the Baseline Policy (Audit Mode)

**What this does:** Uses the **App Control Policy Wizard** GUI to build a **Multiple-Policy Format** base policy from the **Allow Microsoft** template in **Audit Mode**, including Microsoft's Recommended User Mode and Kernel Mode Block Rules.
**Why we need it:** Starting from *Allow Microsoft* in Audit Mode trusts Windows and Microsoft-signed binaries (including PowerShell 7, `CiTool.exe`, and Microsoft-signed VS Code binaries) while logging Event ID `3076` for everything else (like WinDirStat, non-Microsoft VS Code extension binaries, or unsigned Python DLLs) without blocking anything yet.

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

**Why we need it:** Windows cannot log `3076` events until an audit policy is actually active on the system!

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC`:

```powershell
$BaseXml = 'C:\WDAC\Source\Base-Audit.xml'

# 1. Stamp helpful Name, ID label, and VersionEx (NEVER use -ResetPolicyID!)
Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'PAW-WDAC-Audit-Baseline' -PolicyId 'PAW-AUDIT-BASE-v1'
Set-CIPolicyVersion -FilePath $BaseXml -Version '2026.10.21.1'

# 2. Read the PolicyID GUID and verify rule options in the XML
[xml]$BaseDoc = Get-Content -LiteralPath $BaseXml
$PolicyGuid   = $BaseDoc.SiPolicy.PolicyID
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

Now compile and deploy the baseline audit policy:

```powershell
# 3. Compile Base-Audit.xml to C:\WDAC\Compiled\{PolicyID}.cip
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $BaseXml -BinaryFilePath $CipFile

# Save an archive copy of v2026.10.21.1 for our audit trail
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip' -Force

# 4. Deploy the Baseline Audit Policy live with CiTool.exe (no reboot required)
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
```

### Verify Stage 1 Activation (`0 / 0` → `1 / 1` and Event ID `3099`)

```powershell
# 1. Stage 1 STIG Check — Expect BOTH values to now be 1 (Audit Mode)!
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
} -MaxEvents 5 | Select-Object TimeCreated, Id, Message | Format-List
```

---

## 5. Step 3 — Exercise Approved Apps to Generate `3076` Audit Events (Leave Out Firefox!)

**What this does:** Marks the exact timestamp `$AuditRoundStart` and runs every application and workflow you want to permit on the PAW (**WinDirStat**, **Azure CLI (`az`)**, and **VS Code including updating**) while **leaving Firefox completely untouched**.
**Why we need it:** Code Integrity only logs Event ID `3076` when a binary is actually loaded into memory. Recording `$AuditRoundStart` lets us export *only* the events generated during this controlled test window.

### 3.1 Mark the Start of the Audit Test Window (PowerShell 7)

```powershell
$AuditRoundStart = Get-Date
$AuditRoundStart.ToString('o') | Set-Content -LiteralPath 'C:\WDAC\Events\AuditRoundStart.txt'
Write-Host "Audit test window started at: $($AuditRoundStart.ToString('o'))" -ForegroundColor Green
```

### 3.2 Run Each Approved Application on `WIN11-PAW-WDAC`

1. **WinDirStat (`WinDirStat.exe`):**
   - Launch **WinDirStat** from the Start Menu (or run `& "$env:ProgramFiles\WinDirStat\WinDirStat.exe"`).
   - Select `C:\` and let it scan for a few seconds, then close it.
2. **Azure CLI (`az`):**
   - In your PowerShell 7 window, run a representative set of Azure CLI commands so its embedded Python interpreter (`python.exe`) and `.dll`/`.pyd` libraries load:
     ```powershell
     az --version
     az account list 2>$null
     az extension list 2>$null
     az help | Out-Null
     ```
3. **VS Code (including the Update Mechanism):**
   - Launch **Visual Studio Code**.
   - Open a folder/file so your installed extensions activate.
   - Click **Help -> Check for Updates...** (or if an update is staged, let it run; you can also run `winget upgrade Microsoft.VisualStudioCode` or launch the `VSCodeSetup-x64-*.exe` / `VSCodeUserSetup-x64-*.exe` installer if you want to capture the setup binary explicitly).
   - *(Why this works cleanly: Microsoft signs `Code.exe`, its updater `inno_updater.exe`, and its installers with Microsoft certificates already trusted by **Allow Microsoft**. Running VS Code now captures any non-Microsoft extension helper binaries under `%USERPROFILE%\.vscode\extensions`!)*
4. **🚫 DO NOT Open Firefox:**
   - Leave **Firefox** closed! Because we never run Firefox during Audit Mode (and we exclude any Mozilla event if one ever appears), Firefox will have **zero** allow rules in our policy.

---

## 6. Step 4 — Export Time-Boxed Events & Use the Wizard to Capture `3076` Events as New Rules

### 4.1 Preview `3076` Events and Export a Time-Boxed `.evtx` File (PowerShell 7)

**What this does:**
1. Queries `Microsoft-Windows-CodeIntegrity/Operational` for all Event ID `3076` ("would have been blocked") records created since `$AuditRoundStart` and displays the unique file paths.
2. Uses `wevtutil epl` to export a clean `.evtx` file (`C:\WDAC\Events\PAW-Audit-3076.evtx`) containing **only Event IDs `3076` and `3089`** created since `$AuditRoundStart`.

**Why we need it:**
- Event ID `3076` records the file that would have been blocked; Event ID `3089` records the file's Authenticode signature chain. The Wizard needs **both `3076` and `3089`** in the `.evtx` file to create `Publisher` / `FilePublisher` rules.
- Time-boxing to `$AuditRoundStart` prevents stale historical events from sneaking into your policy.

```powershell
$AuditRoundStart = [datetime]::Parse((Get-Content -LiteralPath 'C:\WDAC\Events\AuditRoundStart.txt' -Raw).Trim())

# 1. Preview unique files that generated Event ID 3076 during our test window
$Events3076 = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $AuditRoundStart
} -ErrorAction SilentlyContinue

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
Get-Item -LiteralPath $EvtxPath | Select-Object FullName, Length, LastWriteTime
```

### 4.2 Convert the `.evtx` Events into a Policy in the Wizard GUI

**What this does:** Parses `C:\WDAC\Events\PAW-Audit-3076.evtx` in the App Control Policy Wizard and builds `C:\WDAC\Source\Events-Allow.xml` containing allow rules for your approved apps.
**Why we need it:** Converts the real-world telemetry from Step 3 into structured XML allow rules ready to be merged into our baseline.

1. Open the **App Control Policy Wizard** -> click **Policy Editor**.
2. Select **Convert Event Logs to a Policy**.
3. Under **Parse Event Log evtx Files to Policy**, click **Parse Log File(s)** and select:
   - **`C:\WDAC\Events\PAW-Audit-3076.evtx`**
4. Once the notification confirms parsing succeeded, click **Next** to open the **Configure Event Log Rules** table.
5. For each approved application in the table, select the row, choose the **Rule Type**, and click **Add Allow Rule** (the row will show *"Added to policy"*):
   - **WinDirStat (`WinDirStat.exe`):**
     - If signed (modern WinDirStat 2.x releases are signed by *WinDirStat Project* / *Open Source Developer*): choose **Publisher** (or **FilePublisher**) and click **Add Allow Rule**.
     - If unsigned (older WinDirStat 1.1.2): choose **Hash** and click **Add Allow Rule**.
   - **Azure CLI (`az`) & VS Code Extension Binaries:**
     - Add **Publisher** or **Hash** rules for the flagged binaries in the table.
     - *(Pro Tip for Azure CLI: Because `az` contains hundreds of Python `.pyd` and `.dll` files under `C:\Program Files\Microsoft SDKs\Azure\CLI2\`, we will also add a single clean `FilePath` rule for that admin-protected folder in Step 5 so future `az` commands never hit an uncaptured `.pyd` file!)*
   - **🚫 Firefox / Mozilla Check:**
     - Verify there are **no** `firefox.exe` or `Mozilla` entries added. If any appear, **do not add them** (or delete them from the rules list).
6. Click **Next** and save the output XML as:
   - **`C:\WDAC\Source\Events-Allow.xml`**

> ⚠️ **Important:** Do **not** compile or deploy `Events-Allow.xml` by itself! It is only an input file for the merge in Step 5.

---

## 7. Step 5 — Use PowerShell 7 to Merge Baseline + Events, Keep in Audit Mode, and Screen (`1 / 1`)

**What this does:**
1. Adds a folder-scoped `FilePath` allow rule for Azure CLI's admin-protected install directory (`C:\Program Files\Microsoft SDKs\Azure\CLI2\*` or `C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\*`) if present, so every `az` subcommand and Python module is covered.
2. Merges `Base-Audit.xml` (**FIRST**) and `Events-Allow.xml` (**SECOND**) into `C:\WDAC\Source\Base-Audit-Merged.xml`.
3. Cleans up any unwanted rule options (such as `Dynamic Code Security` or `Revoked Expired As Unsigned`) that `Merge-CIPolicy` unioned from the Wizard's event policy XML, while guaranteeing **Audit Mode** (`Option 3`), **Boot Audit on Failure** (`Option 10`), **Allow Supplemental Policies** (`Option 17`), and **Disable Script Enforcement** (`Option 11`) stay enabled.
4. Stamps a helpful ID (`PAW-AUDIT-MERGED-v2`), Name (`PAW-WDAC-Audit-Merged`), and bumped Version (`2026.10.21.2`) while keeping the **exact same `PolicyID` GUID**.
5. Compiles and deploys the merged audit policy live via `CiTool.exe`, then screens the apps again to confirm **zero** new `3076` events.

**Why we need it:** Merging into `Base-Audit.xml` (with `Base-Audit.xml` listed first) preserves our base `PolicyID` GUID and Microsoft allow/deny rules while adding the new application allow rules. Screening in Audit Mode proves our rules are complete *before* we switch to Enforce Mode.

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC`:

```powershell
$BaseXml   = 'C:\WDAC\Source\Base-Audit.xml'
$EventsXml = 'C:\WDAC\Source\Events-Allow.xml'
$MergedXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()

# 1. Merge Base-Audit.xml (FIRST!) and Events-Allow.xml (SECOND)
Merge-CIPolicy -PolicyPaths $BaseXml, $EventsXml -OutputFilePath $MergedXml

# 2. Optional but Recommended for Azure CLI: Ensure the admin-only Program Files Azure CLI folder is covered
#    (Runs New-CIPolicyRule in Windows PowerShell 5.1 so Rule objects serialize cleanly into Merge-CIPolicy)
foreach ($AzFolder in @('C:\Program Files\Microsoft SDKs\Azure\CLI2\*', 'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\*')) {
    if (Test-Path (Split-Path $AzFolder -Parent)) {
        Write-Host "Adding admin-protected FilePath rule for Azure CLI: $AzFolder" -ForegroundColor Cyan
        powershell.exe -NoProfile -Command "
            Import-Module ConfigCI
            `$Rule = New-CIPolicyRule -FilePathRule '$AzFolder'
            Merge-CIPolicy -PolicyPaths '$MergedXml' -Rules `$Rule -OutputFilePath '$MergedXml.tmp' | Out-Null
            Move-Item -LiteralPath '$MergedXml.tmp' -Destination '$MergedXml' -Force
        "
    }
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
    Set-RuleOption -FilePath $MergedXml -Option $OptOn
}
#    Ensure UNWANTED options (often leaked by Wizard event policies) are OFF:
#     13 = Enabled:Managed Installer
#     14 = Enabled:Intelligent Security Graph Authorization
#     15 = Enabled:Invalidate EAs on Reboot
#     18 = Disabled:Runtime FilePath Rule Protection (deleting Option 18 keeps Runtime Protection ON!)
#     19 = Enabled:Dynamic Code Security
#     20 = Enabled:Revoked Expired As Unsigned
foreach ($OptOff in @(13, 14, 15, 18, 19, 20)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOff -Delete
}

# 4. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.2) — DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $MergedXml -PolicyName 'PAW-WDAC-Audit-Merged' -PolicyId 'PAW-AUDIT-MERGED-v2'
Set-CIPolicyVersion -FilePath $MergedXml -Version '2026.10.21.2'

# 5. Verify PolicyID GUID is unchanged, Audit Mode is still ON, and no Firefox/Mozilla rules exist
[xml]$MergedDoc = Get-Content -LiteralPath $MergedXml
$HasFirefox = (Get-Content -LiteralPath $MergedXml -Raw) -match 'Mozilla|Firefox'

[pscustomobject]@{
    PolicyName       = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel    = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyID_GUID    = $MergedDoc.SiPolicy.PolicyID
    MatchesBaseline  = ($MergedDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    VersionEx        = $MergedDoc.SiPolicy.VersionEx
    AuditModeOn      = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Audit Mode')
    SupplementalOn   = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Allow Supplemental Policies')
    BootAuditOn      = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Boot Audit On Failure')
    FirefoxInPolicy  = $HasFirefox
} | Format-List
```

**Check the output above:**
- `MatchesBaseline` **must be `True`**
- `AuditModeOn`, `SupplementalOn`, and `BootAuditOn` **must all be `True`**
- `FirefoxInPolicy` **must be `False`**

Now compile and deploy the merged audit policy:

```powershell
# 6. Compile Base-Audit-Merged.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $MergedXml -BinaryFilePath $CipFile
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Merged_v2026.10.21.2.cip' -Force

# 7. Apply the updated Merged Audit Policy live with CiTool.exe
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json

# 8. Confirm STIG status is still 1 / 1 (Audit Mode) and FriendlyName updated to PAW-WDAC-Audit-Merged
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized
```

### Screen the Merged Audit Policy (Verify `0` New `3076` Events for Approved Apps)

**What this does:** Marks a fresh timestamp (`$ScreenStart = Get-Date`), re-runs **WinDirStat**, **Azure CLI (`az`)**, and **VS Code (including update check)**, and checks if any new `3076` events appear.
**Why we need it:** Because old `3076` events remain in Event Viewer permanently, filtering for events after `$ScreenStart` proves whether our merged rules completely cover the approved apps.

```powershell
# 1. Mark the start of the screening round BEFORE re-running the apps
$ScreenStart = Get-Date
Write-Host "Screening round started at: $($ScreenStart.ToString('o')) — Now run WinDirStat, az, and VS Code!" -ForegroundColor Yellow
```

Now launch **WinDirStat**, run **`az --version`** / **`az account list`**, and launch **VS Code** (and check for updates). Then run:

```powershell
# 2. Check for any NEW 3076 events generated after $ScreenStart
$Remaining3076 = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $ScreenStart
} -ErrorAction SilentlyContinue)

Write-Host "New 3076 events since screening started: $($Remaining3076.Count)" -ForegroundColor Cyan
$Remaining3076 | Select-Object TimeCreated, Message | Format-List
```

- **If `New 3076 events since screening started: 0`:** Your policy allowlist is complete! Proceed to **Step 6**.
- **If any new `3076` events appear for an approved app:** Export and convert those remaining events in the Wizard, merge them into `Base-Audit-Merged.xml` (keeping `Base-Audit-Merged.xml` first), bump the version, and re-screen until the count is `0`.

---

## 8. Step 6 — Use the Wizard to Keep Boot Audit Enabled and Switch from Audit to Enforce

**What this does:** Copies our validated `Base-Audit-Merged.xml` to `C:\WDAC\Source\Base-Enforce.xml`, opens it in the **App Control Policy Wizard**, confirms **Boot Audit on Failure** remains **ON**, and turns **Audit Mode OFF**.
**Why we need it:**
- Working on a copy (`Base-Enforce.xml`) preserves your known-good `Base-Audit-Merged.xml` file for instant rollback.
- Turning **Audit Mode OFF** deletes `<Option>Enabled:Audit Mode</Option>` from the XML, switching the policy from Audit (`1`) to Enforced (`2`).
- Keeping **Boot Audit on Failure ON** ensures that if a boot-critical kernel driver ever fails validation during a future reboot, Windows falls back to audit mode rather than failing to boot.

### 6.1 Copy the Validated Merged Audit XML to `Base-Enforce.xml` (PowerShell 7)

```powershell
Copy-Item -LiteralPath 'C:\WDAC\Source\Base-Audit-Merged.xml' -Destination 'C:\WDAC\Source\Base-Enforce.xml' -Force
```

### 6.2 Switch from Audit to Enforce in the Wizard GUI

1. Open the **App Control Policy Wizard** -> click **Policy Editor**.
2. Select **Edit Policy XML File** -> click **Browse** and select:
   - **`C:\WDAC\Source\Base-Enforce.xml`**
   - Click **Next**.
3. On the **Policy Rules** screen, click **+ Advanced Options** so you can see both columns:
   - **Turn OFF:**
     - ❌ **Audit Mode** -> toggle to **OFF (Disabled)** *(this puts the policy into Enforce Mode!)*
   - **Keep ON (Verify these remain enabled):**
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

---

## 9. Step 7 — Use PowerShell 7 to Bump Version, Verify Multi-Policy Suitability, and Apply (`1 / 1` → `2 / 2`)

**What this does:**
1. Stamps `Base-Enforce.xml` with a helpful name (`PAW-WDAC-Enforced`), ID (`PAW-ENFORCED-v3`), and bumped version (`2026.10.21.3`) while keeping the **exact same `PolicyID` GUID**.
2. Runs a pre-deployment gate to verify that the policy is suitable for the **multi-policy method** (`PolicyID == BasePolicyID`, `Allow Supplemental Policies = ON`, `Boot Audit on Failure = ON`, `UMCI = ON`, `Audit Mode = OFF`, and no `Mozilla`/`Firefox` rules).
3. Compiles `Base-Enforce.xml` into `C:\WDAC\Compiled\{PolicyID}.cip` and applies it live with `CiTool.exe --update-policy`.

**Why we need it:** Because the enforced policy has the **same `PolicyID` GUID** and a **higher version (`2026.10.21.3` > `2026.10.21.2`)**, `CiTool.exe --update-policy` seamlessly upgrades the active policy in place from Audit Mode to Enforce Mode without a reboot and without creating duplicate policies.

Run in your **elevated PowerShell 7 (`pwsh`)** window on `WIN11-PAW-WDAC`:

```powershell
$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()

# If the Wizard wrote a version-suffixed file (e.g., Base-Enforce_v*.xml), normalize it to Base-Enforce.xml
$LatestEnforceXml = Get-ChildItem -Path 'C:\WDAC\Source' -Filter 'Base-Enforce*.xml' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$EnforceXml = 'C:\WDAC\Source\Base-Enforce.xml'
if ($LatestEnforceXml.FullName -ne $EnforceXml) {
    Copy-Item -LiteralPath $LatestEnforceXml.FullName -Destination $EnforceXml -Force
}

# 1. Guarantee Enforce Mode options (Audit Mode OFF, Boot Audit ON, Supplemental ON, UMCI ON, Script Enforcement Disabled)
foreach ($OptOn in @(0, 2, 6, 9, 10, 11, 16, 17)) {
    Set-RuleOption -FilePath $EnforceXml -Option $OptOn
}
foreach ($OptOff in @(3, 13, 14, 15, 18, 19, 20)) {
    # Option 3 = Enabled:Audit Mode -> Deleting Option 3 guarantees ENFORCE MODE!
    Set-RuleOption -FilePath $EnforceXml -Option $OptOff -Delete
}

# 2. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.3) — DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $EnforceXml -PolicyName 'PAW-WDAC-Enforced' -PolicyId 'PAW-ENFORCED-v3'
Set-CIPolicyVersion -FilePath $EnforceXml -Version '2026.10.21.3'

# 3. Verify Multi-Policy Suitability & Enforce Readiness before compiling
[xml]$EnfDoc = Get-Content -LiteralPath $EnforceXml
$Opts = $EnfDoc.SiPolicy.Rules.Rule.Option
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
    UMCI_Enabled            = ($Opts -contains 'Enabled:UMCI')
    BootAuditEnabled        = ($Opts -contains 'Enabled:Boot Audit On Failure')
    AllowSupplemental       = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    ScriptEnforceDisabled   = ($Opts -contains 'Disabled:Script Enforcement')
    UpdateNoRebootEnabled   = ($Opts -contains 'Enabled:Update Policy No Reboot')
    NoFirefoxRules          = (-not ((Get-Content -LiteralPath $EnforceXml -Raw) -match 'Mozilla|Firefox'))
}
$Check | Format-List

if (-not ($Check.SameGuidAsAudit -and $Check.MultiPolicyFormatValid -and $Check.AuditModeRemoved -and $Check.UMCI_Enabled -and $Check.BootAuditEnabled -and $Check.AllowSupplemental -and $Check.NoFirefoxRules)) {
    throw 'STOP: Pre-deployment verification failed! Review the False property above before applying.'
}
Write-Host 'PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!' -ForegroundColor Green
```

Now compile and apply the enforced policy live:

```powershell
# 4. Compile Base-Enforce.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $EnforceXml -BinaryFilePath $CipFile
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Enforced_v2026.10.21.3.cip' -Force

# Record SHA256 hash of the enforced .cip binary for your audit evidence
Get-FileHash -LiteralPath $CipFile -Algorithm SHA256 | Format-List

# 5. Apply the Enforced Policy live with CiTool.exe (no reboot required)
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
```

---

## 10. Step 8 — Validate STIG Compliance (`2` and `2`) and Prove Enforcement by Blocking Firefox

### 8.1 Run the Official DISA STIG Check (`V-243450` & `V-243451`)

**What this does:** Runs the exact elevated WMI/CIM query from the STIG repository (`Win32_DeviceGuard`) and checks that **both** `CodeIntegrityPolicyEnforcementStatus` and `UsermodeCodeIntegrityPolicyEnforcementStatus` return **`2`**.
**Why we need it:** A value of `2` for both properties is the definitive STIG requirement proving that both Kernel-Mode Code Integrity (**V-243450**) and User-Mode Code Integrity (**V-243451**) are actively **Enforced** on `WIN11-PAW-WDAC`.

```powershell
# Official DISA STIG Check (must be run in an elevated PowerShell session)
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'Run the STIG check in an elevated PowerShell session (Run as administrator).' }

$DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
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

```powershell
# 1. Confirm the active multi-policy binary exists under CiPolicies\Active\{PolicyID}.cip (and no legacy SiPolicy.p7b exists)
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.cip' |
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
} -MaxEvents 5 | Select-Object TimeCreated, Id, Message | Format-List
```

### 8.3 Positive Test — Confirm Approved Apps Still Work

1. **WinDirStat:** Launch **WinDirStat** -> opens and scans normally.
2. **Azure CLI (`az`):** Run `az --version` and `az account list` -> runs normally.
3. **VS Code (including updates):** Launch **VS Code** and run **Help -> Check for Updates...** -> runs normally.
4. **PowerShell Language Mode:** Verify your interactive PowerShell session is still in `FullLanguage`:
   ```powershell
   $ExecutionContext.SessionState.LanguageMode   # Expect: FullLanguage
   ```

### 8.4 Negative Test — Launch Firefox to Prove Enforcement (`Event ID 3077`)

**What this does:** Attempts to launch **Mozilla Firefox** (which we intentionally excluded from our policy) and queries `Microsoft-Windows-CodeIntegrity/Operational` for **Event ID `3077`**.
**Why we need it:** Proves that enforcement is actively blocking unapproved user-mode executables in real time.

1. Double-click **Firefox** on the desktop/Start Menu, or try to launch it from PowerShell:
   ```powershell
   & "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
   ```
2. **Expected Result on Screen:**
   - Windows immediately blocks `firefox.exe` from starting.
   - On the desktop, Windows displays the toast notification:
     > *"Your organization used App Control for Business to block this app"*
   - In PowerShell, launching `firefox.exe` fails immediately with:
     > *"An Application Control policy has blocked this file"*
3. **Confirm Event ID `3077` (Enforced Block Event) in the Event Log:**
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
       Id        = 3077
       StartTime = (Get-Date).AddMinutes(-15)
   } -MaxEvents 10 | Select-Object TimeCreated, Id, Message | Format-List
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

Set-CIPolicyVersion -FilePath $RollbackXml -Version '2026.10.21.4'
ConvertFrom-CIPolicy -XmlFilePath $RollbackXml -BinaryFilePath $CipFile
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
