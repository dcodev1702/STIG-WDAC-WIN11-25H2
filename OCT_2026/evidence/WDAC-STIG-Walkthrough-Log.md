# App Control for Business (WDAC) — STIG Walkthrough Log · `WIN11-PAW-WDAC`

| | |
|---|---|
| **Guide followed** | `C:\WDAC\config\README.md` (Simplified Manual Multi-Policy Guide, no GPO) |
| **Operator** | Claude Code (agent) running **on** `WIN11-PAW-WDAC` inside VS Code, as `skynet\lorenzo` (elevated, PowerShell 7.6.8) — Wizard GUI steps performed by the user |
| **Started** | 2026-10-23 10:26:45 (+02:00) |
| **Goal** | Move **V-243451** (`UsermodeCodeIntegrityPolicyEnforcementStatus`) from `1` to **`2`** (and keep **V-243450** at `2`) with the approved applications still working and **Firefox blocked** |

## STIG Status by Stage

| Stage | When | V-243450 · KMCI (`CodeIntegrityPolicyEnforcementStatus`) | V-243451 · UMCI (`UsermodeCodeIntegrityPolicyEnforcementStatus`) | Notes |
|---|---|:---:|:---:|---|
| **0 — Baseline (pre-flight)** | 2026-10-23 10:27:04 | **2** ✅ PASS | **1** ❌ OPEN | OS ships with Microsoft platform `.cip` policies (Smart App Control *Evaluation*, Driver blocklist, VBS, Endpoint Security). `0 / 0` requirement waived by the user. |
| **1 — Baseline audit policy loaded** | 2026-10-23 10:49:19 | **2** ✅ PASS | **1** ❌ OPEN (audit) | `PAW-WDAC-Audit-Baseline` v`2026.10.21.1` active. KMCI was already `2` from the OS platform policies, so the README's `1 / 1` reads as `2 / 1` here. |
| **2 — Merged audit policy loaded** | 2026-10-23 11:23:22 | **2** ✅ PASS | **1** ❌ OPEN (audit) | `PAW-WDAC-Audit-Merged` v`2026.10.21.2` + supplemental `PAW-WDAC-Supp-ClaudeCode` v`2026.10.23.1`. Screening: **0** new 3076. |
| **3 — Enforced policy loaded** | 2026-10-23 11:37:30 | **2** ✅ PASS | **2** ✅ **PASS** | `PAW-WDAC-Enforced` v`2026.10.21.3`. **V-243451 closed.** 0 × 3077 in the first minutes. |
| **4 — After post-enforcement reboot** | 2026-10-23 11:42:35 | **2** ✅ PASS | **2** ✅ **PASS** | Booted 11:41:31 under enforcement; 0 × 3077; all approved apps re-tested OK. |

## Application Scope

| Application | Decision | Binary / location | Signer (Authenticode) |
|---|---|---|---|
| PowerShell 7 | **Allow** | `C:\Program Files\PowerShell\7\pwsh.exe` | Microsoft Corporation |
| VS Code | **Allow** | `C:\Program Files\Microsoft VS Code\Code.exe` | Microsoft Corporation |
| Claude Code (VS Code extension) | **Allow** | `C:\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-2.1.309-win32-x64\resources\native-binary\claude.exe` | Anthropic |
| Azure CLI | **Allow** | `C:\Program Files\Microsoft SDKs\Azure\CLI2\` (139 PE files; sample of 60 → 14 signed / 46 unsigned; `python.exe` signed by Python Software Foundation) | mixed |
| WinDirStat | **Allow** | `C:\Program Files\WinDirStat\WinDirStat.exe` | Open Source Developer Bryan Berns |
| WSL — Ubuntu 26.04 | **Allow** | `C:\WINDOWS\system32\wsl.exe` (WSL 3.0.3.0) + distro `Ubuntu` (OsVersion 26.04, WSL 2) | Microsoft Windows |
| **Firefox** | **BLOCK — omit from policy, do NOT uninstall** (demo of application control) | `C:\Program Files\Mozilla Firefox\firefox.exe` | Mozilla Corporation |

## Decisions Agreed Before Starting

| Topic | Decision |
|---|---|
| `0 / 0` baseline | Waived — start from the OS's native `2 / 1`. |
| Wizard GUI steps (Step 1, 4.2, 6) | **User drives the App Control Policy Wizard**; agent stops with exact settings and validates the saved XML afterwards. |
| Reboots (Step 3, Step 5 screen, Step 8.3) | **Agent runs `Restart-Computer` after asking for confirmation each time**; user re-opens VS Code and says "continue"; agent resumes from this log. |
| Claude Code | **Allowed** (captured during the audit like the other apps). |
| WSL | **Install Ubuntu (26.04) before the audit** so install noise is outside the audit window. |
| Firefox exclusion | Never launched; every Mozilla-signed file is left out of the event rules; `$ExcludedAppPattern = 'Mozilla\|Firefox'` gate set in the working copies of scripts 4 and 6. |
| Final report | HTML report written to `C:\WDAC\results\` at the end, alongside this log. |

## Deviations From the README (and why)

| # | Deviation | Reason |
|---|---|---|
| D1 | Baseline is `2 / 1`, not `0 / 0` | Windows 11 build 28000 ships with active Microsoft platform `.cip` policies (Smart App Control in *Evaluation* mode = audit-mode UMCI → UMCI `1`; `Microsoft Windows Driver Policy` enforced → KMCI `2`). Approved by user. |
| D2 | Scripts run from `C:\WDAC-Scripts\` (copy of `C:\WDAC\config\scripts\`) | README's documented run location; lets the Firefox gate be set without touching the originals. |
| D3 | `$ExcludedAppPattern = 'Mozilla\|Firefox'` in `C:\WDAC-Scripts\4_…ps1` and `C:\WDAC-Scripts\6_enforce_policy.ps1` (originals: `''`) | README's own optional gate; scripts 4 and 6 stop before compiling if any Mozilla/Firefox rule reaches the policy. |
| D4 | CodeIntegrity/Operational log max size raised **1 MB → 100 MB** | The log was full at 1 MB (180 records, circular). az CLI alone has ~100 unsigned files; `3076` + `3089` pairs would overwrite each other before the Step 4.1 export. |
| D5 | Agent runs on the PAW itself (no PowerShell Direct session from the host) | Claude Code is executing inside VS Code on `WIN11-PAW-WDAC`; Step 0.2 is not applicable. |
| D6 | **No Hyper-V checkpoint** (Step 0.1 skipped) | User's decision. Rollback relies on README §11 Option A (fix-forward to audit) or Option B (`CiTool.exe --remove-policy`). |
| D7 | **6 WSL deny rules removed** from the Recommended User Mode Block Rules in `Base-Audit.xml` (`ID_DENY_BASH`, `ID_DENY_LXRUN`, `ID_DENY_LXSS`, `ID_DENY_WSL`, `ID_DENY_WSLCONFIG`, `ID_DENY_WSLHOST`) | Deny beats allow; without removal WSL/Ubuntu would be blocked after enforcement. User approved the trade-off (Linux code inside WSL is outside App Control's reach). |
| D8 | **`Enabled:Managed Installer` (Option 13) kept ON** — README says OFF | **The production environment uses MECM (Microsoft Configuration Manager) as its software-distribution system, so Option 13 is required.** With Option 13 ON, App Control trusts files written by a designated *managed installer*: when MECM (or Intune) is configured as one via an AppLocker `ManagedInstaller` rule collection (for MECM, the CCM client `CcmExec.exe` / `CCMSetup.exe`; for Intune, the Intune Management Extension `Microsoft.Management.Services.IntuneWindowsAgent.exe`), every file it installs is tagged with an origin-claim extended attribute and is allowed to run without a per-app rule. That lets MECM-deployed software keep working under the enforced policy without re-running the audit → merge cycle for each package. On this lab PAW the MECM client is not visible yet: no AppLocker `ManagedInstaller` collection is configured (checked 10:42) and `AppIDSvc` is Running/Manual, so the option is present but inert until the managed-installer AppLocker policy is deployed (normally via MECM's *Windows Defender Application Control* / managed-installer setting or a GPO). Scripts 4 and 6 (both editions) now **keep** Option 13 (moved from the OFF list to the ON list), so the merge doesn't strip it and script 6's "only Audit Mode turned off" gate stays valid. |
| D9 | **Source scripts changed** in `C:\WDAC\config\scripts\` (PS7) and `C:\WDAC\config\scripts\pwsh_5.1\` (Windows PowerShell 5.1): scripts 4 and 6 | Option 13 is a standing requirement of the MECM environment (not a one-off for this run), so it was applied to the source scripts in **both editions**. Script 6's error text no longer lists *Managed Installer* among the options the guide requires OFF. The Firefox gate (D3) is demo-specific and is set **only** in the working copies under `C:\WDAC-Scripts\`. The README's Step 1 / Policy Rule Options tables still say Option 13 OFF. |

## Environment

| Item | Value |
|---|---|
| Hostname | `WIN11-PAW-WDAC` (Hyper-V Virtual Machine) |
| OS | Microsoft Windows 11 Enterprise 10.0.28000 (build 28000) |
| Account | `skynet\lorenzo` — elevated (Administrator = True) |
| Shell | PowerShell 7.6.8 (Core) |
| App Control Policy Wizard | `Microsoft.WDAC.WDACWizard` 2.8.1.0 (`C:\Program Files\WDAC`) |
| `CiTool.exe` | Present |
| Legacy `SiPolicy.p7b` | Not present (`False`) |
| Smart App Control | `VerifiedAndReputablePolicyState = 2` (Evaluation) |
| VBS | `VirtualizationBasedSecurityStatus = 2` (running), `SecurityServicesRunning = {1}` |
| Vulnerable driver blocklist | `VulnerableDriverBlocklistEnable = 1` |
| Default browser | Microsoft Edge (`MSEdgeHTM`) — links will not open Firefox |
| Firefox background components | Service `MozillaMaintenance` (Stopped/Manual); scheduled tasks `\Mozilla\Firefox Background Update …` ×2 (next runs 14:59 and 16:06 today) and `\Mozilla\Firefox Default Browser Agent …` (next run 22:05). These can log `3076` without Firefox being launched — they must **not** be converted into allow rules. |

---

## Step Log

Status legend: ✅ done · ⚠️ done with a deviation/notice · ⏸ waiting on user · ⏳ pending · ❌ failed

### Step 0.1 — Hyper-V checkpoint (host `RYZEN-BEE`) — ⏸ waiting on user
- **Action:** `Checkpoint-VM -Name 'WIN11-PAW-WDAC' -SnapshotName 'Pre-WDAC-Manual-Walkthrough'` must be run on the Hyper-V host. The agent runs inside the guest and cannot do this.
- **Status:** Requested from the user before any policy is loaded.

### Step 0.2 — Persistent PowerShell Direct session — ⚠️ not applicable
- Agent runs locally on the PAW (see D5).

### Prep — Recon (read-only) — ✅ 2026-10-23 ~10:20
- Confirmed host, elevation, OS build, `Win32_DeviceGuard` values (`2 / 1`), CiTool policy inventory, active `.cip` files, Smart App Control state, installed apps and signers, Firefox services/tasks, CI log size, Wizard install. Details are captured in the tables above.

### Prep — Working copy of scripts — ✅ 2026-10-23 10:26:45
- **Action:** `Copy-Item C:\WDAC\config\scripts → C:\WDAC-Scripts` (11 files).
- **Action:** Edited `$ExcludedAppPattern` from `''` to `'Mozilla|Firefox'` in `C:\WDAC-Scripts\4_merge_audit_base_and_events_policies.ps1` (line 11) and `C:\WDAC-Scripts\6_enforce_policy.ps1` (line 6). No other edits.
- Original script SHA-256 (first 16 hex) at copy time:

| Script | SHA-256 (prefix) |
|---|---|
| `0_pre-flight.ps1` | `1079D0143AD0CC44` |
| `1_compile_and_deploy.ps1` | `3A74D7A7172DF69A` |
| `2_audit_policy_activation.ps1` | `EFFB8D7A63C6F0FF` |
| `3_1_validate_winevent_rules.ps1` | `F8A5BFE65DBC9D94` |
| `3_capture_ciaudit_events.ps1` | `0B868DE5BE291C51` |
| `4_merge_audit_base_and_events_policies.ps1` | `7519491B66CC6AF8` (before D3 edit) |
| `5_audit_merged_events.ps1` | `AE853EF29FD420C9` |
| `6_enforce_policy.ps1` | `121A2ADEB1A5D812` (before D3 edit) |
| `7_DISA_STIG_CHECK.ps1` | `084D2EBB4B84BBFB` |
| `8_validate_multipolicy_layout.ps1` | `04CF7C6059644892` |
| `Get-Blocked_CI_Events.ps1` | `277D122CE20B278D` |

### Step 0.3 – 0.4 — `0_pre-flight.ps1` — ✅ 2026-10-23 10:27:04
- **Command:** `& 'C:\WDAC-Scripts\0_pre-flight.ps1'`
- **Results:**
  - Admin check: passed.
  - Created `C:\WDAC\Source`, `C:\WDAC\Compiled`, `C:\WDAC\Events`, `C:\WDAC\Logs`.
  - Transcript: `C:\WDAC\Logs\WDAC-Manual-Run-20261023-102705.log`.
  - `ConfigCI` loaded via `-UseWindowsPowerShell` (16 cmdlets incl. `New-CIPolicy`, `Merge-CIPolicy`, `ConvertFrom-CIPolicy`, `Set-RuleOption`, `Set-CIPolicyIdInfo`, `Set-CIPolicyVersion`).
  - `CiTool.exe` present.
  - **STIG:** `CodeIntegrityPolicyEnforcementStatus = 2`, `UsermodeCodeIntegrityPolicyEnforcementStatus = 1`.
  - `SiPolicy.p7b` present: `False`.
  - CiTool inventory — **only Microsoft system policies** (`IsSystemPolicy = True`):

| PolicyID | FriendlyName | IsEnforced | IsAuthorized |
|---|---|:---:|:---:|
| `1283ac0f-…-8a933130cad6` | VerifiedAndReputableDesktopEvaluation | True | True |
| `2678656c-…-ebd8c991502d` | VerifiedAndReputableDesktopEvaluationFlightSupplemental | True | True |
| `784c4414-…-f0fb42a51d0d` | Microsoft Windows Cross Certificates for Code Integrity Exceptions Audit Policy | True | True |
| `d2bda982-…-0b44427b6816` | Microsoft Windows Driver Policy | True | True |
| `a072029f-…-7df687` | Microsoft Windows Virtualization Based Security Policy | True | True |
| `60fd87f8-…-0da022f248` | Microsoft Windows Endpoint Security Policy | True | True |
| 8 others | VerifiedAndReputableDesktop, WindowsE_Lockdown_*, Windows10S_Lockdown_*, *TestSupplemental, *FlightSupplemental | False | False |

### Step 0.4 (record) — `7_DISA_STIG_CHECK.ps1` — ✅ 2026-10-23 10:27:04
```text
V-243450 (CodeIntegrityPolicyEnforcementStatus)         : 2 [PASS - NOT A FINDING]
V-243451 (UsermodeCodeIntegrityPolicyEnforcementStatus) : 1 [OPEN FINDING]
```

### Prep — Enlarge CodeIntegrity/Operational log (D4) — ✅ 2026-10-23 10:27:13
- **Command:** `wevtutil.exe sl Microsoft-Windows-CodeIntegrity/Operational /ms:104857600` → exit code `0`.
- **Before:** `MaximumSizeInBytes = 1052672`, `FileSize = 1052672`, `RecordCount = 180`, `LogMode = Circular`.
- **After:** `MaximumSizeInBytes = 104857600` (100 MB), `LogMode = Circular`.

### Step 0.4 — Install everything before audit: WSL Ubuntu 26.04 — ✅ 2026-10-23 10:27:18 → 10:29:48 · ⏸ first launch pending
- **Command:** `wsl.exe --install -d Ubuntu --no-launch` → `Distribution successfully installed`, exit code `0`.
- `wsl -l -v`: `* Ubuntu  Stopped  2`.
- Registry metadata: `DistributionName = Ubuntu`, `Flavor = ubuntu`, **`OsVersion = 26.04`**, `Version = 2`, `RunOOBE = 1`.
- WSL: 3.0.3.0 · Kernel 6.18.54.1-1 · WSLg 1.0.79.
- **Pending:** First launch (`wsl -d Ubuntu`) to create the Linux user. This is interactive, so the user does it **before** the audit policy is loaded, keeping the one-time setup noise out of the audit window.
- Other approved apps were already installed (PowerShell 7, VS Code + Claude Code, az CLI, WinDirStat). Firefox remains installed and has **not** been launched.

### Step 1 — App Control Policy Wizard: create `C:\WDAC\Source\Base-Audit.xml` — ✅ saved by user 10:36:31 · ⚠️ 2 findings
- **Performed by:** user, App Control Policy Wizard 2.8.1.0 (Policy Creator → Base Policy → Multiple Policy Format → Allow Microsoft; both recommended block-rule boxes checked).
- **Output:** `C:\WDAC\Source\Base-Audit.xml` (655,174 bytes, SHA-256 `1CC20C9C0D6CDD4001ACCE04FD6EDADE0C661001352464D75F5A93787841122A`) and a Wizard-compiled `C:\WDAC\Source\{75AFC1CF-5372-491A-80CA-7BBB694F0A00}.cip` (312,888 bytes, SHA-256 `F548B42EF40889BAF3A27CD4ABBE1899C64998D223782B9C966DD0C787D72965` — not used; README compiles its own into `C:\WDAC\Compiled\`).
- **Agent validation (2026-10-23 10:37):**

| Check | Result |
|---|---|
| `PolicyType` | `Base Policy` ✅ |
| `PolicyID` / `BasePolicyID` | `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}` / same ✅ (Multiple-Policy Format) |
| Name / Id / VersionEx (pre-stamp) | `PAW-WDAC-Audit-Baseline` / `2026-10-23` / `10.0.5.0` |
| Signers / File rules | 223 signers · 2,509 file rules (2,363 Deny, 1 Allow, 146 FileAttrib) — both recommended block lists merged ✅ |
| Signing scenarios | `131` Kernel Mode · `12` User Mode ✅ |
| Required options present | All 9 ✅ (`Audit Mode`, `UMCI`, `Allow Supplemental Policies`, `Boot Audit On Failure`, `Disabled:Script Enforcement`, `Update Policy No Reboot`, `Unsigned System Integrity Policy`, `Advanced Boot Options Menu`, `Required:WHQL`) |
| Template extra | `Enabled:Inherit Default Policy` (no effect) |
| Forbidden options present | ⚠️ **`Enabled:Managed Installer` (Option 13)** — README requires OFF |
| `Mozilla\|Firefox` text in XML | `0` matches ✅ (the exclusion gate will not false-positive on the base policy) |

- **Finding F1 — Managed Installer ON:** README Step 1 table requires it OFF. (Script 4 would delete Option 13 at merge time, but the baseline audit policy would carry it until then.)
- **Finding F2 — Recommended User Mode Block Rules deny WSL.** Six deny rules in the User Mode scenario (`12`) cover **every** version (`0.0.0.0`–`65355.65355.65355.65355`):

| Deny rule ID | FileName |
|---|---|
| `ID_DENY_BASH` | `bash.exe` |
| `ID_DENY_LXRUN` | `lxrun.exe` |
| `ID_DENY_LXSS` | `LxssManager.dll` |
| `ID_DENY_WSL` | `wsl.exe` |
| `ID_DENY_WSLCONFIG` | `wslconfig.exe` |
| `ID_DENY_WSLHOST` | `wslhost.exe` |

  In App Control an explicit **deny always wins over an allow**, so with these rules in place WSL (`C:\Program Files\WSL\wsl.exe` / `wslhost.exe` 3.0.3.0) would be **blocked after enforcement** regardless of any event-derived allow rules. In Audit Mode they only log `3076`. Microsoft blocks WSL on locked-down devices because Linux binaries inside WSL are not governed by App Control. Allowing WSL on a PAW is a deliberate trade-off.
- **Ubuntu first launch:** at 10:37 `DefaultUid = 0`, `RunOOBE = 1`, `getent passwd 1000` → no entry. The Linux user has **not** been created yet. `/etc/os-release` → `PRETTY_NAME="Ubuntu 26.04.1 LTS"`.
- **User decisions (10:41):** F2 → remove all 6 WSL denies · F1 → initially "fix with `Set-RuleOption`", then **reversed by the user: Managed Installer must stay ON** · Ubuntu → user completes first launch now · Checkpoint → proceed without one (D6).

### Step 1 (fix-up) — Agent edits to `Base-Audit.xml` — ✅ 2026-10-23 10:42:06 – 10:42:50
- **Backup:** `C:\WDAC\Source\Base-Audit.wizard-original-20261023-104208.xml` (SHA-256 `1CC20C9C…41122A`, identical to the Wizard output).
- **Commands (ConfigCI via `-UseWindowsPowerShell`):**
  1. `Set-RuleOption -FilePath Base-Audit.xml -Option 13 -Delete` (10:42:06) → later **reverted** with `Set-RuleOption -FilePath Base-Audit.xml -Option 13` (10:42:50) per the user's request (D8). Net effect on Option 13: **none, ON as the Wizard saved it**.
  2. `Remove-CIPolicyRule -FilePath Base-Audit.xml -Id <id>` for `ID_DENY_BASH`, `ID_DENY_LXRUN`, `ID_DENY_LXSS`, `ID_DENY_WSL`, `ID_DENY_WSLCONFIG`, `ID_DENY_WSLHOST` (D7).
- **Verification:** each removed ID → `rule=0 refs=0`; deny rules `2,363 → 2,357`; dangling `FileRuleRef` = `0`; PolicyID = BasePolicyID unchanged `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}`; test compile with `ConvertFrom-CIPolicy` to the scratchpad → **OK** (312,224 bytes, not deployed).
- **Options now (11):** `Disabled:Script Enforcement`, `Enabled:Advanced Boot Options Menu`, `Enabled:Allow Supplemental Policies`, `Enabled:Audit Mode`, `Enabled:Boot Audit On Failure`, `Enabled:Inherit Default Policy`, `Enabled:Managed Installer`, `Enabled:UMCI`, `Enabled:Unsigned System Integrity Policy`, `Enabled:Update Policy No Reboot`, `Required:WHQL`.
- **Resulting file:** SHA-256 `1DF5458A210B2FE47CD2F7C422FE5C57218B926B2FE18B15EB419F6EA9FF6569` (pre-stamp).
- **AppLocker check:** effective AppLocker policy has **no** `ManagedInstaller` collection; `AppIDSvc` = Running / Manual.

### Prep — Script working copies updated for Managed Installer (D8) — ✅ 2026-10-23 10:43
- `C:\WDAC-Scripts\4_merge_audit_base_and_events_policies.ps1`: ON list `0,2,3,6,9,10,11,16,17` → **`0,2,3,6,9,10,11,13,16,17`**; OFF list `13,14,15,18,19,20` → **`14,15,18,19,20`**.
- `C:\WDAC-Scripts\6_enforce_policy.ps1`: ON list `0,2,6,9,10,11,16,17` → **`0,2,6,9,10,11,13,16,17`**; OFF list `3,13,14,15,18,19,20` → **`3,14,15,18,19,20`**.

### Prep — Option 13 applied to the source scripts, both editions (D9) — ✅ 2026-10-23 10:46 – 10:48
- **Discovery:** `C:\WDAC\config\scripts\pwsh_5.1\` (11 Windows PowerShell 5.1 scripts) was not present in the agent's first scan and so was not in the 10:26 working copy.
- **Original SHA-256 (prefix) of the 5.1 scripts before editing:** `0_pre-flight` `8394AEBAB2281C8E` · `1_compile_and_deploy` `C48A798FE09AC8FB` · `2_audit_policy_activation` `758AD40E62E5DF33` · `3_1_validate_winevent_rules` `877DE65DFF2F1BE5` · `3_capture_ciaudit_events` `2E71F6974078F488` · `4_merge_audit_base_and_events_policies` `D35BAB4D5257FA58` · `5_audit_merged_events` `D8EDCF8F82E9DD21` · `6_enforce_policy` `3DA7047F32D55F31` · `7_DISA_STIG_CHECK` `37C6C722F940FA84` · `8_validate_multipolicy_layout` `BBFF4544000857EA` · `Get-Blocked_CI_Events` `F254D468FEBAE3F6`.
- **Edits (identical in PS7 and 5.1 sources):**

| File | Change |
|---|---|
| `4_merge_audit_base_and_events_policies.ps1` | ON list → `0, 2, 3, 6, 9, 10, 11, 13, 16, 17` (comment: *13 = Enabled:Managed Installer (MECM / Intune is the managed installer in this environment)*); OFF list → `14, 15, 18, 19, 20` |
| `6_enforce_policy.ps1` | ON list → `0, 2, 6, 9, 10, 11, 13, 16, 17`; OFF list → `3, 14, 15, 18, 19, 20`; error text: removed "Managed Installer" from the list of options the guide requires OFF |

- **Working copies rebuilt:** `Copy-Item C:\WDAC\config\scripts\* → C:\WDAC-Scripts -Recurse -Force` (now includes `C:\WDAC-Scripts\pwsh_5.1\`), then `$ExcludedAppPattern = 'Mozilla|Firefox'` re-applied to scripts 4 and 6 in **both** editions.
- **Verification (10:48:16):**
  - Parser: 0 errors in all 8 edited files under PowerShell 7; 0 errors in the four 5.1 files under `powershell.exe` (Windows PowerShell 5.1).
  - Working copy vs source: exactly **one** differing line per edited file (`$ExcludedAppPattern`); every unedited script is byte-identical.
  - New SHA-256 (prefix): source PS7 4 `ACF770FCB3C44759`, 6 `97D1F9814C0D6579` · source 5.1 4 `265FA3E6A5F0C06E`, 6 `C3B823EEE2B3D947` · working PS7 4 `7AAFEAF402AA6AC2`, 6 `A8C6FA2F1FC545CE` · working 5.1 4 `C6FD4C3726B98A49`, 6 `C7559768D76F37BB`.

### Step 0.4 (cont.) — Ubuntu 26.04 first launch — ✅ completed by user, verified 10:48
- Linux user **`lorenzo`** created by the user: `lorenzo:x:1000:1000::/home/lorenzo:/bin/bash`.
- Registry: `DefaultUid = 1000`, `RunOOBE = 0`, `OsVersion = 26.04`. `wsl -l -v`: `* Ubuntu Running 2`.

### Step 2 — `1_compile_and_deploy.ps1` (stamp, compile, deploy baseline audit policy) — ✅ 2026-10-23 10:49:08 – 10:49:19
- **Command:** `& 'C:\WDAC-Scripts\1_compile_and_deploy.ps1'` · transcript `C:\WDAC\Logs\Agent-Transcript-Step2-20261023-104908.log`
- **Stamped:** `PolicyName = PAW-WDAC-Audit-Baseline`, `PolicyId = PAW-AUDIT-BASE-v1`, `VersionEx = 2026.10.21.1` (no `-ResetPolicyID`).
- **Verified in XML:** `PolicyType = Base Policy`; `PolicyID = BasePolicyID = {75AFC1CF-5372-491A-80CA-7BBB694F0A00}`; RuleOptions: `Unsigned System Integrity Policy, Advanced Boot Options Menu, UMCI, Inherit Default Policy, Update Policy No Reboot, Allow Supplemental Policies, Audit Mode, Required:WHQL, Boot Audit On Failure, Disabled:Script Enforcement, Managed Installer`.
- `C:\WDAC\Source\PolicyGuid.txt` → `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}`.
- **Compiled:** `C:\WDAC\Compiled\{75AFC1CF-5372-491A-80CA-7BBB694F0A00}.cip` (312,240 bytes) + archive `PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip` — SHA-256 `6581BF7C513BF3DD432CB861ECECE47E02D9C9D05484BFACE496A4D967815AB6`.
- `Base-Audit.xml` after stamping: SHA-256 `C7FABAC7D0CC1988FAAD6929A52BCFFB555426449C1801C3BD78B37FFD4C073D`.
- **Deploy:** `CiTool.exe --update-policy … -json` → `{"OperationResult":0}`, exit code `0`. No reboot needed.
- **Audit window start:** `C:\WDAC\Events\AuditRoundStart.txt` = **`2026-10-23T10:49:19.0983537+02:00`** (no earlier file existed).

### Step 2 (verify) — `2_audit_policy_activation.ps1` + `7_DISA_STIG_CHECK.ps1` — ✅ 2026-10-23 10:49:20
- **STIG:** `CodeIntegrityPolicyEnforcementStatus = 2` · `UsermodeCodeIntegrityPolicyEnforcementStatus = 1` → V-243450 **PASS**, V-243451 **OPEN** (audit mode, as expected at this stage).
- **CiTool (non-system):** `PolicyID 75afc1cf-5372-491a-80ca-7bbb694f0a00` · `BasePolicyID` same · `FriendlyName PAW-WDAC-Audit-Baseline` · `VersionString 2026.10.21.1` · `IsEnforced True` (= active) · `IsAuthorized True`.
- **Event 3099:** script 2's 10-minute query printed nothing (it ran within ~1 s of the load; the event was most likely not yet flushed). A follow-up query found it: `10:49:19 — 3099 — Refreshed and activated Code Integrity policy {75afc1cf-5372-491a-80ca-7bbb694f0a00} PAW-WDAC-Audit-Baseline. id PAW-AUDIT-BASE-v1. Status 0x0`, together with `3102 — Code Integrity policy refresh finished for 7 policies` and `3096 — No change` for the 4 Microsoft platform policies (Driver, Endpoint Security, VBS, SAC Evaluation Flight Supplemental). ✅
- Smart App Control still `VerifiedAndReputablePolicyState = 2` (Evaluation).
- `3076` events since the window started: **0** at 10:50 (processes that were already running are not re-evaluated; new ones will be).

### Request — README restructure (D10) — ⏳ queued 2026-10-23 10:52, to be done after the Step 3 reboot
- **User request:**
  - Update `C:\WDAC\config\README.md` so the Option 13 (Managed Installer) change is unmistakable, and mention **Intune** and **MECM**.
  - Restructure the README for better flow and structure.
  - Keep emojis only where they communicate status; use GitHub callouts (`[!TIP]`, `[!NOTE]`, `[!IMPORTANT]`, `[!WARNING]`, `[!CAUTION]`) for the important points.
- **Planned scope:** every place Option 13 appears (Step 1 Wizard table, the Policy Rule Options tables, the embedded code for scripts 4 and 6, script 6's example output), plus this run's lessons learned as callouts.

### Step 3 — Reboot, then run every approved application — 🔄 reboot issued
- D10 acknowledged by the agent. The user then said **"go and reboot"**, so the agent ran `Restart-Computer` as originally agreed.
- Audit window (`AuditRoundStart.txt`) = `2026-10-23T10:49:19.0983537+02:00`; it survives the reboot.
- **After sign-in (pending):** user opens VS Code / Claude Code → agent exercises the CLI apps (pwsh, az, code, wsl/Ubuntu) → user exercises WinDirStat and an Ubuntu terminal → wait for background activity → Step 4.1 export. 🚫 Firefox is not launched.
- **Reboot command issued:** 2026-10-23T10:52:12.2229662+02:00 — `Restart-Computer`
- **Back online:** `LastBootUpTime = 2026-10-23T10:52:25`. Post-boot check 10:53:25: elevated `skynet\lorenzo`; STIG `2 / 1`; `PAW-WDAC-Audit-Baseline` v`2026.10.21.1` active and authorized; Firefox processes `0`.

### Step 3 (cont.) — Exercise the approved applications under the audit policy — ✅ 2026-10-23 10:53 – 10:55
| App | Who | What was run | Result |
|---|---|---|---|
| VS Code + Claude Code | user + agent | VS Code reopened after reboot; Claude Code session resumed; agent tools (PowerShell, Grep/Read/Edit) used | ✅ running |
| PowerShell 7 | agent | `pwsh -NoProfile -Command …` → `7.6.8`, `LanguageMode = FullLanguage`, 78 modules listed | ✅ |
| VS Code CLI | agent | `code --version` → `1.143.1` (`e646868…`, x64); `code --list-extensions --show-versions` → `anthropic.claude-code@2.1.309`, `ms-vscode.powershell@2025.4.0` | ✅ |
| Azure CLI | agent + user | `az --version` → `azure-cli 2.91.0`, Python 3.14.7, *"Your CLI is up-to-date"* (update check); `az version`, `az extension list`, `az config get`, `az vm/storage account/network vnet --help`, `az account list` (*"Please run az login"*); `az bicep version` → *Bicep CLI not found* (not installed, intentionally left uninstalled). The user ran additional az commands. | ✅ |
| WSL front-end | agent | `wsl --version` (WSL 3.0.3.0, kernel 6.18.54.1-1), `wsl --status`, `wsl -l -v` | ✅ |
| Ubuntu 26.04 | agent + user | as `lorenzo`: `whoami/id/uname -a`, `/etc/os-release` → *Ubuntu 26.04.1 LTS*, `df`, `python3 --version` → 3.14.4, `/mnt/c` access, interop `cmd.exe /c ver` → *Microsoft Windows [Version 10.0.28000.3231]*, `whoami.exe` → `skynet\lorenzo`; as root: `apt-get -s upgrade` → *0 upgraded*, `dpkg -l` → 549 lines, `systemctl is-system-running` → `running`. The user also used Ubuntu interactively as `lorenzo`. | ✅ |
| WinDirStat | user | Launched and used by the user | ✅ |
| **Firefox** | — | **Not launched** | 🚫 by design |

- **Audit capture at 10:55:06** (since `AuditRoundStart` 10:49:19): **31 × `3076`** and **31 × `3089`**, all attributed to `PAW-WDAC-Audit-Baseline`:

| Source | `3076` events |
|---|---:|
| az CLI (`C:\Program Files\Microsoft SDKs\Azure\CLI2\…`) | 27 (27 unique files) |
| Claude Code (`claude.exe` ×2, `audio-capture.node` ×1) | 3 |
| WinDirStat (`WinDirStat.exe`) | 1 |
| WSL / Ubuntu, VS Code, PowerShell 7 | **0**. All Microsoft-signed and covered by the Allow Microsoft template. `wsl.exe`/`wslhost.exe` produced no `3076`, which confirms that removing the 6 WSL deny rules (D7) worked. |
| **Mozilla / Firefox** (file or parent process) | **0** ✅ |

- CI log: 284 records (growing toward the new 100 MB cap).
- **Observation:** az CLI only loads the native modules a given command needs, so the 27 captured files cover the commands that were run. Other az commands (for example `az login`, which loads MSAL/cryptography extensions) may need more files. Option: allow the admin-protected `CLI2` folder with a `FilePath` rule via `$AdditionalFolderRules` in script 4 (README Step 5). Decision pending with the user.

### Step 4.1 — `3_capture_ciaudit_events.ps1` (preview + time-boxed export) — ✅ 2026-10-23 10:56:06
- **Command:** `& 'C:\WDAC-Scripts\3_capture_ciaudit_events.ps1'` · transcript `C:\WDAC\Logs\Agent-Transcript-Step4.1-20261023-105606.log`
- **Window:** `AuditRoundStart = 2026-10-23T10:49:19.0983537+02:00` → export at 10:56:07 (about 4 min after boot; no new `3076` after 10:54:24, so background activity had settled).
- **Export:** `wevtutil epl … "/q:*[System[(EventID=3076 or EventID=3089) and TimeCreated[@SystemTime>='…']]]"` → exit `0` → `C:\WDAC\Events\PAW-Audit-3076.evtx` (1,118,208 bytes, SHA-256 `F1E943107E3A7BBAB97868B66AB7BD23ABFA011055C28AEF8F17D9AB16CE2A0F`).
- **Contents (read back from the .evtx):** **31 × `3076`** + **31 × `3089`** (1:1 via ActivityId). All `Status = 0xC0E90002` (*would have been blocked by policy*), all `PolicyName = PAW-WDAC-Audit-Baseline` / `PolicyID = PAW-AUDIT-BASE-v1` / `PolicyHash = 6581BF7C…5AB6`, all user-mode (`SI Signing Scenario = 1`). Time range **10:50:09.212 → 10:54:24.779**. Cross-check against the live log: 31 ✅.
- **Full evidence (all fields: hashes, signer, issuer, cert validity, signing levels, policy hash, ActivityId):** `C:\WDAC\results\evidence\Round1-Audit-3076-Events.csv` (SHA-256 `1A1F26856AE49C5CC2A30BBE51BDE1F35B8EA35416F2A6136865A327755E4818`). Extractor: `Export-CIEventEvidence.ps1` (agent scratchpad), which joins each `3076` to its `3089` signature record(s).

**Signer summary**

| App | Signer (publisher → issuing CA) | Files |
|---|---|---:|
| Azure CLI | Python Software Foundation → Microsoft ID Verified CS EOC CA 04 | 20 |
| Azure CLI | Python Software Foundation → Microsoft ID Verified CS AOC CA 03 | 2 |
| Azure CLI | Python Software Foundation → DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 | 1 |
| Azure CLI | **unsigned** (`charset_normalizer\cd/md.cp314-win_amd64.pyd`, `psutil\_psutil_windows.pyd`, `yaml\_yaml.cp314-win_amd64.pyd`) | 4 |
| Claude Code | Anthropic, PBC → DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 (`claude.exe`, 2 loads) | 2 |
| Claude Code | **unsigned** (`resources\audio-capture\x64-win32\audio-capture.node`) | 1 |
| WinDirStat | Open Source Developer Bryan Berns → Certum Code Signing 2021 CA | 1 |
| Mozilla / Firefox | — | **0** ✅ |

**Every `3076` event in the audit window (round 1)**

| # | Time | Record | App | File | Process | Signer (3089) | Validated level | SHA-256 (Authenticode) | User-writeable |
|---:|---|---:|---|---|---|---|---|---|:---:|
| 1 | 2026-10-23 10:50:09.212 | 209 | Claude Code | `C:\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-2.1.309-win32-x64\resources\native-binary\claude.exe` | `claude.exe` | Anthropic, PBC — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | 2 (Enterprise) | `0367971DF5F6C8C3F0BF29F3CA0CD1D727DA66FD74C0A414DC4FE41303F3306C` | false |
| 2 | 2026-10-23 10:53:08.060 | 225 | Claude Code | `C:\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-2.1.309-win32-x64\resources\native-binary\claude.exe` | `Code.exe` | Anthropic, PBC — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | 2 (Enterprise) | `0367971DF5F6C8C3F0BF29F3CA0CD1D727DA66FD74C0A414DC4FE41303F3306C` | false |
| 3 | 2026-10-23 10:53:08.162 | 227 | Claude Code | `C:\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-2.1.309-win32-x64\resources\audio-capture\x64-win32\audio-capture.node` | `Code.exe` | *unsigned* | 2 (Enterprise) | `59171207CA736823FC8506CC5DF7A5BC8874225D9D8D2345CF4726733D04A879` | false |
| 4 | 2026-10-23 10:53:39.507 | 229 | WinDirStat | `C:\Program Files\WinDirStat\WinDirStat.exe` | `explorer.exe` | Open Source Developer Bryan Berns — *Certum Code Signing 2021 CA* | 2 (Enterprise) | `86A16339AD119A33DF06F9E49312DA4797B31923D3E1196FA184CFAF35DDA5E8` | false |
| 5 | 2026-10-23 10:53:48.034 | 231 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe` | `cmd.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `14E54B276C598A946BCF6D89C96EDC6607A213DA7737AA16C43CEBA269E25CC5` | false |
| 6 | 2026-10-23 10:53:48.488 | 233 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\python314.dll` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `C2C60043C97F78663F32BB84D95F066AEA768830215D57B9A7EE3B834C289860` | false |
| 7 | 2026-10-23 10:53:48.894 | 235 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\python3.dll` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `BCD7BA17B7922E9A338A16587AE59779EF2131CF725C91F36CD01979806B6195` | false |
| 8 | 2026-10-23 10:53:49.101 | 237 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_wmi.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `E0905040031061D190EBA19DC3667C27035F74AE1700784CA0046BCBFF6C85C2` | false |
| 9 | 2026-10-23 10:53:49.362 | 239 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_uuid.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `404F42A5A1DC8657BABC896DA94FB241707A2B68F51CD9408CE7CEA916D39C8B` | false |
| 10 | 2026-10-23 10:53:49.656 | 241 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_queue.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `AB641BA0199D09BA1766403C1F5037787BCCD5B02C2DC865FC843C193733B319` | false |
| 11 | 2026-10-23 10:53:50.009 | 243 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_socket.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `879F0AA86076EC2F5C89E00342FC073D7C1089CD5EF2DE6F45D271B3C12B5DDE` | false |
| 12 | 2026-10-23 10:53:50.537 | 245 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_ssl.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `76964C9662173CC6C19456C36FBF81BBFAC5338BA42D90B6D634262AAEB10AA3` | false |
| 13 | 2026-10-23 10:53:51.204 | 247 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\libcrypto-3.dll` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS AOC CA 03* | 4 (Authenticode) | `D97D4B92546A2B4DF4EB01FFCD24B6C1DFB0B298FF7E469870189601A42947A3` | false |
| 14 | 2026-10-23 10:53:58.580 | 249 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\libssl-3.dll` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS AOC CA 03* | 4 (Authenticode) | `8F7CF52A2E2DB9F0109E23BEAF8829D483EFEC555B14A5069DECA8682BE760DB` | false |
| 15 | 2026-10-23 10:53:58.920 | 251 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_zstd.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `9DCACA2C7DFBE7405284A7FD538D735E36044735E6F9141E0F80CA0E8DDFEED2` | false |
| 16 | 2026-10-23 10:53:59.155 | 253 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_hashlib.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `F317A42469AC01287FF81607E491EE3434CB5C793885CAB83B9C55E2EAC7ED8D` | false |
| 17 | 2026-10-23 10:53:59.451 | 255 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\select.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `6F999EC58B3333471C11B31646CFAAE027235E9EBD155CDD8550B3CD252C27FE` | false |
| 18 | 2026-10-23 10:54:07.537 | 257 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_bz2.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `70C984D38A1B1F3892C54C1B66D6AD5DDE97425C3DDC9339692DFA58CC5B6E1B` | false |
| 19 | 2026-10-23 10:54:08.487 | 259 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_lzma.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `674142A5AA20AFE2C325A36DE88A43789B8E5D25C549D1CEF36F4C9E70190106` | false |
| 20 | 2026-10-23 10:54:08.622 | 261 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\charset_normalizer\cd.cp314-win_amd64.pyd` | `python.exe` | *unsigned* | 2 (Enterprise) | `B27C43A82773AD3360B22B6586FB9AE8CE6EE2224708CB88951A72EAA3F74F94` | false |
| 21 | 2026-10-23 10:54:08.637 | 263 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\charset_normalizer\md.cp314-win_amd64.pyd` | `python.exe` | *unsigned* | 2 (Enterprise) | `F7375A027580987111E898636494ACF8EB66E46A8AED354144F140C08503B438` | false |
| 22 | 2026-10-23 10:54:11.634 | 265 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\unicodedata.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `30C245623859DF0B9D83B0D43DC683C8133C4919438044FF22B9EBB52691626C` | false |
| 23 | 2026-10-23 10:54:14.937 | 267 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_elementtree.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `F3662725CD2607D50D59D98957D0C2CAEB69AD1526A6616ABC87CF88B8C8B3B9` | false |
| 24 | 2026-10-23 10:54:15.429 | 269 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\pyexpat.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `93B7B3623F7CE811A6951F22724BB96373627A9A71460648271F6CF0722040DC` | false |
| 25 | 2026-10-23 10:54:17.796 | 271 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_asyncio.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `31049BD1A5D746233CFAE9DF470C3FC1DA404AB4783995B9B6937D6C6F0B514F` | false |
| 26 | 2026-10-23 10:54:18.023 | 273 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_overlapped.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `0735EF213E801769433A95F256C1A8DC598E307229024BE32229EC812082DA85` | false |
| 27 | 2026-10-23 10:54:18.303 | 275 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_decimal.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `193B7DD6CF46D6004EB582FAAC26FFE5826798A6B1E2D3DE27C90177CB0A7A94` | false |
| 28 | 2026-10-23 10:54:18.624 | 277 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\psutil\_psutil_windows.pyd` | `python.exe` | *unsigned* | 2 (Enterprise) | `0AD936B54937C401E12C8C24F27BF274D242091B421257806438F034B87085F6` | false |
| 29 | 2026-10-23 10:54:20.943 | 279 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages\yaml\_yaml.cp314-win_amd64.pyd` | `python.exe` | *unsigned* | 2 (Enterprise) | `1D35EE37137D8D3AC2B4B647BE661E7C22498E094FA9AEF116B376E3E04C2AEE` | false |
| 30 | 2026-10-23 10:54:24.735 | 281 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\_ctypes.pyd` | `python.exe` | Python Software Foundation — *Microsoft ID Verified CS EOC CA 04* | 4 (Authenticode) | `EC0CA615D31240911E0B519602F97EF693B3B6B4BA0E5327CD271DA0E006B060` | false |
| 31 | 2026-10-23 10:54:24.779 | 283 | Azure CLI | `C:\Program Files\Microsoft SDKs\Azure\CLI2\libffi-8.dll` | `python.exe` | Python Software Foundation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | 2 (Enterprise) | `28E0F1587C1F183E6476E22B70A925BFEC559C6F4B32D61392B326659DC40C67` | false |



### Decision — az CLI FilePath rule (D11) — ✅ 2026-10-23 11:00
- **User decision:** in addition to the event-derived rules, allow the admin-protected az CLI folder with a FilePath rule so every az command and future az upgrades keep working.
- **Change:** `C:\WDAC-Scripts\4_merge_audit_base_and_events_policies.ps1` and `C:\WDAC-Scripts\pwsh_5.1\4_merge_audit_base_and_events_policies.ps1`: ` = @('C:\Program Files\Microsoft SDKs\Azure\CLI2\*')` (was `@()`). Working copies only.
- **Safety check (ACL of `C:\Program Files\Microsoft SDKs\Azure\CLI2`):** TrustedInstaller / SYSTEM / Administrators = FullControl; Users and ALL APPLICATION PACKAGES = ReadAndExecute only. **0 non-admin write ACEs**, so runtime FilePath rule protection (Option 18 absent) will honor the rule. Folder holds 139 PE files (`.exe/.dll/.pyd`).

### Request — Make the run agent-free (D12) — ⏳ in progress 2026-10-23 11:00
- **User request:** enhance the scripts and README so the whole workflow can be run with **only the scripts + the App Control Policy Wizard** (no agent), later today on another machine that uses **MECM**.
- **Plan:** fold every manual check the agent did in this run into the source scripts (both editions); restructure the README (D10 scope included); then finish this run **using the enhanced scripts** so they are tested end to end.

### Step 4.2 — App Control Policy Wizard: convert `PAW-Audit-3076.evtx` → `C:\WDAC\Source\Events-Allow.xml` — ⏸ user (instructions given 11:00)
- Rule types advised: Claude Code `claude.exe` → Publisher; `audio-capture.node` → Hash; `WinDirStat.exe` → Publisher; az CLI Python-Software-Foundation-signed rows → Publisher; 4 unsigned az `.pyd` → Hash. No Mozilla/Firefox rows exist; none to be added.

### D12 — Agent-free script enhancements (source `C:\WDAC\config\scripts\`, both editions) — ✅ 2026-10-23 11:00 – 11:10
**Design rule (user requirement 10:58):** the source scripts must work on a machine **without** Firefox or az CLI. No application name is hard-coded. Run-specific values (`-ExcludedAppPattern`, `-AdditionalFolderRules`) are **parameters that default to empty**, and a FilePath folder that doesn't exist is skipped with a warning.

**Managed installer research (Microsoft Learn, 11:00):**
- MECM configures itself as the managed installer automatically **only** when one of its *built-in* App Control policies is deployed.
- For a custom, CiTool-deployed policy (this guide), either install or repair the client with `CCMSetup.exe MANAGEDINSTALLER=1` (sets ccmsetup.exe and client.msi as managed installers), or deploy an MECM built-in **audit-mode** App Control policy alongside.
- Intune: Endpoint security → App Control for Business → **Managed installer** tab → *Enable Intune Managed Extension as Managed Installer*.
- Verify with `Get-AppLockerPolicy -Effective -Xml` (a `ManagedInstaller` RuleCollection), `appidsvc` + `AppLockerFltr` RUNNING (`appidtel.exe start -mionly` if not), and `fsutil file queryEA <file>` → `$KERNEL.SMARTLOCKER.ORIGINCLAIM`.

| Script | Change |
|---|---|
| `0_pre-flight.ps1` | `param(-CILogSizeMB 100, -ExcludedAppPattern '')`. Baseline comment no longer assumes `0/0`. Reports Smart App Control state. Raises the CodeIntegrity log to ≥ `-CILogSizeMB` (never shrinks it). **Managed-installer readiness report** (MECM `CcmExec`, Intune IME, AppLocker `ManagedInstaller` collection, `AppIDSvc`, `AppLockerFltr`) with MECM/Intune guidance when not configured. Lists scheduled tasks and services matching `-ExcludedAppPattern`. |
| **`0_1_validate_base_policy.ps1`** *(new)* | Step 1.1 gate for the Wizard's `Base-Audit.xml`: Multiple Policy Format, the **10 required options (incl. 13)**, the 5 forbidden options, both recommended block lists merged, **`-AllowWSL`** removes the 6 WSL deny rules, `-ExcludedAppPattern` false-positive check, `-ReportOnly`. Backs up before any change, proves the result with `ConvertFrom-CIPolicy`, restores the backup if the compile fails, and never calls CiTool. Writes a findings CSV to `C:\WDAC\Logs`. |
| `2_audit_policy_activation.ps1` | Event 3099 query retried for ~10 s (the D-event at 10:49 had not been flushed yet); KMCI-may-stay-2 note. |
| `3_capture_ciaudit_events.ps1` | Reads the exported `.evtx` back and compares the 3076 count with the live log; points to the evidence exporter. |
| `4_merge_audit_base_and_events_policies.ps1` | `$AdditionalFolderRules` and `$ExcludedAppPattern` are now **parameters**. FilePath folders that standard users can write to are **skipped with a warning** (runtime FilePath protection would ignore them). |
| `5_audit_merged_events.ps1` | When the screening is not clean, prints the exporter command for the screening window. |
| `6_enforce_policy.ps1` | `$ExcludedAppPattern` is now a **parameter**. |
| **`Export-CIEventEvidence.ps1`** *(new, identical in both folders, ASCII-only, no ConfigCI)* | Writes every 3076/3077 event joined to its 3089 signer(s) as CSV + Markdown (time, record ID, install location, file, process, signer/issuer, cert validity, signing levels, status, SHA-256/SHA-1, policy name/ID/hash, ActivityId). Groups by install location, never by app name. |

**Tests (11:05 – 11:10, on this PAW, scratch copies where files would change):**
- Parser: **0 errors** in all 16 changed files under PowerShell 7 **and** Windows PowerShell 5.1; all `pwsh_5.1` files and the exporter are pure ASCII.
- `Export-CIEventEvidence.ps1`: PS7 (`-EvtxPath`) and 5.1 (default = live log since `AuditRoundStart.txt`) → **31 × 3076 / 31 × 3089** each; SHA-256 sets identical to each other and to `evidence\Round1-Audit-3076-Events.csv`. A linter finding (`$Event` automatic variable) was fixed.
- `0_1_validate_base_policy.ps1`:
  - PS7 `-ReportOnly` on the live `Base-Audit.xml` → all OK, PASSED, file unchanged (SHA-256 still `C7FABAC7…C073D`).
  - 5.1 on a scratch copy of the Wizard original → WARN for the 6 WSL denies ("PASSED with warnings").
  - 5.1 `-AllowWSL` on a scratch copy with Option 13 removed and Option 14 added → **8 fixes applied**, compiles, backup written; a re-check is clean.
- `0_pre-flight.ps1`:
  - PS7 with `'Mozilla|Firefox'` → lists 3 Mozilla scheduled tasks (with next run times) and the `MozillaMaintenance` service; MI report: CcmExec / IME *Not installed*, ManagedInstaller *Not configured*, AppIDSvc + AppLockerFltr *Running*.
  - 5.1 with a pattern matching nothing (simulating a machine without the block-test app) → `0 scheduled task(s), 0 service(s)`, no errors.
- FilePath ACL check: `…\Azure\CLI2` → 0 user-writable ACEs (rule added); `%LOCALAPPDATA%` → `SKYNET\lorenzo` (skipped); a missing folder → skipped with a warning.

**Working copies re-synced (11:10):** `C:\WDAC-Scripts\` (26 files) is now **byte-identical** to `C:\WDAC\config\scripts\`. The demo values from D3 and D11 are passed as parameters from now on, the same way an operator would run them:
- `4_merge…ps1 -ExcludedAppPattern 'Mozilla|Firefox' -AdditionalFolderRules 'C:\Program Files\Microsoft SDKs\Azure\CLI2\*'`
- `6_enforce_policy.ps1 -ExcludedAppPattern 'Mozilla|Firefox'`

### Step 4.2 — Wizard output — ✅ saved by user 11:12:35 · ⚠️ wrong location, copied by hand
- The Wizard saved to `C:\Users\Lorenzo.SKYNET\Documents\EventLogPolicy_2026-10-23T09-12-35.xml` (the Wizard names the file in **UTC**: 09:12:35Z = 11:12:35 local). It also listed a `{3A521741-54DA-4E1F-AF89-007AE037307D}.cip`, but that file **does not exist** on disk, so nothing needed cleaning up or quarantining. It would never be deployed anyway (Golden Rule 3).
- **Manual action (user instruction: "rename and continue", no script changes):** `Copy-Item` → **`C:\WDAC\Source\Events-Allow.xml`** (original left in Documents). SHA-256 of both: `DD96DE7D8DC0923779B50B637EFC226495569BDA5C5E014B140BE543B9D6042B`.
- **Contents:** `PolicyType = Supplemental Policy`, `PolicyID {3A521741-…}`, `BasePolicyID = {75AFC1CF-…}` (our base); options `Unsigned System Integrity Policy`, `Inherit Default Policy`; **25 signers** (25 FileAttrib FilePublisher-style rules) + **10 FilePath allow rules**, **0 deny rules**; `Mozilla|Firefox` matches **0** ✅. The merge keeps the base's type and ID (base listed first).

| Rule(s) | Type | Verdict |
|---|---|---|
| `claude.exe` → `ID_SIGNER_A_0` (Anthropic, PBC / DigiCert G4) + `ProductName="Claude Code"`, `MinimumFileVersion=2.1.309.0` | FilePublisher | ✅ valid; also covers newer Claude Code versions |
| `WinDirStat.exe` → `ID_SIGNER_A_1` (Bryan Berns / Certum) + `FileName=WinDirStat.exe ≥ 2.9.3.2253` | FilePublisher | ✅ |
| 23 az files → `ID_SIGNER_A_2…A_23` (Python Software Foundation / Microsoft ID Verified CS EOC CA 04 & AOC CA 03) | FilePublisher | ✅ |
| `libffi-8.dll` → `ID_SIGNER_A_24` + `ID_FILEATTRIB_A_24` (no FileName/ProductName, version 0.0.0.0) | FilePublisher | ❌ **invalid** (no identifying attribute) |
| az `cd/md.cp314…pyd`, `_psutil_windows.pyd`, `_yaml.cp314…pyd` (file + folder `\*`) → `ID_ALLOW_C_2…C_9` | **FilePath** under `C:\Program Files\…` | ✅ admin-only folder, honored |
| Claude Code `audio-capture.node` (file + folder `\*`) → `ID_ALLOW_C_0`, `ID_ALLOW_C_1` | **FilePath** under `%OSDRIVE%\Users\Lorenzo.SKYNET\.vscode\…` | ⚠️ **user-writable**: runtime FilePath rule protection will **not** honor these, so the file stays blocked |

### Step 4.3 (preview) — `3_1_validate_winevent_rules.ps1 -ReportOnly` — ✅ 2026-10-23 11:15:30
- Transcript `C:\WDAC\Logs\Agent-Transcript-Step4.3-ReportOnly-20261023-111530.log`; findings `C:\WDAC\Logs\Events-Allow-Sanitize-20261023-111533.csv`.
- **0 fixed, 5 removed, 0 warnings:** `ID_FILEATTRIB_A_24` (invalid), its `FileAttribRef`, `ID_SIGNER_A_24` (all its FileAttribs invalid, so it is kept out instead of widening into a whole-publisher rule), and its `AllowedSigner` / `CiSigner` references.
- `PASSED (-ReportOnly)`: the sanitized policy compiles and merges with `Base-Audit.xml`. File not modified (hash unchanged).
- `libffi-8.dll` remains covered by the CLI2 FilePath rule (D11) at merge time.

### Decision — Claude Code `audio-capture.node` (D13) — ✅ user decision 11:19
- **Problem:** the Wizard made the unsigned `audio-capture.node` a FilePath rule inside the user profile; runtime FilePath rule protection (kept ON in the base) ignores user-writable paths, so it would stay blocked.
- **User requirements:** no Hash rule (it must not break on extension updates); **folder-wide** rule; **machine-specific only. Not in the README or any script**, because the target machines will not have Claude Code.
- **Microsoft Learn (verified 11:18):** Option 18 `Disabled:Runtime FilePath Rule Protection` is a **valid supplemental option**, and Windows 11 supports **wildcards anywhere** in a FilePath rule.
- **Approach:** a separate **supplemental policy** carries Option 18 plus one wildcard FilePath rule, so the base keeps runtime protection and Option 18 stays OFF there, as the guide requires.

### Manual action — Supplemental policy `PAW-WDAC-Supp-ClaudeCode` — ✅ 2026-10-23 11:20:55 – 11:21:18
- **Built by hand** with ConfigCI under Windows PowerShell 5.1 (`powershell.exe -File <scratchpad>\Build-SuppClaudeCode.ps1`; nested 5.1 so the rule object serializes cleanly, same reason as script 4). Commands: `New-CIPolicyRule -FilePathRule '%OSDRIVE%\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-*\*'` → `New-CIPolicy -Rules … -UserPEs -MultiplePolicyFormat` → `Set-CIPolicyIdInfo -SupplementsBasePolicyID {75AFC1CF-…}` → `Set-CIPolicyIdInfo -PolicyName 'PAW-WDAC-Supp-ClaudeCode' -PolicyId 'PAW-SUPP-CLAUDE-v1'` → `Set-CIPolicyVersion 2026.10.23.1` → options pruned to **6 + 18** → `ConvertFrom-CIPolicy`.
- **Result:**

| Field | Value |
|---|---|
| File | `C:\WDAC\Source\Supp-ClaudeCode.xml` (SHA-256 `0063B7AF94FB040EDF3F8EA7C9CA0059D220805C2E1A83C534017D320E9AF73D`) |
| PolicyType / PolicyID | Supplemental Policy / **`{0585A4C6-99AE-42CB-91E9-C34AD7AFB041}`** (its own new GUID; the base GUID is untouched) |
| BasePolicyID | `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}` (PAW base) |
| Name / Id / VersionEx | `PAW-WDAC-Supp-ClaudeCode` / `PAW-SUPP-CLAUDE-v1` / `2026.10.23.1` |
| Options | `Enabled:Unsigned System Integrity Policy`, `Disabled:Runtime FilePath Rule Protection` |
| File rules | **1** — `Allow ID_ALLOW_A_1 FilePath=%OSDRIVE%\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-*\*`, referenced only in the **user-mode** scenario (12); kernel scenario empty; no signers |
| Compiled | `C:\WDAC\Compiled\{0585A4C6-99AE-42CB-91E9-C34AD7AFB041}.cip` + archive `PAW-WDAC-Supp-ClaudeCode_v2026.10.23.1.cip` (SHA-256 `B0493C0E0BE5698A272D9C9A99BF7812C26B1C3956577155386069C135D92FDD`) |
| Matches today | `anthropic.claude-code-2.1.309-win32-x64` (folder is user-writable: `SKYNET\lorenzo` FullControl, as expected) |

- **Deploy (11:21:18):** `CiTool.exe --update-policy {0585A4C6…}.cip -json` → `{"OperationResult":0}`, exit `0`. Transcript `C:\WDAC\Logs\Agent-Transcript-SuppClaudeCode-20261023-112118.log`.
- **Verify:**
  - CiTool lists `PAW-WDAC-Supp-ClaudeCode` `2026.10.23.1`, BasePolicyID = the base, `IsAuthorized True`, `IsOnDisk True`, next to `PAW-WDAC-Audit-Baseline` `2026.10.21.1`.
  - Event **3099** at 11:21:18: *"Refreshed and activated Code Integrity policy {0585a4c6-…} PAW-WDAC-Supp-ClaudeCode. id PAW-SUPP-CLAUDE-v1. Status 0x0"*.
  - `CiPolicies\Active\{0585a4c6-…}.CIP` (752 bytes). STIG unchanged `2 / 1`.
- **Notes:**
  - A supplemental follows its base's mode (audit now, enforced after Step 7) and is **not** touched by scripts 4 and 6, which only rewrite the base (same GUID).
  - The two inert user-profile FilePath rules the Wizard put in `Events-Allow.xml` (`ID_ALLOW_C_0/C_1`) were left as the Wizard wrote them. Either way, the effective exposure is limited to the Claude Code extension folder.
  - **Accepted risk:** any process running as `lorenzo` could plant a binary under `…\.vscode\extensions\anthropic.claude-code-*\` and it would be allowed.
- README check: the one lab-example mention of Claude Code in `C:\WDAC\config\README.md` §3.1 was removed; `grep -i "claude|anthropic"` over `C:\WDAC\config\` → **0 matches**.

### Step 4.3 — `3_1_validate_winevent_rules.ps1` (sanitize) — ✅ 2026-10-23 11:22:00
- Transcript `C:\WDAC\Logs\Agent-Transcript-Step4.3-20261023-112200.log`; findings `C:\WDAC\Logs\Events-Allow-Sanitize-20261023-112203.csv`.
- **0 fixed, 5 removed, 0 warnings** (the same as the preview): `ID_FILEATTRIB_A_24` + its `FileAttribRef`, `ID_SIGNER_A_24`, `AllowedSigner`/`CiSigner` refs.
- `PASSED`: sanitized file compiles and merges. Backup `C:\WDAC\Source\Events-Allow.original-20261023-112210.xml` (SHA-256 `DD96DE7D…6042B`); new `Events-Allow.xml` SHA-256 `319CA2D4819075CF4E81DD16156C1D7870768C486AF1A5C246BCFBC50550FB2A` → **24 signers, 24 FileAttrib, 10 FilePath allow rules**.

### Step 5 — `4_merge_audit_base_and_events_policies.ps1` (merge v2 + deploy) — ✅ 2026-10-23 11:22:25 – 11:23:22
- **Command:** `.\4_merge_audit_base_and_events_policies.ps1 -ExcludedAppPattern 'Mozilla|Firefox' -AdditionalFolderRules 'C:\Program Files\Microsoft SDKs\Azure\CLI2\*'` (unmodified script, parameters only) · transcript `C:\WDAC\Logs\Agent-Transcript-Step5-20261023-112225.log`.
- `Adding admin-protected FilePath rule: C:\Program Files\Microsoft SDKs\Azure\CLI2\*` → `ID_ALLOW_A_1_1`.
- **Gate:** `PolicyName PAW-WDAC-Audit-Merged` · `PolicyIdLabel PAW-AUDIT-MERGED-v2` · `PolicyID {75AFC1CF-…}` · **`MatchesBaseline True`** · `VersionEx 2026.10.21.2` · **`AuditModeOn True`** · **`SupplementalOn True`** · **`BootAuditOn True`** · **`ExcludedAppInPolicy False`**.
- **Compiled:** `C:\WDAC\Compiled\{75AFC1CF-…}.cip` + archive `PAW-WDAC-Audit-Merged_v2026.10.21.2.cip` (318,388 bytes, SHA-256 `D3C4B7AA7392CC6C5226AE63994302108E8A41AA532591B9BAFAB61A2DE5F5BA`). `Base-Audit-Merged.xml` SHA-256 `2C7BD6054BD17816FD0F6B051BDAB838B01190BE8E9A851E11CF56C0B9485F11`.
- **Deploy:** `{"OperationResult":0}`. Event 3099 at 11:23:22: *"Refreshed and activated … PAW-WDAC-Audit-Merged. id PAW-AUDIT-MERGED-v2. Status 0x0"*.
- **STIG:** `2 / 1` (audit). CiTool: `PAW-WDAC-Audit-Merged` `2026.10.21.2` + `PAW-WDAC-Supp-ClaudeCode` `2026.10.23.1`, both `IsAuthorized True`.
- **Screening window start:** `C:\WDAC\Events\ScreenStart.txt` = **`2026-10-23T11:23:22.8295707+02:00`**.
- **Merged policy:** 224 signers · 10 FilePath allow rules · 2,357 deny rules · 170 FileAttrib. Options: `Disabled:Script Enforcement`, `Advanced Boot Options Menu`, `Allow Supplemental Policies`, `Audit Mode`, `Boot Audit On Failure`, `Inherit Default Policy`, **`Managed Installer`**, `UMCI`, `Unsigned System Integrity Policy`, `Update Policy No Reboot`, `Required:WHQL`. WSL deny rules **0**; `Mozilla|Firefox` matches **0**.

**How the event rules apply (printout requested by the user)**
- A **signer** = issuing CA (`CertRoot`, the TBS hash of the intermediate certificate) + publisher (`CertPublisher`, the leaf certificate CN). On its own it would allow everything that publisher signs through that CA.
- Each signer here is paired with a **FileAttrib** (FileAttribRef), which makes a **FilePublisher** rule. A file must be (1) signed by that publisher through that CA, (2) have a matching `FileName` (OriginalFileName) or `ProductName`, and (3) have a file version **≥ `MinimumFileVersion`**. Newer versions keep working; a different or older file from the same publisher does not.
- The Wizard writes one signer per file (24). `Merge-CIPolicy` collapsed identical certificates, so the merged policy holds **4 signers** carrying all **24 FileAttribs**, all listed as AllowedSigners in the user-mode scenario (12).

| Merged signer | Publisher → issuing CA | FileAttribs (match → min version) | Files |
|---|---|---:|---|
| `ID_SIGNER_A_0_1_0` | Anthropic, PBC → DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 | 1 (`ProductName=Claude Code` ≥ 2.1.309.0) | `claude.exe` |
| `ID_SIGNER_A_1_1_0` | Open Source Developer Bryan Berns → Certum Code Signing 2021 CA | 1 (`WinDirStat.exe` ≥ 2.9.3.2253) | `WinDirStat.exe` |
| `ID_SIGNER_A_2_1_0` | Python Software Foundation → Microsoft ID Verified CS EOC CA 04 | 20 (≥ 3.14.7150.1013): `python.exe`, `python314.dll`, `python3.dll`, `_wmi`, `_uuid`, `_queue`, `_socket`, `_ssl`, `_zstd`, `_hashlib`, `select`, `_bz2`, `_lzma`, `unicodedata`, `_elementtree`, `pyexpat`, `_asyncio`, `_overlapped`, `_decimal`, `_ctypes` (`.pyd`) | az CLI Python runtime |
| `ID_SIGNER_A_10_1_0` | Python Software Foundation → Microsoft ID Verified CS AOC CA 03 | 2 (`libcrypto`, `libssl` ≥ 3.5.7.0) | `libcrypto-3.dll`, `libssl-3.dll` |

| FilePath rule | Path | Kind | Honored? |
|---|---|---|---|
| `ID_ALLOW_C_0` / `C_1` | `%OSDRIVE%\Users\Lorenzo.SKYNET\.vscode\extensions\anthropic.claude-code-2.1.309-win32-x64\resources\audio-capture\x64-win32\audio-capture.node` / `…\x64-win32\*` | file / folder | ❌ **No**: user-writable (covered instead by the supplemental, D13) |
| `ID_ALLOW_C_2`, `C_4` / `C_3`=`C_5` | `CLI2\Lib\site-packages\charset_normalizer\cd.cp314-win_amd64.pyd`, `md.cp314-win_amd64.pyd` / `…\charset_normalizer\*` | files / folder | ✅ admin-only (C_3 and C_5 identical, de-duplicated in the merge) |
| `ID_ALLOW_C_6` / `C_7` | `CLI2\Lib\site-packages\psutil\_psutil_windows.pyd` / `…\psutil\*` | file / folder | ✅ |
| `ID_ALLOW_C_8` / `C_9` | `CLI2\Lib\site-packages\yaml\_yaml.cp314-win_amd64.pyd` / `…\yaml\*` | file / folder | ✅ |
| `ID_ALLOW_A_1_1` *(script 4, D11)* | `C:\Program Files\Microsoft SDKs\Azure\CLI2\*` | folder (recursive) | ✅ (covers the 8 above and `libffi-8.dll`) |

**Merge integrity verification (11:25)**
- Signers: base 223 + 4 new = 227 expected vs **224** merged. The base contains signers that share one certificate (e.g. each Microsoft root signer and its `…_UMCI` twin), and the merge folded 3 of them. Distinct certificates **203 → 207 (+4 exactly)**.
- Two base signers, `ID_SIGNER_ZEMANA_2` (VeriSign Class 3 Code Signing 2010 CA / Zemana Ltd.) and `ID_SIGNER_ZEMANA_3` (Microsoft Windows Third Party Component CA 2014 / OEM *ZEMANA A.Ş.*), are absent after the merge. Both were **orphans in Microsoft's kernel block list** (referenced by no `DeniedSigner`/`AllowedSigner`), so they never had any effect, and `Merge-CIPolicy` drops unreferenced signers. **No deny coverage changed.**
- References: kernel scenario 131 **identical** (8 AllowedSigner / 202 DeniedSigner / 1,706 FileRuleRef). User scenario 12: AllowedSigner 10 → 14 (+4 new signers), FileRuleRef 655 → 665 (+9 unique event paths + 1 CLI2 rule). No signer is both allowed and denied.

### Step 5 (screen) — 🔄 Reboot — issued 2026-10-23T11:26:40.7669051+02:00
- User confirmed **"Yes, reboot now"**. Agent ran `Restart-Computer`. `ScreenStart.txt` = `2026-10-23T11:23:22.8295707+02:00` (survives the reboot).
- **After sign-in (pending):** re-open VS Code / Claude Code → re-run every approved app (WSL as lorenzo, WinDirStat, az, pwsh) → `5_audit_merged_events.ps1`. 🚫 Firefox not launched.
- **Back online:** `LastBootUpTime = 2026-10-23T11:26:52`. Check at 11:28:03: STIG `2 / 1`; CiTool `PAW-WDAC-Audit-Merged 2026.10.21.2` + `PAW-WDAC-Supp-ClaudeCode 2026.10.23.1` (both `IsAuthorized True`); **0 × 3076** since `ScreenStart`, including the VS Code + Claude Code start-up. In round 1, `claude.exe` and `audio-capture.node` logged 3076 at exactly this point, so the FilePublisher rule and the supplemental (D13) are proven.

### Step 5 (screen) — Re-run every approved application — ✅ 2026-10-23 11:28:18 – 11:29
| App | Who | What | Result |
|---|---|---|---|
| VS Code + Claude Code | user + agent | VS Code re-opened after the reboot; Claude Code session resumed | ✅ |
| PowerShell 7 | agent | `pwsh -NoProfile …` → 7.6.8, `FullLanguage`, 78 modules | ✅ |
| VS Code CLI | agent | `code --version` → 1.143.1; `--list-extensions` | ✅ |
| Azure CLI | agent + user | `az --version`, `version`, `extension list`, `config get`, `vm/storage account/network vnet/group/keyvault/aks/webapp --help`, `find`, `account list` (more command modules than round 1) + the user's own commands | ✅ |
| WSL / Ubuntu 26.04 | agent + user | `wsl --version`; as `lorenzo`: `whoami`, `uname -r`, os-release (*Ubuntu 26.04.1 LTS*), `python3`, `/mnt/c`, interop `cmd.exe /c ver`, `whoami.exe` → `skynet\lorenzo`; plus interactive use by the user | ✅ |
| WinDirStat | user | Used by the user | ✅ |
| Firefox | — | Not launched | 🚫 by design |

### Step 5 (screen) — `5_audit_merged_events.ps1` — ✅ 2026-10-23 11:29:11
- Transcript `C:\WDAC\Logs\Agent-Transcript-Step5-Screen-20261023-112911.log`.
- **`New 3076 events since screening started: 0`** (window `11:23:22 →` 11:29:11, spanning the reboot, sign-in, and every approved app). Other CI events in the window: only policy and refresh events (3084×1, 3096×7, 3099×9, 3101×1, 3102×1, 3103×4, 3105×16, 3116×6) and **no 3077**.
- **`Base-Enforce.xml prepared from Base-Audit-Merged.xml`**: `C:\WDAC\Source\Base-Enforce.xml` (686,299 bytes, SHA-256 `2C7BD6054BD17816FD0F6B051BDAB838B01190BE8E9A851E11CF56C0B9485F11`, byte-identical to the screened policy; timestamp set to match its source so a Wizard save is recognizable).
- No second Steps 4–5 loop was needed.

### Step 6 — App Control Policy Wizard: Audit Mode OFF in `Base-Enforce.xml` — ⏸ user (instructions given 11:30)
- **Custom rule added by the user in the Wizard (Step 6, File Rules screen):** `Allow · FolderPath · Files under path: C:\ADMIN\*` (a FilePath rule required by the environment).
- **Agent ACL check of `C:\ADMIN` (read-only, 11:33):** owner `SKYNET\Lorenzo`; inherited ACEs from `C:\`: Administrators/SYSTEM FullControl, Users ReadAndExecute, **`NT AUTHORITY\Authenticated Users` Modify** (+ generic rights `0xE0010000` on children) → **1 non-admin write ACE**, so the folder is **user-writable**. 2 PE files inside. Under runtime FilePath rule protection (Option 18 absent in the base) this rule is **not honored**, so files in `C:\ADMIN` will be blocked once enforced.
- **Offered:** harden the ACL (owner → Administrators, inheritance off, remove Authenticated Users, Users RX) and a README callout. **User decision: leave both as is.** ⚠️ Known condition; expect `3077` for `C:\ADMIN\…` binaries after enforcement.


### Step 6 — Wizard: Audit Mode OFF — ✅ saved by user 11:35:08
- User opened `C:\WDAC\Source\Base-Enforce.xml` in the Wizard (Policy Editor → Edit Policy File); left Policy Name/ID unchanged (script 6 stamps them) and the save location blank. Turned **Audit Mode OFF** and added the custom rule `C:\ADMIN\*` (see above).
- Output: **`C:\WDAC\Source\Base-Enforce_v10.0.0.0.xml`** (686,403 bytes, 11:35:08), plus a Wizard-compiled `C:\WDAC\Source\{75AFC1CF-…}.cip` (318,512 bytes), which is **not used** (script 6 compiles its own into `C:\WDAC\Compiled\`).
- **Agent diff vs the screened `Base-Audit-Merged.xml` (11:36:20):** same PolicyType/PolicyID/BasePolicyID; VersionEx already bumped by the Wizard to `2026.10.21.3`; **options removed: `Enabled:Audit Mode` only; options added: none**; signers 224 = 224; deny 2,357 = 2,357; FileAttrib 170 = 170; kernel scenario identical (1,706 refs, 202 denied signers); **+1 allow rule** `ID_ALLOW_PATH_0` `FilePath=%OSDRIVE%\ADMIN\*` (+1 user-mode ref, 665 → 666); **0 screened rules missing**; `Mozilla|Firefox` = 0.

### Step 7 — `6_enforce_policy.ps1` (gate, stamp v3, compile, ENFORCE) — ✅ 2026-10-23 11:36:33 – 11:37:30
- **Command:** `.\6_enforce_policy.ps1 -ExcludedAppPattern 'Mozilla|Firefox'` (unmodified script, parameter only) · transcript `C:\WDAC\Logs\Agent-Transcript-Step7-20261023-113633.log`. The script used the newest `Base-Enforce_v10.0.0.0.xml` → `Base-Enforce.xml`.
- **Gate (all pass):** `PolicyName PAW-WDAC-Enforced` · `PolicyIdLabel PAW-ENFORCED-v3` · `Base Policy` · `SameGuidAsAudit True` · `MultiPolicyFormatValid True` · `VersionEx 2026.10.21.3` · **`AuditModeRemoved True`** · **`OnlyAuditModeTurnedOff True`** (`OtherOptionsTurnedOff` empty, `OptionsAdded` empty) · `UMCI_Enabled True` · `BootAuditEnabled True` · `AllowSupplemental True` · `ScriptEnforceDisabled True` · `UpdateNoRebootEnabled True` · **`ExcludedAppInPolicy False`** → `PRE-DEPLOYMENT CHECK PASSED`.
- **Options that stay enabled (10):** `Disabled:Script Enforcement`, `Enabled:Advanced Boot Options Menu`, `Enabled:Allow Supplemental Policies`, `Enabled:Boot Audit On Failure`, `Enabled:Inherit Default Policy`, **`Enabled:Managed Installer`**, `Enabled:UMCI`, `Enabled:Unsigned System Integrity Policy`, `Enabled:Update Policy No Reboot`, `Required:WHQL`.
- **Compiled:** `C:\WDAC\Compiled\{75AFC1CF-5372-491A-80CA-7BBB694F0A00}.cip` + archive `PAW-WDAC-Enforced_v2026.10.21.3.cip` (318,496 bytes) — **SHA-256 `D814CBCF8A3698198D5E16C01013B9459E3E285B2E721A21214C40720ACBEF63`**. Final `Base-Enforce.xml` SHA-256 `44B7C8B232084D7299B56366AEFF917C2EB8439463C6E961A0DCAFDA530738CF`.
- **Deploy:** `CiTool.exe --update-policy` → **`{"OperationResult":0}`**, exit `0`, live (no reboot).

### Step 8.1 — `7_DISA_STIG_CHECK.ps1` — ✅ **PASS** 2026-10-23 11:37:45
```text
CodeIntegrityPolicyEnforcementStatus         : 2
UsermodeCodeIntegrityPolicyEnforcementStatus : 2
V-243450 (CodeIntegrityPolicyEnforcementStatus)         : 2 [PASS - NOT A FINDING]
V-243451 (UsermodeCodeIntegrityPolicyEnforcementStatus) : 2 [PASS - NOT A FINDING]
```

### Step 8.2 — `8_validate_multipolicy_layout.ps1` — ✅ 2026-10-23 11:37:45
- `CiPolicies\Active\`: `{75afc1cf-…}.CIP` (318,496 bytes, 11:37:30) and `{0585a4c6-…}.CIP` (752 bytes) next to the Microsoft platform policies. **`SiPolicy.p7b`: `False`**.
- CiTool: **`PAW-WDAC-Enforced` `2026.10.21.3`** (`IsEnforced True`, `IsAuthorized True`) + `PAW-WDAC-Supp-ClaudeCode` `2026.10.23.1` (BasePolicyID = the base, `IsAuthorized True`).
- Event **3099** at 11:37:30: *"Refreshed and activated Code Integrity policy {75afc1cf-…} PAW-WDAC-Enforced. id PAW-ENFORCED-v3. Status 0x0"*.
- Smart App Control still `VerifiedAndReputablePolicyState = 2` (Evaluation).
- **Immediate post-enforcement checks (11:37:59):** 0 × 3077, 0 × 3076 since 11:37:30; Claude Code session alive (the agent kept running through enforcement); `pwsh` → `FullLanguage`; `az --version` → 2.91.0; `wsl -d Ubuntu -- whoami` → `lorenzo`.

### Step 8.3 — 🔄 Reboot + positive test — ✅
- User confirmed **"Yes, reboot now"**; Step 8.4 Firefox launch to be done **by the user** (GUI demo). Agent ran `Restart-Computer` at 2026-10-23T11:41:23.3583832+02:00.
- **After sign-in (pending):** re-open VS Code / Claude Code (proves Claude Code starts under enforcement) → agent re-tests the CLI apps, user re-tests WinDirStat/Ubuntu → user launches Firefox → agent collects 3077 + evidence.

- **Back online:** `LastBootUpTime = 2026-10-23T11:41:31` (booted **under the enforced policy**). Check 11:42:35: **STIG `2 / 2`**; CiTool `PAW-WDAC-Enforced 2026.10.21.3` + `PAW-WDAC-Supp-ClaudeCode 2026.10.23.1` (both `IsAuthorized True`); **0 × 3077 and 0 × 3076 since enforcement (11:37:30)**, covering boot, services, sign-in and VS Code + Claude Code start-up; no boot-time driver failure events (3001–3005). Claude Code starting and running the agent is itself the first positive test.

| App (Step 8.3, under enforcement) | Who | Test | Result |
|---|---|---|---|
| VS Code + Claude Code | user + agent | Started after the reboot; agent session running | ✅ |
| PowerShell 7 | agent | `pwsh -NoProfile` → `FullLanguage` (agent session also `FullLanguage`) | ✅ |
| VS Code CLI | agent | `code --version` → 1.143.1; extensions `anthropic.claude-code`, `ms-vscode.powershell` | ✅ |
| Azure CLI | agent | `az --version` 2.91.0; `vm`/`keyvault`/`aks`/`webapp --help`; `account list` (*Please run az login*) | ✅ (a `--query` quoting error in the agent's own test command is not a block) |
| WSL / Ubuntu 26.04 | agent | as `lorenzo`: os-release, `python3` 3.14.4, interop `cmd.exe /c ver` | ✅ |
| WinDirStat | agent | `Start-Process …\WinDirStat.exe` → still running after 8 s (PID 9936), then closed | ✅ |
- **3077 after all tests (11:43:06): 0.** 

### Step 8.4 — 🚫 Negative test: Firefox — ✅ BLOCKED

- **11:43:08 / 11:43:34 — user (GUI):** launched `C:\Users\Lorenzo.SKYNET\Desktop\Firefox.exe` (a Mozilla-signed copy of Firefox's **desktop launcher**, OriginalFileName `desktop-launcher.exe`, 402,048 bytes) from Explorer, twice. **Blocked** with the toast *"Your organization used App Control for Business to block this app · C:\Users\Lorenzo.SKYNET\Desktop\Firefox.exe · Contact your support person for more info."* (screenshot provided by the user).
- **11:45:20 — agent (PowerShell, at the user's request):** `Start-Process 'C:\Program Files\Mozilla Firefox\firefox.exe'` → **`An Application Control policy has blocked this file.`**; `& firefox.exe --version` → *"Program 'firefox.exe' failed to run … An Application Control policy has blocked this file."* Firefox processes afterwards: **0**.
- `Get-Blocked_CI_Events.ps1` → *"Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\explorer.exe) attempted to load …\Desktop\Firefox.exe that did not meet the Enterprise signing level requirements or violated code integrity policy (Policy ID:{75afc1cf-5372-491a-80ca-7bbb694f0a00})."*
- **Evidence:** `.\Export-CIEventEvidence.ps1 -EventId 3077 -StartTime '2026-10-23T11:37:30'` → **5 × 3077, 10 × 3089**, all `Status 0xC0E90002`, all Mozilla Corporation, all `PAW-WDAC-Enforced`. Files: `C:\WDAC\results\evidence\Enforced-3077-Events.csv` / `.md`. The installed `firefox.exe` is 1,080,448 bytes, SHA-256 (flat file) `76732D4E…CED9B`; the desktop launcher is SHA-256 `084F19D3…665F7`. Both are signature-valid (Mozilla Corporation), and both are blocked because **no rule trusts Mozilla**.

| Time | Record | File | Parent process | Signer (3089) | OriginalFileName / Product / Version | SHA-256 (Authenticode) | Status | Policy |
|---|---:|---|---|---|---|---|---|---|
| 2026-10-23 11:43:08.798 | 407 | `C:\Users\Lorenzo.SKYNET\Desktop\Firefox.exe` | `explorer.exe` | Mozilla Corporation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | desktop-launcher.exe / Firefox 158.0.1.691 | `4184508E0AAC871B3942EF5EB50E22BF3298834E5637BC819298C8A0FA774F8B` | 0xc0e90002 | PAW-WDAC-Enforced |
| 2026-10-23 11:43:34.624 | 411 | `C:\Users\Lorenzo.SKYNET\Desktop\Firefox.exe` | `explorer.exe` | Mozilla Corporation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | desktop-launcher.exe / Firefox 158.0.1.691 | `4184508E0AAC871B3942EF5EB50E22BF3298834E5637BC819298C8A0FA774F8B` | 0xc0e90002 | PAW-WDAC-Enforced |
| 2026-10-23 11:45:20.554 | 415 | `C:\Program Files\Mozilla Firefox\firefox.exe` | `pwsh.exe` | Mozilla Corporation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | firefox.exe / Firefox 158.0.1.691 | `E3BF27C91DA59BA69E05A6E7F4F14E1D6BF85DC555C3523189E036D85061D9C3` | 0xc0e90002 | PAW-WDAC-Enforced |
| 2026-10-23 11:45:20.659 | 419 | `C:\Program Files\Mozilla Firefox\firefox.exe` | `pwsh.exe` | Mozilla Corporation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | firefox.exe / Firefox 158.0.1.691 | `E3BF27C91DA59BA69E05A6E7F4F14E1D6BF85DC555C3523189E036D85061D9C3` | 0xc0e90002 | PAW-WDAC-Enforced |
| 2026-10-23 11:45:20.737 | 423 | `C:\Program Files\Mozilla Firefox\firefox.exe` | `pwsh.exe` | Mozilla Corporation — *DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1* | firefox.exe / Firefox 158.0.1.691 | `E3BF27C91DA59BA69E05A6E7F4F14E1D6BF85DC555C3523189E036D85061D9C3` | 0xc0e90002 | PAW-WDAC-Enforced |

- STIG after the block test: **`2 / 2`**. Firefox remains **installed** (`C:\Program Files\Mozilla Firefox`), as required for the demo.

---

## Final Result — ✅ V-243450 and V-243451 PASS (`2 / 2`)

| Item | Result |
|---|---|
| STIG progression | `2 / 1` (OS baseline) → `2 / 1` (baseline audit) → `2 / 1` (merged audit) → **`2 / 2`** (enforced, 11:37:30) → **`2 / 2`** (after reboot, 11:42) |
| Active custom policies | `PAW-WDAC-Enforced` `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}` v`2026.10.21.3` (base, Multiple Policy Format) · `PAW-WDAC-Supp-ClaudeCode` `{0585A4C6-99AE-42CB-91E9-C34AD7AFB041}` v`2026.10.23.1` (supplemental, machine-specific) |
| Enforced `.cip` SHA-256 | `D814CBCF8A3698198D5E16C01013B9459E3E285B2E721A21214C40720ACBEF63` |
| Allowed and verified under enforcement | PowerShell 7, VS Code (+ extensions), Claude Code, Azure CLI, WinDirStat, WSL Ubuntu 26.04 — **0 × 3077** |
| Blocked and verified | **Firefox** (installed `firefox.exe` + desktop launcher) — **5 × 3077** |
| Audit rounds | 1 capture round (31 × 3076) + 1 screening round (**0** × 3076); no extra loop needed |
| Option 13 (Managed Installer) | ON in every stage (MECM / Intune); inert here until a managed installer is configured |
| Known, accepted conditions | `C:\ADMIN\*` FilePath rule is user-writable, so it isn't honored (user declined to harden the ACL) · Claude Code supplemental relaxes runtime FilePath protection for its own folder only · 6 WSL deny rules removed from the recommended block list · no Hyper-V checkpoint was taken |
| Deliverables | This log · `C:\WDAC\results\WDAC-STIG-Walkthrough-Report.html` · evidence CSV/MD in `C:\WDAC\results\evidence\` · enhanced scripts (both editions) + restructured README in `C:\WDAC\config\` |

### Artifact Inventory (SHA-256)
| File | Bytes | Time | SHA-256 |
|---|---:|---|---|
| `C:\WDAC\Source\{75AFC1CF-5372-491A-80CA-7BBB694F0A00}.cip` | 318,512 | 11:35:10 | `B85E94D931115170C361E2AC2B6DB4E362B4900D0B228E4EEF2C8E3AA22B505E` |
| `C:\WDAC\Source\Base-Audit-Merged.xml` | 686,299 | 11:23:20 | `2C7BD6054BD17816FD0F6B051BDAB838B01190BE8E9A851E11CF56C0B9485F11` |
| `C:\WDAC\Source\Base-Audit.wizard-original-20261023-104208.xml` | 655,174 | 10:36:31 | `1CC20C9C0D6CDD4001ACCE04FD6EDADE0C661001352464D75F5A93787841122A` |
| `C:\WDAC\Source\Base-Audit.xml` | 653,948 | 10:49:16 | `C7FABAC7D0CC1988FAAD6929A52BCFFB555426449C1801C3BD78B37FFD4C073D` |
| `C:\WDAC\Source\Base-Enforce_v10.0.0.0.xml` | 686,403 | 11:35:08 | `8DB2DC00BCC4682C67DCCD7BDE5F860C1753B11A6277BB979460B5F2B4CA3FBE` |
| `C:\WDAC\Source\Base-Enforce.xml` | 686,398 | 11:37:28 | `44B7C8B232084D7299B56366AEFF917C2EB8439463C6E961A0DCAFDA530738CF` |
| `C:\WDAC\Source\Events-Allow.original-20261023-112210.xml` | 20,651 | 11:12:35 | `DD96DE7D8DC0923779B50B637EFC226495569BDA5C5E014B140BE543B9D6042B` |
| `C:\WDAC\Source\Events-Allow.xml` | 20,072 | 11:22:03 | `319CA2D4819075CF4E81DD16156C1D7870768C486AF1A5C246BCFBC50550FB2A` |
| `C:\WDAC\Source\PolicyGuid.txt` | 40 | 10:49:16 | `35BDE5C94897B492A669EADB7694AE955CE78EC56BBF62EAE87BEF4EDD31DF7B` |
| `C:\WDAC\Source\Supp-ClaudeCode.xml` | 1,922 | 11:20:57 | `0063B7AF94FB040EDF3F8EA7C9CA0059D220805C2E1A83C534017D320E9AF73D` |
| `C:\WDAC\Compiled\{0585A4C6-99AE-42CB-91E9-C34AD7AFB041}.cip` | 752 | 11:20:57 | `B0493C0E0BE5698A272D9C9A99BF7812C26B1C3956577155386069C135D92FDD` |
| `C:\WDAC\Compiled\{75AFC1CF-5372-491A-80CA-7BBB694F0A00}.cip` | 318,496 | 11:37:30 | `D814CBCF8A3698198D5E16C01013B9459E3E285B2E721A21214C40720ACBEF63` |
| `C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip` | 312,240 | 10:49:18 | `6581BF7C513BF3DD432CB861ECECE47E02D9C9D05484BFACE496A4D967815AB6` |
| `C:\WDAC\Compiled\PAW-WDAC-Audit-Merged_v2026.10.21.2.cip` | 318,388 | 11:23:22 | `D3C4B7AA7392CC6C5226AE63994302108E8A41AA532591B9BAFAB61A2DE5F5BA` |
| `C:\WDAC\Compiled\PAW-WDAC-Enforced_v2026.10.21.3.cip` | 318,496 | 11:37:30 | `D814CBCF8A3698198D5E16C01013B9459E3E285B2E721A21214C40720ACBEF63` |
| `C:\WDAC\Compiled\PAW-WDAC-Supp-ClaudeCode_v2026.10.23.1.cip` | 752 | 11:20:57 | `B0493C0E0BE5698A272D9C9A99BF7812C26B1C3956577155386069C135D92FDD` |
| `C:\WDAC\Events\AuditRoundStart.txt` | 35 | 10:49:19 | `051A60D623495549C83CAD72A66BCB0789421DCC072650E469B30C2E7BD88201` |
| `C:\WDAC\Events\PAW-Audit-3076.evtx` | 1,118,208 | 10:56:07 | `F1E943107E3A7BBAB97868B66AB7BD23ABFA011055C28AEF8F17D9AB16CE2A0F` |
| `C:\WDAC\Events\ScreenStart.txt` | 35 | 11:23:22 | `F26AC5C2564A9D7065BB196A9CC47810E831C8E2250AC48C2C6E05649B811E82` |
| `C:\WDAC\results\evidence\Enforced-3077-Events.csv` | 3,989 | 11:45:23 | `D6414DB59C1BF5D56072FCE42AD55B10DD1B3EA311C760AE74B300378ED8442D` |
| `C:\WDAC\results\evidence\Enforced-3077-Events.md` | 1,583 | 11:45:23 | `89CADC419EF521BD1D71AAF94277AA61A34592EA344C021841DA2F047397AF9F` |
| `C:\WDAC\results\evidence\Round1-Audit-3076-Events.csv` | 23,394 | 10:57:18 | `1A1F26856AE49C5CC2A30BBE51BDE1F35B8EA35416F2A6136865A327755E4818` |
| `C:\WDAC\results\evidence\Round1-Audit-3076-Events.md` | 9,322 | 10:57:18 | `582346DD38AC5ED2E758EA4DE6B4A09C58ADDCC20D100C470C7FE356CBA2D23E` |

Logs in `C:\WDAC\Logs`: `Agent-Transcript-Step2-20261023-104908.log` · `Agent-Transcript-Step4.1-20261023-105606.log` · `Agent-Transcript-Step4.3-20261023-112200.log` · `Agent-Transcript-Step4.3-ReportOnly-20261023-111530.log` · `Agent-Transcript-Step5-20261023-112225.log` · `Agent-Transcript-Step5-Screen-20261023-112911.log` · `Agent-Transcript-Step7-20261023-113633.log` · `Agent-Transcript-Step8-20261023-113745.log` · `Agent-Transcript-SuppClaudeCode-20261023-112118.log` · `Base-Audit-Validate-20261023-110811.csv` · `Base-Audit-Validate-20261023-110835.csv` · `Base-Audit-Validate-20261023-110839.csv` · `Base-Audit-Validate-20261023-110903.csv` · `Base-Audit-Validate-20261023-111003.csv` · `Events-Allow-Sanitize-20261023-111533.csv` · `Events-Allow-Sanitize-20261023-112203.csv` · `WDAC-Manual-Run-20261023-102705.log` · `WDAC-Manual-Run-20261023-110943.log` · `WDAC-Manual-Run-20261023-110958.log`

*Log closed 2026-10-23 11:46:03 (+02:00).*

### Post-run — Pre-upload script verification — ✅ 2026-10-23 11:48:46
- Scripts changed in D12 but not yet executed since the change, now executed:
  - `2_audit_policy_activation.ps1`, PS7 + 5.1: STIG `2 / 2`, CiTool inventory, 3099 found (retry loop OK).
  - `3_capture_ciaudit_events.ps1`, PS7 + 5.1: `Exported: 31 x 3076, 41 x 3089 (live log: 31 x 3076 …)` (the extra 3089s belong to the Firefox 3077 blocks).
  - The evidence file `C:\WDAC\Events\PAW-Audit-3076.evtx` was **backed up before and restored after**; SHA-256 identical (`F1E94310…2A0F`).
- `pwsh_5.1\4_…`/`6_…` bodies were not executed (that would redeploy policy). Parameter binding verified with `Get-Command` under Windows PowerShell 5.1 and PS7: identical parameter sets for 0, 0_1, 3_1, 4, 5, 6 and the exporter.
- `C:\WDAC-Scripts` remains byte-identical to `C:\WDAC\config\scripts`.
- **Verdict:** the scripts in `C:\WDAC\config\scripts\` (+ `pwsh_5.1\`) are ready to copy to the file share; they contain no Claude/Firefox/az-specific values.

### Post-run — README completion + reusable run report (D14) — ✅ 2026-10-23 11:56
- **User decisions:** README gaps to add = **Step 4.2 save location** and **Step 6 Wizard fields** (not the Step 8.4 multi-binary note). The HTML report generator should be **reusable**.
- **README additions:**
  - Step 4.2 `[!NOTE]`: the Wizard can save to `%USERPROFILE%\Documents\EventLogPolicy_<UTC timestamp>.xml`; copy the newest into `C:\WDAC\Source\Events-Allow.xml`. Its *Supplemental Policy* type is expected.
  - Step 6: leave Policy Name/ID unchanged (labels; the GUID isn't editable there) and New Save Location blank; `Base-Enforce_v10.0.0.0.xml` and a bumped VersionEx are fine.
  - New Step **8.5** + run-order row 18 + quick-start line + Appendix A/B entries for `New-WDACRunReport.ps1`.
- **New script `New-WDACRunReport.ps1`** (identical in `scripts\` and `scripts\pwsh_5.1\`; ASCII-only; no ConfigCI; no application names). It builds one self-contained HTML report:
  - STIG history parsed from `C:\WDAC\Logs` transcripts, plus the live value
  - CiTool custom policies; XML stages; `.cip` hashes
  - every FilePath rule with an honored / NOT-honored / runtime-check-disabled verdict from the live ACL
  - managed-installer readiness; latest 0_1/3_1 findings
  - every 3076 (audit `.evtx` + screening) and 3077 (since the enforced `.cip`), via `Export-CIEventEvidence.ps1`, with `-BlockTestPattern` marking expected blocks
  - artifact inventory; optional `-NotesMarkdown`
- **Tests (11:52 – 11:55):**
  - 0 non-ASCII bytes; 0 parse errors (PS7 + 5.1).
  - PS7 run → `STIG 2 / 2 | screening 3076: 0 | 3077: 5 (0 to review)`; 5.1 run without a pattern → `5 to review`, and with a pattern → `0 to review`; both reports identical in content.
  - The FilePath section correctly flags `C:\ADMIN\*` and the two Wizard user-profile rules as **NOT honored**, the 8 az + CLI2 rules as honored, and the supplemental as *honored (runtime check disabled)*.
  - Fixes made during testing: empty-array-as-`\` (unary comma) and the STIG history sort order.
- **README validation:** 15/15 in-page links resolve; all 14 script names exist in both folders; no stale "Option 13 OFF" wording; 0 Claude/Anthropic mentions; 752 lines.
- `C:\WDAC-Scripts` re-synced (byte-identical to `C:\WDAC\config\scripts`).

### Upload manifest — `C:\WDAC\config\` (copy this whole folder to the file share)
- CSV: `C:\WDAC\results\config-upload-manifest-SHA256.csv`. To verify a copy, compare `Get-FileHash` of each file against the manifest.

| File | Bytes | SHA-256 |
|---|---:|---|
| `README.md` | 52,790 | `D11AACAC41D1D54AFF3C09F8E4BDBEB451C1260B02C8168B2B3705E79A667D5D` |
| `scripts\0_1_validate_base_policy.ps1` | 9,548 | `7F6C6B7156E687F7B0DB7798495654736DBDE08921D15ED440EF9B64C759C1B5` |
| `scripts\0_pre-flight.ps1` | 7,317 | `FA1A4339590FDB3E977BBCDFAD2A1A358EEF4CEF6B182D193225CD18E95190F2` |
| `scripts\1_compile_and_deploy.ps1` | 3,173 | `3A74D7A7172DF69A01E9E755EA9252A2FDEDE3470C15BA3A99F57D05DFE4F9A2` |
| `scripts\2_audit_policy_activation.ps1` | 1,557 | `9C8556789D799560FA472B9456773B17A2610AD903781A768F63084324990346` |
| `scripts\3_1_validate_winevent_rules.ps1` | 20,398 | `F8A5BFE65DBC9D9422B0DE5BB2ADC1B713AF3E7805F2168CE367C50DFBDBFACE` |
| `scripts\3_capture_ciaudit_events.ps1` | 2,742 | `B97CC65A5C3FFF0DFE39ECDF6947C0051328C0AF99E21F3860DF3C9582C16ABD` |
| `scripts\4_merge_audit_base_and_events_policies.ps1` | 9,860 | `9E21E8128B8118482CDBCEA1AD53FE5BFB4ED314EA70A5D2A01B79E2080BC648` |
| `scripts\5_audit_merged_events.ps1` | 4,897 | `A6ED0B9781A62E0B193442EACF534CE2CF66592AE36AD398DE5D4E296E47DCCB` |
| `scripts\6_enforce_policy.ps1` | 8,366 | `12B908584B5975DFB4BAF7C4B403EEFAFD4365EB00EB7CCDF2721A0336C1E0A6` |
| `scripts\7_DISA_STIG_CHECK.ps1` | 1,267 | `084D2EBB4B84BBFB64A27690D3C35D1DD801464C0B583492850BC4C9A2FAD52E` |
| `scripts\8_validate_multipolicy_layout.ps1` | 1,075 | `04CF7C6059644892A3D9BAAB5405C38A9472440F087E4D04D7C93C3E42B8BF54` |
| `scripts\Export-CIEventEvidence.ps1` | 8,249 | `2E3BE6E1C1EEC2BA330D2C0E721BEF5CC1D7C89AFFE5078ADDFF9C8828811FF3` |
| `scripts\Get-Blocked_CI_Events.ps1` | 265 | `277D122CE20B278D0CFE8537B5DA7852BC3A2F903D2175113998E5D6BD55FE84` |
| `scripts\New-WDACRunReport.ps1` | 29,633 | `DC56B4C33B645B98FF88AB941A6184F7DB448E82E71FA813DC1CCBEDE51B17AA` |
| `scripts\pwsh_5.1\0_1_validate_base_policy.ps1` | 9,613 | `5933E56CA3F29A6C0B6859C0ECA8A272CCD52DCC1218F646DA486147C96393FA` |
| `scripts\pwsh_5.1\0_pre-flight.ps1` | 7,405 | `929642A2093FD16E74059407C3114A9AD94E3B4119008C2985AF2460B195C7E6` |
| `scripts\pwsh_5.1\1_compile_and_deploy.ps1` | 3,389 | `C48A798FE09AC8FB53C9795971D68C4F23BE5DA36C7E14543DCF08CF6B6DD417` |
| `scripts\pwsh_5.1\2_audit_policy_activation.ps1` | 1,649 | `F40787D740E0368A19D41178CA9B56A1BB810DC16F3FB09EB6AD2B6DF9959BC1` |
| `scripts\pwsh_5.1\3_1_validate_winevent_rules.ps1` | 20,347 | `877DE65DFF2F1BE5B1650E225F805D2D88006D7541218FDBFC03E77F5072A66A` |
| `scripts\pwsh_5.1\3_capture_ciaudit_events.ps1` | 2,836 | `7EA013BA11812D0649459FA638C87A55236FB11962BBF17BD9743993AA98C593` |
| `scripts\pwsh_5.1\4_merge_audit_base_and_events_policies.ps1` | 9,806 | `591C87AAEB1E547973FA27E70A10EFCBC7528DB2FB881329C0FECC8615FD2758` |
| `scripts\pwsh_5.1\5_audit_merged_events.ps1` | 4,929 | `727AAAD3A5E399F136B7C9E4201C659E989FD95E3DA4DA0EE97881175C4BA574` |
| `scripts\pwsh_5.1\6_enforce_policy.ps1` | 8,534 | `56585A5BA054DE8C064613B8715E91549EA19FCD0D95CB70F2930BE5A6F64FF3` |
| `scripts\pwsh_5.1\7_DISA_STIG_CHECK.ps1` | 1,289 | `37C6C722F940FA84E882AD8FB9A1BF1A9ED68B1915BD3C98AE78D9045538E4F6` |
| `scripts\pwsh_5.1\8_validate_multipolicy_layout.ps1` | 1,169 | `BBFF4544000857EAF50E0B854221C1CA280EF0A79EEE10D8DBB2EF16935D6B9B` |
| `scripts\pwsh_5.1\Export-CIEventEvidence.ps1` | 8,249 | `2E3BE6E1C1EEC2BA330D2C0E721BEF5CC1D7C89AFFE5078ADDFF9C8828811FF3` |
| `scripts\pwsh_5.1\Get-Blocked_CI_Events.ps1` | 357 | `F254D468FEBAE3F614BFF91E2FEDAF33F81F739C7F683CE30582CB20CE01A687` |
| `scripts\pwsh_5.1\New-WDACRunReport.ps1` | 29,633 | `DC56B4C33B645B98FF88AB941A6184F7DB448E82E71FA813DC1CCBEDE51B17AA` |
