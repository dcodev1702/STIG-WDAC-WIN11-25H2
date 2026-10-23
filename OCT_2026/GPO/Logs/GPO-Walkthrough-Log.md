# WDAC Multi-Policy GPO Deployment — Proving-Ground Log · `WIN11-PAW-WDAC`

| | |
|---|---|
| **Effort** | Deploy the App Control multiple-policy-format base policy through **two GPOs** (Audit / Enforce) linked to the device's OU. A separate effort from `C:\WDAC\config\README.md`, which was **not modified**. |
| **Guide** | `C:\WDAC\GPO\GPO-README.md` · scripts `C:\WDAC\GPO\scripts\` · logs `C:\WDAC\GPO\Logs\` · packages `C:\WDAC\GPO\Packages\` |
| **Operator** | Claude Code (agent) on `WIN11-PAW-WDAC` as `skynet\lorenzo` (Domain Admin), with user decisions recorded below |
| **Started** | 2026-10-23 18:17 (+02:00) |

## Discovery (read-only) — 2026-10-23 18:17 – 18:20

| Item | Value |
|---|---|
| Computer DN | `CN=WIN11-PAW-WDAC,OU=JMSC-WDAC-WRKSTNS,DC=skynet-home,DC=local` |
| **Target OU** | **`OU=JMSC-WDAC-WRKSTNS,DC=skynet-home,DC=local`**: only member `WIN11-PAW-WDAC`; no child OUs; no GPO links; ProtectedFromAccidentalDeletion = True |
| Domain | `skynet-home.local` (`SKYNET`), domain mode `Windows2025Domain`, PDC/only DC `DC25-1.skynet-home.local` (192.168.10.100) |
| GPOs applied to the VM before this effort | Default Domain Policy only |
| Tools / rights | GroupPolicy + ActiveDirectory modules present; operator in `SKYNET\Domain Admins`; SYSVOL and central store reachable |
| Other WDAC/AppLocker GPOs in the domain | Exist but are linked to other OUs. **Out of scope by user instruction**: this effort uses the multiple-policy model only, scoped to this OU/VM. |

**Microsoft Learn (verified 18:22):** *"Group Policy-based deployment of App Control for Business policies only supports single-policy format"*; multiple-policy `.cip` files are deployed by script with `CiTool --update-policy` (Windows 11 22H2+ / Server 2025). Hence the GPOs carry a **startup script + scheduled task + payload**, not the built-in *Deploy App Control for Business* setting.

## Decisions (user, 2026-10-23)

| # | Topic | Decision |
|---|---|---|
| G1 | Platforms | **Windows 11 Enterprise only.** No Server Core; DCs never get WDAC. The endpoint script skips non-client OSes (ProductType ≠ 1). |
| G2 | Delivery | **Startup script + recurring task** (GPP scheduled task as SYSTEM: at creation and every 4 h; removed when the GPO no longer applies) |
| G3 | Rollout | **Two GPOs**: one puts the OU's devices in **Audit**, the other in **Enforce** |
| G4 | Switching | **Both linked to the OU; only one link enabled at a time** (`3_GPO_set_mode.ps1`) |
| G5 | Packages | **Same rules, mode-only difference**, both built from the reference device's `Base-Enforce.xml`. Audit = rules + Audit Mode, version N; Enforce = version N+1. |
| G6 | GPO names | **`JMSC-WDAC-PAWS - AppControl Audit`** / **`JMSC-WDAC-PAWS - AppControl Enforce`** |
| G7 | Managed installer | **Left to MECM** (`CCMSetup.exe MANAGEDINSTALLER=1`); the GPOs stay pure App Control |
| G8 | Proof on this VM | **Remove the local base policy, then redeploy through the GPOs** (Audit → Enforce) |
| G9 | Machine-specific supplemental | `PAW-WDAC-Supp-ClaudeCode` stays local to this VM and is **not** packaged into the GPOs |

## Build — scripts written 2026-10-23 18:30 – 18:55
- `GPO-Settings.psd1`, `WDAC-GPO-Common.ps1`, `0_GPO_pre-flight.ps1`, `1_GPO_build_packages.ps1`, `2_GPO_create_gpos.ps1`, `3_GPO_set_mode.ps1`, `4_GPO_validate_gpos.ps1`, `5_GPO_validate_endpoint.ps1`, `6_GPO_rollback.ps1`, `Deploy-WDACPolicy.ps1` (endpoint).
- Static checks: 0 parse errors under PowerShell 7 **and** Windows PowerShell 5.1; all files ASCII-only. A linter-style fix (`$Args` automatic variable renamed in script 4) and an exit-code fix in `Deploy-WDACPolicy.ps1` (`do { } while ($false)` so guard paths still exit non-zero).

## Step Log

### Step 0 — `0_GPO_pre-flight.ps1` — ✅ PASSED 2026-10-23 18:59:32
- 20/20 OK: elevated `SKYNET\Lorenzo` (PS 7.6.8); domain `skynet-home.local`; GroupPolicy, ActiveDirectory and ConfigCI modules loaded; Domain Admins; PDC `DC25-1` with SYSVOL reachable; target OU auto-detected `OU=JMSC-WDAC-WRKSTNS,DC=skynet-home,DC=local` (member: `WIN11-PAW-WDAC`, Windows 11 Enterprise 28000); no GPO links; neither GPO existed yet.
- Reference policy: `Base-Enforce.xml` `{75AFC1CF-5372-491A-80CA-7BBB694F0A00}` v`2026.10.21.3`, Audit Mode OFF, Option 13 ON; active on the device at the same version (`PAW-WDAC-Enforced`, authorized); STIG `2 / 2`; local supplemental `PAW-WDAC-Supp-ClaudeCode` flagged *not packaged*.
- Results `C:\WDAC\GPO\Logs\0_GPO_pre-flight-20261023-185932.csv` + transcript.

### Step 1 — `1_GPO_build_packages.ps1` — ✅ PASSED 2026-10-23 18:59:44
- Highest version seen for the GUID: v`2026.10.21.3`, so **Audit = v`2026.10.21.4`**, **Enforce = v`2026.10.21.5`**.
- Gate: same GUID (base policy); options differ **only** by `Enabled:Audit Mode`; `<EKUs>`, `<FileRules>` (2,538 nodes), `<Signers>` (224), `<SigningScenarios>`, `<UpdatePolicySigners>`, `<CiSigners>` **byte-identical**; rule counts: signers 224, allow 11, deny 2,357, FileAttrib 170.
- Enforce options: Disabled:Script Enforcement, Advanced Boot Options Menu, Allow Supplemental Policies, Boot Audit On Failure, Inherit Default Policy, **Managed Installer**, UMCI, Unsigned System Integrity Policy, Update Policy No Reboot, Required:WHQL.
- Package `C:\WDAC\GPO\Packages\20261023-185944\`:

| Package | Policy | Version | `.cip` bytes | SHA-256 |
|---|---|---|---:|---|
| Audit | `PAW-WDAC-GPO-Audit` | 2026.10.21.4 | 318,508 | `F04241D3FD46A97E60D3B07166796E04B450837C58C574D89A706FD3ACAA19D2` |
| Enforce | `PAW-WDAC-GPO-Enforce` | 2026.10.21.5 | 318,516 | `51D133AAA3A5D731DB28336F991A69E5D1F1C1BF6C3E32C239315F39EDD089AB` |

- Source `Base-Enforce.xml` SHA-256 `44B7C8B2…738CF` (matches the config walkthrough); `Deploy-WDACPolicy.ps1` SHA-256 `85E1B22E…AA65C`.

### Step 2 — `2_GPO_create_gpos.ps1` — ✅ PASSED 2026-10-23 19:00:16
| | Audit | Enforce |
|---|---|---|
| GPO | `JMSC-WDAC-PAWS - AppControl Audit` `{85B428C6-DD0F-4A6A-B672-AC7F70716A6C}` | `JMSC-WDAC-PAWS - AppControl Enforce` `{432B37D5-1A72-4372-B157-5CBAD32EB908}` |
| Payload | `…\{85B428C6…}\Machine\Scripts\Startup\WDAC\` (`.cip`, manifest, deploy script) | `…\{432B37D5…}\Machine\Scripts\Startup\WDAC\` |
| Startup script | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\skynet-home.local\SysVol\…\Deploy-WDACPolicy.ps1" -Mode Audit` | same with `-Mode Enforce` |
| GPP task | `WDAC-GPO-Deploy-Audit` (SYSTEM, at creation +1 min, every 4 h, removePolicy) | `WDAC-GPO-Deploy-Enforce` |
| Other | UserSettingsDisabled; `SyncForegroundPolicy = 1`; computer version 2; CSEs GPP core + Registry + Scripts + GPP Scheduled Tasks | same |
| Link | `JMSC-WDAC-WRKSTNS` **DISABLED** (order 1) | **DISABLED** (order 2) |

### Step 4 — `4_GPO_validate_gpos.ps1` — ✅ PASSED 2026-10-23 19:00:19
- 26/26 OK: AD/SYSVOL version 2/2 for both; CSEs registered; GpoApply = Authenticated Users; payload hashes match the manifests on `DC25-1`; startup script and task definitions correct; same GUID; Audit v.4 < Enforce v.5; **active mode for the OU: None**.
- GPMC's own report (`Get-GPOReport`) parses both GPOs: *Scripts → Startup → powershell.exe … -Mode Audit|Enforce*; *Scheduled Tasks → TaskV2 WDAC-GPO-Deploy-Audit|Enforce, action R, runAs NT AUTHORITY\System, triggers RegistrationTrigger + TimeTrigger*. (The registry value shows without a display name because the central store has no `Logon.admx`; the value itself is in `Registry.pol`.)

### Proving ground (G8) — Step P1: remove the local base policy — ✅ 2026-10-23 19:02:31
- User confirmed: **"Remove now, I'll reboot."** Command: `.\6_GPO_rollback.ps1 -Action RemovePolicy -Confirm:$false`. The guard passed: both WDAC GPO links were disabled, so nothing would redeploy it.
- Before: STIG `2 / 2`; `PAW-WDAC-Enforced` v`2026.10.21.3` active.
- `CiTool --remove-policy {75AFC1CF-5372-491A-80CA-7BBB694F0A00} -json` → `{"OperationResult":0}`. **Effective immediately:** policy no longer listed, `{75afc1cf…}.cip` gone from `CiPolicies\Active`, **STIG `2 / 1`** (UMCI back to the OS's Smart App Control evaluation).
- `PAW-WDAC-Supp-ClaudeCode` remains on disk (`IsOnDisk True`) but **inactive** (`IsEnforced False`, `IsAuthorized False`): a supplemental needs its base.
- Results `C:\WDAC\GPO\Logs\6_GPO_rollback-20261023-190231.csv`.

### Proving ground — Step P2: reboot (by the user) — ✅ booted 2026-10-23 19:03:31
- Check 19:10:55: **STIG `2 / 1`**; no custom base policy; `PAW-WDAC-Supp-ClaudeCode` inactive; no `WDAC-GPO-*` tasks; no deploy log; both links disabled; `gpresult` → only *Default Domain Policy* applied. Clean starting point for a first-time GPO deployment.

### Proving ground — Step P3: OU → **Audit** via GPO — ✅ 2026-10-23 19:11:08 – 19:13:05
- `.\3_GPO_set_mode.ps1 -Mode Audit -GpUpdate` → Audit link **enabled** (was False), Enforce link disabled; `gpupdate` → *Computer Policy update has completed successfully*.
- GPP created task `WDAC-GPO-Deploy-Audit`: SYSTEM / Highest; triggers `RegistrationTrigger (delay PT1M)` + `TimeTrigger every PT4H` (next 20:00); action `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\skynet-home.local\SysVol\…\{85B428C6…}\Machine\Scripts\Startup\WDAC\Deploy-WDACPolicy.ps1" -Mode Audit`.
- **19:12:10 task ran (result 0).** Deploy log, 19:12:38: *"PAW-WDAC-GPO-Audit {75afc1cf…}: deployed v2026.10.21.4 (Audit), was not active; CiTool now reports v2026.10.21.4, IsAuthorized True. SHA-256 F04241D3…19D2. run as NT AUTHORITY\SYSTEM from \\skynet-home.local\SysVol\…\WDAC"* · *"KMCI/UMCI = 2 / 1 (expected UMCI 1 for Audit)"*. Application events 1001 + 1002 (source WDAC-GPO).
- `PAW-WDAC-Supp-ClaudeCode` became **active and authorized** again once its base returned.
- **`5_GPO_validate_endpoint.ps1` → PASSED 14/14** (results `5_GPO_validate_endpoint-20261023-191301.csv`): in OU; applied GPOs = *JMSC-WDAC-PAWS - AppControl Audit; Default Domain Policy*; task result 0; state `Deployed`; active `PAW-WDAC-GPO-Audit` v.4 authorized = package v.4; `.cip` on disk; **3099** *"…PAW-WDAC-GPO-Audit. id GPO-AUDIT-2026.10.21.4. Status 0x0"*; **STIG `2 / 1`** (audit); 3076 = 0, 3077 = 0.
- `4_GPO_validate_gpos.ps1` → PASSED; **active mode for the OU: Audit**.

### Proving ground — Step P4: OU → **Enforce** via GPO — ✅ 2026-10-23 19:13:26 – 19:15:47
- `.\3_GPO_set_mode.ps1 -Mode Enforce -GpUpdate` → Audit link disabled (was True), **Enforce link enabled**; `gpupdate` succeeded. Right after it:
  - GPP **removed** `WDAC-GPO-Deploy-Audit` (removePolicy, since that GPO no longer applies) and **created** `WDAC-GPO-Deploy-Enforce`.
  - `gpresult` → *JMSC-WDAC-PAWS - AppControl Enforce; Default Domain Policy*.
- **19:14:28 task ran (result 0).** Deploy log, 19:14:32: *"PAW-WDAC-GPO-Enforce {75afc1cf…}: deployed v2026.10.21.5 (Enforce), **was v2026.10.21.4**; CiTool now reports v2026.10.21.5, IsAuthorized True. SHA-256 51D133AA…89AB. run as NT AUTHORITY\SYSTEM from \\skynet-home.local\SysVol\…\{432B37D5…}\…\WDAC"* · *"KMCI/UMCI = 2 / 2 (expected UMCI 2 for Enforce)"*. This is an **in-place replace** (same GUID, higher version, no reboot).
- **`5_GPO_validate_endpoint.ps1` → PASSED 15/15** (`5_GPO_validate_endpoint-20261023-191509.csv`): applied GPO = Enforce only; task result 0; state `Deployed 2026.10.21.4 -> 2026.10.21.5`; active `PAW-WDAC-GPO-Enforce` v.5 authorized = package; `.cip` on disk; **3099** *"…PAW-WDAC-GPO-Enforce. id GPO-ENFORCE-2026.10.21.5. Status 0x0"*; **`2 / 2` — V-243450 & V-243451 PASS**; 3076 = 0, 3077 = 0; supplemental authorized.
- `C:\WDAC\config\scripts\7_DISA_STIG_CHECK.ps1` → **V-243450 = 2 PASS, V-243451 = 2 PASS**.
- **Positive test (19:15:29):** `pwsh` FullLanguage; VS Code 1.143.1; az 2.91.0; Ubuntu 26.04.1 as `lorenzo`; WinDirStat launched and ran; the Claude Code session kept running.
- **Negative test (19:15:46):** `C:\Program Files\Mozilla Firefox\firefox.exe` and `Desktop\Firefox.exe` → **"An Application Control policy has blocked this file."**; 0 Firefox processes; **2 × 3077 attributed to `PAW-WDAC-GPO-Enforce`** (records 585, 589; Mozilla Corporation). Evidence `C:\WDAC\GPO\Logs\GPO-Enforce-3077-Events.csv/.md`.

### Proving ground — Step P5: cold boot under the GPO (startup-script path) — ✅
- User chose **"You reboot now"**. Agent ran `Restart-Computer` at 2026-10-23T19:16:55.0350388+02:00. Expected after boot: the startup script logs *already active* for v.5 (SYSTEM, from SYSVOL), STIG `2 / 2`, Enforce GPO applied.
- **Booted 2026-10-23 19:17:02.** Group Policy Operational log:
  - **4018 / 5018** *"Starting / Completed Startup script for SKYNET\WIN11-PAW-WDAC$"* at 19:17:11
  - **4016 / 5016** *"…Group Policy Scheduled Tasks Extension Processing"* at 19:17:11 (GPP re-created the task)
- **Startup-script path proven:** deploy log 19:17:17 *"PAW-WDAC-GPO-Enforce {75afc1cf…}: v2026.10.21.5 (Enforce) is already active. run as NT AUTHORITY\SYSTEM from \\skynet-home.local\SysVol\…\{432B37D5…}\…\WDAC"* (before the task's first run).
- **Task path after boot:** `WDAC-GPO-Deploy-Enforce` ran 19:18:12 (result 0) → *already active* at 19:18:14. Application events 1000 + 1002 for both runs.
- **3099 at boot (19:17:00):** *"…PAW-WDAC-GPO-Enforce. id GPO-ENFORCE-2026.10.21.5. Status 0x0"*: the policy loaded from `CiPolicies\Active` at boot, before Group Policy even ran.
- **3077 review:** 3 blocks since enforcement, **all Firefox** (records 585 + 589 = agent's PowerShell launches; 593 at 19:16:24 = `Desktop\Firefox.exe` from **explorer.exe**, i.e. a user double-click). Evidence `C:\WDAC\GPO\Logs\GPO-Enforce-3077-Events.csv/.md`.
- **Script enhancement:** `5_GPO_validate_endpoint.ps1` gained **`-BlockTestPattern`** (default empty). 3077s matching it are listed as *expected*; anything else is a *block to review* (WARN), with drive-letter paths. Re-tested: PS7 with pattern → **PASSED, 15/15 OK**; 5.1 without pattern → *PASSED with 2 warnings* (blocks to review), as designed. 0 parse errors / ASCII.
- **Final `5_GPO_validate_endpoint.ps1 -BlockTestPattern 'Mozilla|Firefox'` (19:21:48) → PASSED, 15/15 OK**: applied GPO = Enforce only; task result 0; state `NoChange (Current 2026.10.21.5)`; v.5 active and authorized; `.cip` on disk; 3099; **STIG `2 / 2` — V-243450 & V-243451 PASS**; expected blocks: both Firefox binaries; supplemental authorized.
- **Final `4_GPO_validate_gpos.ps1` (19:21:52) → PASSED; active mode for the OU: Enforce.**

## Proving-Ground Result — ✅ GPO deployment proven end to end

| Stage | When | Mechanism | Policy on the VM | STIG (KMCI / UMCI) |
|---|---|---|---|:---:|
| P1 local policy removed | 19:02:31 | `6_GPO_rollback.ps1 -Action RemovePolicy` | none (supplemental inactive) | 2 / 1 |
| P2 reboot | 19:03:31 | — | none | 2 / 1 |
| P3 OU → Audit | 19:12:10 | GPP task (SYSTEM, SYSVOL) | `PAW-WDAC-GPO-Audit` v2026.10.21.4 | 2 / 1 |
| P4 OU → Enforce | 19:14:28 | GPP task, in-place v.4 → v.5 | `PAW-WDAC-GPO-Enforce` v2026.10.21.5 | **2 / 2** |
| P5 cold boot | 19:17:17 | **startup script** + task, both *already active* | v2026.10.21.5 | **2 / 2** |

- Approved apps verified under the GPO-deployed policy (pwsh FullLanguage, VS Code, Claude Code, az, Ubuntu 26.04, WinDirStat); Firefox **blocked**.
- Current state: OU `JMSC-WDAC-WRKSTNS` in **Enforce** mode (Enforce link enabled, Audit link disabled).

## Deliverables — 2026-10-23 19:24
- `C:\WDAC\GPO\GPO-README.md`: step-by-step guide with validations (441 lines; 16/16 in-page links resolve; every referenced script exists; no machine-specific content).
- `C:\WDAC\GPO\scripts\`: `GPO-Settings.psd1`, `WDAC-GPO-Common.ps1`, `0_`–`6_` scripts, endpoint `Deploy-WDACPolicy.ps1`. All run in PowerShell 7 and Windows PowerShell 5.1 (0 parse errors in both, ASCII-only).
- `C:\WDAC\GPO\Packages\20261023-185944\`: the deployed Audit v.4 / Enforce v.5 packages.
- `C:\WDAC\GPO\Logs\`: this log, every script transcript and PASS/FAIL CSV, `GPO-Inventory.json`, 3077 evidence, `GPO-Deployment-Report.html`.
- `C:\WDAC\config\` **not modified** by this effort (README SHA-256 prefix unchanged `D11AACAC41D1D54A`).

*Log closed 2026-10-23 19:24:57 (+02:00).*
