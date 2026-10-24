# WDAC Multi-Policy GPO Deployment — Proving-Ground Log · `WIN11-PAW-WDAC`

| | |
|---|---|
| **Effort** | Deploy the App Control multiple-policy-format base policy through **two GPOs** (Audit / Enforce) linked to the device's OU. A separate effort from `C:\WDAC\config\README.md`, which was **not modified**. |
| **Guide** | `C:\WDAC\GPO\README.md` (named `GPO-README.md` until 2026-10-24) · diagram `C:\WDAC\GPO\images\` · scripts `C:\WDAC\GPO\scripts\` · logs `C:\WDAC\GPO\Logs\` · packages `C:\WDAC\GPO\Packages\` |
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
- `C:\WDAC\GPO\GPO-README.md` (renamed `README.md` by the user on 2026-10-24): step-by-step guide with validations (441 lines; 16/16 in-page links resolve; every referenced script exists; no machine-specific content).
- `C:\WDAC\GPO\scripts\`: `GPO-Settings.psd1`, `WDAC-GPO-Common.ps1`, `0_`–`6_` scripts, endpoint `Deploy-WDACPolicy.ps1`. All run in PowerShell 7 and Windows PowerShell 5.1 (0 parse errors in both, ASCII-only).
- `C:\WDAC\GPO\Packages\20261023-185944\`: the deployed Audit v.4 / Enforce v.5 packages.
- `C:\WDAC\GPO\Logs\`: this log, every script transcript and PASS/FAIL CSV, `GPO-Inventory.json`, 3077 evidence, `GPO-Deployment-Report.html`.
- `C:\WDAC\config\` **not modified** by this effort (README SHA-256 prefix unchanged `D11AACAC41D1D54A`).

*Log closed 2026-10-23 19:24:57 (+02:00).*

### Correction — Enforce → Audit order — 2026-10-23 23:20
- Found while answering *"how do I go from Enforcing to Audit via GPO?"*: GPO-README §10.2 and the warning text in `3_GPO_set_mode.ps1` said *build + publish a new pair, then switch to Audit*. That leaves a race: `2_GPO_create_gpos.ps1` updates **both** GPOs, so with the Enforce link still enabled a device refreshing in between takes the new, higher **Enforce** version and then ignores the new Audit one.
- **Fixed order (README §10.2 + script 3 warning):** `3_GPO_set_mode.ps1 -Mode Audit` **first**, then `1_GPO_build_packages.ps1` → `2_GPO_create_gpos.ps1` → `4_GPO_validate_gpos.ps1` → endpoint refresh → `5_GPO_validate_endpoint.ps1`. README also notes passing `-AuditVersion` explicitly when building on a different reference device. Script 3 re-checked: 0 parse errors (PS7 + 5.1), ASCII-only. Not executed (the OU stays in Enforce).

### Change — Date-based policy versions `YYYY.MM.DD.N` (D15 / G10) — ✅ 2026-10-23 23:50
- **User decision:** adopt `YYYY.MM.DD.N` (local date; counter N restarts at 1 each day) in the GPO **and** config scripts, so administrators can read the build date from the version. Lifts the earlier "don't touch config README" for this one cross-cutting change.
- **Safety rule:** a new version is never lower than the highest version already known for the policy. Windows compares the four parts in order (date outranks counter), and CiTool/the GPO endpoint script only move forward. Clock skew or a later-dated version → continue after it.
- **Shared helper `WDAC-Version.ps1`**, identical (hash-verified) in `C:\WDAC\config\scripts`, `…\pwsh_5.1`, `C:\WDAC\GPO\scripts` (and the `C:\WDAC-Scripts` working copies): `Get-WdacNextVersion`, `Get-WdacActivePolicyVersion`, `Get-WdacVersionsFromXml`, `Get-WdacVersionsFromArchive -Name` (only the base policy's own archives; a local supplemental's archive was being counted before the filter was added), `Get-WdacVersionsFromManifests`.
- **Config scripts 1 / 4 / 6 (both editions):** hard-coded `2026.10.21.1/.2/.3` replaced by the helper (known = active policy + previous stage's XML + base-policy archives); archive names use the computed version; each script prints *"Policy version … (basis; highest known …)"*. Script 8 comment updated.
- **GPO:** `1_GPO_build_packages.ps1` picks today's pair above every known version, **including the packages already published in both GPOs (SYSVOL)**; an explicit `-AuditVersion` that isn't higher is refused. `0_GPO_pre-flight.ps1` shows the pair the next build would use and recognizes a GPO-deployed active policy (*"deployed by the Enforce GPO package"*).
- **READMEs:** config README §1.5 (scheme + IMPORTANT callout), Step 2/5/6/7/8.2 wording, §11 Option A snippet, Appendix B; GPO-README §1.2 note, §5 row, §6 versions + proven output, §10.2, Appendix A. Links: config 15/15, GPO 16/16 resolve; no Claude mentions.
- **Tests:**
  - Helper unit tests identical in PS7 and 5.1: no history → `2026.10.23.1`; after `.21.5` → `.23.1/.2`; same day after `.23.3` → `.4/.5`; future `.25.2` → `.25.3`; next day → `.24.1`; 9 Oct → `2026.10.9.1`; overflow guard.
  - GPO pre-flight PASSED (PS7 + 5.1) → next pair `2026.10.23.1 / .2` (2 published payloads read).
  - 5.1 `1_GPO_build_packages.ps1 -AuditVersion 2026.10.21.5` → refused (STOP, nothing built); 5.1 automatic build → `PAW-WDAC-GPO-Audit v2026.10.23.1` / `-Enforce v2026.10.23.2`, gate PASSED. The **test package was deleted** and `latest.txt` restored to `Packages\20261023-185944`. **Nothing was published**: the OU stays in Enforce at `2026.10.21.5`.
  - Config selection lines with real data → `2026.10.23.1`; a same-day chain gives `.1 → .2 → .3`. (Config scripts 1/4/6 themselves were not run, because they deploy.)
  - 40 script files: 0 parse errors (PS7 + 5.1), ASCII-only.
- `C:\WDAC\results\config-upload-manifest-SHA256.csv` regenerated (31 files) because config changed.

### Operation — OU Enforce → **Audit** via GPO (README §10.2, as written) — ✅ 2026-10-24 01:27 – 01:28
- **User request:** *"put the system back in Audit mode and install all the tools you need … You'll have to go to Audit mode via GPO first."*
- `3_GPO_set_mode.ps1 -Mode Audit` (01:27:06) → PASSED with the expected WARN (*"Devices that already run Enforce v2026.10.21.5 will NOT go back to Audit v2026.10.21.4 … build a new pair"*); Audit link enabled, Enforce link disabled.
- `1_GPO_build_packages.ps1` (01:27:15) → PASSED: pair **`2026.10.24.1` / `2026.10.24.2`** (today, counter 1; highest known v2026.10.21.5 incl. 2 published payloads); gate identical to the first build (options differ only by Audit Mode; 2,538 FileRules / 224 Signers identical). Package `Packages\20261024-012715`; Audit `.cip` SHA-256 `CAC570F1…84D0`, Enforce `87BA852A…923E`.
- `2_GPO_create_gpos.ps1` (01:27:53) → PASSED (both GPOs updated in place, links left as they were); `4_GPO_validate_gpos.ps1` (01:27:56) → PASSED, no FAIL or WARN rows, **active mode for the OU: Audit**, Audit v.24.1 < Enforce v.24.2.
- `gpupdate /target:computer /force`, then `Start-ScheduledTask WDAC-GPO-Deploy-Audit` (01:28:22, result 0). Deploy log 01:28:27: *"PAW-WDAC-GPO-Audit {75afc1cf…}: deployed v2026.10.24.1 (Audit), was v2026.10.21.5 … IsAuthorized True … run as NT AUTHORITY\SYSTEM"* · *"KMCI/UMCI = 2 / 1"*. In place, no reboot.
- `5_GPO_validate_endpoint.ps1` (01:28:37) → **PASSED**: applied GPOs = Audit + Default Domain Policy; active `PAW-WDAC-GPO-Audit` v2026.10.24.1 = package; 3099 *"id GPO-AUDIT-2026.10.24.1. Status 0x0"*; **STIG 2 / 1**; supplemental authorized.

### Tooling installed while in Audit (user request) — 2026-10-24 01:29 – 01:35
| Tool | How | Result |
|---|---|---|
| Git | `winget install --id Git.Git -e --scope machine --silent` | 2.55.0.5, installer hash verified by winget |
| GitHub CLI | `winget install --id GitHub.cli -e --scope machine --silent` | 2.103.1, installer hash verified |
| GitHub login | `gh auth login --web --git-protocol https` (device code entered by the user) | account `dcodev1702`, token in the Windows keyring, scopes gist / read:org / repo |
| Az PowerShell (PS7) | `Install-PSResource -Name Az -Scope AllUsers -TrustRepository` (PSGallery) | Az 16.4.0 + 102 `Az.*` modules in `C:\Program Files\PowerShell\Modules`; `Import-Module Az.Accounts` OK in a fresh pwsh |
- These ran under the **Audit** policy, so their files are logged as 3076, not blocked. **Under Enforce they will be blocked** unless the reference policy allows them (rebuild → new pair). Pending user decision.
- The private reference repo `dcodev1702/USAREUR-AF-CYBER-RANGE` was cloned read-only into the agent's scratch folder (nothing from it was executed) to match its diagram style.

### Change — STIG values shown with their meaning — ✅ 2026-10-24 01:20 – 01:45
- **User request:** show `0` / `1` / `2` as **OFF / AUDIT / ENFORCING** next to the STIG IDs, and have the STIG check name the policy, version and other details so the result can be explained.
- GPO scripts: `WDAC-GPO-Common.ps1` gained `Format-WdacCiStatus` / `Format-WdacStig` (e.g. *"V-243450 kernel 2 (ENFORCING) / V-243451 user 1 (AUDIT)"*), used by `0_GPO_pre-flight.ps1`, `5_GPO_validate_endpoint.ps1` (*"user mode 1 (AUDIT) expected in Audit mode: V-243451 stays open until Enforce"*) and `6_GPO_rollback.ps1`. `Deploy-WDACPolicy.ps1` logs *"Win32_DeviceGuard V-243450 kernel = 2 (ENFORCING), V-243451 user = 1 (AUDIT) (expected user 1 (AUDIT) for Audit)"* (verified in a manual run). The published GPOs still carry the earlier endpoint script until the next package is published.
- Config: see the entry of the same time in `C:\WDAC\results\WDAC-STIG-Walkthrough-Log.md` (script 7 rewrite, stage checks 0/2/4, run report).

### Change — Architecture diagram (README §1.1) — ✅ 2026-10-24 01:40 – 01:50
- The ASCII block in §1.1 is replaced by `images\WDAC-GPO-Architecture.png` (3200 × 3616, rendered at 2x) with descriptive alt text and a link to the source `images\WDAC-GPO-Architecture.svg` (1600 × 1808). `images\WDAC-GPO-Architecture.spec.json` is the layout source the SVG was generated from.
- Style taken from the user's reference repo (`RANGE-INFRA\usareur-af-cyber-range.svg`): dark neon palette, cards with glowing top bars, uppercase section labels with coloured bullets, callouts, footer pills, dashed connectors into a bar, a two-lane corridor, a panel with banner and sub-cards, legend.
- Content: reference device / domain + SYSVOL (two GPOs) / Windows 11 endpoints; target-OU bar; policy-delivery and proof lanes; STIG outcome (V-243450, V-243451 with 0/1/2 meanings), versions, mode change order, validation, rollback. Every claim checked against the scripts (e.g. `-WhatIf` via `SupportsShouldProcess`, `exit 1` on FAIL, Event 2001/2004). Layout checker: no text overflow; PNG reviewed visually.

### Change — Y/N confirmation before App Control changes (`-NoConfirm`) — ✅ 2026-10-24 01:45 – 02:00
- **User request:** scripts that apply policy or change WDAC must warn in yellow and ask Y/N, with a `-NoConfirm` switch for automation (e.g. GPO), in config and GPO scripts, and the documentation must say what the user has to do and why.
- **Helper `WDAC-Confirm.ps1`** (`Confirm-WdacChange`, `Test-WdacInteractive`), identical (hash `4CF7BAF9…7F2B`) in `config\scripts`, `config\scripts\pwsh_5.1`, `GPO\scripts`. Yellow summary → `Continue? [Y/N]`; Y/Yes continues; N/No stops; 3 invalid answers stop; `-NoConfirm` continues without asking; a non-interactive session (not `UserInteractive`, started with `-NonInteractive`, or stdin redirected) without `-NoConfirm` **stops before any change** instead of waiting.
- **Gated:** config 1 / 4 / 6 (both editions: after the checks, before compile/archive/deploy); GPO 2 (after the manifests are validated, before any GPO change; shows the pair and the enabled link), 3 (only when the mode actually changes; shows before → after), 6 (one prompt per action, then `$ConfirmPreference = 'None'` so `ShouldProcess` only serves `-WhatIf`; the RemovePolicy link guard now runs before the prompt). `Deploy-WDACPolicy.ps1` asks only when it is about to deploy; it logs **2005** (not confirmed) or **3006** (non-interactive without `-NoConfirm`) and deploys nothing. `2_GPO_create_gpos.ps1` now writes `-NoConfirm` into `scripts.ini` and the GPP task; `4_GPO_validate_gpos.ps1` fails a GPO without it. Not gated (read-only or local files only): config 0, 0_1, 2, 3, 3_1, 5, 7, 8; GPO 0, 1, 4, 5.
- **Tests (2026-10-24 01:50 – 01:54):**
  - Unit, PS7 and 5.1 identical: non-interactive → STOP; `-NoConfirm` → continue; `y` → continue; `N` → STOP; `maybe` then `Yes` → continue; 3 invalid → STOP.
  - Integration (non-interactive shell, so the gates must stop): `3 -Mode Audit` (no change, no prompt) PASSED; `3 -Mode Enforce`, `2`, `6 -Action DisableLinks` → yellow summary + **STOP, nothing changed**. A before/after snapshot of both links, GPO modification times and versions was **identical**. `6 -Action DisableLinks -WhatIf` → *What if* only.
  - Script 2 first showed `v?` when the package path was wrong (test-harness argument). Fixed so it validates both manifests **before** the prompt; re-run shows `Audit v2026.10.24.1 / Enforce v2026.10.24.2` and stops.
  - Endpoint: `Deploy-WDACPolicy.ps1` (new) against a scratch copy of the Audit package whose manifest claimed v2026.10.24.9 → yellow warning, **ERROR 3006, not deployed**, active policy still v2026.10.24.1. State restored by running the GPO task (01:53:47, `NoChange`).
  - 43 script files: 0 parse errors in PS7 and 5.1, ASCII-only.
- **Docs:** GPO README IMPORTANT block in §4 (what each step shows, Y/N, `-NoConfirm`, `-WhatIf`, why the GPO passes `-NoConfirm`), "(asks first)" in the run-order table, startup-script row, §11 rollback table, troubleshooting rows, Appendix A/B/C (2005, 3006). Config README: see the config log. Links: GPO 18/18, config 23/23 resolve; no Claude mentions.
- **Open:** `4_GPO_validate_gpos.ps1` now reports **4 FAIL** on the live GPOs (startup script and task of both lack `-NoConfirm`) because they were published before this change. Building and publishing a new pair (`1_` → `2_ -NoConfirm`) fixes it and ships the new endpoint script. **Not done; waiting for the user.** → done below.

### Operation — Republish in **Audit** (new endpoint script + `-NoConfirm`) — ✅ 2026-10-24 02:21 – 02:23
- **User decision:** *"I don't want the machine to be in enforcing mode. Once Audit is back and correct …"* Links before and after: Audit **enabled**, Enforce disabled (unchanged).
- `1_GPO_build_packages.ps1` (02:21:34) → PASSED: pair **`2026.10.24.3` / `2026.10.24.4`**, package `Packages\20261024-022134` (Audit `.cip` SHA-256 `DEE8B2FB…8530`, Enforce `0C457AC9…305C`); now contains the new `Deploy-WDACPolicy.ps1`.
- `2_GPO_create_gpos.ps1 -NoConfirm` (02:22:06) → yellow summary (*"publish Audit v2026.10.24.3 / Enforce v2026.10.24.4 … Enabled link now: JMSC-WDAC-PAWS - AppControl Audit"*), *-NoConfirm: continuing*, PASSED. Startup script and task now end in `-Mode <Mode> -NoConfirm`.
- `4_GPO_validate_gpos.ps1` (02:22:09) → **PASSED** (the 4 FAILs are gone); active mode for the OU: **Audit**; Audit v.24.3 < Enforce v.24.4.
- `gpupdate` + `WDAC-GPO-Deploy-Audit` (02:22:31, result 0; task arguments `… -Mode Audit -NoConfirm`). **First run of the new endpoint script under SYSTEM:** *"deployed v2026.10.24.3 (Audit), was v2026.10.24.1 … IsAuthorized True"* · *"Win32_DeviceGuard V-243450 kernel = 2 (ENFORCING), V-243451 user = 1 (AUDIT) (expected user 1 (AUDIT) for Audit)"*.
- `5_GPO_validate_endpoint.ps1` (02:22:42) → **PASSED**, no WARN/FAIL: Audit GPO only; v.24.3 active = package; 3099 *"id GPO-AUDIT-2026.10.24.3. Status 0x0"*; `V-243450 kernel 2 (ENFORCING) / V-243451 user 1 (AUDIT)`. `7_DISA_STIG_CHECK.ps1` → `RESULT: 2 / 1 = ENFORCING / AUDIT`, effective policy `PAW-WDAC-GPO-Audit v2026.10.24.3 (AUDIT)`.
- Round 2 of the allow list (git, gh, Az) continues on the reference device: see `C:\WDAC\results\WDAC-STIG-Walkthrough-Log.md`.

### Correction — STIG terminology — ✅ 2026-10-24 02:30 – 02:35
- **User:** *"the optional fix is important for accurate messaging."* Verified against the Microsoft Windows PAW STIG (stigviewer mirror, 2026-02-25 release): **V-243450 / V-243451 are Vulnerability (Finding) IDs**; **WPAW-00-001050 / WPAW-00-001060 are the STIG IDs**; both medium = **CAT II**; DISA check text names the values *0 Not Configured · 1 Audit · 2 Enforced*.
- Diagram: the two finding cards now read *"STIG ID WPAW-00-001050 · CAT II · kernel mode"* / *"STIG ID WPAW-00-001060 · CAT II · user mode (UMCI)"*; banner *"Microsoft Windows PAW STIG · App Control"*. Regenerated (no overflow warnings) and reviewed visually. README §1.1 contains only the image embed; no copy of the old ASCII diagram exists anywhere under `C:\WDAC` (grep of its lines: no match). The GPO README only uses the Vulnerability IDs, correctly.

### Change — versioned XML names in GPO packages — ✅ 2026-10-24 02:40
- **`1_GPO_build_packages.ps1`:** `Packages\<stamp>\xml\` (never published to SYSVOL) now names the compiled XMLs with their versions (`PAW-WDAC-GPO-Audit_v<N>.xml`, `PAW-WDAC-GPO-Enforce_v<N+1>.xml`) and keeps `source_Base-Enforce_v<version>.xml`. The naming lines were unit-tested; the full build runs at the next package build.
  - The config scripts now count this device's GPO package versions, so a reference device never stamps a local policy with a version that a published package already uses. Found on the live system: the round-2 merge would have taken v2026.10.24.4 = the Enforce package in SYSVOL.
  - README §6 and §8.3 updated (later rounds → config README §11 Option D, `-BaseXml Base-Enforce.xml`).

### Reference-device note — round 2 merged locally (Audit) — 2026-10-24 04:13
- The config round 2 (git, gh, Az) deployed **PAW-WDAC-Audit-Merged v2026.10.24.5** (Audit) locally on this VM, which is also the only endpoint in the OU. That is above the published Audit package v2026.10.24.3. Expect the GPO task to log **2001** (*newer version active … not downgrading*), and `5_GPO_validate_endpoint.ps1` to flag active ≠ package, until a new pair is built from the screened policy and published (Audit link stays enabled). The OU stays in **Audit**; the Enforce link was not touched. Details: `C:\WDAC\results\WDAC-STIG-Walkthrough-Log.md`.
- At 04:24:15 the scheduled task logged exactly that: *"v2026.10.24.5 is active, newer than the GPO's v2026.10.24.3 (Audit). Not downgrading"*.

### Operation — publish round 2 (git, gh, Az) with the OU in **Audit** — ✅ 2026-10-24 04:33 – 04:36
- **User decision:** *"Go with decision 2."* Links before and after: Audit **enabled**, Enforce disabled.
- New reference `C:\WDAC\Source\Base-Enforce.xml` = **PAW-WDAC-Enforced v2026.10.24.6**: the screened round-2 policy with Audit Mode OFF, prepared and gate-checked without deploying (see the config log).
- `0_GPO_pre-flight.ps1` (04:33:13) → PASSED with 2 expected WARNs: the reference device's active v.24.5 differs from `Base-Enforce.xml` v.24.6, and its STIG is `2 (ENFORCING) / 1 (AUDIT)`; the device is intentionally in Audit.
- `1_GPO_build_packages.ps1` (04:33:18) → PASSED:
  - pair **`2026.10.24.7` / `2026.10.24.8`**; options differ only by Audit Mode; FileRules (2,607) / Signers (228) identical; signers 228, allow 76, deny 2,357, FileAttrib 174;
  - Audit `.cip` SHA-256 `61347594…549C`, Enforce `22F9FDC6…22BD`; package `Packages\20261024-043318`;
  - first real run of the versioned `xml\` names: `PAW-WDAC-GPO-Audit_v2026.10.24.7.xml`, `PAW-WDAC-GPO-Enforce_v2026.10.24.8.xml`, `source_Base-Enforce_v2026.10.24.6.xml`.
- `2_GPO_create_gpos.ps1 -NoConfirm` (04:33:51) → PASSED (yellow summary: *"publish Audit v2026.10.24.7 / Enforce v2026.10.24.8 … Enabled link now: … AppControl Audit"*). `4_GPO_validate_gpos.ps1` (04:33:54) → PASSED; payload hashes match on DC25-1; **active mode for the OU: Audit**.
- `gpupdate` + `WDAC-GPO-Deploy-Audit` (04:34:17, result 0) → *"deployed v2026.10.24.7 (Audit), was v2026.10.24.5; CiTool now reports v2026.10.24.7, IsAuthorized True … run as NT AUTHORITY\SYSTEM"*.
- `5_GPO_validate_endpoint.ps1` (04:34:20) → **PASSED**, no WARN/FAIL: 3099 *"id GPO-AUDIT-2026.10.24.7. Status 0x0"*; `V-243450 kernel 2 (ENFORCING) / V-243451 user 1 (AUDIT)`; supplemental authorized.
- git, gh and Az re-run under the GPO-delivered policy → **0 × 3076, 0 × 3077** (04:34:40 onward).
- **State:** OU in Audit; the VM is GPO-managed again at v2026.10.24.7; the SYSVOL Enforce package v2026.10.24.8 is ready, with the new rules, for a later `3_GPO_set_mode.ps1 -Mode Enforce`. It still contains the 12 FileName-only rules (open decision). → superseded below.

### Operation — publish round 2b (file-name rules removed), OU stays in **Audit** — ✅ 2026-10-24 05:21 – 05:23
- **User:** *"do whatever you feel is easiest for long term maint."* The 12 unsigned file-name rules were removed. They are redundant with the Git path and folder rules, and can be spoofed. The reference was rebuilt with the hardened config scripts (config log, round 2b). New reference: `Base-Enforce.xml` = **PAW-WDAC-Enforced v2026.10.24.10**, prepared with the new `6_enforce_policy.ps1 -PrepareOnly`, so nothing was deployed locally.
- `1_GPO_build_packages.ps1` (05:21:13) → PASSED:
  - pair **`2026.10.24.11` / `2026.10.24.12`**; options differ only by Audit Mode; signers 228, **allow 66** (76 − 10 unique file-name rules), deny 2,357, FileAttrib 174;
  - Audit `.cip` SHA-256 `AB19EF6D…F482`, Enforce `74A25C73…D00B`; package `Packages\20261024-052113`.
- `2_GPO_create_gpos.ps1 -NoConfirm` (05:21:37) → PASSED; links unchanged (Audit enabled, Enforce disabled). `4_GPO_validate_gpos.ps1` (05:21:40) → PASSED; hashes match on DC25-1; **active mode: Audit**.
- `gpupdate` + task (05:22:07, result 0) → *"deployed v2026.10.24.11 (Audit), was v2026.10.24.9 … IsAuthorized True … NT AUTHORITY\SYSTEM"*.
- `5_GPO_validate_endpoint.ps1` (05:22:09) → **PASSED**: 3099 *"id GPO-AUDIT-2026.10.24.11. Status 0x0"*; `V-243450 kernel 2 (ENFORCING) / V-243451 user 1 (AUDIT)`.
- git, gh and Az under the GPO policy → **0 × 3076, 0 × 3077** (05:22:13 onward).
- **State:** OU in Audit; VM GPO-managed at v2026.10.24.11. The SYSVOL **Enforce package v2026.10.24.12** has the full allow list (round 1 + `C:\ADMIN\*` + git/gh/Az) and **no file-name rules**: ready for a later `3_GPO_set_mode.ps1 -Mode Enforce` when the user decides. No open rule decisions.

### Decision + documentation pass — 2026-10-24 05:35
- **User:** *"No thanks ..do not move to enforce. Does any documentation require updating?"* The OU **stays in Audit**; the links were checked again: Audit enabled, Enforce disabled.
- **Docs brought up to date with today's changes:**
  - GPO README §1.3 *Proven On*: three rows added (Enforce → Audit, Y/N + `-NoConfirm`, adding applications in a later round).
  - GPO README §2 and §5: the reference device may stay in Audit for a later round (`-PrepareOnly`); expect two pre-flight WARNs then.
  - GPO README §1.1 caption: new size.
- **Diagram regenerated** (1600 × 1828, no overflow; reviewed visually):
  - reference card: enforce-ready via script 6 / `-PrepareOnly`; "2, 3 and 6 ask Y/N · -NoConfirm";
  - domain card: scripts.ini + task run `… -Mode <Mode> -NoConfirm`;
  - endpoint card: Y/N on manual runs, 3006, event range 1000–3006;
  - Change-mode / Roll-back chips: Y/N, `-WhatIf`, `-NoConfirm`.
- **Config README:**
  - §1.3 workflow: sanitize drops file-name rules; `6 -PrepareOnly`; "Later · Add apps" line;
  - §1.4 golden rules 3 and 7;
  - §1.5 *Prepared for GPO* row;
  - §4 rows 9 and 14.
- Links: config 23/23, GPO 18/18; no Claude mentions; upload manifest 33 files.
- Not changed: `GPO-Deployment-Report.html` and `C:\WDAC\results\WDAC-STIG-Walkthrough-Report.html`. They are point-in-time records of 10/23.
