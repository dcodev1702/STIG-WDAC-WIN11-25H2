# App Control for Business (WDAC) — Multi-Policy GPO Deployment (Audit / Enforce GPOs)

> [!NOTE]
> This guide takes the **enforced multiple-policy-format base policy** built on a fully configured reference device (see `C:\WDAC\config\README.md`) and deploys it to every Windows 11 Enterprise computer in an OU with **two GPOs**: one puts the OU in **Audit** mode, the other in **Enforce** mode. Only one is active at a time. Endpoints deploy the policy themselves with `CiTool.exe`, run by a GPO **startup script** and a recurring **scheduled task**, and they never downgrade. Every step has a script and a validation.

> [!IMPORTANT]
> **Why a script inside a GPO, and not the built-in setting?** Microsoft: *"Group Policy-based deployment of App Control for Business policies only supports single-policy format."* The built-in *Deploy App Control for Business* setting writes a legacy `SiPolicy.p7b`. Multiple-policy `{GUID}.cip` files must be deployed with `CiTool --update-policy` (Windows 11 22H2+). These GPOs carry the `.cip`, a manifest, and the deployment script in their own SYSVOL folder, and run it as SYSTEM.

---

## Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Settings](#3-settings)
4. [Scripts at a Glance — Run Order](#4-scripts-at-a-glance--run-order)
5. [Phase 1 — Pre-Flight (Step 0)](#5-phase-1--pre-flight-step-0)
6. [Phase 2 — Build the Packages (Step 1)](#6-phase-2--build-the-packages-step-1)
7. [Phase 3 — Create and Validate the GPOs (Steps 2 and 4)](#7-phase-3--create-and-validate-the-gpos-steps-2-and-4)
8. [Phase 4 — Audit the OU (Steps 3 and 5)](#8-phase-4--audit-the-ou-steps-3-and-5)
9. [Phase 5 — Enforce the OU (Steps 3 and 5)](#9-phase-5--enforce-the-ou-steps-3-and-5)
10. [Ongoing Operations](#10-ongoing-operations)
11. [Rollback and Removal (Step 6)](#11-rollback-and-removal-step-6)
12. [Proving-Ground Procedure](#12-proving-ground-procedure)
13. [Troubleshooting](#13-troubleshooting)
- [Appendix A — Script Parameters](#appendix-a--script-parameters)
- [Appendix B — What the GPOs Contain](#appendix-b--what-the-gpos-contain)
- [Appendix C — Endpoint Artifacts and Event IDs](#appendix-c--endpoint-artifacts-and-event-ids)

---

## 1. Overview

### 1.1 Architecture

```text
 Reference device (fully configured, STIG 2/2)          Domain (SYSVOL + AD)                         Endpoints in the target OU
 ----------------------------------------------         ------------------------------------         ---------------------------------
 C:\WDAC\Source\Base-Enforce.xml                        GPO "...AppControl Audit"   (link ON|off)    Startup script (boot, SYSTEM)
   |  1_GPO_build_packages.ps1                            Machine\Scripts\Startup\WDAC\              GPP task WDAC-GPO-Deploy-<Mode>
   v                                                        {GUID}.cip  v N   (Audit Mode)             (at creation + every 4 h)
 C:\WDAC\GPO\Packages\<stamp>\Audit\   v N            -->   manifest.json  Deploy-WDACPolicy.ps1  -->      |
 C:\WDAC\GPO\Packages\<stamp>\Enforce\ v N+1              scripts.ini + ScheduledTasks.xml            Deploy-WDACPolicy.ps1:
   |  2_GPO_create_gpos.ps1                             GPO "...AppControl Enforce" (link off|ON)      verify SHA-256 -> compare version
   +------------------------------------------------>      same layout, {GUID}.cip v N+1             -> CiTool --update-policy if newer
                                                         3_GPO_set_mode.ps1 enables ONE link          -> log + event + state.json
```

### 1.2 How the Two GPOs Work Together

| Rule | Consequence |
|---|---|
| Both packages carry the **same policy GUID** | The Enforce policy **replaces** the Audit policy in place. No second base policy, so no intersection. |
| **Enforce version = Audit version + 1** | Audit → Enforce works with a simple link switch, and **no reboot** is needed. |
| The endpoint script **never downgrades** | Going **back** from Enforce to Audit needs a **new pair** with higher versions (§10.2). |
| Both GPOs are linked to the OU; **only one link is enabled** | `3_GPO_set_mode.ps1` disables before it enables, and step 4 fails if both are on. |
| **Disabling or deleting a GPO never removes the policy** from a device | Removal is an explicit step (`6_GPO_rollback.ps1 -Action RemovePolicy`). |
| The two packages are built from the **same enforced XML** | They differ **only** by `Enabled:Audit Mode`; step 1 proves it before compiling. |

> [!NOTE]
> **Versions are date-based: `YYYY.MM.DD.N`.** The date is the local date of the build, and **N** restarts at 1 each day. Today's first pair is Audit `2026.10.23.1` / Enforce `2026.10.23.2`, a second build the same day gives `.3` / `.4`, and tomorrow starts at `2026.10.24.1`. Windows compares the parts in order, so the date outranks the counter. Step 1 never picks a version below the highest one already known: the source XML, the reference device's active policy, earlier packages, and **the packages already published in both GPOs**. Any reference device therefore produces a version the endpoints accept. The helper is `scripts\WDAC-Version.ps1`, identical to the copy in `C:\WDAC\config\scripts\`. CiTool shows 9 October as `2026.10.9.1`, with no leading zeros.

### 1.3 Proven On

| Item | Value |
|---|---|
| Endpoint | Windows 11 Enterprise (build 28000), domain-joined, in OU `JMSC-WDAC-WRKSTNS` |
| Domain | `skynet-home.local`, domain mode Windows Server 2025, DC `DC25-1` |
| GPOs | `JMSC-WDAC-PAWS - AppControl Audit` / `JMSC-WDAC-PAWS - AppControl Enforce` |
| Result | A **first-time deployment** from no policy: Audit v`2026.10.21.4` (STIG `2/1`), then Enforce v`2026.10.21.5` in place (**STIG `2/2`**). Survives a cold boot (startup script *and* task). Approved apps work; the block-test app is blocked. Full record: `C:\WDAC\GPO\Logs\GPO-Walkthrough-Log.md`. |

---

## 2. Prerequisites

| Where | Requirement |
|---|---|
| **Reference device** | Finished `C:\WDAC\config\README.md`: `C:\WDAC\Source\Base-Enforce.xml` + `PolicyGuid.txt`, the enforced policy active, STIG `2 / 2`. Windows 11 Enterprise 22H2+ with **RSAT Group Policy + AD** (`Get-WindowsCapability -Online -Name Rsat.GroupPolicy*, Rsat.ActiveDirectory* \| Add-WindowsCapability -Online`) and ConfigCI (inbox). |
| **Rights** | **Domain Admins**, or **Group Policy Creator Owners** plus *Link GPOs* permission on the target OU |
| **Endpoints** | Windows 11 Enterprise **22H2 or later** (`CiTool.exe`), domain-joined, **in the target OU**. Read access to SYSVOL is the default. WinRM only for remote validation. |
| **Scope** | Windows client editions only. The endpoint script **skips** servers and domain controllers (`ProductType ≠ 1`). |
| **Managed installer** | Option 13 is ON in the policy. Designate MECM as the managed installer with `CCMSetup.exe MANAGEDINSTALLER=1`; see `C:\WDAC\config\README.md` §2. The GPOs don't configure AppLocker. |
| **Scripts** | Copy `C:\WDAC\GPO\` to the reference device. If blocked: `Get-ChildItem C:\WDAC\GPO -Recurse \| Unblock-File`. Run every script **elevated**, in PowerShell 7 **or** Windows PowerShell 5.1. |

> [!WARNING]
> Keep target computers out of the scope of any GPO that uses the legacy *Deploy App Control for Business* (`SiPolicy.p7b`) setting. A legacy single policy and this multiple-policy base policy would both be active, and they **intersect**: files would need to pass both.

---

## 3. Settings

Edit **`C:\WDAC\GPO\scripts\GPO-Settings.psd1`** once. Any script parameter with the same name overrides it.

| Setting | Proven value | Meaning |
|---|---|---|
| `TargetOU` | `''` | Distinguished name of the target OU. **Empty = the OU of the computer running the scripts.** |
| `AuditGpoName` | `JMSC-WDAC-PAWS - AppControl Audit` | Audit GPO name |
| `EnforceGpoName` | `JMSC-WDAC-PAWS - AppControl Enforce` | Enforce GPO name |
| `PolicyNamePrefix` | `PAW-WDAC-GPO` | Friendly name stamped into the packages, e.g. `PAW-WDAC-GPO-Enforce` in CiTool and Event 3099 |
| `TaskIntervalHours` | `4` | The endpoint task re-runs every N hours. It also runs about 1 minute after Group Policy (re)creates it. |
| `WdacRoot` | `C:\WDAC` | The reference device's working folders (config README layout) |
| `GpoRoot` | `C:\WDAC\GPO` | Scripts, `Packages\`, `Logs\` |

> [!IMPORTANT]
> If the reference device is **not** in the target OU, set `TargetOU` explicitly. Otherwise the GPOs are linked to the reference device's own OU.

---

## 4. Scripts at a Glance — Run Order

All scripts are in `C:\WDAC\GPO\scripts\`. Each one writes a transcript and a PASS/WARN/FAIL CSV to `C:\WDAC\GPO\Logs\`, and stops with `STOP:` on any failure.

| # | Script | Runs on | Changes | Success looks like |
|:---:|---|---|---|---|
| 0 | `0_GPO_pre-flight.ps1` | reference device | nothing (read-only) | `GPO pre-flight: PASSED` |
| 1 | `1_GPO_build_packages.ps1` | reference device | local files in `Packages\<stamp>\` | `Package build: PASSED`; Audit v N < Enforce v N+1 |
| 2 | `2_GPO_create_gpos.ps1` | reference device | creates/updates both GPOs; links them **disabled** | `GPO create / update: PASSED` |
| 4 | `4_GPO_validate_gpos.ps1` | reference device | nothing | `GPO validation: PASSED`; *Active mode: None* |
| 3 | `3_GPO_set_mode.ps1 -Mode Audit` | reference device | enables the Audit link | `Set mode Audit: PASSED` |
| 5 | `5_GPO_validate_endpoint.ps1` | reference device → endpoint(s) | nothing | `Endpoint validation (Audit): PASSED`; UMCI 1 |
| 3 | `3_GPO_set_mode.ps1 -Mode Enforce` | reference device | switches to the Enforce link | `Set mode Enforce: PASSED` |
| 5 | `5_GPO_validate_endpoint.ps1 -BlockTestPattern <regex>` | reference device → endpoint(s) | nothing | `Endpoint validation (Enforce): PASSED`; **STIG 2 / 2** |
| 6 | `6_GPO_rollback.ps1 -Action …` | reference device / endpoint | rollback / removal (asks first) | as stated |

**Quick start:**

```powershell
Set-Location C:\WDAC\GPO\scripts
.\0_GPO_pre-flight.ps1
.\1_GPO_build_packages.ps1
.\2_GPO_create_gpos.ps1
.\4_GPO_validate_gpos.ps1
.\3_GPO_set_mode.ps1 -Mode Audit            # on the proving-ground device add -GpUpdate
#   >>> endpoints: next GP refresh (or gpupdate /target:computer /force), the task runs ~1 min later
.\5_GPO_validate_endpoint.ps1 -ComputerName PAW01, PAW02
#   >>> audit period: run every app, review 3076 events (section 8.3)
.\3_GPO_set_mode.ps1 -Mode Enforce
.\5_GPO_validate_endpoint.ps1 -ComputerName PAW01, PAW02 -BlockTestPattern 'MyBlockedApp'
```

---

## 5. Phase 1 — Pre-Flight (Step 0)

```powershell
.\0_GPO_pre-flight.ps1                          # optional: -TargetOU 'OU=...,DC=...'
```

| Check | Expect |
|---|---|
| Session, domain membership, GroupPolicy / ActiveDirectory / ConfigCI modules | OK |
| Rights | `Domain Admins` (or `Group Policy Creator Owners`) |
| Domain, PDC emulator, **SYSVOL on every DC** | reachable |
| Target OU and **every member**, with OS | Windows client editions. Anything else is WARN; the endpoint script skips it. |
| GPOs already linked to the OU; whether the two GPOs exist | "will create" or "will UPDATE" |
| `Base-Enforce.xml`: GUID = `PolicyGuid.txt`, base policy, **Audit Mode OFF**, Option 13 | OK |
| Reference device: that policy **active at the same version**, STIG | `2 / 2` |
| Local supplemental policies | listed as *NOT packaged* unless you pass them to step 1 |
| `CiTool.exe` / build | build ≥ 22621 |
| Next package versions | the pair step 1 would build, e.g. *"Audit 2026.10.23.1 / Enforce 2026.10.23.2 - today …; highest known v… (… 2 published GPO payload(s))"* |

If the reference device sits in the target OU and runs a GPO-deployed version, the active-policy check reports *"deployed by the Enforce GPO package"*.

---

## 6. Phase 2 — Build the Packages (Step 1)

```powershell
.\1_GPO_build_packages.ps1                      # versions chosen automatically
.\1_GPO_build_packages.ps1 -AuditVersion 2026.11.1.10 -EnforceVersion 2026.11.1.11
.\1_GPO_build_packages.ps1 -SupplementalXml 'C:\WDAC\Source\Supp-LOB.xml'   # ship a supplemental in BOTH packages
```

1. **Versions.** By default the pair is today's `YYYY.MM.DD.N` and `N+1`, always above the highest version known for this GUID: the XML, the reference device's active policy, every earlier package, and the packages published in both GPOs. An explicit `-AuditVersion` that isn't higher than that is **refused** with `STOP:`, because endpoints would ignore it.
2. **Build.** Two copies of `Base-Enforce.xml`. The Audit copy gets `Set-RuleOption -Option 3`; the Enforce copy gets Option 3 removed. Each is stamped with the name `<prefix>-Audit|Enforce`, the ID `GPO-AUDIT|ENFORCE-<version>`, and its version.
3. **Gate.** This runs before anything compiles:
   - both copies have the same GUID and are base policies;
   - the options differ **only** by `Enabled:Audit Mode`;
   - `<EKUs>`, `<FileRules>`, `<Signers>`, `<SigningScenarios>`, `<UpdatePolicySigners>` and `<CiSigners>` are **byte-identical**.
4. **Output.** Compiled into `C:\WDAC\GPO\Packages\<stamp>\{Audit,Enforce}\`, each with `{GUID}.cip`, `manifest.json` (GUID, version, SHA-256, mode, source XML hash) and a copy of `Deploy-WDACPolicy.ps1`. `Packages\latest.txt` points to the new folder.

**Proven output** (test build with date-based versions, after the proving ground had published `2026.10.21.4` / `.5`):

```text
OK  Version plan                      next pair 2026.10.23.1 / 2026.10.23.2 - today 2026-10-23, counter 1; highest known v2026.10.21.5
                                      (source XML, this device's active policy, earlier packages, 2 published GPO payload(s))
OK  Options differ only by Audit Mode only in Audit: Enabled:Audit Mode; only in Enforce: (none)
OK  Identical <FileRules>             2538 child node(s)
OK  Audit package                     Base PAW-WDAC-GPO-Audit v2026.10.23.1 - {75AFC1CF-...}.cip 318508 bytes SHA-256 B2B3DE38...
OK  Enforce package                   Base PAW-WDAC-GPO-Enforce v2026.10.23.2 - {75AFC1CF-...}.cip 318516 bytes SHA-256 E07DE5AE...
Package build: PASSED.
```

> [!TIP]
> Machine-specific exceptions for one device don't belong in the OU-wide packages. Deploy those as a local supplemental policy on that device.

---

## 7. Phase 3 — Create and Validate the GPOs (Steps 2 and 4)

```powershell
.\2_GPO_create_gpos.ps1                         # uses Packages\latest.txt; -PackagePath <folder> to pick one
.\4_GPO_validate_gpos.ps1
```

**Step 2**, for each GPO. It **creates** the GPO if missing and **updates** it otherwise (that's also how you publish a new package):

| Action | Detail |
|---|---|
| GPO status | `UserSettingsDisabled` |
| Registry setting | *Always wait for the network at computer startup and logon* = Enabled, so the startup script has network |
| Payload | Copied to `\\<PDC>\SYSVOL\<domain>\Policies\{GPO}\Machine\Scripts\Startup\WDAC\`, replacing any earlier payload |
| Startup script | `scripts.ini`: `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\<domain>\SysVol\<domain>\Policies\{GPO}\Machine\Scripts\Startup\WDAC\Deploy-WDACPolicy.ps1" -Mode <Mode>` |
| GPP scheduled task | `WDAC-GPO-Deploy-<Mode>`: SYSTEM; runs at task creation (+1 min) and every `TaskIntervalHours`; *Replace*; **removed when the GPO no longer applies** |
| Extensions and version | Client-side extensions registered in AD; computer version raised in AD and `GPT.INI` |
| Link | Linked to the target OU **disabled**; an existing link is left as is |

**Step 4** checks, for each GPO:
- status, AD = SYSVOL version, extensions, security filtering (*Authenticated Users / Domain Computers* GpoApply), and *wait for network*;
- the payload and its hashes on **every DC**, the manifest mode, and the `scripts.ini` and `ScheduledTasks.xml` contents.

Then it checks both GPOs together:
- the link exists;
- **same GUID**, and **Audit version < Enforce version**;
- the **active mode for the OU** (`None` / `Audit` / `Enforce`), which **FAILS** if both links are enabled.

> [!NOTE]
> GPMC shows both GPOs normally: *Scripts → Startup* and *Preferences → Scheduled Tasks*. The *Always wait for the network* value may appear under *Extra Registry Settings* if your central store has no `Logon.admx`. It still applies.

---

## 8. Phase 4 — Audit the OU (Steps 3 and 5)

### 8.1 Switch the OU to Audit

```powershell
.\3_GPO_set_mode.ps1 -Mode Audit
```

Endpoints pick this up at their next background refresh (90 ± 30 minutes) or at the next boot. To speed it up on a device, run `gpupdate /target:computer /force` there. GPP creates the task, and it runs about 1 minute later.

**Proven:** the deploy log on the endpoint read *"PAW-WDAC-GPO-Audit {75afc1cf…}: deployed v2026.10.21.4 (Audit), was not active; CiTool now reports v2026.10.21.4, IsAuthorized True. … run as NT AUTHORITY\SYSTEM from \\skynet-home.local\SysVol\…"*.

### 8.2 Validate the Endpoints

```powershell
.\5_GPO_validate_endpoint.ps1                                   # this computer
.\5_GPO_validate_endpoint.ps1 -ComputerName PAW01, PAW02        # remote, over WinRM
```

| Check | Audit expectation |
|---|---|
| Computer in the target OU; `gpresult` applied GPOs | **Audit GPO only** |
| Scheduled task `WDAC-GPO-Deploy-Audit` | present, last result `0` |
| `state.json` / deploy log / events | `Deployed` or `NoChange` |
| CiTool | GUID active at the **Audit package version**, authorized; `.cip` in `CiPolicies\Active` |
| Event 3099 | *"Refreshed and activated … <prefix>-Audit. id GPO-AUDIT-<version>. Status 0x0"* |
| `Win32_DeviceGuard` | **UMCI = 1** (KMCI 1, or 2 if platform policies already enforce kernel mode) |
| 3076 / 3077 since deployment | reported |

### 8.3 The Audit Period

1. Let users run **every** application and workflow on the audited devices for long enough to cover the normal work cycle.
2. Review what would have been blocked, on an endpoint or via remoting:

   ```powershell
   C:\WDAC\config\scripts\Export-CIEventEvidence.ps1 -StartTime (Get-Date).AddDays(-7)
   ```

3. **Gaps found?** Fix them on the **reference device**:
   - capture and merge the missing apps with the config README loop (Steps 4–5 there), and enforce them there (Steps 6–7);
   - then **rebuild and publish**: `1_GPO_build_packages.ps1` → `2_GPO_create_gpos.ps1` → `4_GPO_validate_gpos.ps1`;
   - audited endpoints move to the new, higher Audit version automatically.
4. **No gaps** (only the block-test app, or nothing at all)? Go to Phase 5.

---

## 9. Phase 5 — Enforce the OU (Steps 3 and 5)

```powershell
.\3_GPO_set_mode.ps1 -Mode Enforce
.\5_GPO_validate_endpoint.ps1 -ComputerName PAW01, PAW02 -BlockTestPattern 'MyBlockedApp'
```

What happens on each endpoint at its next refresh:
- The Audit GPO no longer applies, so GPP **removes** `WDAC-GPO-Deploy-Audit`.
- The Enforce GPO creates `WDAC-GPO-Deploy-Enforce`. That task replaces the Audit version with Enforce version + 1 **in place, without a reboot**.

| Check | Enforce expectation |
|---|---|
| Applied GPOs | **Enforce GPO only** |
| CiTool | GUID active at the **Enforce package version**, authorized |
| `Win32_DeviceGuard` | **`2 / 2` — V-243450 & V-243451 PASS** |
| 3077 | Only the block-test app (expected with `-BlockTestPattern`). Anything else appears as *blocks to review*. |

**Proven endpoint result:**

```text
OK  active policy      PAW-WDAC-GPO-Enforce {75afc1cf-...} v2026.10.21.5 active=True authorized=True (GPO package v2026.10.21.5)
OK  Event 3099         Refreshed and activated Code Integrity policy {75afc1cf-...} PAW-WDAC-GPO-Enforce. id GPO-ENFORCE-2026.10.21.5. Status 0x0
OK  Win32_DeviceGuard  2 / 2 - V-243450 & V-243451 PASS
OK  expected blocks    matching 'Mozilla|Firefox': C:\Program Files\Mozilla Firefox\firefox.exe <- pwsh.exe; ...
Endpoint validation (Enforce): PASSED.
```

**Then prove the block and the reboot:**
- Launching the block-test app shows *"Your organization used App Control for Business to block this app"*, or in PowerShell *"An Application Control policy has blocked this file."*
- After a **reboot**, step 5 should still pass. The deploy log shows the startup script at boot: *"… is already active. run as NT AUTHORITY\SYSTEM from \\<domain>\SysVol\…"*. The GroupPolicy/Operational log shows events **4018 / 5018** *Starting / Completed Startup script*.

---

## 10. Ongoing Operations

### 10.1 Publish an Updated Policy (Same Mode, No Reboot)

1. On the reference device, change and enforce the policy with the config README.
2. Run `.\1_GPO_build_packages.ps1`. It produces a new pair with higher versions.
3. Run `.\2_GPO_create_gpos.ps1` (it updates both GPOs in place), then `.\4_GPO_validate_gpos.ps1`.
4. Endpoints apply the new version at their next refresh, within `TaskIntervalHours`, or at boot.

### 10.2 Demote Enforce → Audit

> [!CAUTION]
> Switching the link back to Audit **alone does nothing** on devices that already run the higher Enforce version, because the endpoint script never downgrades. `3_GPO_set_mode.ps1 -Mode Audit` warns about this.

Do it in **this order**. Switching first closes a race: if you publish while the Enforce link is still enabled, a device that refreshes in between takes the new, higher **Enforce** version and then ignores the new Audit one.

1. `.\3_GPO_set_mode.ps1 -Mode Audit`. Expect the warning. Devices stay enforced for now: they log **2001** *"newer version active … not downgrading"* against the old Audit package.
2. `.\1_GPO_build_packages.ps1`. The new pair uses today's date and is above the published Enforce version, e.g. Audit `2026.10.24.1` / Enforce `2026.10.24.2`.
3. `.\2_GPO_create_gpos.ps1`, then `.\4_GPO_validate_gpos.ps1`. Expect *Active mode: Audit* and Audit < Enforce.
4. On the endpoints, wait for the next refresh or run `gpupdate /target:computer /force`, then `.\5_GPO_validate_endpoint.ps1`. Expect the new Audit version active and **UMCI = 1**.

Later, `3_GPO_set_mode.ps1 -Mode Enforce` returns to Enforce **in place**, because the new Enforce version is higher.

> [!NOTE]
> Building on a different reference device than last time is safe. Step 1 reads the versions already **published in both GPOs**, so the new pair is always above what the endpoints run. Step 0 shows the pair it will pick.

### 10.3 Add or Remove Devices

- **Add:** move the computer account into the target OU, then reboot or run `gpupdate /target:computer /force`. It gets whichever mode is enabled.
- **Remove from scope:** moving a computer out of the OU stops future updates, and GPP removes the task. **The policy stays on the device** until you remove it (§11).

---

## 11. Rollback and Removal (Step 6)

```powershell
.\6_GPO_rollback.ps1 -Action DisableLinks                                  # OU -> mode None; devices KEEP their policy
.\6_GPO_rollback.ps1 -Action RemovePolicy -ComputerName PAW01, PAW02       # CiTool --remove-policy <GUID> (WinRM)
.\6_GPO_rollback.ps1 -Action RemoveGpos                                    # unlink + delete both GPOs
```

| Action | Effect | Guard |
|---|---|---|
| `DisableLinks` | No more deployments; the tasks are removed at the next refresh | asks for confirmation |
| `RemovePolicy` | `CiTool --remove-policy`. **Takes effect immediately** (proven: STIG `2 / 2` → `2 / 1` without a reboot). | **Refuses while any WDAC link is enabled**, because the GPO would redeploy it (`-Force` overrides for tests) |
| `RemoveGpos` | Deletes both GPOs; devices keep their policy | asks for confirmation |

> [!TIP]
> To relax policy on devices without removing it, publish a corrected package (§10.1), or demote to Audit (§10.2). Both keep the devices managed.

---

## 12. Proving-Ground Procedure

Use this on one device in the target OU (ideally the reference device) before you trust the GPOs with more. It proves a **first-time deployment** and both delivery paths.

| Step | Command | Expected |
|---|---|---|
| P0 | Steps 0, 1, 2, 4 (links disabled) | all PASSED; *Active mode: None* |
| P1 | `.\6_GPO_rollback.ps1 -Action RemovePolicy` on the device | `OperationResult 0`; the GUID is gone from CiTool; UMCI drops to the OS baseline |
| P2 | Reboot | no custom base policy; only the default GPOs applied |
| P3 | `.\3_GPO_set_mode.ps1 -Mode Audit -GpUpdate`, wait ~2 min, `.\5_GPO_validate_endpoint.ps1` | task deployed Audit v N; **UMCI 1**; PASSED |
| P4 | `.\3_GPO_set_mode.ps1 -Mode Enforce -GpUpdate`, wait ~2 min, `.\5_GPO_validate_endpoint.ps1 -BlockTestPattern <regex>` | Audit task removed; v N → v N+1 in place; **2 / 2**; PASSED |
| P4b | Run every approved app; launch the block-test app | apps work; block-test app blocked (3077) |
| P5 | Reboot; `.\5_GPO_validate_endpoint.ps1 -BlockTestPattern <regex>` | GP events 4018/5018; deploy log *already active* from the startup script; **2 / 2**; PASSED |

**Proven timeline** (from `C:\WDAC\GPO\Logs\GPO-Walkthrough-Log.md`):

| Stage | Time | Mechanism | Policy | STIG |
|---|---|---|---|:---:|
| P1 removed | 19:02:31 | `RemovePolicy` | none | 2 / 1 |
| P3 Audit | 19:12:10 | GPP task | `PAW-WDAC-GPO-Audit` v2026.10.21.4 | 2 / 1 |
| P4 Enforce | 19:14:28 | GPP task (in place) | `PAW-WDAC-GPO-Enforce` v2026.10.21.5 | **2 / 2** |
| P5 cold boot | 19:17:17 | startup script, then task | v2026.10.21.5 *already active* | **2 / 2** |

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Step 5: *"WDAC-GPO-Deploy-<Mode> not present"* | The endpoint hasn't refreshed Group Policy yet | `gpupdate /target:computer /force` on the endpoint, wait ~1–2 min |
| Step 5: *applied GPOs* missing the WDAC GPO | Computer not in the OU, link disabled, or security filtering | Check the computer DN; `4_GPO_validate_gpos.ps1`; `gpresult /scope computer /r` |
| Deploy log **2001** *"newer version active … not downgrading"* | You switched Enforce → Audit, or published an older package | Build a new pair (§10.2) |
| Deploy log **3004** *hash mismatch* | Payload in SYSVOL altered, or SYSVOL replication incomplete | `4_GPO_validate_gpos.ps1` (checks every DC); re-run `2_GPO_create_gpos.ps1` |
| Deploy log **3001** *CiTool.exe not found* | Endpoint older than Windows 11 22H2 | Upgrade the endpoint (out of scope) |
| Deploy log **2003** *Skipped: not a workstation* | A server or DC is in the OU | Move it out; servers aren't in scope |
| Deploy log **2002** *another custom base policy* | A different base policy is active (intersection) | Remove that policy, or keep that device out of the OU |
| Startup script didn't run at boot | No network at startup | Both GPOs enable *Always wait for the network*; the task also covers it within minutes |
| Step 4 **FAIL** *BOTH links are enabled* | Links edited by hand in GPMC | `3_GPO_set_mode.ps1 -Mode Audit\|Enforce` |
| Step 4 **FAIL** *version AD/SYSVOL* differ | Replication in progress, or a manual SYSVOL edit | Wait for replication; re-run `2_GPO_create_gpos.ps1` |
| Unexpected **3077** under Enforce | An app was missing from the reference policy | Fix on the reference device → `1_` → `2_` (§10.1), or demote (§10.2) |

---

## Appendix A — Script Parameters

| Script | Parameters (default) |
|---|---|
| `0_GPO_pre-flight.ps1` | `-TargetOU` |
| `1_GPO_build_packages.ps1` | `-EnforceXml` (`<WdacRoot>\Source\Base-Enforce.xml`) · `-AuditVersion` / `-EnforceVersion` (auto: today's `YYYY.MM.DD.N` / `N+1`, above every known version; a lower explicit value is refused) · `-SupplementalXml` (`@()`) |
| `WDAC-Version.ps1` *(helper, dot-sourced)* | `Get-WdacNextVersion`, `Get-WdacActivePolicyVersion`, `Get-WdacVersionsFromXml`, `-FromArchive`, `-FromManifests`. Identical to `C:\WDAC\config\scripts\WDAC-Version.ps1`. |
| `2_GPO_create_gpos.ps1` | `-PackagePath` (`Packages\latest.txt`) · `-TargetOU` · `-AuditGpoName` · `-EnforceGpoName` · `-TaskIntervalHours` |
| `3_GPO_set_mode.ps1` | **`-Mode Audit\|Enforce\|None`** · `-GpUpdate` (this computer) · `-TargetOU` · GPO names |
| `4_GPO_validate_gpos.ps1` | `-TargetOU` · GPO names |
| `5_GPO_validate_endpoint.ps1` | `-ComputerName` (this computer) · `-ExpectedMode` (from the enabled link) · `-BlockTestPattern` (`''`) · `-TargetOU` · GPO names |
| `6_GPO_rollback.ps1` | **`-Action DisableLinks\|RemovePolicy\|RemoveGpos`** · `-ComputerName` · `-Force` · `-Confirm` / `-WhatIf` |
| `Deploy-WDACPolicy.ps1` *(endpoint, run by the GPO)* | `-Mode Audit\|Enforce` · `-PayloadPath` (its own folder) |

## Appendix B — What the GPOs Contain

```text
\\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\
  GPT.INI                                        computer version (kept equal to AD versionNumber)
  Machine\Registry.pol                           HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon\SyncForegroundPolicy = 1
  Machine\Scripts\scripts.ini                    [Startup] 0CmdLine=powershell.exe / 0Parameters=... -Mode <Mode>   (UTF-16 LE)
  Machine\Scripts\Startup\WDAC\
      {POLICY-GUID}.cip                          compiled policy (Audit: version N, Enforce: N+1)
      manifest.json                              Mode, Policies[] {Type, PolicyGuid, Version, Name, File, Sha256}, source XML hash, deploy-script hash
      Deploy-WDACPolicy.ps1                      endpoint script
  Machine\Preferences\ScheduledTasks\ScheduledTasks.xml   TaskV2 WDAC-GPO-Deploy-<Mode> (Replace, removePolicy=1, SYSTEM)
AD: CN={GPO-GUID},CN=Policies,CN=System,<domain DN>
  gPCMachineExtensionNames = [{00000000-…}{CAB54552-…}][{35378EAC-…}{D02B1F72-…}][{42B5FAAE-…}{40B6664F-…}][{AADCED64-…}{CAB54552-…}]
                              GPP core           Registry            Scripts            GPP Scheduled Tasks
```

## Appendix C — Endpoint Artifacts and Event IDs

| Artifact | Path |
|---|---|
| Deploy log | `C:\Windows\Logs\WDAC-GPO\Deploy-WDACPolicy.log` (rotates at 2 MB) |
| State | `C:\ProgramData\WDAC-GPO\state.json` (last run, result, before/after versions, KMCI/UMCI, last change) |
| Local copy of the deployed `.cip` | `C:\ProgramData\WDAC-GPO\{POLICY-GUID}.cip` |
| Scheduled task | `\WDAC-GPO-Deploy-Audit` or `\WDAC-GPO-Deploy-Enforce` |
| Event log | **Application**, source **WDAC-GPO** |

| Event ID | Level | Meaning |
|:---:|---|---|
| 1000 | Information | Package version already active (no change) |
| 1001 | Information | Policy deployed (old → new version) |
| 1002 | Information | `Win32_DeviceGuard` UMCI matches the mode |
| 2001 | Warning | A newer version is active; not downgrading |
| 2002 | Warning | Another custom base policy is active (intersection) |
| 2003 | Warning | Skipped: not a Windows client edition |
| 2004 | Warning | UMCI doesn't match the mode |
| 2010 | Warning | Another run is in progress |
| 3000–3005 | Error | Unexpected error / no CiTool / mode mismatch / file missing / hash mismatch / CiTool failed |
