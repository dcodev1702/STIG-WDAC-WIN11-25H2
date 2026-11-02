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
   - [3.1 One Policy Kit, Several Enclaves (Domains and OUs)](#31-one-policy-kit-several-enclaves-domains-and-ous)
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

![WDAC multi-policy GPO deployment: a reference device builds an Audit and an Enforce package from one enforced policy and publishes them to two GPOs in SYSVOL; both GPOs are linked to the target OU with one link enabled; Windows 11 endpoints run Deploy-WDACPolicy.ps1 as SYSTEM from the startup script and a scheduled task, verify the SHA-256 hash and deploy the {GUID}.cip with CiTool only when the version is higher; Win32_DeviceGuard then reports V-243450 and V-243451, where 0 is OFF, 1 is AUDIT and 2 is ENFORCING](images/WDAC-GPO-Architecture.png)

<sub>Source: [`images/WDAC-GPO-Architecture.svg`](images/WDAC-GPO-Architecture.svg) · 1600 × 1828. The PNG is rendered from the SVG at 2x: edit the SVG, then re-render the PNG, and keep both.</sub>

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
| Enforce → Audit (§10.2) | Switched the OU to Audit first, then published a new, higher pair. Devices moved in place from Enforce v`2026.10.21.5` to Audit v`2026.10.24.1`, with no reboot. |
| Y/N and `-NoConfirm` | The endpoint script ran under SYSTEM with `-NoConfirm` from the GPO and deployed Audit v`2026.10.24.3`. Without `-NoConfirm`, steps 2, 3 and 6 and the endpoint script stopped before changing anything (Event 3006 on the endpoint). |
| Adding applications (§10.1) | Git, GitHub CLI and the Az module were added in a later audit round (config README §11 Option D), with the reference device kept in Audit (`6_enforce_policy.ps1 -PrepareOnly`). The new pair was published with the OU in Audit, and endpoints moved in place to Audit v`2026.10.24.11`. The tools logged 0 new `3076` events. |

---

## 2. Prerequisites

| Where | Requirement |
|---|---|
| **Reference device** | Finished `C:\WDAC\config\README.md`: `C:\WDAC\Source\Base-Enforce.xml` + `PolicyGuid.txt`, the enforced policy active, STIG `2 / 2`. For a later round the device may stay in Audit, with `Base-Enforce.xml` prepared by `6_enforce_policy.ps1 -PrepareOnly` (§10.1). Windows 11 Enterprise 22H2+ with **RSAT Group Policy + AD** (`dism.exe /Online /Add-Capability /CapabilityName:Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`; list with `dism.exe /Online /Get-Capabilities`) and ConfigCI (inbox). |
| **Rights** | **Domain Admins**, or **Group Policy Creator Owners** plus *Link GPOs* permission on the target OU |
| **Endpoints** | Windows 11 Enterprise **22H2 or later** (`CiTool.exe`), domain-joined, **in the target OU**. Read access to SYSVOL is the default. WinRM only for remote validation. |
| **Scope** | Windows client editions only. The endpoint script **skips** servers and domain controllers (`ProductType ≠ 1`). |
| **Managed installer** | Option 13 is ON in the policy. Designate MECM as the managed installer with `CCMSetup.exe MANAGEDINSTALLER=1`; see `C:\WDAC\config\README.md` §2. The GPOs don't configure AppLocker. |
| **Scripts** | Copy `C:\WDAC\GPO\` to the reference device. If blocked: `Get-ChildItem C:\WDAC\GPO -Recurse \| Unblock-File`. Run every script **elevated**, in PowerShell 7 **or** Windows PowerShell 5.1. |

> [!IMPORTANT]
> **Produce the policies first.** Run the [Application Control for Business Wizard](https://webapp-wdac-wizard.azurewebsites.net/) to create the base policy (and any supplemental policies), then finish `C:\WDAC\config\README.md` on the reference device. Nothing in this folder can be built or published until `Base-Enforce.xml` and `PolicyGuid.txt` exist. Step 0 prints this reminder and fails when those files are missing.

> [!WARNING]
> Keep target computers out of the scope of any GPO that uses the legacy *Deploy App Control for Business* (`SiPolicy.p7b`) setting. A legacy single policy and this multiple-policy base policy would both be active, and they **intersect**: files would need to pass both.

---

## 3. Settings

Edit **`C:\WDAC\GPO\scripts\GPO-Settings.psd1`** once per enclave. Any script parameter with the same name overrides it. The repo copy is a template: **`AuditGpoName` and `EnforceGpoName` are empty, and every step stops until you set both.**

| Setting | Proven value | Meaning |
|---|---|---|
| `TargetOU` | `''` | Distinguished name of the target OU. **Empty = the OU of the computer running the scripts**, read from its computer account on the PDC emulator of its own domain. It must be an OU of that domain; one from another domain, or a container such as `CN=Computers`, stops every step with nothing changed. |
| `AuditGpoName` | `''`, **required** | Name of this enclave's Audit GPO, for example `PAW-WDAC - AppControl Audit`. Empty stops every step. |
| `EnforceGpoName` | `''`, **required** | Name of this enclave's Enforce GPO, for example `PAW-WDAC - AppControl Enforce`. Must differ from `AuditGpoName`. |
| `PolicyNamePrefix` | `PAW-WDAC-GPO` | Friendly name stamped into the packages, e.g. `PAW-WDAC-GPO-Enforce` in CiTool and Event 3099 |
| `TaskIntervalHours` | `4` | The endpoint task re-runs every N hours. It also runs about 1 minute after Group Policy (re)creates it. |
| `WdacRoot` | `C:\WDAC` | The reference device's working folders (config README layout) |
| `GpoRoot` | `C:\WDAC\GPO` | Scripts, `Packages\`, `Logs\` |

> [!IMPORTANT]
> If the reference device is **not** in the target OU, set `TargetOU` explicitly. Otherwise the GPOs are linked to the reference device's own OU.

The target OU comes from the first of these that is set: **`-TargetOU`** on the command line, then **`TargetOU` in `GPO-Settings.psd1`**, then **the OU of this computer**. A `TargetOU` left in the settings file therefore wins over the computer's own OU. Steps 0, 2 and 3 print the OU with its source (`-TargetOU parameter`, `TargetOU in GPO-Settings.psd1`, or `auto-detected: OU of this computer <name>`), and steps 2 and 3 show it again in the yellow Y/N prompt, so check it there before you answer **Y**. `-TargetOU` works with or without quotes; quote it when an OU name contains a space.

### 3.1 One Policy Kit, Several Enclaves (Domains and OUs)

The policy holds rules, options and one GUID. It names no domain, OU, computer or user. One known-good policy therefore serves every enclave whose PAWs come from the same image. Each enclave builds and publishes its **own** packages from the **same** kit, in its own domain, with these scripts. No per-enclave policy and no signing step are needed (the policy is unsigned).

**The kit** is [`policy/`](policy/). Copy all five files into `C:\WDAC\Source` on the enclave's reference device:

| File | What it is |
|---|---|
| `Base-Enforce.xml` | The enforced known-good base policy. Step 1 builds both packages (Audit and Enforce) from it. |
| `Base-Audit-Merged.xml` | The same rules with Audit Mode ON, for a later audit round with the config guide (§11 Option D there) |
| `Base-Audit.xml` | The Wizard baseline (Allow Microsoft and both block lists, no application rules), for a first audit round with the config guide |
| `PolicyGuid.txt` | The policy GUID. It is the same in every enclave, so each enclave's packages replace the policy in place. |
| `SHA256SUMS.txt` | SHA-256 of the four files. Check them after every transfer (below). |

**In each enclave:**

1. On a reference device in that enclave (a domain-joined PAW from the same image, with RSAT), copy this `scripts` folder to `C:\WDAC\GPO\scripts` and the kit to `C:\WDAC\Source`, then check the hashes:

   ```powershell
   Get-Content C:\WDAC\Source\SHA256SUMS.txt | ForEach-Object {
       $Hash, $File = $_ -split '\s+', 2
       '{0}  {1}' -f $(if ((Get-FileHash -LiteralPath "C:\WDAC\Source\$File").Hash -eq $Hash) { 'OK  ' } else { 'FAIL' }), $File
   }
   ```

2. Edit `GPO-Settings.psd1` for that enclave. Set `TargetOU` to the enclave's PAW OU, or leave it empty when the reference device sits in that OU. Set `AuditGpoName` and `EnforceGpoName` to this enclave's GPO names (required; the repo copy leaves them empty). Nothing else is domain-specific: the scripts read the domain, its PDC emulator and SYSVOL from Active Directory at run time.
3. Run the normal order (§4): `0` → `1` → `2` → `4` → `3 -Mode Audit` → `5` → audit period → `3 -Mode Enforce` → `5`.

**Guards that keep it portable:**

| Guard | Steps | What it stops |
|---|---|---|
| OU in this domain | 0, 2 – 6 | A `TargetOU` from another domain, such as a settings file copied between enclaves: *"STOP: target OU … is not in domain …"*, with nothing changed. A container such as `CN=Computers` stops the same way: *"… is not an organizational unit"*. |
| Portability gate | 0, 1 | A FilePath rule under a named user profile (`C:\Users\<name>\…`) in `Base-Enforce.xml` or a `-SupplementalXml`: **FAIL**, nothing compiled. Such a rule allows files for one user only. It carries that user's name, and the domain in `<user>.<DOMAIN>` profile folders, into every enclave. Runtime FilePath rule protection ignores user-writable folders anyway. The FAIL row prints the `Remove-CIPolicyRule` command that removes it. A user profile that appears only in rule text, such as a FriendlyName, is a **WARN**. |
| FilePath rule folders | 0 (reference device), 5 (each endpoint) | A FilePath rule folder that standard users can write to, or that doesn't exist: **WARN**. Windows ignores that rule, so the files in that folder are **blocked** under Enforce. Fix the folder's ACL in the image. |

Some things differ per enclave by design. Each enclave's step 1 picks the next date-based version pair above what *that* enclave knows. `manifest.json` (`BuiltBy`, `BuiltOn`) and the scheduled task's author record whoever ran the build there. The rules are identical everywhere: `SourceXmlSha256` in every `manifest.json` equals the kit's `Base-Enforce.xml` hash. Built on the same day, the `.cip` files are byte-identical across enclaves.

> [!WARNING]
> **`%OSDRIVE%\ADMIN\*`:** on the lab image, `C:\ADMIN` inherits *Authenticated Users: Modify* from `C:\`. Runtime FilePath rule protection therefore ignores this rule, and step 0 reports it. In the image, either remove that write access, for example `icacls C:\ADMIN /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"` (Administrators and SYSTEM full control, Users read and execute), or allow the files in `C:\ADMIN` by publisher or hash and drop the rule.

**Prove it** with [`tests/Test-WdacGpoPortability.ps1`](tests/Test-WdacGpoPortability.ps1) (elevated, Windows PowerShell 5.1 or PowerShell 7). It checks the kit and the new guards. It then runs the real steps 0, 1, 2, 4 and 3, plus step 5's FilePath rows, unchanged in two simulated domains with different names and OUs. In-memory stand-ins replace every Active Directory and Group Policy command, and the test refuses to start unless each one resolves to its stand-in. Each simulated SYSVOL is a folder reached through the `\\localhost\C$` share. The real GPOs, links and active policies are compared before and after. **It changes nothing.**

```powershell
.\tests\Test-WdacGpoPortability.ps1          # kit = .\policy; results: %TEMP%\WDAC-GPO-Portability-<stamp>\Test-WdacGpoPortability.csv
```

**Proven** on 2026-11-02 in both editions: 99 checks, 0 FAIL.

- `enclave2.example` (`OU=PAW Workstations`) and `ops.enclave3.mil` (`OU=Tier0,OU=PAWs,OU=Admin`): step 0 PASSED. Step 1 built Audit `2026.11.2.3` / Enforce `2026.11.2.4` from the kit. Step 2 wrote startup scripts and tasks for `\\<that domain>\SysVol\<that domain>\…` and linked the GPOs to that domain's OU only. Steps 4 and 3 then went Audit → Enforce and PASSED.
- Both enclaves produced byte-identical `.cip` files (Audit `AFF66DE1…`, Enforce `9EBE6C99…`).
- Refused with nothing changed: the other enclave's OU, a publish without confirmation, and a policy with a user-profile rule.
- The lab domain's real GPOs, links and active policies were identical before and after.
- Separately, steps 0 and 1 ran for real in the lab domain (packages to a scratch folder, no GPO touched). They built the same `.cip` hashes, and step 1 refused the pre-cleanup lab policy at the portability gate.

---

## 4. Scripts at a Glance — Run Order

All scripts are in `C:\WDAC\GPO\scripts\`. Each one writes a transcript and a PASS/WARN/FAIL CSV to `C:\WDAC\GPO\Logs\`, and stops with `STOP:` on any failure.

> [!IMPORTANT]
> **Steps 2, 3 and 6 ask before they change anything.** Each prints in **yellow** what is about to change, then waits for `Continue? [Y/N]`:
> - **Step 2** shows the versions it will publish and which link is enabled. The devices behind the enabled link pick up the new version on their own.
> - **Step 3** shows the OU's mode before and after. **Enforce** means every file the policy does not allow is blocked on every device in the OU.
> - **Step 6** shows what it will disable, remove or delete.
>
> Type **Y** to go ahead. **N**, or no valid answer after three tries, stops the script with nothing changed and a `FAIL` row in the results.
>
> **For unattended runs, add `-NoConfirm`.** Step 6 also takes `-WhatIf` to preview. A non-interactive session without `-NoConfirm` stops before changing anything, so automation must pass it.
>
> **On the endpoints, the GPO already runs `Deploy-WDACPolicy.ps1 -NoConfirm`,** because SYSTEM has no console to answer. Step 4 fails a GPO whose startup script or task lacks it. If you run `Deploy-WDACPolicy.ps1` by hand, it asks too, but only when it is about to deploy a new version.

| # | Script | Runs on | Changes | Success looks like |
|:---:|---|---|---|---|
| 0 | `0_GPO_pre-flight.ps1` | reference device | nothing (read-only) | `GPO pre-flight: PASSED` |
| 1 | `1_GPO_build_packages.ps1` | reference device | local files in `Packages\<stamp>\` | `Package build: PASSED`; Audit v N < Enforce v N+1 |
| 2 | `2_GPO_create_gpos.ps1` | reference device | creates/updates both GPOs; links them **disabled** (asks first) | `GPO create / update: PASSED` |
| 4 | `4_GPO_validate_gpos.ps1` | reference device | nothing | `GPO validation: PASSED`; *Active mode: None* |
| 3 | `3_GPO_set_mode.ps1 -Mode Audit` | reference device | enables the Audit link (asks first) | `Set mode Audit: PASSED` |
| 5 | `5_GPO_validate_endpoint.ps1` | reference device → endpoint(s) | nothing | `Endpoint validation (Audit): PASSED`; UMCI 1 |
| 3 | `3_GPO_set_mode.ps1 -Mode Enforce` | reference device | switches to the Enforce link (asks first) | `Set mode Enforce: PASSED` |
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

> [!IMPORTANT]
> Before running Step 0, produce the required policies with the [Application Control for Business Wizard](https://webapp-wdac-wizard.azurewebsites.net/). The script reminds you and links the Wizard, and its *Reference policy files* check fails until the policies exist.

```powershell
.\0_GPO_pre-flight.ps1                          # optional: -TargetOU 'OU=...,DC=...'
```

| Check | Expect |
|---|---|
| Session, domain membership, GroupPolicy / ActiveDirectory / ConfigCI modules | OK |
| Rights | `Domain Admins` (or `Group Policy Creator Owners`) |
| Domain, PDC emulator, **SYSVOL on every DC** | reachable |
| Target OU (**must be in this domain**, §3.1) and **every member**, with OS | Windows client editions. Anything else is WARN; the endpoint script skips it. |
| GPOs already linked to the OU; whether the two GPOs exist | "will create" or "will UPDATE" |
| `Base-Enforce.xml`: GUID = `PolicyGuid.txt`, base policy, **Audit Mode OFF**, Option 13 | OK |
| `Base-Enforce.xml` portability: no FilePath rule names a user profile (§3.1) | OK. FAIL prints the `Remove-CIPolicyRule` fix. |
| FilePath rule folders on this device, which uses the same image as the endpoints | `N of N rule folder(s) admin-only`. A folder that is missing or user-writable is a WARN. |
| Reference device: that policy **active at the same version**, STIG | `2 / 2`. Expect two WARNs (active version differs, STIG `2 / 1`) when the device stays in Audit for a later round. |
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
   - `<EKUs>`, `<FileRules>`, `<Signers>`, `<SigningScenarios>`, `<UpdatePolicySigners>` and `<CiSigners>` are **byte-identical**;
   - **portability**: no FilePath rule in `Base-Enforce.xml` or in any `-SupplementalXml` names a user profile (§3.1).
4. **Output.** Compiled into `C:\WDAC\GPO\Packages\<stamp>\{Audit,Enforce}\`, each with `{GUID}.cip`, `manifest.json` (GUID, version, SHA-256, mode, source XML hash, and the FilePath rules that step 5 checks on the endpoints) and a copy of `Deploy-WDACPolicy.ps1`. `Packages\latest.txt` points to the new folder. `Packages\<stamp>\xml\` (never published) keeps the exact XML behind each `.cip`, named with its version (`<prefix>-Audit_v<N>.xml`, `<prefix>-Enforce_v<N+1>.xml`), plus `source_Base-Enforce_v<version>.xml`, so every package can be traced and rebuilt.

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

Before anything changes, step 2 shows the target OU and where it came from (§3) in its *Inputs* row and in the yellow Y/N prompt. Answer **N** if it isn't the OU you want.

**Step 2**, for each GPO. It **creates** the GPO if missing and **updates** it otherwise (that's also how you publish a new package):

| Action | Detail |
|---|---|
| GPO status | `UserSettingsDisabled` |
| Registry setting | *Always wait for the network at computer startup and logon* = Enabled, so the startup script has network |
| Payload | Copied to `\\<PDC>\SYSVOL\<domain>\Policies\{GPO}\Machine\Scripts\Startup\WDAC\`, replacing any earlier payload |
| Startup script | `scripts.ini`: `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\<domain>\SysVol\<domain>\Policies\{GPO}\Machine\Scripts\Startup\WDAC\Deploy-WDACPolicy.ps1" -Mode <Mode> -NoConfirm` |
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

To check the computer you are on, run it **on that computer** without `-ComputerName`. That never uses WinRM. Its own name in any form also stays local: the NetBIOS name, the full DNS host name, the FQDN, `localhost` or `.`. This matters for host names longer than 15 characters, whose `$env:COMPUTERNAME` is truncated. Only other computers are reached over WinRM.

| Check | Audit expectation |
|---|---|
| Computer in the target OU; `gpresult` applied GPOs | **Audit GPO only** |
| Scheduled task `WDAC-GPO-Deploy-Audit` | present, last result `0` |
| `state.json` / deploy log / events | `Deployed` or `NoChange` |
| CiTool | GUID active at the **Audit package version**, authorized; `.cip` in `CiPolicies\Active` |
| Event 3099 | *"Refreshed and activated … <prefix>-Audit. id GPO-AUDIT-<version>. Status 0x0"* |
| `Win32_DeviceGuard` (`0` OFF · `1` AUDIT · `2` ENFORCING) | **V-243451 user `1 (AUDIT)`**, an open finding until Enforce. V-243450 kernel reads `1 (AUDIT)`, or `2 (ENFORCING)` if platform policies already enforce kernel mode. |
| 3076 / 3077 since deployment | reported |
| FilePath rule folders listed in the published `manifest.json`, checked on the endpoint | admin-only. A folder that is missing or user-writable is a WARN: Windows ignores that rule, so the files there are blocked under Enforce (§3.1). |

After the results table, step 5 prints the **STIG check** for each computer, one coloured line per control:

| Colour | `Win32_DeviceGuard` value | Meaning |
|---|---|---|
| **Green** | `2 (ENFORCING)` | **COMPLIANT** |
| **Yellow** | `1 (AUDIT)` | Logs only. Not compliant until Enforce. |
| **Red** | `0 (OFF)` or any other value | **NOT COMPLIANT**: App Control is not active |

```text
STIG check on PAW01 (Win32_DeviceGuard):
  V-243450 kernel-mode code integrity  2 (ENFORCING)  COMPLIANT
  V-243451 user-mode code integrity    1 (AUDIT)  AUDIT - logs only, not compliant until Enforce
```

### 8.3 The Audit Period

1. Let users run **every** application and workflow on the audited devices for long enough to cover the normal work cycle.
2. Review what would have been blocked, on an endpoint or via remoting:

   ```powershell
   C:\WDAC\config\scripts\Export-CIEventEvidence.ps1 -StartTime (Get-Date).AddDays(-7)
   ```

3. **Gaps found?** Fix them on the **reference device**:
   - capture and merge the missing apps with the config README's **§11 Option D**, which merges into `Base-Enforce.xml` (`-BaseXml`) so no earlier rule is lost, and enforce them there (Steps 6–7);
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
| `Win32_DeviceGuard` | **V-243450 kernel `2 (ENFORCING)` / V-243451 user `2 (ENFORCING)` — both PASS** |
| 3077 | Only the block-test app (expected with `-BlockTestPattern`). Anything else appears as *blocks to review*. |

**Proven endpoint result** (shown in the current output format):

```text
OK  active policy      PAW-WDAC-GPO-Enforce {75afc1cf-...} v2026.10.21.5 active=True authorized=True (GPO package v2026.10.21.5)
OK  Event 3099         Refreshed and activated Code Integrity policy {75afc1cf-...} PAW-WDAC-GPO-Enforce. id GPO-ENFORCE-2026.10.21.5. Status 0x0
OK  Win32_DeviceGuard  V-243450 kernel 2 (ENFORCING) / V-243451 user 2 (ENFORCING) - both PASS
OK  expected blocks    matching 'Mozilla|Firefox': C:\Program Files\Mozilla Firefox\firefox.exe <- pwsh.exe; ...
Endpoint validation (Enforce): PASSED.
```

**Then prove the block and the reboot:**
- Launching the block-test app shows *"Your organization used App Control for Business to block this app"*, or in PowerShell *"An Application Control policy has blocked this file."*
- After a **reboot**, step 5 should still pass. The deploy log shows the startup script at boot: *"… is already active. run as NT AUTHORITY\SYSTEM from \\<domain>\SysVol\…"*. The GroupPolicy/Operational log shows events **4018 / 5018** *Starting / Completed Startup script*.

---

## 10. Ongoing Operations

### 10.1 Publish an Updated Policy (Same Mode, No Reboot)

1. On the reference device, change the policy with the config README. To add applications, use its §11 Option D, which merges into `Base-Enforce.xml`. Then either enforce it there (Steps 6–7), or keep the device in Audit and prepare `Base-Enforce.xml` with **`6_enforce_policy.ps1 -PrepareOnly`**, which deploys nothing.
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
.\6_GPO_rollback.ps1 -Action DisableLinks -WhatIf                          # preview only, nothing changes
```

Every action asks **Y/N** once, in yellow. `-NoConfirm` skips the prompt for automation.

| Action | Effect | Guard |
|---|---|---|
| `DisableLinks` | No more deployments; the tasks are removed at the next refresh | Y/N confirmation |
| `RemovePolicy` | `CiTool --remove-policy`. **Takes effect immediately** (proven: STIG `2 (ENFORCING) / 2 (ENFORCING)` → `2 / 1 (AUDIT)` without a reboot). | **Refuses while any WDAC link is enabled**, because the GPO would redeploy it (`-Force` overrides for tests); then Y/N confirmation |
| `RemoveGpos` | Deletes both GPOs; devices keep their policy | Y/N confirmation |

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
| Step 4 **FAIL** *startup script* / *scheduled task* lacks `-NoConfirm` | The GPO was published by an older step 2 | Build and publish a new pair: `1_GPO_build_packages.ps1` → `2_GPO_create_gpos.ps1` |
| Steps 2, 3, 6: **FAIL** *"needs a Y/N confirmation, but the session is non-interactive"* | Run from automation, a remote session or a redirected console | Run interactively, or add `-NoConfirm` |
| Deploy log **3006** *NOT deployed - cannot answer the Y/N confirmation* | `Deploy-WDACPolicy.ps1` started without `-NoConfirm` by something other than the GPO | Pass `-NoConfirm`, or let the GPO run it |
| Step 4 **FAIL** *version AD/SYSVOL* differ | Replication in progress, or a manual SYSVOL edit | Wait for replication; re-run `2_GPO_create_gpos.ps1` |
| Unexpected **3077** under Enforce | An app was missing from the reference policy | Fix on the reference device → `1_` → `2_` (§10.1), or demote (§10.2) |
| Any step: **STOP** *"target OU … is not in domain …"* | `TargetOU` belongs to another domain, for example a settings file copied from another enclave | Set `TargetOU` to an OU of this domain, or leave it empty when the reference device is in the target OU (§3.1) |
| Any step: **STOP** *"AuditGpoName is empty"* or *"… are both '…'"* | `AuditGpoName` or `EnforceGpoName` is empty in `GPO-Settings.psd1` (the repo copy ships them empty), or both names are the same | Set both to the enclave's two (different) GPO names |
| Step 2 picked an OU you didn't expect | The source in brackets says why. *TargetOU in GPO-Settings.psd1*: a value left in the settings file wins over the computer's own OU. *auto-detected*: the computer account was read on the PDC emulator, so a computer moved on another DC moments ago may not have replicated there yet. | Answer **N**. Clear `TargetOU` in the settings file or pass `-TargetOU`. After a move, wait for replication, then run step 2 again. |
| Any step: **STOP** *"target OU 'OU=x DC=y DC=z' is not in domain …"* (scripts before 2026-11-02) | `-TargetOU` typed without quotes reached the script split at its commas | Update the scripts (they now accept it), or put the DN in quotes |
| Steps 0, 2 – 6: **STOP** *"… is not an organizational unit"* | The target is a container, such as `CN=Computers`, which can't have GPO links | Move the computer accounts into an OU and set `TargetOU` to it |
| Step 2: **STOP** *"target OU … was not found on …"* (the PDC emulator) | A typo in the DN, or an OU created on another DC that hasn't replicated to the PDC emulator yet | Check the DN (copy it from the OU's *distinguishedName* attribute); wait for replication |
| Steps 0 / 1: **FAIL** *user-profile rules* | A FilePath rule names `C:\Users\<name>`: it works for one user only and carries that name into every enclave | On the reference device, run the `Remove-CIPolicyRule` command the row prints (or remove the rule in the Wizard), then run the step again |
| Steps 0 / 5: **WARN** *FilePath folder … is writable by …* | Standard users can write to a FilePath rule's folder, so Windows ignores the rule | Remove that write access in the image (§3.1), or allow those files by publisher or hash |
| Step 5: **WARN** *manifest has no FilePathRules* | The published package was built before this check | Build and publish a new pair: `1_GPO_build_packages.ps1` → `2_GPO_create_gpos.ps1` |
| Step 5: **FAIL** *Unexpected error: The parameter is incorrect.* (scripts before 2026-11-02) | `Get-WinEvent` throws this for an event source that isn't registered. `WDAC-GPO` exists only after `Deploy-WDACPolicy.ps1` has run on that computer. | Update the scripts. Step 5 now reports it as the WARN below and finishes all other checks. |
| Step 5: **WARN** *event source WDAC-GPO is not registered* | The GPO startup script or task hasn't run on that computer yet | `gpupdate /target:computer /force` on it, wait ~2 minutes, run step 5 again |
| Step 5: **FAIL** *WinRM cannot process the request … Cannot find the computer* | The name isn't reachable over WinRM (DNS, WinRM not enabled), or it is this computer under a name the script doesn't recognise | On the endpoint itself, run step 5 **without** `-ComputerName`. That never uses WinRM. |

---

## Appendix A — Script Parameters

| Script | Parameters (default) |
|---|---|
| `0_GPO_pre-flight.ps1` | `-TargetOU` |
| `1_GPO_build_packages.ps1` | `-EnforceXml` (`<WdacRoot>\Source\Base-Enforce.xml`) · `-AuditVersion` / `-EnforceVersion` (auto: today's `YYYY.MM.DD.N` / `N+1`, above every known version; a lower explicit value is refused) · `-SupplementalXml` (`@()`) |
| `WDAC-Version.ps1` *(helper, dot-sourced)* | `Get-WdacNextVersion`, `Get-WdacActivePolicyVersion`, `Get-WdacVersionsFromXml`, `-FromArchive`, `-FromManifests`. Identical to `C:\WDAC\config\scripts\WDAC-Version.ps1`. |
| `2_GPO_create_gpos.ps1` | `-PackagePath` (`Packages\latest.txt`) · `-TargetOU` · `-AuditGpoName` · `-EnforceGpoName` · `-TaskIntervalHours` · `-NoConfirm` |
| `3_GPO_set_mode.ps1` | **`-Mode Audit\|Enforce\|None`** · `-GpUpdate` (this computer) · `-TargetOU` · GPO names · `-NoConfirm` |
| `4_GPO_validate_gpos.ps1` | `-TargetOU` · GPO names |
| `5_GPO_validate_endpoint.ps1` | `-ComputerName` (this computer, checked locally without WinRM; other names use WinRM) · `-ExpectedMode` (from the enabled link) · `-BlockTestPattern` (`''`) · `-TargetOU` · GPO names |
| `6_GPO_rollback.ps1` | **`-Action DisableLinks\|RemovePolicy\|RemoveGpos`** · `-ComputerName` · `-Force` · `-NoConfirm` · `-WhatIf` |
| `Deploy-WDACPolicy.ps1` *(endpoint, run by the GPO)* | `-Mode Audit\|Enforce` · `-PayloadPath` (its own folder) · `-NoConfirm` (always passed by the GPO) |
| `WDAC-Confirm.ps1` *(helper, dot-sourced)* | `Confirm-WdacChange`: the yellow Y/N prompt used by steps 2, 3 and 6. Identical to `C:\WDAC\config\scripts\WDAC-Confirm.ps1`. |
| `tests\Test-WdacGpoPortability.ps1` *(test, changes nothing)* | `-KitPath` (`..\policy`) · `-ScriptsPath` (`..\scripts`) · `-WorkRoot` (`%TEMP%\WDAC-GPO-Portability-<stamp>`). Keep `-WorkRoot` short: Windows PowerShell 5.1 can't write the simulated SYSVOL paths past 260 characters. See §3.1. |

`-TargetOU` (steps 0 and 2–6) overrides `TargetOU` in `GPO-Settings.psd1`, with or without quotes (§3).

## Appendix B — What the GPOs Contain

```text
\\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\
  GPT.INI                                        computer version (kept equal to AD versionNumber)
  Machine\Registry.pol                           HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon\SyncForegroundPolicy = 1
  Machine\Scripts\scripts.ini                    [Startup] 0CmdLine=powershell.exe / 0Parameters=... -Mode <Mode> -NoConfirm   (UTF-16 LE)
  Machine\Scripts\Startup\WDAC\
      {POLICY-GUID}.cip                          compiled policy (Audit: version N, Enforce: N+1)
      manifest.json                              Mode, Policies[] {Type, PolicyGuid, Version, Name, File, Sha256}, source XML hash, deploy-script hash, FilePathRules[]
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
| 2005 | Warning | Manual run: the new version was **not confirmed** at the Y/N prompt, so nothing was deployed |
| 2010 | Warning | Another run is in progress |
| 3000–3005 | Error | Unexpected error / no CiTool / mode mismatch / file missing / hash mismatch / CiTool failed |
| 3006 | Error | Not deployed: the session can't answer the Y/N prompt and `-NoConfirm` was not passed. Re-publish with step 2, which adds `-NoConfirm`. |
