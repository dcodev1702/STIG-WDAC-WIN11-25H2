# 🛡️ App Control for Business (WDAC) on Windows 11 Enterprise 25H2 — PAW How-To

> [!NOTE]
> **Environment:**  
> &nbsp;&nbsp;• Windows 11 Enterprise 25H2  
> &nbsp;&nbsp;• Windows Server 2025 Core  
> &nbsp;&nbsp;• Lab domain `skynet-home.local`  
> &nbsp;&nbsp;• App Control Policy Wizard 2.7  
> **Deployment method:** Group Policy (GPO)  
> **Connectivity assumption:** Fully offline / disconnected — no ISG / cloud reputation  
> **Primary driver:** DISA STIG — two CAT II findings on Privileged Access Workstations (PAWs)  
> **POC policy XML:** [`poc_policy/WIN11-WDAC-CIPolicy_v10.0.5.1.xml`](poc_policy/WIN11-WDAC-CIPolicy_v10.0.5.1.xml) — the enforce-mode policy built during this walkthrough

---

## 1. 🎯 Why This Matters — The Two STIG CAT II Findings

Before touching the wizard, understand what you are satisfying.

### V-243450 / WPAW-00-001050 — CAT II · Device Guard Code Integrity Policy

> *The Windows PAW must have a WDAC / Code Integrity policy deployed and active to restrict which applications can run on the system.*

**Check (PowerShell):**
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | FL *codeintegrity*
```
`CodeIntegrityPolicyEnforcementStatus` must be **2** (Enforced). This field reports the effective Code Integrity policy status on the PAW. A value of `1` is Audit and remains a finding.

### V-243451 / WPAW-00-001060 — CAT II · Device Guard User Mode Code Integrity (UMCI)

> *Same requirement as 001050, but specifically verifies that User Mode Code Integrity (UMCI) is enforced — not just kernel mode.*

**Check (same command):**  
`UsermodeCodeIntegrityPolicyEnforcementStatus` must **independently** be **2** (Enforced). This field reports the effective user mode policy status. Enabling `UMCI` in the policy extends App Control checks to user mode executables and scripts, but the XML setting alone does not prove enforcement on a PAW.

These are two separate [DISA PAW V3R3 STIG](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_PAW_V3R3_STIG.zip) checks. For **each** field, `0` means Not Configured, `1` means Audit, and `2` means Enforced. The number `2` is a status code, not a requirement to deploy two policies. In Audit mode, applications that would be blocked can still run while App Control logs the event; after removing the Audit Mode option, the policy runs in enforced mode. See [Microsoft's status definitions](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) and [App Control policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create).

| CI status | UMCI status | STIG result |
|---|---|---|
| `2` | `2` | Both numeric checks met; confirm the active policy allows only approved PAW applications. |
| `2` | `0` or `1` | V-243450 numeric check met; V-243451 remains a finding. |
| `0` or `1` | `2` | V-243450 remains a finding; V-243451 numeric check met. |
| `0` or `1` | `0` or `1` | Both remain findings. |

### How this solution satisfies both findings

| Finding | What is checked | How this policy addresses it |
|---|---|---|
| V-243450 / 001050 | Effective CI policy enforcement | Deploy the policy, confirm it loaded, and verify `CodeIntegrityPolicyEnforcementStatus = 2` on each PAW. |
| V-243451 / 001060 | Effective user mode CI enforcement | Enable UMCI, deploy the policy, and verify `UsermodeCodeIntegrityPolicyEnforcementStatus = 2` on each PAW. |

Both values must return `2` on the target PAW. A policy XML file, GPO link, or Event ID 3099 alone cannot establish that either numeric check is met.

---

## 2. 📋 Pre-Requisites and Environment Assumptions

- **WDAC / App Control Policy Wizard 2.7** installed on the admin workstation
- **MECM / ConfigMgr** present → keep **Managed Installer** enabled in the policy  
  (Note: ConfigMgr may require re-deployment or a registry workaround to be recognized as a trusted managed installer — see the Managed-Installer reference PDF shared during session)
- Group Policy infrastructure available (domain-joined PAWs in a dedicated OU — `Workstation` in this lab)
- **No Internet access** → **Intelligent Security Graph (ISG) must be disabled**
- `RefreshPolicy.exe` (Refresh CI Policy, AMD64) available for no-reboot policy refresh
- Admin rights on the PAW being tested

---

## 3. 🔨 Step-by-Step Walkthrough

> [!IMPORTANT]
> **`Disabled:Script Enforcement` — Design Decision for PAW Environments**
>
> This policy ships with script enforcement disabled. This is a deliberate PAW design choice: it keeps PowerShell in Full Language Mode for administrators while relying on OS-level privilege controls (not WDAC) to prevent standard users from launching PowerShell at all. When script enforcement is **enabled**, WDAC applies Constrained Language Mode machine-wide based on script policy coverage — not caller identity — which affects Domain Admins, SYSTEM, and standard users equally, including GPO startup scripts and admin tooling.
>
> **Verify the active language mode at any time:**
> ```powershell
> $ExecutionContext.SessionState.LanguageMode
> # FullLanguage  → script enforcement is OFF (expected with this policy)
> # ConstrainedLanguage → script enforcement is ON
> ```
>
> See [Section 6 — Caveats & Advanced Options](#6-️-caveats-advanced-options--policy-rule-recommendations) for the full mechanics of CLM behavior and why this is the correct posture for a PAW.

### Step 1 — Create the Base Policy in the Wizard (Audit Mode First)

Open the App Control Policy Wizard → **Policy Creator** → choose a single base policy template.

**Key decisions on the Policy Rules screen:**

| Rule | Setting | Reason |
|---|---|---|
| Audit Mode | **ON** | Always start here — never enforce an untested policy |
| User Mode Code Integrity (UMCI) | **ON** | Required for WPAW-00-001060 |
| Managed Installer | **ON** | MECM present in environment |
| Unsigned System Integrity Policy | **ON** | Unsigned policy for initial deployment |
| Update Policy without Rebooting | **ON** | Allows `RefreshPolicy.exe` to apply changes live |
| Advanced Boot Options Menu | **ON** | Safety net during testing |
| Boot Audit on Failure | **ON** *(Advanced Options)* | If a driver/boot component fails, system falls back to audit rather than hard-blocking — critical safety net |
| Intelligent Security Graph | **OFF** | No Internet access — ISG will not function |
| Treat Revoked as Unsigned | **OFF** | Government environments may have older cert chains (e.g., Axway/Tumbleweed) — leaving this off avoids false blocks |
| Hypervisor-Protected Code Integrity | **OFF** | Not required for this scenario |

![Policy Rules — Audit Mode with Advanced Options](images/01_policy_rules_audit_advanced.png)

> ⚠️ **Note:** The Advanced Options panel (toggled at top-right) exposes **Boot Audit on Failure**, which is off by default. Enable it.

---

### Step 2 — File Rules: Merge the Microsoft Block Lists

On the **File Rules** screen you will see the default Microsoft root publisher allow rules already populated.

At the bottom, check **both**:
- ✅ Merge with Recommended User Mode Block Rules
- ✅ Merge with Recommended Kernel Mode Block Rules

These block lists cover known bypass tools such as `msbuild.exe`, `mshta.exe`, `wmic.exe`, `wscript.exe`, `wsl.exe`, and older BGInfo versions. They increase policy file size but add meaningful coverage.

![File Rules — Microsoft Roots + Block Rules checked](images/02_file_rules_block_rules_checked.png)

Save the policy XML (e.g., `AllowMicrosoft_2026-03-27.xml`) to `Documents` for now. The wizard will compile and place it appropriately in a later step.

> 💡 **Microsoft-signed tools are covered automatically.** Any binary signed under the `CN=Microsoft Windows Publisher` chain — including tools like Sysmon — is allowed by the base Microsoft publisher rules without requiring an explicit rule. You can verify a tool's signing chain with:
> ```powershell
> Get-AuthenticodeSignature .\Sysmon64.exe | FL SignerCertificate, Status, IsOSBinary
> ```
> If `Status` is `Valid` and the subject shows `CN=Microsoft Windows Publisher`, no additional rule is needed.

---

### Step 3 — Deploy to the Active Path and Refresh

Compiled `.p7b` policies live in:
```
C:\Windows\System32\CodeIntegrity\CIPolicies\Active\
```

![CodeIntegrity folder showing SiPolicy.p7b placed](images/05_codeintegrity_folder.png)

The `SiPolicy.p7b` file (306 KB, timestamped 3/27/2026) is the compiled policy now sitting in the active location. The older `driversipolicy.p7b` and `VbsSiPolicy.p7b` are pre-existing system policies — leave them alone.

Trigger a no-reboot refresh:
```powershell
# Using the RefreshPolicy.exe tool (AMD64 binary from Microsoft)
.\RefreshPolicy.exe
```
Or via GPO:
```
gpupdate /force
```
Validate that the GPO has been applied to the Workstation (WIN11):
```
gpresult /r /scope computer
```

---

### Step 4 — Confirm Policy Activation (Event ID 3099) 🔍

After refreshing, verify the policy loaded successfully by watching the **Microsoft-Windows-CodeIntegrity/Operational** log for **Event ID 3099** — the activation confirmation:

```powershell
# Quick PowerShell one-liner to check recent relevant events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 |
    Where-Object Id -in 3076, 3089 |
    Select-Object TimeCreated, Id, Message
```

![PowerShell output showing Event IDs 3076 and 3089](images/03_powershell_3076_3089.png)

| Event ID | Meaning |
|---|---|
| **3099** ⭐ | Policy refreshed and **activated** — the one to watch for |
| **3102** | Policy refresh finished (may show count of active policies) |
| **3103** | Policy refresh ignored (e.g., duplicate or unchanged) |
| **3096** | No change in active CI policy |
| **3076** | Image **would have been blocked** but was allowed due to **audit mode** |
| **3089** | Signature information associated with another event (use Correlation ID to link) |

You want to see **3099** ⭐ to confirm your policy is live.

---

### Step 5 — Collect Audit Telemetry (Event ID 3076)

With the policy confirmed active, leave it in audit mode and use the PAW normally — launch the applications that need to be allowed (Adobe, 7-Zip, admin tooling, etc.). The **3076** events are your audit telemetry — they tell you exactly what would be blocked if you switched to enforce today.

Open Event Viewer and filter the CodeIntegrity/Operational log to **Event ID 3076**:

```
C:\Windows\System32\mmc.exe eventvwr.msc /c:"Microsoft-Windows-CodeIntegrity/Operational"
```

![Event Viewer filtered to 3076 — 7-Zip would-have-been-blocked](images/04_event_viewer_3076_7zip.png)

The example above shows `explorer.exe` attempting to load `7-Zip\7zFM.exe` — it was allowed because of audit mode, but the event tells you a rule for 7-Zip is needed before you enforce.

> 💡 **Tip:** The filter banner at the top shows **29 events** for Event ID 3076 in this lab run — each one is a rule gap you need to close before enforcing.

---

### Step 6 — Convert Event Logs to Policy Rules

Back in the wizard → **Policy Editor** → **Convert Event Logs to a Policy**.

Select **Parse Event Logs from the system Event Viewer to Policy** (uses local `Microsoft-Windows-CodeIntegrity/Operational` and `Microsoft-Windows-AppLocker/MSI and Script` logs), then click **Parse Event Logs**.

![Wizard — Convert Event Logs screen, successfully parsed](images/06_convert_event_logs.png)

When the wizard presents candidate rules from the parsed 3076 events, you must choose a **rule level** for each one. Picking the right level is the most important decision in this step — too specific and you'll be updating rules constantly; too broad and you lose meaningful control. See [Rule Levels Reference](#rule-levels-available-on-windows-11) below for the full table.

#### 📐 Rule Selection for This Session

Apply the hierarchy: **Publisher → FilePublisher → SignedVersion → FileName → FilePath → Hash**. Only drop down to the next level when the level above doesn't cleanly cover the target binary.

- **Adobe components** → use **Publisher** — Adobe consistently signs its binaries with a clean chain; one rule covers all related executables
- **7-Zip** → use **FileName** or **File Attributes** — the publisher chain is less clean in event-log conversion; FileName is more stable than Hash across updates
- **Vendors with frequent updates** (e.g., a tool that ships monthly patches) → consider **SignedVersion** — allows all future versions at or above a version floor without policy changes
- **Custom admin tools in locked-down directories** → consider **FilePath** — appropriate when the binary is unsigned but lives in an admin-only path like `C:\Program Files\CustomTool\`; WDAC enforces a runtime check that the path is not user-writable
- 🚫 **Avoid Hash as primary strategy** — every binary update invalidates the rule and requires a policy change; use it only when no signing info is available and FilePath isn't appropriate

> ⚠️ **UX warning:** The wizard does not make undo easy after rules are added. Review each candidate carefully before clicking through.

---

### Step 7 — Rename and Version the Policy for Enforce

Before merging and switching to enforce, edit the policy identity so audit vs. enforce is unambiguous.

Policy Editor → **Edit Policy XML File** → browse to your base XML → update:

| Field | Example value |
|---|---|
| Policy Name | `Enforce-Microsoft_2026-03-27` |
| Policy ID | `2026-03-27v3` |

![Wizard — Edit Policy screen with enforce naming](images/07_edit_policy_naming.png)

> 💡 Convention: include `Enforce`/`Audit`, a date, and a version number. This makes troubleshooting much easier when you are looking at event logs days later.

---

### Step 8 — Switch to Enforce Mode 🔒

On the **Policy Rules** screen, turn **Audit Mode OFF**. All other settings carry forward.

![Policy Rules — Enforce Mode (Audit Mode off)](images/08_policy_rules_enforce.png)

Note: In enforce mode the Advanced Options panel is collapsed by default — the rules you set earlier (Boot Audit on Failure, etc.) are still in the XML; they just are not shown by default in this view.

---

### Step 9 — File Rules After Merge with Block Lists (Enforce Policy)

After merging the event-log-derived allow rules into the enforce policy and re-merging the block lists, the File Rules screen now shows both **Allow** (Microsoft root publishers) and **Deny** entries (DigiCert/VeriSign chains associated with known bypass tools).

![File Rules — Enforce policy with Deny rules from block lists](images/09_file_rules_deny_rules.png)

> In this view the "Merge with Recommended Block Rules" checkboxes are unchecked — that is correct; the deny rules have already been merged into the policy XML. The resulting deny entries for DigiCert Assured ID, DigiCert SHA2, and VeriSign Class 3 chains are visible in the list.

---

### Step 10 — Deploy via Group Policy 📡

GPO path:
```
Computer Configuration\Administrative Templates\System\Device Guard
→ Deploy App Control for Business → Edit
```

In this lab: GPO `GPO_WDAC_Enforcement` is linked to the `Workstation` OU in `skynet-home.local`.

![Group Policy Management — GPO_WDAC_Enforcement linked to Workstation OU](images/11_gpo_management.png)

Push the policy:
```
gpupdate /force
```

---

### Step 11 — Validate: Enforcement in Action 🚨

#### App Control block toast

After the enforce policy refreshes (watch for Event ID **3099**), attempt to launch an unauthorized application — Firefox in this test:

![Desktop — Firefox blocked, GPO_WDAC_Enforcement visible in GPMC](images/12_firefox_blocked_desktop.png)

The end-user sees:
> *"Your organization used App Control for Business to block this app"*  
> `C:\Users\Lorenzo.SKYNET\Desktop\Firefox.exe`

#### Event log confirmation

The Event Viewer simultaneously shows the 3099 activation event alongside the block:

![Event Viewer — 3099 activation + Firefox block toast](images/10_event_viewer_3099_block.png)

The before/after pattern:
| Mode | What you see |
|---|---|
| **Audit** | Event 3076 — *"would have been blocked... allowed to load"* |
| **Enforce** 🔒 | App Control block toast + Event 3099 confirming policy active |

---

## 4. ✅ STIG Compliance Verification

With the enforce policy active, run the STIG check command:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | FL *codeintegrity*
```

![PowerShell — Both enforcement status values = 2](images/14_enforcement_status_2.png)

```
CodeIntegrityPolicyEnforcementStatus          : 2
UsermodeCodeIntegrityPolicyEnforcementStatus  : 2
```

| Value | Meaning |
|---|---|
| `2` | ✅ **Enforced** — that field meets its numeric STIG check |
| `1` | ⚠️ Audit only — finding is open |
| `0` | ❌ Not Configured — finding is open |

With both values at `2`, the two numeric STIG checks are met on the tested PAW. Confirm that the loaded policy is the approved PAW allowlist before recording the final assessment.

> For the full finding descriptions and what each check verifies, see [Section 1 — Why This Matters](#1--why-this-matters--the-two-stig-cat-ii-findings).

---

## 5. 📚 Key Reference Material

### Paths and Commands

| Item | Value |
|---|---|
| Active policy path | `C:\Windows\System32\CodeIntegrity\CIPolicies\Active\` |
| Open CI event log | `C:\Windows\System32\mmc.exe eventvwr.msc /c:"Microsoft-Windows-CodeIntegrity/Operational"` |
| GPO node | `Computer Configuration\Administrative Templates\System\Device Guard\Deploy App Control for Business` |
| Force GPO refresh | `gpupdate /force` |
| STIG check | `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard \| FL *codeintegrity*` |

### Event ID Reference

| ID | Meaning |
|---|---|
| 3076 | Would-have-been-blocked (audit mode telemetry) |
| 3089 | Signature info for a correlated event |
| 3096 | No change in active CI policy |
| 3099 ⭐ | Policy **refreshed and activated** |
| 3102 | Policy refresh finished |
| 3103 | Policy refresh ignored |
| 3105 | Policy refresh in progress |

### Rule Levels Available on Windows 11

> Reference: [App Control for Business feature availability — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)

| Rule Level | What it matches on | Windows 11 | Best used when |
|---|---|---|---|
| **Publisher** | The code-signing certificate's Issuing CA + the publisher's common name | ✅ | Vendor is well-known and consistently signs their software (e.g., Adobe, Microsoft) |
| **FilePublisher** | Publisher + specific filename + minimum version | ✅ | You want Publisher-level trust but scoped to a specific executable and version floor |
| **SignedVersion** | Publisher + a minimum version number (allows all files from that publisher at or above that version) | ✅ | Vendor ships frequent updates; you want to allow future versions without a policy change |
| **FileName** | The `OriginalFileName` attribute in the file's resource header (not the on-disk name) | ✅ | App is not well-signed but has a stable, predictable original filename across updates |
| **FilePath** | A specific file system path (user mode only — cannot allow kernel drivers) | ✅ (Win 10 1903+) | Trusted admin-only directories; runtime check enforces the path is not user-writable |
| **Hash** | A unique cryptographic fingerprint of the exact binary | ✅ | Last resort only — every update changes the hash and requires a policy update |
| **PackagedFamilyName** | MSIX/AppX package family name | ✅ | Store apps or MSIX-packaged software |
| **WHQLFilePublisher** | WHQL-certified driver publisher + filename + version | ✅ | Driver allowlisting with version floors |

### Links From the Session

| Resource | URL |
|---|---|
| Deploy App Control via Group Policy | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy |
| App Control feature availability | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability |
| Path-based rules | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create |
| Script Enforcement + PowerShell CLM | https://github.com/HotCakeX/Harden-Windows-Security/wiki/Script-Enforcement-and-PowerShell-Constrained-Language-Mode-in-WDAC-App-Control-Policies |

---

## 6. ⚠️ Caveats, Advanced Options & Policy Rule Recommendations

This section consolidates operational gotchas and Advanced Options panel settings you need to understand before deploying to production.

### Operational Gotchas

- 🔀 **Merge order matters:** When merging policies in the wizard, the **first policy selected is the primary/winner**. Always put your base policy first. Reversing this can corrupt the effective policy.
- 🖥️ **One effective policy per endpoint:** Even with multiple GPO links across OUs, the endpoint enforces one effective WDAC policy. Plan accordingly.
- 📡 **ISG must be off** for any disconnected/air-gapped environment. Leaving it on with no Internet will cause unexpected allow/block behavior.
- 🥾 **Boot Audit on Failure** is hidden under Advanced Options and is **off by default**. Always enable it during initial testing phases to prevent an untested policy from hard-locking a system on reboot.
- 🔧 **Managed Installer and MECM:** Managed Installer does not automatically register ConfigMgr as trusted in every deployment. You may need a re-deployment or a registry-key workaround to properly mark MECM as a trusted managed installer.

### 🐚 Script Enforcement + PowerShell Constrained Language Mode — Deep Dive

This policy ships with `Disabled:Script Enforcement` — a deliberate PAW design decision. Here is the full picture of what this means and why:

**What script enforcement does when enabled:** WDAC enforces Constrained Language Mode (CLM) based on **script policy coverage, not caller identity**. Any script not explicitly covered by a policy allow rule runs in CLM regardless of who runs it — Domain Admin, SYSTEM, or standard user. Interactive PowerShell is also placed in CLM machine-wide whenever script enforcement is active on any UMCI policy, even if that policy is in audit mode. This means GPO startup scripts, admin `.ps1` tooling, and scheduled tasks running as SYSTEM are all equally subject to CLM if their scripts aren't covered by explicit policy allow rules.

**What disabling it does:** Removes the WDAC-level script constraint entirely. PowerShell runs in Full Language Mode for anyone who can launch it; access control is handled at the OS privilege layer instead.

**The net result in this lab:** Regular users cannot execute PowerShell (OS privilege control), Domain Admins can run scripts in Full Language Mode (WDAC not interfering). This is the correct posture for a PAW.

**Verify the active language mode at any time:**
```powershell
$ExecutionContext.SessionState.LanguageMode
# FullLanguage  → script enforcement is OFF (expected with this policy)
# ConstrainedLanguage → script enforcement is ON
```

### Advanced Options Panel — Setting-by-Setting Analysis

The following settings appear in the wizard's Advanced Options panel or on the main Policy Rules screen. Each has been evaluated specifically for a **disconnected PAW environment** running Windows 11 Enterprise 25H2.

#### Summary

| Setting | Recommendation | Reason |
|---|---|---|
| Treat Revoked as Unsigned | ✅ Leave **OFF** | Legacy cert chains in gov environments |
| Disable Runtime Filepath Rules | ✅ Leave **OFF** | Keeping it OFF means the runtime path protection is ON |
| Dynamic Code Security | ⚠️ Leave **OFF** for now | No audit mode — enforce-only, high break risk |
| Invalidate EAs on Reboot | ✅ Leave **OFF** | ISG is disabled, this setting has no effect |
| Require EV Signers | ✅ Leave **OFF** | Older drivers lack EV certs, boot risk |

---

#### Treat Revoked as Unsigned — ✅ Leave OFF

Treats binaries signed with revoked certificates as unsigned. In government and DoD environments you will frequently encounter legacy software with expired or revoked cert chains (Axway/Tumbleweed is a real-world example). On a PAW where the binary allowlist is already the primary enforcement control, the risk of silently breaking legitimate legacy tools outweighs the marginal security gain from this setting.

---

#### Disable Runtime Filepath Rules — ✅ Leave OFF

The naming is counterintuitive. Leaving this **OFF** means the protection is **ON** — the runtime check that ensures FilePath rules only apply to admin-writable paths is actively enforced. Enabling this toggle would allow FilePath rules to match user-writable paths, which undermines the security model entirely. Never appropriate on a PAW.

---

#### Dynamic Code Security — ⚠️ Leave OFF for now

Extends WDAC enforcement to .NET assemblies and dynamically loaded code. Valuable in theory on a PAW, but carries a critical operational risk: **there is no audit mode for this setting**. The moment it is enabled it enforces immediately with no warning telemetry to identify what will break. Any .NET-based admin tooling, MMC snap-ins, or PowerShell modules that load dynamic assemblies could stop working instantly. Given the working set already includes Adobe, ADUC snap-ins, and GPO tools, leave this OFF for now. Treat it as a future hardening step requiring dedicated testing in a snapshot/rollback-capable lab environment before being applied to a production PAW.

---

#### Invalidate EAs on Reboot — ✅ Leave OFF

This setting only has an effect when **Intelligent Security Graph (ISG)** is enabled — it forces ISG-authorized files to be revalidated against Microsoft's cloud reputation service on each reboot. Since this policy has ISG **disabled** (disconnected / no Internet environment), this toggle has no functional effect in either state. Leave it OFF.

---

#### Require EV Signers — ✅ Leave OFF

Requires all drivers to carry **Extended Validation (EV) certificates**. Many older drivers — including common enterprise and government tooling — were signed with standard code signing certificates that predate the EV requirement. Enabling this without a complete driver inventory is a credible path to a boot failure. Leave it OFF unless you have audited every driver on the PAW and confirmed full EV coverage.

---

## 7. 🖥️ Virtualization Based Security (VBS) & HVCI — Hyper-V Lab Setup

VBS and HVCI are complementary to WDAC and are typically configured as part of the same PAW hardening effort. WDAC governs what can run; HVCI ensures those enforcement decisions cannot be subverted at the kernel level. This section covers enabling both in a Hyper-V lab environment.

Enabling VBS and HVCI on a Hyper-V guest requires configuration at two layers — the **host** (to expose virtualization extensions to the VM) and the **guest** (to configure and activate the VBS stack via GPO).

---

### On the Hyper-V Host

> [!IMPORTANT]
> The VM must be **shut down** before running these commands. Nested virtualization cannot be enabled on a running VM.

**Step 1 — Expose virtualization extensions to the guest:**
```powershell
Set-VMProcessor -VMName "YourVMName" -ExposeVirtualizationExtensions $true
```

**Step 2 — Disable dynamic memory** (incompatible with VBS):
```powershell
Set-VMMemory -VMName "YourVMName" -DynamicMemoryEnabled $false
```

**Step 3 — Verify nested virtualization is enabled:**
```powershell
Get-VMProcessor -VMName "YourVMName" | Select-Object ExposeVirtualizationExtensions
# ExposeVirtualizationExtensions : True
```

Boot the VM and proceed with guest configuration.

---

### On the Guest — Enable VBS via Group Policy

**Step 1 — Open Group Policy Editor and navigate to:**
```
Computer Configuration → Administrative Templates → System → Device Guard
→ Turn On Virtualization Based Security → Edit
```

**Step 2 — Set the following options:**

| Setting | Recommended Value |
|---|---|
| Turn On Virtualization Based Security | **Enabled** |
| Select Platform Security Level | Secure Boot and DMA Protection |
| Virtualization Based Protection of Code Integrity | Enabled without UEFI lock |
| Credential Guard Configuration | Enabled without UEFI lock |

> [!IMPORTANT]
> **Consider UEFI lock for production PAWs.** Enabling with UEFI lock writes the VBS configuration into firmware, meaning it cannot be disabled via software, Group Policy, or even a compromised OS. This is the right choice for a production PAW precisely because it prevents an attacker with SYSTEM or Domain Admin access from turning off Credential Guard or HVCI to facilitate credential theft or kernel exploitation. Without the lock, a sufficiently privileged attacker could simply GPO or registry their way around it.

**Step 3 — Apply and reboot:**
```
gpupdate /force
```
Reboot the guest.

**Step 4 — Verify the posture after reboot:**
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | FL *virtualization*, *security*
```

---

### Before / After — Expected State Change

| Property | Before | After | Meaning |
|---|---|---|---|
| `VirtualizationBasedSecurityStatus` | `2` | `2` | ✅ VBS running at both stages |
| `RequiredSecurityProperties` | `{0}` | `{1, 2}` | ✅ Now requires Secure Boot (1) + DMA Protection (2) |
| `SecurityServicesConfigured` | `{0}` | `{1, 2}` | ✅ Credential Guard (1) + HVCI (2) configured |
| `SecurityServicesRunning` | `{1}` | `{1, 2}` | ✅ Both Credential Guard (1) and HVCI (2) now running |
| `SecurityFeaturesEnabled` | `{0}` | `{0}` | GPO-driven — reflects firmware-level features, expected |

**Value decode for `SecurityServicesRunning` / `SecurityServicesConfigured`:**
| Value | Service |
|---|---|
| `1` | Credential Guard |
| `2` | HVCI (Hypervisor-Protected Code Integrity) |

**Value decode for `RequiredSecurityProperties`:**
| Value | Property |
|---|---|
| `1` | Secure Boot |
| `2` | DMA Protection |

---

### What This Posture Provides

**Credential Guard** isolates LSASS into a VBS-protected enclave, preventing credential material (NTLM hashes, Kerberos tickets) from being read by tools like Mimikatz even with SYSTEM-level access. On a PAW this is critical — admin credentials are high-value targets.

**HVCI (Hypervisor-Protected Code Integrity)** enforces kernel code integrity from the hypervisor layer, sitting below the OS. It prevents unsigned or malicious code from being injected into the kernel, and it strengthens WDAC enforcement by making it significantly harder to bypass — the hypervisor validates kernel code integrity independent of the OS itself.

Together they form the hardware-backed security baseline that makes a PAW meaningfully resistant to credential theft and kernel-level attacks, not just application-layer controls.

> 💡 **Combined with WDAC:** HVCI and WDAC are complementary controls. WDAC governs what can run in user mode and kernel mode. HVCI ensures those enforcement decisions cannot be subverted by kernel-level attackers. Running both is the recommended PAW posture.

---

### Microsoft Documentation

| Resource | URL |
|---|---|
| Virtualization Based Security | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs |
| Configure Credential Guard | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure |
