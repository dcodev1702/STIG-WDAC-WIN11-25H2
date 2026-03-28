# 🛡️ App Control for Business (WDAC) on Windows 11 Enterprise 25H2 — PAW How-To

> **Environment:** Windows 11 Enterprise 25H2 · lab domain `skynet-home.local` · App Control Policy Wizard 2.7  
> **Deployment method:** Group Policy (GPO)  
> **Connectivity assumption:** Fully offline / disconnected — no ISG / cloud reputation  
> **Primary driver:** DISA STIG — two CAT II findings on Privileged Access Workstations (PAWs)

---

## 1. 🎯 Why This Matters — The Two STIG CAT II Findings

Before touching the wizard, understand what you are satisfying.

### WPAW-00-001050 — CAT II · Device Guard Code Integrity Policy (CI policy active)

> *The Windows PAW must have a WDAC / Code Integrity policy deployed and active to restrict which applications can run on the system.*

**Check (PowerShell):**
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | FL *codeintegrity*
```
`CodeIntegrityPolicyEnforcementStatus` must be **2** (enforced) or **1** (audit).

### WPAW-00-001060 — CAT II · Device Guard User Mode Code Integrity (UMCI)

> *Same requirement as 001050, but specifically verifies that User Mode Code Integrity (UMCI) is enforced — not just kernel mode.*

**Check (same command):**  
`UsermodeCodeIntegrityPolicyEnforcementStatus` must be **2** (enforced) or **1** (audit).

### How this solution satisfies both findings

| Finding | What is checked | How this policy addresses it |
|---|---|---|
| 001050 | A CI policy is deployed and active | Policy is created, compiled to `.p7b`, deployed via GPO, and confirmed active via Event ID 3099 |
| 001060 | UMCI is specifically enabled | `User Mode Code Integrity` rule is toggled **ON** in the wizard, making `UsermodeCodeIntegrityPolicyEnforcementStatus = 2` |

Once the policy is in **enforce mode** and both values return `2`, both CAT II findings are closed. ✅

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
> This policy is built with **script enforcement disabled** (`Disabled:Script Enforcement` in the XML). This is a deliberate choice for PAW environments where administrators need to run PowerShell scripts.
>
> What this setting does **not** do: it does not grant or remove the ability to run PowerShell for any user. WDAC has no admin-vs-user awareness at the script enforcement layer — it is a machine-wide binary switch. The binary `powershell.exe` itself is still subject to WDAC file rules.
>
> What this setting **does** do: when script enforcement is **enabled**, WDAC forces PowerShell into **Constrained Language Mode** for all users, machine-wide. This breaks admin tooling, Sysmon, and GPO-driven scripts. Disabling it keeps PowerShell in **Full Language Mode** for anyone who can launch the binary — which on a PAW is controlled by OS-level privilege separation, not WDAC.
>
> **Verify the active language mode at any time:**
> ```powershell
> $ExecutionContext.SessionState.LanguageMode
> # FullLanguage  → script enforcement is OFF (expected with this policy)
> # ConstrainedLanguage → script enforcement is ON
> ```
>
> The net result in this lab: regular users cannot execute PowerShell (OS privilege control), Domain Admins can run scripts in Full Language Mode (WDAC not interfering), and system services like Sysmon operate normally. This is the correct posture for a PAW. See [Section 6 — Caveats](#6-️-important-caveats-and-gotchas) for further detail.

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

### Step 4 — Confirm Activation via Event Log 🔍

Watch the **Microsoft-Windows-CodeIntegrity/Operational** log:

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

You want to see **3099** ⭐ to confirm your policy is live. The **3076** events are your audit telemetry — they tell you exactly what would be blocked if you switched to enforce today.

---

### Step 5 — Audit: Let It Run, Collect Events

Leave the policy in audit mode and use the PAW normally — launch the applications that need to be allowed (Adobe, 7-Zip, admin tooling, etc.).

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

When the wizard presents candidate rules from the parsed 3076 events, you must choose a **rule level** for each one. Picking the right level is the most important decision in this step — too specific and you'll be updating rules constantly; too broad and you lose meaningful control.

#### Rule Levels Available on Windows 11

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

#### 📐 Rule Selection for This Session

Apply the hierarchy: **Publisher → FilePublisher → SignedVersion → FileName → FilePath → Hash**. Only drop down to the next level when the level above doesn't cleanly cover the target binary.

- **Adobe components** → use **Publisher** — Adobe consistently signs its binaries with a clean chain; one rule covers all related executables
- **7-Zip** → use **FileName** or **File Attributes** — the publisher chain is less clean in event-log conversion; FileName is more stable than Hash across updates
- 🚫 **Avoid Hash as primary strategy** — every binary update invalidates the rule and requires a policy change; use it only when no signing info is available

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
| `2` | ✅ **Enforced** — finding is closed |
| `1` | ⚠️ Audit only — finding is open |
| `0` | ❌ Not running — finding is open |

Both `WPAW-00-001050` and `WPAW-00-001060` are **satisfied** (status = 2). 🎉

---

**WPAW-00-001050** — CAT II *Device Guard Code Integrity Policy must be used on the Windows PAW to restrict applications that can run on the system (Device Guard Code Integrity Policy)*

Checks that a WDAC/Code Integrity policy is deployed and active on the PAW. Verify with:

```powershell
Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | FL *codeintegrity*
```

`CodeIntegrityPolicyEnforcementStatus` must be **2** (enforced) or **1** (audit).

---

**WPAW-00-001060** — CAT II *Device Guard Code Integrity Policy must be used on the Windows PAW to restrict applications that can run on the system (Device Guard User Mode Code Integrity)*

Specifically checks that UMCI (User Mode Code Integrity) is enforced — not just kernel mode. Same command, but look for:

`UsermodeCodeIntegrityPolicyEnforcementStatus` = **2** (enforced) or **1** (audit).

---

> These are the two WDAC checks — `001050` covers the CI policy existing at all, `001060` covers UMCI enforcement specifically. Your current policy has `Enabled:UMCI` in the rules, so you're on track to satisfy both once you move from audit to enforce mode.

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

### Links From the Session

| Resource | URL |
|---|---|
| Deploy App Control via Group Policy | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy |
| App Control feature availability | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability |
| Path-based rules | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create |
| Script Enforcement + PowerShell CLM | https://github.com/HotCakeX/Harden-Windows-Security/wiki/Script-Enforcement-and-PowerShell-Constrained-Language-Mode-in-WDAC-App-Control-Policies |

---

## 6. ⚠️ Important Caveats and Gotchas

- 🐚 **Script enforcement + PowerShell CLM:** This policy ships with `Disabled:Script Enforcement` — a deliberate PAW design decision. When enabled, script enforcement pushes PowerShell into Constrained Language Mode machine-wide, breaking admin tooling, Sysmon, and GPO scripts. With it disabled, PowerShell runs in Full Language Mode for anyone who can launch it; access control is handled at the OS privilege layer, not by WDAC. See the [!IMPORTANT] callout at the top of Section 3 for full detail and the language mode verification command.
- 🔧 **Managed Installer and MECM:** Managed Installer does not automatically register ConfigMgr as trusted in every deployment. You may need a re-deployment or a registry-key workaround to properly mark MECM as a trusted managed installer.
- 🔀 **Merge order matters:** When merging policies in the wizard, the **first policy selected is the primary/winner**. Always put your base policy first. Reversing this can corrupt the effective policy.
- 🖥️ **One effective policy per endpoint:** Even with multiple GPO links across OUs, the endpoint enforces one effective WDAC policy. Plan accordingly.
- 📡 **ISG must be off** for any disconnected/air-gapped environment. Leaving it on with no Internet will cause unexpected allow/block behavior.
- 🥾 **Boot Audit on Failure** is hidden under Advanced Options and is **off by default**. Always enable it during initial testing phases to prevent an untested policy from hard-locking a system on reboot.
