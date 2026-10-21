# WDAC/GPO Node.js Install Runbook

> 📅 **Date:** May 22, 2026  
> 💻 **Client:** `WIN11-ENT-2`  
> 🏢 **Domain:** `skynet-home.local`  
> 🗄️ **GPO/Share Host:** `DC25-1`, Windows Server 2025  
> 🎯 **Goal:** Allow Node.js installs/upgrades while keeping WDAC UMCI enforcement enabled.

## Executive Summary

The original `winget install` for Node.js failed because Windows Defender Application Control (WDAC) was enforcing a GPO-delivered Code Integrity policy. The first block was the OpenJS Node.js MSI itself. After allowing OpenJS-signed MSI installers with a supplemental WDAC policy, the MSI started but failed later because `msiexec.exe` extracted and loaded an unsigned temporary custom-action DLL from `C:\Windows\Installer`.

The final fix keeps UMCI enabled and adds a targeted supplemental WDAC policy for the Node MSI custom-action binaries:

- ✅ Base WDAC policy remains enforced and UMCI-enabled.
- ✅ Base WDAC policy allows supplemental policies.
- ✅ OpenJS publisher supplemental policy allows the signed Node MSI installers.
- ✅ Node MSI custom-action supplemental policy allows the extracted MSI DLLs narrowly.
- ✅ `winget install --id OpenJS.NodeJS` now succeeds.

> [!IMPORTANT]
> We did **not** leave DLL/user-mode enforcement disabled. UMCI was restored in a forward base policy revision, `10.0.5.9`.

> [!NOTE]
> This is a historical lab record, not evidence of the current endpoint state. Microsoft's built-in **Deploy App Control for Business** GPO setting supports single-policy format only; it does not deploy a base-plus-supplemental policy set. The `.cip` registration below was a separate local CiTool action. For a reproducible supported design, choose either the [single merged-policy GPO workflow](../README.md#choose-the-policy-management-model-first) or a deliberately planned [multiple-policy deployment](../README.md#alternative-base-plus-supplemental-policies). Verify actual identities, format, signing, and activation rather than inferring them from extensions or this reserved legacy GUID. See [current diagnostic procedures](../DIAGNOSTICS-README.md).

## Active WDAC State

### Base WDAC Policy

| Item | Value |
|---|---|
| Policy ID | `{a244370e-44c9-4c06-b551-f6016e563076}` |
| Friendly name | `GPO_Enforcement_ISG_WSL_DKR-Microsoft_2026-03-29` |
| Current version | `10.0.5.9` |
| Enforcement | Enabled |
| UMCI | Enabled |
| Supplemental policies | Enabled |
| GPO policy path | `\\DC25-1\Temp\GPO_WDAC_ISG_WSL_DKR_Enforce_SiPolicy.p7b` |

### Supplemental Policies

| Purpose | Policy ID | Status |
|---|---|---|
| Allow OpenJS Node.js publisher MSI installers | `{AFD20339-E36B-4A56-82A2-46702A81DFAB}` | Enforced/authorized |
| Allow Node.js MSI custom-action binaries | `{1718C157-3476-4749-A294-5DD64991A55E}` | Enforced/authorized |

## What Was Happening

The install command was:

```powershell
winget install --id OpenJS.NodeJS -e --source winget
```

The first failure was:

```text
Organization policies are preventing installation.
Installer failed with exit code: 1625
```

That pointed to policy enforcement, not a normal MSI failure. AppLocker service was present, but the decisive enforcement came from WDAC/Code Integrity through GPO.

The active GPO registry settings pointed to the network-share policy:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
    Select-Object DeployConfigCIPolicy, ConfigCIPolicyFilePath
```

Expected values:

```text
DeployConfigCIPolicy = 1
ConfigCIPolicyFilePath = \\DC25-1\Temp\GPO_WDAC_ISG_WSL_DKR_Enforce_SiPolicy.p7b
```

### Why the First Supplemental Policy Was Not Enough

The OpenJS supplemental policy allowed the signed MSI installer. After that, Code Integrity allowed the MSI itself:

```text
node-v26.2.0-x64.msi passed Config CI policy and was allowed to run.
```

But then MSI execution failed with:

```text
Error 1723. There is a problem with this Windows Installer package.
Action SetInstallScope, entry: SetInstallScope,
library: C:\WINDOWS\Installer\MSIEE79.tmp
```

And Code Integrity logged event `3077`:

```text
msiexec.exe attempted to load C:\Windows\Installer\MSIEE79.tmp
that did not meet Enterprise signing level requirements or violated code integrity policy.
Policy ID: {a244370e-44c9-4c06-b551-f6016e563076}
```

> [!TIP]
> MSI publisher trust does not automatically trust every temporary custom-action DLL extracted by the MSI. UMCI evaluates that DLL when `msiexec.exe` loads it.

## What Was Changed

### 1. Allowed Supplemental WDAC Policies in the Base Policy

The editable base XML was found under:

```text
C:\Users\Lorenzo.SKYNET\Documents\STIG - WPAW
```

The base policy was revised to include:

```xml
<Option>Enabled:Allow Supplemental Policies</Option>
```

That produced the revised base used in this lab's subsequent local `.cip` registration tests. Option 17 alone is not a complete supplemental deployment procedure; policy format, base association, signing authorization, and actual loading must also be verified.

> [!IMPORTANT]
> The base policy must have `Enabled:Allow Supplemental Policies`; otherwise, supplemental `.cip` files may exist on disk but will not be authorized by the base policy. This option is **not required** when event-derived rules are merged into a single updated base instead.

### 2. Built an OpenJS Publisher Supplemental Policy

The OpenJS supplemental policy allows Node MSI installers signed by OpenJS Foundation.

Key files:

```text
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Allow-OpenJS-NodeJS.xml
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\{AFD20339-E36B-4A56-82A2-46702A81DFAB}.cip
```

The policy contains a publisher rule for:

```text
OpenJS Foundation
```

### 3. Kept UMCI Enabled

We briefly tested a no-UMCI base policy direction, then decided that was too broad. WDAC would not accept rolling back from active version `10.0.5.8` to older version `10.0.5.7`, so the UMCI-enabled base policy was restored as a forward revision:

```text
10.0.5.9
```

> [!WARNING]
> WDAC base policy updates are effectively forward-versioned. If a higher `VersionEx` has already become active, restore older settings by creating a **newer** policy version, not by redeploying an older version.

### 4. Extracted the Node MSI Custom-Action Binaries

The Node MSI `CustomAction` table showed the failing action:

| Action | Type | Source | Target |
|---|---:|---|---|
| `SetInstallScope` | `1` | `CustomActionsDLL` | `SetInstallScope` |

The MSI `Binary` table included:

```text
CustomActionsDLL
Wix4UtilCA_X64
Wix4UtilCA_X86
WixUiCa_X86
```

The extracted PE files showed:

| Binary | Signature | WDAC allow method |
|---|---|---|
| `CustomActionsDLL.dll` | Not signed | Hash rule |
| `Wix4UtilCA_X64.dll` | WiX Toolset (.NET Foundation) | Publisher rule |
| `Wix4UtilCA_X86.dll` | WiX Toolset (.NET Foundation) | Publisher rule |
| `WixUiCa_X86.dll` | WiX Toolset (.NET Foundation) | Publisher rule |

> [!CAUTION]
> `CustomActionsDLL.dll` is unsigned. Its hash is version-specific, so future Node MSI upgrades may require rebuilding and re-registering the custom-action supplemental policy.

### 5. Built the Targeted Custom-Action Supplemental Policy

New helper scripts were created:

```text
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-Node-MSI-CustomActions-WDAC.ps1
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Register-Node-MSI-CustomActions-WDAC-With-CiTool.ps1
```

Generated policy files:

```text
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Allow-Node-MSI-CustomActions.xml
C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\{1718C157-3476-4749-A294-5DD64991A55E}.cip
```

The custom-action supplemental policy:

- Hash-allows the unsigned Node `CustomActionsDLL.dll` files.
- Publisher-allows WiX Toolset custom-action helper DLLs.
- Supplements base policy `{A244370E-44C9-4C06-B551-F6016E563076}`.

## Observed Lab: GPO Base and Separate Local Supplemental Registration

### Base `.p7b` via Server 2025 Network Share

The base WDAC policy is distributed through GPO using this network share path:

```text
\\DC25-1\Temp\GPO_WDAC_ISG_WSL_DKR_Enforce_SiPolicy.p7b
```

The client receives that path through:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigCIPolicyFilePath
```

When `DeployConfigCIPolicy = 1`, the client applies the `.p7b` policy from the network share as the WDAC base policy.

### Why the New `.cip` Is Authorized

The lab recorded authorization after the following configuration and registration steps. Do not generalize these observations into support for multiple-policy delivery by the built-in GPO setting:

1. The active base `.p7b` contains `Enabled:Allow Supplemental Policies`.
2. The supplemental policy has this base reference:

   ```xml
   <BasePolicyID>{A244370E-44C9-4C06-B551-F6016E563076}</BasePolicyID>
   ```

3. The supplemental policy was registered with `CiTool.exe --update-policy`.
4. Code Integrity refreshed and reported the supplemental as enforced and authorized.

> [!NOTE]
> The GPO network share delivers the base `.p7b`. The supplemental `.cip` was registered locally with CiTool in this VM. For multiple machines, deploy/register that `.cip` with a GPO startup script, software deployment tool, Intune, ConfigMgr, or another admin-managed mechanism.

## Important Commands Used

### Check WDAC GPO Registry Settings

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' |
    Select-Object DeployConfigCIPolicy, ConfigCIPolicyFilePath
```

### Check Device Guard / WDAC Status

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object CodeIntegrityPolicyEnforcementStatus,
                  UsermodeCodeIntegrityPolicyEnforcementStatus,
                  VirtualizationBasedSecurityStatus
```

Expected enforcement status observed:

```text
CodeIntegrityPolicyEnforcementStatus = 2
UsermodeCodeIntegrityPolicyEnforcementStatus = 2
VirtualizationBasedSecurityStatus = 2
```

### List Active WDAC Policies

```powershell
& "$env:WINDIR\System32\CiTool.exe" --list-policies --verbose
```

> [!TIP]
> On this build, `CiTool.exe --json --verbose` was not valid. Use `--verbose` by itself.

### Refresh WDAC Policies

```powershell
& "$env:WINDIR\System32\CiTool.exe" --refresh --verbose
```

### Update a Policy with CiTool

```powershell
& "$env:WINDIR\System32\CiTool.exe" --update-policy "C:\Path\To\Policy.cip" --verbose
```

For the GPO base `.p7b`:

```powershell
& "$env:WINDIR\System32\CiTool.exe" --update-policy "\\DC25-1\Temp\GPO_WDAC_ISG_WSL_DKR_Enforce_SiPolicy.p7b" --verbose
```

### Build the OpenJS Publisher Supplemental Policy

```powershell
& 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-And-Stage-OpenJS-Node-WDAC.ps1'
```

### Register the OpenJS Publisher Supplemental Policy

```powershell
$script = 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Register-OpenJS-Node-WDAC-With-CiTool.ps1'
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
Start-Process -FilePath $ps -Verb RunAs -ArgumentList $args -Wait
```

### Build the Node MSI Custom-Action Supplemental Policy

```powershell
& 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-Node-MSI-CustomActions-WDAC.ps1'
```

To build for explicit MSI files:

```powershell
& 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-Node-MSI-CustomActions-WDAC.ps1' `
    -MsiPath @(
        'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\node-v26.2.0-x64.msi',
        'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\node-v24.16.0-x64.msi'
    )
```

### Register the Node MSI Custom-Action Supplemental Policy

```powershell
$script = 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Register-Node-MSI-CustomActions-WDAC-With-CiTool.ps1'
$ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
Start-Process -FilePath $ps -Verb RunAs -ArgumentList $args -Wait
```

### Retry Node Install

```powershell
winget install --id OpenJS.NodeJS -e --source winget --accept-package-agreements --accept-source-agreements
```

### Validate Node and npm

```powershell
node --version
npm --version
where.exe node
where.exe npm
```

Validated result:

```text
node --version = v26.2.0
npm --version  = 11.13.0
node.exe       = C:\Program Files\nodejs\node.exe
npm            = C:\Program Files\nodejs\npm
npm.cmd        = C:\Program Files\nodejs\npm.cmd
```

## Event Log Commands

### Recent Code Integrity Blocks

```powershell
$start = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    StartTime = $start
    Id = 3077
} | Select-Object TimeCreated, Id, @{Name='Message'; Expression = { $_.Message -replace "`r?`n\s*", ' ' }}
```

### AppLocker MSI and Script Events

```powershell
$start = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
    StartTime = $start
} | Select-Object TimeCreated, Id, LevelDisplayName, Message
```

## Future Node Upgrade Process

Use this process before installing a future Node MSI version.

1. Download or let winget cache the new Node MSI.
2. Copy the MSI into:

   ```text
   C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS
   ```

3. Verify the MSI is signed by OpenJS Foundation:

   ```powershell
   Get-AuthenticodeSignature 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\node-vNEW-x64.msi' |
       Select-Object Status, @{Name='Signer'; Expression = { $_.SignerCertificate.Subject }},
                     @{Name='Issuer'; Expression = { $_.SignerCertificate.Issuer }}
   ```

4. Rebuild the custom-action supplemental policy:

   ```powershell
   & 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-Node-MSI-CustomActions-WDAC.ps1'
   ```

5. Register the updated `.cip` with CiTool:

   ```powershell
   $script = 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Register-Node-MSI-CustomActions-WDAC-With-CiTool.ps1'
   $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
   $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
   Start-Process -FilePath $ps -Verb RunAs -ArgumentList $args -Wait
   ```

6. Install or upgrade Node:

   ```powershell
   winget upgrade --id OpenJS.NodeJS -e --source winget --accept-package-agreements --accept-source-agreements
   ```

   Or, for a fresh install:

   ```powershell
   winget install --id OpenJS.NodeJS -e --source winget --accept-package-agreements --accept-source-agreements
   ```

> [!WARNING]
> If rebuilding the supplemental policy multiple times in the same minute, pass a higher `-PolicyVersion` manually. WDAC expects policy versions to move forward.

Example:

```powershell
& 'C:\Users\Lorenzo.SKYNET\Documents\WDAC\Allow-OpenJS-NodeJS\Build-Node-MSI-CustomActions-WDAC.ps1' -PolicyVersion '1.26.142.800'
```

## Troubleshooting Notes

### `1625` / Organization Policies Preventing Installation

Likely meaning:

```text
The MSI itself is blocked by WDAC or another enterprise policy.
```

Check:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
    Id = 8028, 8029, 8036, 8037
} -MaxEvents 20
```

Also check Code Integrity Operational logs.

### `1603` with MSI `Error 1723`

Likely meaning:

```text
The MSI started, but a custom-action DLL failed to load.
```

For Node, the important failure was:

```text
Action SetInstallScope
library: C:\WINDOWS\Installer\MSIEE79.tmp
```

That was resolved by allowing the extracted `CustomActionsDLL.dll` by hash.

### CiTool Error `0x800711C7`

Observed when trying to apply an older base policy version after a newer version had already become active.

Fix:

```text
Create a new policy revision with a higher VersionEx and the desired settings.
```

### CiTool Prompts for Enter

`CiTool.exe` prints:

```text
Press Enter to Continue
```

The registration scripts handle that by redirecting standard input and writing a newline.

### Unrelated WDAC Event Seen After Node Install

After Node succeeded, a recent Code Integrity `3077` event remained for Docker Compose:

```text
com.docker.backend.exe attempted to load ...\.docker\modules\tmp\compose\cli-plugins\compose\windows\docker-compose.exe
```

That event is unrelated to the Node.js install path.

## Security Notes

> [!IMPORTANT]
> Keeping UMCI enabled preserves user-mode code integrity enforcement. The final solution allows only the specific Node MSI custom-action pieces needed for install/upgrade.

> [!CAUTION]
> A publisher rule for WiX Toolset is broader than a hash rule for each WiX DLL. If a stricter posture is required, rebuild the custom-action policy at `-Level Hash` only, or edit the policy to hash-allow the WiX helper DLLs instead of using the WiX publisher signer.

> [!TIP]
> For fleet rollout, treat the custom-action `.cip` like a managed deployment artifact. Register it before the Node upgrade window, then run the `winget` upgrade after Code Integrity confirms the supplemental is authorized.

## Final Validation

The final validation command succeeded:

```powershell
winget install --id OpenJS.NodeJS -e --source winget --accept-package-agreements --accept-source-agreements
```

Result:

```text
Successfully installed
```

Runtime validation:

```text
node --version = v26.2.0
npm --version  = 11.13.0
```

The targeted supplemental policy was visible in CiTool output:

```text
Policy ID: 1718c157-3476-4749-a294-5dd64991a55e
Friendly Name: Allow Node.js MSI custom action binaries
Is Currently Enforced: true
Is Authorized: true
```

✅ **Resolution:** Node.js installs successfully under the WDAC GPO policy while UMCI remains enabled.