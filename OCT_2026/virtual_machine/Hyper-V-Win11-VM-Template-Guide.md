# Creating and Deploying a Windows 11 VM Template in Hyper-V

Yes — you can turn an existing, fully installed and configured Windows 11 VM into a reusable **Golden Image / Template** in Hyper-V.

Because standalone Hyper-V Manager does not have a single "Convert to Template" button like System Center Virtual Machine Manager (SCVMM) or VMware vCenter, the best practice is to **generalize the OS with Sysprep** and then use either **Hyper-V Export/Import** or a **Read-Only Golden `.vhdx` Disk** (with full copies or differencing disks).

---

## Table of Contents

1. [Why You Must Generalize Before Cloning](#1-why-you-must-generalize-before-cloning)
2. [Step 1: Back Up or Checkpoint Your VM First](#2-step-1-back-up-or-checkpoint-your-vm-first)
3. [Step 2: Pre-Sysprep Checklist & Windows 11 Gotchas (Research Findings)](#3-step-2-pre-sysprep-checklist--windows-11-gotchas-research-findings)
4. [Step 3: Generalize the VM with Sysprep (`/mode:vm`)](#4-step-3-generalize-the-vm-with-sysprep-modevm)
5. [Step 4: Three Ways to Create New VMs from Your Template](#5-step-4-three-ways-to-create-new-vms-from-your-template)
   - [Option A: Export & Import ("Copy the virtual machine")](#option-a-export--import-copy-the-virtual-machine--easiest-full-vm-template)
   - [Option B: Read-Only Golden `.vhdx` + Full Disk Copy](#option-b-read-only-golden-vhdx--full-disk-copy--cleanest-for-independent-vms)
   - [Option C: Read-Only Golden `.vhdx` + Differencing Disks](#option-c-read-only-golden-vhdx--differencing-disks--best-for-fast-test-labs)
6. [Step 5: Post-Clone Modification & `skynet-home.local` Domain Join Script](#6-step-5-post-clone-modification--skynet-homelocal-domain-join-script)
7. [Bonus: Zero-Touch OOBE with `unattend.xml`](#7-bonus-zero-touch-oobe-with-unattendxml)
8. [Questions & Suggestions for Your Setup](#8-questions--suggestions-for-your-setup)
9. [Resources](#9-resources)

---

## 1. Why You Must Generalize Before Cloning

If you simply copy a `.vhdx` or export/import a VM without generalizing it, every cloned VM will share the exact same:
- **Machine SID (Security Identifier)** — Causes authentication and trust conflicts when joining Active Directory (`skynet-home.local`), Entra ID, or Intune.
- **Computer Name & SMB/NetBIOS Identity** — Causes DNS and network name collisions on your LAN.
- **WSUS / SCCM / Windows Update Client IDs (`SusClientId`)** — Causes cloned VMs to overwrite each other in patch management consoles.
- **KMS Client Machine ID (CMID)** — Breaks volume activation counts.
- **Cryptographic Machine Keys & Event Log Identifiers** — Causes certificate and security auditing collisions.

Running **`sysprep /generalize`** strips all unique machine identity while keeping your installed applications, tools, files, and system configurations intact.

---

## 2. Step 1: Back Up or Checkpoint Your VM First

> **CRITICAL:** Sysprep permanently alters the current Windows installation and prepares it for first-boot Out-of-Box Experience (OOBE). Furthermore, you should never repeatedly boot, update, and re-Sysprep the same post-Sysprep image over and over.

Before doing anything inside the guest OS, choose **one** of these safety patterns on your Hyper-V Host:

### Pattern 1: The "Pre-Sysprep Checkpoint" Workflow (Recommended for Maintenance)
1. Shut down your configured Windows 11 VM.
2. Take a standard checkpoint named **`Pre-Sysprep Master`**:
   ```powershell
   Checkpoint-VM -Name "Win11-Reference" -SnapshotName "Pre-Sysprep Master"
   ```
3. Boot the VM, run Sysprep (which shuts it down), and **export the VM or copy its `.vhdx`**.
4. Next month, when you want to add new software or Windows Updates to your template, simply **Apply** the `Pre-Sysprep Master` checkpoint, install your updates, take a new checkpoint, and run Sysprep again.

### Pattern 2: Full Export Backup Before Sysprep
```powershell
Stop-VM -Name "Win11-Reference"
Export-VM -Name "Win11-Reference" -Path "C:\HyperV\Backups\PreSysprep"
```

---

## 3. Step 2: Pre-Sysprep Checklist & Windows 11 Gotchas (Research Findings)

Windows 11 introduces several specific behaviors that can break Sysprep or prevent cloned VMs from booting if not handled beforehand:

### 1. Suspend / Decrypt BitLocker (`vTPM`)
Windows 11 (especially 24H2+) often enables Device Encryption / BitLocker automatically when a virtual TPM (vTPM) is attached. If BitLocker is active when you run Sysprep or copy the `.vhdx` to a new VM with a new vTPM key protector, Sysprep will fail or the cloned VM will boot into a BitLocker recovery screen.
Run this inside the guest VM (elevated PowerShell) before Sysprep:
```powershell
# Check BitLocker status on all volumes
Get-BitLockerVolume

# If ProtectionStatus is 'On' or VolumeStatus is 'FullyEncrypted', decrypt first:
Disable-BitLocker -MountPoint "C:"

# Monitor decryption until EncryptionPercentage reaches 0%:
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus
```

### 2. Fix Microsoft Store Auto-Updated AppX Packages (`Error 0x80073cf2`)
This is the **#1 cause of Sysprep failures on Windows 11**. When you log into Windows 11 with an active internet connection, Microsoft Store silently updates built-in apps (Notepad, Snipping Tool, Paint, Widgets, etc.) **for your logged-in user only**, creating a version mismatch between the per-user installed package and the all-users provisioned (`Staged`) package. `AppxSysprep.dll` then aborts Sysprep with error `0x80073cf2`.

**How to prevent/fix it before running Sysprep:**
```powershell
# 1. Disable Microsoft Store automatic app updates via Registry policy
$storePolicy = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if (-not (Test-Path $storePolicy)) { New-Item -Path $storePolicy -Force | Out-Null }
Set-ItemProperty -Path $storePolicy -Name "AutoDownload" -Value 2 -Type DWord

# 2. Identify any packages installed for a user that are NOT provisioned for all users
$provisioned = (Get-AppxProvisionedPackage -Online).PackageName
$userOnlyApps = Get-AppxPackage -AllUsers | Where-Object {
    $_.NonRemovable -eq $false -and
    $_.IsFramework -eq $false -and
    ($provisioned -notcontains $_.PackageFullName)
}

# Preview any offending per-user packages:
$userOnlyApps | Select-Object Name, PackageFullName, PackageUserInformation
```
If Sysprep ever fails, inspect `C:\Windows\System32\Sysprep\Panther\setuperr.log` to see the exact `<PackageFullName>` blocking generalization, and remove it with:
```powershell
Remove-AppxPackage -Package "<PackageFullName>" -AllUsers
```

### 3. Never Run Sysprep as `NT AUTHORITY\SYSTEM` on Windows 11 24H2 / 25H2
Per Microsoft Support (`KB5072911`), running `sysprep.exe` under the `SYSTEM` account (for example via `PsExec -s`, a SYSTEM scheduled task, or remote RMM agents) on Windows 11 24H2/25H2 skips XAML/CBS AppX registration (`MicrosoftWindows.Client.CBS`, `Microsoft.UI.Xaml.CBS`, `MicrosoftWindows.Client.Core`), causing a **black screen (`explorer.exe` crash) or broken Start Menu/Settings** after sign-in.
- **Rule:** Always run `sysprep.exe` from an **interactive elevated local Administrator** session.
- **Recovery (if you ever see a black screen or broken Start Menu post-Sysprep):**
  ```powershell
  Add-AppxPackage -Register -Path "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\appxmanifest.xml" -DisableDevelopmentMode
  Add-AppxPackage -Register -Path "C:\Windows\SystemApps\Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe\appxmanifest.xml" -DisableDevelopmentMode
  Add-AppxPackage -Register -Path "C:\Windows\SystemApps\MicrosoftWindows.Client.Core_cw5n1h2txyewy\appxmanifest.xml" -DisableDevelopmentMode
  ```

### 4. Ensure the Template VM is in a Workgroup (Not Already Domain-Joined)
Do **not** join the golden template VM to `skynet-home.local` before running Sysprep. Keep the template in a `WORKGROUP`, generalize it, and join each cloned VM to `skynet-home.local` after deployment using [Join-SkynetDomain.ps1](./Join-SkynetDomain.ps1).

### 5. WDAC / App Control for Business Considerations
If this template is used for **WDAC (App Control for Business)** testing:
- Do **not** leave an **Enforced** WDAC policy active in `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\` when running Sysprep unless you have verified it permits all Windows Setup specialization binaries and scripts. Keep policies in **Audit Mode** (Rule Option `3 Enabled:Audit Mode`) or remove test `.cip` files prior to generalizing.

---

## 4. Step 3: Generalize the VM with Sysprep (`/mode:vm`)

Inside your Windows 11 VM, open an **elevated PowerShell or Command Prompt** as a local Administrator and run:

```powershell
# Optional: Clean up Temp files and Windows Update download cache first
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\*", "C:\Windows\Temp\*", "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue

# Run Sysprep with /mode:vm
C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /mode:vm
```

### Why use `/mode:vm`?
- **`/generalize`**: Removes unique SIDs, resets event logs, clears restore points, and prepares the image for cloning.
- **`/oobe`**: Boots the cloned VM into the Out-of-Box Experience on first start.
- **`/shutdown`**: Powers off the VM automatically when finished so the disk is in a clean, consistent state.
- **`/mode:vm`**: A Hyper-V-specific optimization that skips full PnP hardware re-detection on first boot because every VM on the same Hyper-V host shares the same virtualized hardware profile. This makes first boot significantly faster.

> **Important:** Once the VM shuts down after Sysprep, **DO NOT power it back on** before exporting or copying its `.vhdx`! Turning it back on will trigger OOBE and "consume" the generalized state.

---

## 5. Step 4: Three Ways to Create New VMs from Your Template

### Option A: Export & Import ("Copy the virtual machine") — *Easiest Full-VM Template*

This method preserves the entire VM configuration (vCPU count, RAM, Generation 2 settings, Secure Boot, vTPM settings, and network switch mapping) alongside the generalized `.vhdx`.

#### 1. Export the generalized VM once (on Hyper-V Host):
```powershell
$TemplatePath = "C:\HyperV\Templates"
New-Item -Path $TemplatePath -ItemType Directory -Force | Out-Null

Export-VM -Name "Win11-Reference" -Path $TemplatePath
```

#### 2. Deploy a new VM from the exported template:
**Via Hyper-V Manager GUI:**
1. Click **Action** -> **Import Virtual Machine...**
2. Browse to `C:\HyperV\Templates\Win11-Reference`.
3. On the **Choose Import Type** screen, select:
   - **Copy the virtual machine (create a new unique ID)** *(Crucial! Never select "Register" or "Restore" when creating clones).*
4. Specify custom destination folders for the new VM's configuration and VHDX files.
5. Rename the imported VM in Hyper-V Manager before starting it.

**Via PowerShell (Automated Clone & Rename):**
```powershell
$NewVMName   = "SKYNET-W11-01"
$ExportedVmcx = Get-ChildItem -Path "C:\HyperV\Templates\Win11-Reference\Virtual Machines" -Filter "*.vmcx" | Select-Object -First 1
$DestVMPath  = "C:\HyperV\VMs\$NewVMName"

$ImportedVM = Import-VM -Path $ExportedVmcx.FullName `
    -Copy `
    -GenerateNewId `
    -VhdDestinationPath "$DestVMPath\Virtual Hard Disks" `
    -VirtualMachinePath $DestVMPath

Rename-VM -VM $ImportedVM -NewName $NewVMName

# Generate a fresh local Key Protector and ensure vTPM is enabled for Windows 11
Set-VMKeyProtector -VMName $NewVMName -NewLocalKeyProtector
Enable-VMTPM -VMName $NewVMName

Start-VM -Name $NewVMName
```

---

### Option B: Read-Only Golden `.vhdx` + Full Disk Copy — *Cleanest for Independent VMs*

With this approach, you copy the generalized `.vhdx` file to a dedicated folder, mark it **Read-Only** so it can never be accidentally booted or modified, and script new VM creation in seconds.

#### 1. Save and lock the Golden `.vhdx` (once):
```powershell
$GoldenVhd = "C:\HyperV\Templates\Win11-24H2-Golden.vhdx"
Copy-Item -Path "C:\HyperV\VMs\Win11-Reference\Virtual Hard Disks\Win11-Reference.vhdx" -Destination $GoldenVhd
Set-ItemProperty -Path $GoldenVhd -Name IsReadOnly -Value $true
```

#### 2. Spin up a new independent VM from the Golden `.vhdx`:
```powershell
$VMName     = "SKYNET-W11-01"
$SwitchName = "Default Switch" # Replace with your external/lab Virtual Switch connected to skynet-home.local
$GoldenVhd  = "C:\HyperV\Templates\Win11-24H2-Golden.vhdx"
$VMRoot     = "C:\HyperV\VMs\$VMName"
$NewVhdPath = "$VMRoot\$VMName.vhdx"

# 1. Create folder & copy the golden VHDX (ensure writable on the copy)
New-Item -Path $VMRoot -ItemType Directory -Force | Out-Null
Copy-Item -Path $GoldenVhd -Destination $NewVhdPath
Set-ItemProperty -Path $NewVhdPath -Name IsReadOnly -Value $false

# 2. Create Generation 2 VM & configure Windows 11 hardware requirements
New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 8GB -VHDPath $NewVhdPath -Path $VMRoot -SwitchName $SwitchName
Set-VMProcessor -VMName $VMName -Count 4
Set-VM -Name $VMName -DynamicMemory -MemoryMinimumBytes 4GB -MemoryMaximumBytes 16GB -AutomaticCheckpointsEnabled $false
Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows"

# 3. Enable vTPM (Required for Windows 11)
Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
Enable-VMTPM -VMName $VMName

# 4. Enable Guest Services & Start VM
Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface"
Start-VM -Name $VMName
```

---

### Option C: Read-Only Golden `.vhdx` + Differencing Disks — *Best for Fast Test Labs*

If you are spinning up multiple Windows 11 VMs for lab testing (such as testing WDAC policies across several domain-joined nodes), **Differencing Disks** use the Read-Only Golden `.vhdx` as a shared parent image and only store the changed blocks per VM.
- **Spin-up time:** ~1 second (no multi-gigabyte file copy).
- **Disk savings:** 5 Windows 11 VMs take ~35 GB total instead of ~150 GB.
- **Rule:** The parent `Win11-24H2-Golden.vhdx` **must never be modified or booted directly** once child differencing disks point to it.

```powershell
$VMName     = "SKYNET-WDAC-TEST01"
$SwitchName = "Default Switch" # Replace with your skynet-home.local Virtual Switch
$ParentVhd  = "C:\HyperV\Templates\Win11-24H2-Golden.vhdx"
$VMRoot     = "C:\HyperV\VMs\$VMName"
$DiffVhd    = "$VMRoot\$VMName-Diff.vhdx"

# Ensure parent VHDX is Read-Only
Set-ItemProperty -Path $ParentVhd -Name IsReadOnly -Value $true

# Create child differencing disk in < 1 second
New-Item -Path $VMRoot -ItemType Directory -Force | Out-Null
New-VHD -Path $DiffVhd -ParentPath $ParentVhd -Differencing

# Create and configure Windows 11 VM
New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 8GB -VHDPath $DiffVhd -Path $VMRoot -SwitchName $SwitchName
Set-VMProcessor -VMName $VMName -Count 4
Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows"
Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
Enable-VMTPM -VMName $VMName
Start-VM -Name $VMName
```

---

## 6. Step 5: Post-Clone Modification & `skynet-home.local` Domain Join Script

A ready-to-use script has been created in this folder at [Join-SkynetDomain.ps1](./Join-SkynetDomain.ps1).

### What the Script Modifies & Validates
1. **Verifies Elevation:** Ensures the session is running as Administrator.
2. **Checks Current Domain State:** Exits cleanly if the VM is already joined to `skynet-home.local`.
3. **Resets WSUS / Windows Update Identity:** Deletes `SusClientId`, `SusClientIdValidation`, `PingID`, and `AccountDomainSid` registry values so cloned VMs do not collide in WSUS/update reporting.
4. **Configures DNS for `skynet-home.local`:** Sets the connection-specific DNS suffix to `skynet-home.local`, enables dynamic DNS registration, and optionally configures your Domain Controller's IP address (`-DnsServers`) on the active network adapter.
5. **Synchronizes System Clock (`W32Time`):** Starts `W32Time` and forces a time resync (`w32tm /resync /force`) so Kerberos authentication does not fail due to VM clock drift.
6. **Pre-Flight Domain Controller Check:** Verifies that `_ldap._tcp.dc._msdcs.skynet-home.local` SRV records resolve in DNS before attempting `Add-Computer`.
7. **Renames Host & Joins Domain in One Reboot:** Prompts securely for the password of `lorenzo@skynet-home.local` and runs `Add-Computer -DomainName "skynet-home.local" -NewName <NewComputerName> -Credential $DomainCredential -Restart -Force`.

### How to Run `Join-SkynetDomain.ps1`

#### Usage 1: Run Directly Inside the Cloned Windows 11 VM
Copy [Join-SkynetDomain.ps1](./Join-SkynetDomain.ps1) into the VM (or paste it into an elevated PowerShell window) and run:
```powershell
# If DHCP already assigns your skynet-home.local Domain Controller as DNS:
.\Join-SkynetDomain.ps1 -NewComputerName "SKYNET-W11-01"

# If you need to point the VM's DNS to your Domain Controller IP (e.g., 192.168.1.10):
.\Join-SkynetDomain.ps1 -NewComputerName "SKYNET-W11-01" -DnsServers @("192.168.1.10")

# Optional: Specify a target Organizational Unit (OU)
.\Join-SkynetDomain.ps1 -NewComputerName "SKYNET-W11-01" -DnsServers @("192.168.1.10") -OUPath "OU=Workstations,DC=skynet-home,DC=local"
```

#### Usage 2: Run From the Hyper-V Host via PowerShell Direct (No RDP or IP Required!)
Hyper-V includes **PowerShell Direct**, which executes commands inside a Windows 11 guest VM directly over the Hyper-V VMBus without needing network connectivity, WinRM, or firewall rules:
```powershell
# Run from an elevated PowerShell window on your Hyper-V Host:
.\Join-SkynetDomain.ps1 -TargetVMName "SKYNET-W11-01" -NewComputerName "SKYNET-W11-01" -DnsServers @("192.168.1.10")
```

### Full Script Reference (`Join-SkynetDomain.ps1`)

```powershell
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the new unique computer name for this VM (e.g., SKYNET-W11-01).")]
    [ValidateLength(1, 15)]
    [ValidatePattern('^[a-zA-Z0-9-]+$')]
    [string]$NewComputerName,

    [Parameter(Mandatory = $false)]
    [string]$DomainName = "skynet-home.local",

    [Parameter(Mandatory = $false)]
    [string]$DomainUser = "lorenzo@skynet-home.local",

    [Parameter(Mandatory = $false)]
    [string[]]$DnsServers,

    [Parameter(Mandatory = $false)]
    [string]$OUPath,

    [Parameter(Mandatory = $false)]
    [string]$TargetVMName,

    [Parameter(Mandatory = $false)]
    [switch]$NoRestart
)

$ErrorActionPreference = 'Stop'

$GuestConfigurationBlock = {
    param(
        [string]$NewComputerName,
        [string]$DomainName,
        [PSCredential]$DomainCredential,
        [string[]]$DnsServers,
        [string]$OUPath,
        [bool]$ShouldRestart
    )

    $ErrorActionPreference = 'Stop'

    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  Configuring VM & Joining Domain: $DomainName" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan

    # 1. Verify Administrator / Elevation
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
    }

    # 2. Check current domain status
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    Write-Host "[1/6] Current Hostname: $($cs.Name) | PartOfDomain: $($cs.PartOfDomain) ($($cs.Domain))" -ForegroundColor Gray
    if ($cs.PartOfDomain -and ($cs.Domain -ieq $DomainName)) {
        Write-Warning "This machine is already joined to '$DomainName'."
        return
    }

    # 3. Reset WSUS / Windows Update Client Identity (best practice for cloned/templated VMs)
    Write-Host "[2/6] Resetting Windows Update / WSUS client identity markers..." -ForegroundColor Yellow
    $wuRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
    if (Test-Path $wuRegPath) {
        foreach ($prop in @('SusClientId', 'SusClientIdValidation', 'PingID', 'AccountDomainSid')) {
            Remove-ItemProperty -Path $wuRegPath -Name $prop -ErrorAction SilentlyContinue
        }
    }

    # 4. Configure Active Network Adapter DNS Suffix & Optional DNS Server IPs
    Write-Host "[3/6] Configuring network adapter DNS settings for '$DomainName'..." -ForegroundColor Yellow
    $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }
    if (-not $activeAdapters) {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    }
    if (-not $activeAdapters) {
        throw "No active ('Up') network adapter found. Ensure the VM is connected to a Hyper-V Virtual Switch."
    }

    foreach ($adapter in $activeAdapters) {
        Write-Host "      -> Setting DNS suffix '$DomainName' on adapter '$($adapter.Name)'" -ForegroundColor Gray
        Set-DnsClient -InterfaceIndex $adapter.ifIndex -ConnectionSpecificSuffix $DomainName -RegisterThisConnectionsAddress $true

        if ($DnsServers -and $DnsServers.Count -gt 0) {
            Write-Host "      -> Setting DNS servers ($($DnsServers -join ', ')) on adapter '$($adapter.Name)'" -ForegroundColor Gray
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServers
        }
    }

    Clear-DnsClientCache

    # 5. Synchronize System Clock (Kerberos requires < 5 min clock skew with Domain Controller)
    Write-Host "[4/6] Synchronizing system time (W32Time) to prevent Kerberos authentication errors..." -ForegroundColor Yellow
    try {
        $w32time = Get-Service -Name W32Time -ErrorAction Stop
        if ($w32time.Status -ne 'Running') {
            Start-Service -Name W32Time
        }
        $null = & w32tm.exe /resync /force 2>&1
    } catch {
        Write-Warning "Could not force time resync automatically: $($_.Exception.Message)"
    }

    # 6. Verify Domain Controller DNS & LDAP SRV Reachability
    Write-Host "[5/6] Verifying DNS resolution for '$DomainName'..." -ForegroundColor Yellow
    try {
        $srvRecord = "_ldap._tcp.dc._msdcs.$DomainName"
        $resolved = Resolve-DnsName -Name $srvRecord -Type SRV -ErrorAction Stop
        $dcTarget = ($resolved | Where-Object { $_.Type -eq 'SRV' } | Select-Object -First 1).NameTarget
        Write-Host "      -> Resolved Domain Controller SRV record: $dcTarget" -ForegroundColor Green
    } catch {
        throw "Failed to resolve Domain Controller SRV record '$srvRecord'. Verify that the VM's DNS server points to a '$DomainName' Domain Controller (use -DnsServers @('<DC_IP>')). Details: $($_.Exception.Message)"
    }

    # 7. Rename Computer and Join Domain
    Write-Host "[6/6] Joining domain '$DomainName' as '$NewComputerName' using account '$($DomainCredential.UserName)'..." -ForegroundColor Yellow

    $addComputerParams = @{
        DomainName  = $DomainName
        Credential  = $DomainCredential
        Force       = $true
        ErrorAction = 'Stop'
    }

    if ($env:COMPUTERNAME -ine $NewComputerName) {
        $addComputerParams['NewName'] = $NewComputerName
    }

    if (-not [string]::IsNullOrWhiteSpace($OUPath)) {
        $addComputerParams['OUPath'] = $OUPath
    }

    if ($ShouldRestart) {
        $addComputerParams['Restart'] = $true
    }

    Add-Computer @addComputerParams

    Write-Host "`n[SUCCESS] Successfully joined '$DomainName' as '$NewComputerName'!" -ForegroundColor Green
    if (-not $ShouldRestart) {
        Write-Warning "A system restart is required to complete the rename and domain join. Run 'Restart-Computer' when ready."
    }
}

Write-Host "Prompting for Active Directory credentials for '$DomainUser'..." -ForegroundColor Cyan
$DomainCredential = Get-Credential -UserName $DomainUser -Message "Enter password for $DomainUser to join $DomainName"

$ShouldRestart = -not $NoRestart.IsPresent

if (-not [string]::IsNullOrWhiteSpace($TargetVMName)) {
    Write-Host "Connecting to VM '$TargetVMName' via Hyper-V PowerShell Direct..." -ForegroundColor Cyan
    $LocalAdminCred = Get-Credential -UserName "Administrator" -Message "Enter LOCAL Administrator credentials for guest VM '$TargetVMName'"

    if ($PSCmdlet.ShouldProcess($TargetVMName, "Configure guest OS as '$NewComputerName' and join domain '$DomainName'")) {
        Invoke-Command -VMName $TargetVMName -Credential $LocalAdminCred -ScriptBlock $GuestConfigurationBlock -ArgumentList @(
            $NewComputerName,
            $DomainName,
            $DomainCredential,
            $DnsServers,
            $OUPath,
            $ShouldRestart
        )
    }
} else {
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Rename to '$NewComputerName' and join domain '$DomainName'")) {
        & $GuestConfigurationBlock `
            -NewComputerName $NewComputerName `
            -DomainName $DomainName `
            -DomainCredential $DomainCredential `
            -DnsServers $DnsServers `
            -OUPath $OUPath `
            -ShouldRestart $ShouldRestart
    }
}
```

---

## 7. Bonus: Zero-Touch OOBE with `unattend.xml`

Normally, when you boot a new VM cloned from a Sysprepped image, Windows 11 forces you to click through the Out-of-Box Experience (Language, Keyboard, Network, Microsoft Account prompt, Privacy questions).

To **skip OOBE completely** on every cloned VM and boot straight to the login screen with a local `LabAdmin` account ready for PowerShell Direct, save the following file as `C:\Windows\Panther\unattend.xml` inside your template VM right before running Sysprep:

```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <TimeZone>Eastern Standard Time</TimeZone>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
                        <Name>LabAdmin</Name>
                        <Group>Administrators</Group>
                        <Password>
                            <!-- Replace with your desired initial local admin password before running Sysprep -->
                            <Value>ChangeMe_Lab2026!</Value>
                            <PlainText>true</PlainText>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
        </component>
    </settings>
</unattend>
```

Then run Sysprep pointing to that answer file:
```powershell
C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /mode:vm /unattend:C:\Windows\Panther\unattend.xml
```
*(Windows Setup automatically deletes or strips sensitive password data from `unattend.xml` after OOBE completes).*

---

## 8. Questions & Suggestions for Your Setup

### Suggestions
1. **Use Differencing Disks for WDAC / Security Lab VMs:** Since you are working in a WDAC workspace (`JMSC-WDAC-OCT26`), Differencing Disks (**Option C**) combined with per-VM checkpoints are ideal. You can spin up 3–4 domain-joined Windows 11 machines in under a minute to test Audit vs. Enforced multi-policy deployments without duplicating 30+ GB of disk per VM.
2. **Use Hyper-V PowerShell Direct (`-TargetVMName`):** You don't even need to open an RDP session or look up the VM's DHCP IP address to join `skynet-home.local`. Running `.\Join-SkynetDomain.ps1 -TargetVMName "<VMName>" -NewComputerName "<HostName>"` from your Hyper-V host configures DNS and joins the domain directly over the VMBus.
3. **Keep a "Pre-Sysprep Master" Checkpoint:** Always maintain a checkpoint taken *immediately before* running `sysprep.exe`. Whenever you want to bake new tools, certificates, or cumulative updates into your template, revert to that checkpoint, apply changes, take a fresh checkpoint, and re-run Sysprep on a copy.
4. **Offline VHDX Servicing (`Mount-WindowsImage`):** Did you know you can inject drivers, cumulative updates (`.msu`), or files (like `unattend.xml` or root CA certificates for `skynet-home.local`) directly into your `Win11-24H2-Golden.vhdx` from the Hyper-V host **without booting the VM**? You can mount the `.vhdx` on the host using `Mount-VHD` and service it offline with DISM cmdlets.

### Follow-Up Questions (Optional Refinements)
1. **Domain Controller IP & OU Structure:** Do you have a static IP for your `skynet-home.local` Domain Controller (e.g., `192.168.x.x`) and a preferred default Organizational Unit (e.g., `OU=LabVMs,DC=skynet-home,DC=local`) that you'd like baked in as the default parameter values in [Join-SkynetDomain.ps1](./Join-SkynetDomain.ps1)?
2. **Full Host-Side Provisioning Script:** Would you also like a companion script (`New-SkynetLabVM.ps1`) that runs on the Hyper-V host to automate the entire pipeline in one command (create Differencing/Full VHDX -> create Gen 2 VM with vTPM -> boot -> wait for heartbeat -> run `Join-SkynetDomain.ps1` via PowerShell Direct)?

---

## 9. Resources

- [Sysprep (Generalize) a Windows Installation — Microsoft Learn](https://learn.microsoft.com/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation?view=windows-11)
- [Sysprep Command-Line Options (`/mode:vm`, `/generalize`, `/oobe`) — Microsoft Learn](https://learn.microsoft.com/windows-hardware/manufacture/desktop/sysprep-command-line-options?view=windows-11)
- [Sysprep Fails After Removing or Updating Microsoft Store Apps (`0x80073cf2`) — Microsoft Learn](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps)
- [Fix Black Screen After Running Sysprep as SYSTEM on Windows 11 24H2/25H2 — Microsoft Learn](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-as-system-windows-11)
- [Export and Import Virtual Machines in Hyper-V — Microsoft Learn](https://learn.microsoft.com/windows-server/virtualization/hyper-v/deploy/export-and-import-virtual-machines)
- [Export-VM PowerShell Cmdlet Reference — Microsoft Learn](https://learn.microsoft.com/powershell/module/hyper-v/export-vm?view=windowsserver2025-ps)
- [Set-VMKeyProtector & vTPM PowerShell Reference — Microsoft Learn](https://learn.microsoft.com/powershell/module/hyper-v/set-vmkeyprotector?view=windowsserver2025-ps)
- [Virtual Machine Automation and Management Using PowerShell Direct — Microsoft Learn](https://learn.microsoft.com/windows-server/virtualization/hyper-v/powershell-direct)
- [Add-Computer PowerShell Cmdlet Reference (Domain Join) — Microsoft Learn](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/add-computer?view=powershell-5.1)
- [Automate OOBE and Answer Files (`unattend.xml`) — Microsoft Learn](https://learn.microsoft.com/windows-hardware/customize/desktop/automate-oobe)
- [Windows Setup Automation Overview — Microsoft Learn](https://learn.microsoft.com/windows-hardware/manufacture/desktop/windows-setup-automation-overview?view=windows-11)
