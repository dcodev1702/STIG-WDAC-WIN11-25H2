<#
.SYNOPSIS
    Prepares a cloned Windows 11 Hyper-V VM (network/DNS, time sync, WSUS identity, hostname)
    and joins it to the skynet-home.local Active Directory domain.

.DESCRIPTION
    This script can be executed in two ways:
      1. Directly inside the guest Windows 11 VM (elevated PowerShell).
      2. Remotely from the Hyper-V Host using PowerShell Direct (-TargetVMName), which
         communicates over the Hyper-V VMBus without requiring an IP address or WinRM.

    Modifications performed before joining the domain:
      - Verifies Administrator privileges.
      - Repairs Windows 11 24H2/25H2 XAML/CBS AppX registrations if needed.
      - Resets WSUS SusClientId / SusClientIdValidation keys (prevents duplicate clone reporting).
      - Optionally configures DNS Server IPs and sets the DNS connection suffix to skynet-home.local.
      - Synchronizes the system clock via Windows Time (w32tm) to prevent Kerberos skew errors.
      - Validates DNS SRV & A record resolution for skynet-home.local before attempting join.
      - Renames the computer and joins skynet-home.local using lorenzo@skynet-home.local in a single reboot.

.PARAMETER NewComputerName
    The new unique hostname to assign to the cloned VM (max 15 characters for NetBIOS compatibility).

.PARAMETER DomainName
    Target Active Directory domain name. Defaults to 'skynet-home.local'.

.PARAMETER DomainUser
    User Principal Name (UPN) or Down-Level Logon Name used to join the domain.
    Defaults to 'lorenzo@skynet-home.local'.

.PARAMETER DnsServers
    Optional array of Domain Controller / DNS IPv4 addresses (e.g., @('192.168.1.10')).
    Required if DHCP does not automatically assign your skynet-home.local Domain Controller as DNS.

.PARAMETER OUPath
    Optional Distinguished Name of the Organizational Unit to place the computer account in
    (e.g., 'OU=Workstations,DC=skynet-home,DC=local').

.PARAMETER TargetVMName
    Optional Hyper-V VM Name. If specified, runs this configuration from the Hyper-V Host into
    the guest VM via PowerShell Direct (Invoke-Command -VMName).

.PARAMETER NoRestart
    Suppresses the automatic reboot after joining the domain.

.EXAMPLE
    # Run directly inside the cloned Windows 11 VM:
    .\Join-SkynetDomain.ps1 -NewComputerName "SKYNET-W11-01"

.EXAMPLE
    # Run inside the VM and explicitly point DNS to the Domain Controller first:
    .\Join-SkynetDomain.ps1 -NewComputerName "SKYNET-W11-01" -DnsServers @("192.168.1.10")

.EXAMPLE
    # Run from the Hyper-V Host into the guest VM using PowerShell Direct:
    .\Join-SkynetDomain.ps1 -TargetVMName "Win11-Lab-01" -NewComputerName "SKYNET-W11-01" -DnsServers @("192.168.1.10")
#>

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

# Shared guest execution block (used both locally in-guest and via PowerShell Direct from Host)
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
        DomainName = $DomainName
        Credential = $DomainCredential
        Force      = $true
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

# Prompt for Domain Join Credentials (lorenzo@skynet-home.local)
Write-Host "Prompting for Active Directory credentials for '$DomainUser'..." -ForegroundColor Cyan
$DomainCredential = Get-Credential -UserName $DomainUser -Message "Enter password for $DomainUser to join $DomainName"

$ShouldRestart = -not $NoRestart.IsPresent

if (-not [string]::IsNullOrWhiteSpace($TargetVMName)) {
    # Mode A: Execute from Hyper-V Host via PowerShell Direct
    Write-Host "Connecting to VM '$TargetVMName' via Hyper-V PowerShell Direct..." -ForegroundColor Cyan
    Write-Host "(First prompt is for the LOCAL Administrator inside '$TargetVMName' to establish the VMBus session)" -ForegroundColor Gray
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
    # Mode B: Execute directly inside the Guest VM
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
