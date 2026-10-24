# PowerShell 7 edition - run in an elevated "pwsh" window.
# Step 0.3 - 0.4: working folders, transcript, ConfigCI, baseline STIG record, CodeIntegrity log size, managed installer readiness.
param(
    # Minimum size of the CodeIntegrity/Operational log. The Windows default (1 MB) holds only ~200 events, so 3076/3089 pairs
    # from one audit window can overwrite each other before Step 4.1 exports them. The log is only ever raised, never shrunk.
    [int]$CILogSizeMB = 100,
    # Optional: regex for the application you intend to keep BLOCKED (e.g. 'Mozilla|Firefox'). Its scheduled tasks and services
    # are listed so you know which 3076 rows to leave out in the Wizard (Step 4.2). Leave empty to skip.
    [string]$ExcludedAppPattern = ''
)

# 1. Verify this PowerShell 7 session is running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'STOP: Open PowerShell 7 with "Run as Administrator".' }

# 2. Create the clean directory structure
$Folders = @(
    'C:\WDAC\Source',
    'C:\WDAC\Compiled',
    'C:\WDAC\Events',
    'C:\WDAC\Logs'
)
New-Item -Path $Folders -ItemType Directory -Force -ErrorAction Stop | Out-Null

# 3. Start an audit log transcript of all commands and outputs
Start-Transcript -Path "C:\WDAC\Logs\WDAC-Manual-Run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

# 4. Import ConfigCI into PowerShell 7 and confirm CiTool.exe exists (Windows 11 22H2+ / Server 2025)
Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop
Get-Command -Module ConfigCI
if (-not (Test-Path -LiteralPath "$env:SystemRoot\System32\CiTool.exe")) { throw 'STOP: CiTool.exe was not found. Multiple-policy deployment requires Windows 11 22H2 or later.' }


# 5. Stage 0 STIG Check - record the starting values
#    A clean OS without App Control reports 0 / 0. Newer Windows 11 builds already load Microsoft platform policies
#    (Smart App Control evaluation, vulnerable driver blocklist) and can report 2 / 1 before you start. Both are fine:
#    the goal is 2 / 2 at the end, and every stage is recorded so the change is provable.
#    0 = OFF, 1 = AUDIT, 2 = ENFORCING (only 2 passes); 7_DISA_STIG_CHECK.ps1 shows which policies produce the values.
$CiMode = @{ 0 = 'OFF'; 1 = 'AUDIT'; 2 = 'ENFORCING' }
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List @{ n = 'CodeIntegrityPolicyEnforcementStatus'; e = { '{0} ({1}) - V-243450' -f $_.CodeIntegrityPolicyEnforcementStatus, $CiMode[[int]$_.CodeIntegrityPolicyEnforcementStatus] } },
                @{ n = 'UsermodeCodeIntegrityPolicyEnforcementStatus'; e = { '{0} ({1}) - V-243451' -f $_.UsermodeCodeIntegrityPolicyEnforcementStatus, $CiMode[[int]$_.UsermodeCodeIntegrityPolicyEnforcementStatus] } }

$SacState = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$SacText = switch ($SacState) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation (audit-mode UMCI - can explain a starting UMCI value of 1)' } default { 'Not reported' } }
Write-Host "Smart App Control: $SacText"

# 6. Confirm no legacy single-policy SiPolicy.p7b exists (Expect: False)
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"

# 7. List existing policies in CiTool - Expect ONLY built-in Microsoft Platform policies (IsSystemPolicy = true)
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Select-Object PolicyID, FriendlyName, IsSystemPolicy, IsEnforced, IsAuthorized |
    Format-Table -AutoSize

# 8. Make sure the CodeIntegrity log can hold a whole audit window
$CiLog = 'Microsoft-Windows-CodeIntegrity/Operational'
$CiLogInfo = Get-WinEvent -ListLog $CiLog -ErrorAction Stop
$WantedBytes = [int64]$CILogSizeMB * 1MB
if ($CiLogInfo.MaximumSizeInBytes -lt $WantedBytes) {
    & wevtutil.exe sl $CiLog "/ms:$WantedBytes"
    if ($LASTEXITCODE -ne 0) { throw "STOP: wevtutil.exe could not resize $CiLog (exit code $LASTEXITCODE)." }
    Write-Host "CodeIntegrity log max size raised from $([math]::Round($CiLogInfo.MaximumSizeInBytes / 1MB, 1)) MB to $CILogSizeMB MB." -ForegroundColor Green
}
else { Write-Host "CodeIntegrity log max size is $([math]::Round($CiLogInfo.MaximumSizeInBytes / 1MB, 1)) MB (no change needed)." }

# 9. Managed installer readiness (Option 13 = Enabled:Managed Installer is ON in this guide)
#    Option 13 only takes effect once a managed installer (MECM or Intune) is designated through an AppLocker
#    ManagedInstaller rule collection and the AppLocker services run. This section only REPORTS the state.
function Get-ServiceState([string]$Name) {
    $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($Service) { "$($Service.Status) / $($Service.StartType)" } else { 'Not installed' }
}
$AppLockerDoc = try { [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch { $null }
$MiCollection = if ($AppLockerDoc) { @($AppLockerDoc.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' }) | Select-Object -First 1 }
$MiRules = if ($MiCollection) { @($MiCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | ForEach-Object { $_.GetAttribute('Name') }) } else { @() }
$Filter = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='AppLockerFltr'" -ErrorAction SilentlyContinue
[pscustomobject]@{
    MecmClient_CcmExec           = Get-ServiceState 'CcmExec'
    IntuneManagementExtension    = Get-ServiceState 'IntuneManagementExtension'
    AppLockerManagedInstaller    = $(if ($MiCollection) { "Present ($($MiCollection.EnforcementMode)): $($MiRules -join '; ')" } else { 'Not configured' })
    ApplicationIdentity_AppIDSvc = Get-ServiceState 'AppIDSvc'
    AppLockerFltr                = $(if ($Filter) { "$($Filter.State) / $($Filter.StartMode)" } else { 'Not installed' })
} | Format-List
if (-not $MiCollection) {
    Write-Host 'Managed installer is not configured yet. Option 13 stays ON in the policy but has no effect until MECM (CCMSetup.exe MANAGEDINSTALLER=1, or an MECM built-in audit-mode App Control policy) or Intune (Endpoint security > App Control for Business > Managed installer) is set up. See the README section "Managed Installer (MECM / Intune)".' -ForegroundColor Yellow
}

# 10. Optional: background components of the application you intend to keep BLOCKED
#     Scheduled tasks and services (for example a browser's background updater) can run during the audit window without
#     anyone launching the application and log 3076 events. Leave those rows out in the Wizard (Step 4.2).
if ($ExcludedAppPattern) {
    $Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { "$($_.TaskPath)$($_.TaskName) $($_.Actions.Execute)" -match $ExcludedAppPattern })
    $Services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $ExcludedAppPattern })
    Write-Host "Background components matching '$ExcludedAppPattern': $($Tasks.Count) scheduled task(s), $($Services.Count) service(s)" -ForegroundColor Cyan
    $Tasks | ForEach-Object {
        $Info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [pscustomobject]@{ Task = "$($_.TaskPath)$($_.TaskName)"; State = $_.State; NextRunTime = $Info.NextRunTime }
    } | Format-Table -AutoSize
    $Services | Select-Object Name, State, StartMode, PathName | Format-Table -AutoSize
}

# 11. Install every application you need on this PAW NOW (before any audit policy is loaded).
#     Do NOT launch any application you intend to keep blocked.
