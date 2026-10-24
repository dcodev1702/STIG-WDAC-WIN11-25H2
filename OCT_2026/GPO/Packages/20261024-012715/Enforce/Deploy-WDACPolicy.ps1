# Endpoint deployment script. 2_GPO_create_gpos.ps1 copies it into each WDAC GPO (SYSVOL); SYSTEM runs it from the GPO
# startup script and from the GPP scheduled task. Windows PowerShell 5.1, ASCII-only, no ConfigCI.
# Deploys the multiple-policy-format .cip file(s) listed in manifest.json with CiTool.exe when the GPO carries a NEWER
# version than the one active on this computer. It never downgrades and never removes a policy.
#   Log:    C:\Windows\Logs\WDAC-GPO\Deploy-WDACPolicy.log
#   Events: Application log, source WDAC-GPO (1000 current, 1001 deployed, 2001 newer active, 2002 other base, 2003 scope, 3xxx error)
#   State:  C:\ProgramData\WDAC-GPO\state.json
param(
    [ValidateSet('Audit', 'Enforce')][string]$Mode,
    [string]$PayloadPath = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$LogDir = Join-Path $env:SystemRoot 'Logs\WDAC-GPO'
$StateDir = Join-Path $env:ProgramData 'WDAC-GPO'
$LogFile = Join-Path $LogDir 'Deploy-WDACPolicy.log'
$CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
$Source = 'WDAC-GPO'
New-Item -Path $LogDir, $StateDir -ItemType Directory -Force | Out-Null
if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 2MB) { Move-Item -LiteralPath $LogFile -Destination "$LogFile.old" -Force }
try { if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) { New-EventLog -LogName Application -Source $Source } } catch { }

function Write-Log([string]$Level, [int]$EventId, [string]$Message) {
    $Line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Mode, $Message
    Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8
    $Type = switch ($Level) { 'ERROR' { 'Error' } 'WARN' { 'Warning' } default { 'Information' } }
    try { Write-EventLog -LogName Application -Source $Source -EventId $EventId -EntryType $Type -Message $Message } catch { }
    Write-Output $Line
}

$Mutex = New-Object System.Threading.Mutex($false, 'Global\WDAC-GPO-Deploy')
if (-not $Mutex.WaitOne([TimeSpan]::FromMinutes(5))) { Write-Log 'WARN' 2010 'Another deployment run is still in progress; exiting.'; exit 0 }
$ExitCode = 0
$State = [ordered]@{ LastRun = (Get-Date).ToString('o'); Computer = $env:COMPUTERNAME; Mode = $Mode; Payload = $PayloadPath; Result = ''; Policies = @() }
try { do {
    # (do/while($false) lets the guards below 'break' out and still reach 'exit $ExitCode')
    $Run = "run as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) from $PayloadPath"
    # Scope guard: Windows client editions only (servers and domain controllers never receive this policy)
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($OS.ProductType -ne 1) { Write-Log 'WARN' 2003 "Skipped: this deployment is for Windows client editions only (ProductType $($OS.ProductType), $($OS.Caption)). $Run"; $State.Result = 'Skipped (not a workstation)'; break }
    if (-not (Test-Path -LiteralPath $CiTool)) { Write-Log 'ERROR' 3001 "CiTool.exe not found - multiple-policy deployment needs Windows 11 22H2 or later. $Run"; $State.Result = 'Error (no CiTool)'; $ExitCode = 1; break }

    $Manifest = Get-Content -LiteralPath (Join-Path $PayloadPath 'manifest.json') -Raw | ConvertFrom-Json
    if ($Mode -and $Manifest.Mode -ne $Mode) { Write-Log 'ERROR' 3002 "manifest.json says Mode '$($Manifest.Mode)' but this GPO runs the script with -Mode $Mode. Nothing deployed. $Run"; $State.Result = 'Error (mode mismatch)'; $ExitCode = 1; break }
    $Active = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies)
    $OurGuids = @($Manifest.Policies | ForEach-Object { $_.PolicyGuid.Trim('{}').ToLower() })

    # Another custom BASE policy would intersect with ours (a file must pass both)
    foreach ($Other in @($Active | Where-Object { -not $_.IsSystemPolicy -and $_.IsEnforced -and $_.PolicyID -eq $_.BasePolicyID -and $OurGuids -notcontains $_.PolicyID.ToLower() })) {
        Write-Log 'WARN' 2002 "Another custom base policy is active and will intersect with this one: $($Other.FriendlyName) {$($Other.PolicyID)} v$($Other.VersionString)."
    }

    $Changed = 0
    foreach ($P in @($Manifest.Policies)) {
        $Guid = $P.PolicyGuid.Trim('{}').ToLower()
        $File = Join-Path $PayloadPath $P.File
        $Entry = [ordered]@{ PolicyGuid = $P.PolicyGuid; Type = $P.Type; Name = $P.Name; Wanted = $P.Version; Before = ''; After = ''; Action = '' }
        if (-not (Test-Path -LiteralPath $File)) { Write-Log 'ERROR' 3003 "Payload file missing: $File"; $Entry.Action = 'Error (file missing)'; $ExitCode = 1; $State.Policies += [pscustomobject]$Entry; continue }
        $Hash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
        if ($Hash -ne $P.Sha256) { Write-Log 'ERROR' 3004 "Hash mismatch for $($P.File): payload $Hash, manifest $($P.Sha256). Not deployed."; $Entry.Action = 'Error (hash mismatch)'; $ExitCode = 1; $State.Policies += [pscustomobject]$Entry; continue }

        $Current = $Active | Where-Object { $_.PolicyID.ToLower() -eq $Guid -and $_.IsEnforced } | Select-Object -First 1
        if ($Current) { $Entry.Before = $Current.VersionString }
        if ($Current -and ([version]$Current.VersionString -gt [version]$P.Version)) {
            Write-Log 'WARN' 2001 "$($P.Name) {$Guid}: v$($Current.VersionString) is active, newer than the GPO's v$($P.Version) ($($Manifest.Mode)). Not downgrading - publish a higher version to change it."
            $Entry.Action = 'Skipped (newer active)'; $Entry.After = $Current.VersionString
        }
        elseif ($Current -and ([version]$Current.VersionString -eq [version]$P.Version)) {
            Write-Log 'INFO' 1000 "$($P.Name) {$Guid}: v$($P.Version) ($($Manifest.Mode)) is already active. $Run"
            $Entry.Action = 'Current'; $Entry.After = $Current.VersionString
        }
        else {
            $Local = Join-Path $StateDir $P.File
            Copy-Item -LiteralPath $File -Destination $Local -Force
            $Out = & $CiTool --update-policy $Local -json
            $Op = try { ($Out -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
            if ($LASTEXITCODE -ne 0 -or ($null -ne $Op -and $Op -ne 0)) {
                Write-Log 'ERROR' 3005 "CiTool --update-policy failed for $($P.File) (exit $LASTEXITCODE, OperationResult $Op): $($Out -join ' ')"
                $Entry.Action = 'Error (CiTool)'; $ExitCode = 1
            }
            else {
                $Now = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies) | Where-Object { $_.PolicyID.ToLower() -eq $Guid } | Select-Object -First 1
                $Entry.After = $Now.VersionString; $Entry.Action = 'Deployed'; $Changed++
                Write-Log 'INFO' 1001 "$($P.Name) {$Guid}: deployed v$($P.Version) ($($Manifest.Mode)), was $(if ($Entry.Before) { "v$($Entry.Before)" } else { 'not active' }); CiTool now reports v$($Now.VersionString), IsAuthorized $($Now.IsAuthorized). SHA-256 $Hash. $Run"
            }
        }
        $State.Policies += [pscustomobject]$Entry
    }

    $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    $State.KMCI = [int]$DG.CodeIntegrityPolicyEnforcementStatus
    $State.UMCI = [int]$DG.UsermodeCodeIntegrityPolicyEnforcementStatus
    $Expected = if ($Manifest.Mode -eq 'Enforce') { 2 } else { 1 }
    $State.Result = if ($ExitCode) { 'Error' } elseif ($Changed) { 'Deployed' } else { 'NoChange' }
    if ($Changed) { $State.LastChange = (Get-Date).ToString('o') }
    $Level = if ($State.UMCI -eq $Expected) { 'INFO' } else { 'WARN' }
    Write-Log $Level $(if ($Level -eq 'INFO') { 1002 } else { 2004 }) "Win32_DeviceGuard KMCI/UMCI = $($State.KMCI) / $($State.UMCI) (expected UMCI $Expected for $($Manifest.Mode))."
} while ($false) }
catch {
    Write-Log 'ERROR' 3000 "Unexpected error: $($_.Exception.Message)"
    $State.Result = "Error: $($_.Exception.Message)"; $ExitCode = 1
}
finally {
    $Previous = $null
    $StateFile = Join-Path $StateDir 'state.json'
    if (Test-Path -LiteralPath $StateFile) { try { $Previous = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { } }
    if (-not $State.LastChange -and $Previous -and $Previous.LastChange) { $State.LastChange = $Previous.LastChange }
    try { [pscustomobject]$State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8 } catch { }
    $Mutex.ReleaseMutex(); $Mutex.Dispose()
}
exit $ExitCode
