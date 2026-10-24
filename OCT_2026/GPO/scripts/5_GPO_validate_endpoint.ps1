# Step 5 - validate an endpoint after a mode change (elevated, Windows PowerShell 5.1 or PowerShell 7). Read-only.
#   .\5_GPO_validate_endpoint.ps1                                  # this computer, expected mode = the OU's enabled GPO
#   .\5_GPO_validate_endpoint.ps1 -ComputerName PAW01,PAW02        # remote (WinRM) endpoints
#   .\5_GPO_validate_endpoint.ps1 -ExpectedMode Enforce            # no GroupPolicy module needed
# Checks: computer in the OU, which WDAC GPO applied, scheduled task, deployment log/events/state, CiTool version = the GPO's
# package, .cip on disk, Event 3099, Win32_DeviceGuard (0 = OFF, 1 = AUDIT, 2 = ENFORCING; Audit: UMCI 1 / Enforce: 2 / 2 = STIG
# PASS), 3076/3077 counts.
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [ValidateSet('Audit', 'Enforce')][string]$ExpectedMode,
    # Optional regex for the application you intend to keep BLOCKED; its 3077 events count as expected, not as a warning
    [string]$BlockTestPattern = '',
    [string]$TargetOU,
    [string]$AuditGpoName,
    [string]$EnforceGpoName
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '5_GPO_validate_endpoint' -Overrides @{ TargetOU = $TargetOU; AuditGpoName = $AuditGpoName; EnforceGpoName = $EnforceGpoName }
$R = New-WdacResults
try {
    Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
    $Domain = Get-WdacDomainInfo
    $OU = Resolve-WdacTargetOU $Cfg
    if (-not $ExpectedMode) {
        $On = @((Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks | Where-Object { $_.Enabled -and $_.DisplayName -in $Cfg.AuditGpoName, $Cfg.EnforceGpoName })
        if ($On.Count -ne 1) { throw "STOP: expected exactly one enabled WDAC GPO link on $OU, found $($On.Count). Pass -ExpectedMode or fix the links with 3_GPO_set_mode.ps1." }
        $ExpectedMode = if ($On[0].DisplayName -eq $Cfg.AuditGpoName) { 'Audit' } else { 'Enforce' }
    }
    $GpoName = if ($ExpectedMode -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
    $OtherName = if ($ExpectedMode -eq 'Audit') { $Cfg.EnforceGpoName } else { $Cfg.AuditGpoName }
    $G = Get-GPO -Name $GpoName -Server $Domain.PDC -ErrorAction Stop
    $Paths = Get-WdacGpoPaths $G.Id $Domain
    $Man = Read-WdacManifest (Join-Path $Paths.SysvolPdc $Paths.PayloadRel)
    $Base = $Man.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1
    Add-WdacResult $R 'OK' 'Expected' "mode $ExpectedMode via '$GpoName' - base $($Base.PolicyGuid) v$($Base.Version)"

    $Probe = {
        param($Guid, $Version, $Mode, $GpoName, $OtherName)
        $Out = [ordered]@{}
        $CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
        $Out.OS = (Get-CimInstance Win32_OperatingSystem | ForEach-Object { "$($_.Caption) $($_.Version) ProductType $($_.ProductType)" })
        $S = [adsisearcher]"(&(objectCategory=computer)(sAMAccountName=$env:COMPUTERNAME`$))"; $Out.DN = [string]$S.FindOne().Properties.distinguishedname
        $Gp = @(& gpresult.exe /scope computer /r 2>&1)
        $Start = [array]::IndexOf($Gp, ($Gp | Where-Object { $_ -match 'Applied Group Policy Objects' } | Select-Object -First 1))
        $Applied = @(); if ($Start -ge 0) { for ($i = $Start + 2; $i -lt $Gp.Count -and $Gp[$i].Trim(); $i++) { $Applied += $Gp[$i].Trim() } }
        $Out.AppliedGpos = $Applied
        $Out.Task = foreach ($M in 'Audit', 'Enforce') { $T = Get-ScheduledTask -TaskName "WDAC-GPO-Deploy-$M" -ErrorAction SilentlyContinue; if ($T) { $I = $T | Get-ScheduledTaskInfo; [pscustomobject]@{ Name = $T.TaskName; State = "$($T.State)"; LastRun = "$($I.LastRunTime)"; LastResult = $I.LastTaskResult; NextRun = "$($I.NextRunTime)" } } }
        $StateFile = Join-Path $env:ProgramData 'WDAC-GPO\state.json'
        $Out.State = if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json } else { $null }
        $LogFile = Join-Path $env:SystemRoot 'Logs\WDAC-GPO\Deploy-WDACPolicy.log'
        $Out.LogTail = if (Test-Path $LogFile) { @(Get-Content $LogFile -Tail 8) } else { @() }
        $Out.Events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WDAC-GPO' } -MaxEvents 6 -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) $($_.Id) $($_.LevelDisplayName): $($_.Message)" })
        $Pol = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies)
        $G2 = $Guid.Trim('{}').ToLower()
        $Out.Policy = $Pol | Where-Object { $_.PolicyID -eq $G2 } | Select-Object -First 1 PolicyID, FriendlyName, VersionString, IsEnforced, IsAuthorized
        $Out.OtherBases = @($Pol | Where-Object { -not $_.IsSystemPolicy -and $_.IsEnforced -and $_.PolicyID -eq $_.BasePolicyID -and $_.PolicyID -ne $G2 } | ForEach-Object { "$($_.FriendlyName) {$($_.PolicyID)}" })
        $Out.Supplementals = @($Pol | Where-Object { -not $_.IsSystemPolicy -and $_.BasePolicyID -eq $G2 -and $_.PolicyID -ne $G2 } | ForEach-Object { "$($_.FriendlyName) v$($_.VersionString) authorized=$($_.IsAuthorized)" })
        $Out.CipOnDisk = Test-Path (Join-Path $env:SystemRoot "System32\CodeIntegrity\CiPolicies\Active\{$G2}.cip")
        $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        $Out.KMCI = [int]$DG.CodeIntegrityPolicyEnforcementStatus; $Out.UMCI = [int]$DG.UsermodeCodeIntegrityPolicyEnforcementStatus
        $Since = if ($Out.State -and $Out.State.LastChange) { [datetime]$Out.State.LastChange } else { (Get-Date).AddHours(-24) }
        $Out.Since = $Since.ToString('yyyy-MM-dd HH:mm:ss')
        $Out.Ev3099 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3099; StartTime = $Since.AddMinutes(-2) } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match $G2 } | Select-Object -First 1 | ForEach-Object { "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) $($_.Message)" })
        $Out.Count3076 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3076; StartTime = $Since } -ErrorAction SilentlyContinue).Count
        $Blocks = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3077; StartTime = $Since } -ErrorAction SilentlyContinue)
        $Out.Count3077 = $Blocks.Count
        $Out.BlockedFiles = @($Blocks | ForEach-Object { $D = ([xml]$_.ToXml()).Event.EventData.Data; "$((($D | Where-Object { $_.Name -eq 'File Name' }).'#text') -replace '^\\Device\\HarddiskVolume\d+', $env:SystemDrive) <- $(Split-Path -Leaf (($D | Where-Object { $_.Name -eq 'Process Name' }).'#text'))" } | Select-Object -Unique)
        return [pscustomobject]$Out
    }

    foreach ($Computer in $ComputerName) {
        $X = if ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost') { & $Probe $Base.PolicyGuid $Base.Version $ExpectedMode $GpoName $OtherName }
             else { Invoke-Command -ComputerName $Computer -ScriptBlock $Probe -ArgumentList $Base.PolicyGuid, $Base.Version, $ExpectedMode, $GpoName, $OtherName -ErrorAction Stop }
        $C = $Computer
        Add-WdacResult $R 'OK' "$C OS" $X.OS
        Add-WdacResult $R $(if ($X.DN -match [regex]::Escape(",$OU") -or $X.DN.EndsWith($OU)) { 'OK' } else { 'FAIL' }) "$C in target OU" $X.DN
        $HasMine = $X.AppliedGpos -contains $GpoName; $HasOther = $X.AppliedGpos -contains $OtherName
        Add-WdacResult $R $(if ($HasMine -and -not $HasOther) { 'OK' } else { 'FAIL' }) "$C applied GPOs" ($X.AppliedGpos -join '; ')
        $Mine = @($X.Task | Where-Object { $_.Name -eq "WDAC-GPO-Deploy-$ExpectedMode" }); $Other = @($X.Task | Where-Object { $_.Name -ne "WDAC-GPO-Deploy-$ExpectedMode" })
        Add-WdacResult $R $(if ($Mine -and $Mine[0].LastResult -eq 0) { 'OK' } elseif ($Mine) { 'WARN' } else { 'FAIL' }) "$C scheduled task" $(if ($Mine) { "$($Mine[0].Name) $($Mine[0].State), last run $($Mine[0].LastRun) result $($Mine[0].LastResult), next $($Mine[0].NextRun)" } else { "WDAC-GPO-Deploy-$ExpectedMode not present (run gpupdate /target:computer /force)" })
        if ($Other) { Add-WdacResult $R 'WARN' "$C other-mode task" "$($Other.Name -join ', ') still present (removed at the next policy refresh)" }
        Add-WdacResult $R $(if ($X.State -and $X.State.Result -in 'Deployed', 'NoChange') { 'OK' } else { 'WARN' }) "$C last deployment run" $(if ($X.State) { "$($X.State.LastRun) mode $($X.State.Mode): $($X.State.Result); " + ((@($X.State.Policies) | ForEach-Object { "$($_.Name) $($_.Action) $($_.Before) -> $($_.After)" }) -join '; ') } else { 'no state.json yet' })
        $P = $X.Policy
        $VerOk = ($P -and $P.IsEnforced -and $P.VersionString -eq $Base.Version)
        Add-WdacResult $R $(if ($VerOk) { 'OK' } else { 'FAIL' }) "$C active policy" $(if ($P) { "$($P.FriendlyName) {$($P.PolicyID)} v$($P.VersionString) active=$($P.IsEnforced) authorized=$($P.IsAuthorized) (GPO package v$($Base.Version))" } else { 'policy not present' })
        Add-WdacResult $R $(if ($X.CipOnDisk) { 'OK' } else { 'FAIL' }) "$C .cip on disk" "CiPolicies\Active\$($Base.PolicyGuid).cip present=$($X.CipOnDisk)"
        Add-WdacResult $R $(if ($X.Ev3099) { 'OK' } else { 'WARN' }) "$C Event 3099" $(if ($X.Ev3099) { $X.Ev3099 -join '' } else { "none since $($X.Since)" })
        $Stig = Format-WdacStig $X.KMCI $X.UMCI
        $StigOk = if ($ExpectedMode -eq 'Enforce') { $X.KMCI -eq 2 -and $X.UMCI -eq 2 } else { $X.UMCI -eq 1 }
        Add-WdacResult $R $(if ($StigOk) { 'OK' } else { 'FAIL' }) "$C Win32_DeviceGuard" "$Stig - $(if ($ExpectedMode -eq 'Enforce') { if ($StigOk) { 'both PASS' } else { 'expected 2 (ENFORCING) for both' } } else { 'user mode 1 (AUDIT) expected in Audit mode: V-243451 stays open until Enforce' })"
        $Expected = @($X.BlockedFiles | Where-Object { $BlockTestPattern -and $_ -match $BlockTestPattern })
        $Unexpected = @($X.BlockedFiles | Where-Object { -not ($BlockTestPattern -and $_ -match $BlockTestPattern) })
        Add-WdacResult $R $(if ($ExpectedMode -eq 'Audit' -or $Unexpected.Count -eq 0) { 'OK' } else { 'WARN' }) "$C events since $($X.Since)" "3076 (would block) = $($X.Count3076), 3077 (blocked) = $($X.Count3077)$(if ($ExpectedMode -eq 'Audit' -and $X.Count3076) { ' - review with C:\WDAC\config\scripts\Export-CIEventEvidence.ps1 before enforcing' })"
        if ($Expected) { Add-WdacResult $R 'OK' "$C expected blocks" "matching '$BlockTestPattern': $($Expected -join '; ')" }
        if ($Unexpected) { Add-WdacResult $R 'WARN' "$C blocks to review" (($Unexpected -join '; ') + ' - an approved app needs a fix-forward (new package pair)') }
        if ($X.OtherBases) { Add-WdacResult $R 'WARN' "$C other base policies" ($X.OtherBases -join '; ') }
        if ($X.Supplementals) { Add-WdacResult $R 'OK' "$C supplementals" ($X.Supplementals -join '; ') }
        foreach ($Line in @($X.LogTail | Select-Object -Last 3)) { Add-WdacResult $R 'OK' "$C deploy log" $Line }
    }
}
catch { Add-WdacResult $R 'FAIL' 'Unexpected error' $_.Exception.Message }
finally {
    $Failed = Write-WdacResults $R $Cfg "Endpoint validation ($ExpectedMode)"
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
