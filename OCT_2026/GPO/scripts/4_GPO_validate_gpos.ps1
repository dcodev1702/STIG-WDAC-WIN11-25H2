# Step 4 - validate both WDAC GPOs from the admin side (elevated, Windows PowerShell 5.1 or PowerShell 7). Read-only.
# Checks AD + SYSVOL on EVERY domain controller: payload files and hashes, manifest, startup script, scheduled task, CSEs,
# versions, status, security filtering, links (never both enabled) and the Audit < Enforce version order.
param(
    [string]$TargetOU,
    [string]$AuditGpoName,
    [string]$EnforceGpoName
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '4_GPO_validate_gpos' -Overrides @{ TargetOU = $TargetOU; AuditGpoName = $AuditGpoName; EnforceGpoName = $EnforceGpoName }
$R = New-WdacResults
$Required = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}', '{AADCED64-746C-4633-A97C-D61349046527}', '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', '{00000000-0000-0000-0000-000000000000}'
try {
    Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
    $Domain = Get-WdacDomainInfo
    $OU = Resolve-WdacTargetOU $Cfg
    $DCs = @(Get-ADDomainController -Filter * | Sort-Object HostName | ForEach-Object { $_.HostName })
    $Links = @((Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks)
    $Ver = @{}
    foreach ($Mode in 'Audit', 'Enforce') {
        $Name = if ($Mode -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
        $G = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $G) { Add-WdacResult $R 'FAIL' "$Mode GPO" "'$Name' not found"; continue }
        $Paths = Get-WdacGpoPaths $G.Id $Domain
        Add-WdacResult $R 'OK' "$Mode GPO" "'$Name' {$($G.Id)} - modified $($G.ModificationTime)"
        Add-WdacResult $R $(if ("$($G.GpoStatus)" -eq 'UserSettingsDisabled') { 'OK' } else { 'WARN' }) "$Mode status" "$($G.GpoStatus)"
        $DsV = $G.Computer.DSVersion; $SvV = $G.Computer.SysvolVersion
        Add-WdacResult $R $(if ($DsV -eq $SvV -and $DsV -gt 0) { 'OK' } else { 'FAIL' }) "$Mode version AD/SYSVOL" "$DsV / $SvV"
        $Ad = Get-ADObject -Identity $Paths.AdPath -Properties gPCMachineExtensionNames -Server $Domain.PDC
        $Missing = @($Required | Where-Object { "$($Ad.gPCMachineExtensionNames)" -notmatch [regex]::Escape($_) })
        Add-WdacResult $R $(if ($Missing.Count -eq 0) { 'OK' } else { 'FAIL' }) "$Mode CSEs" $(if ($Missing) { "missing $($Missing -join ', ')" } else { 'GPP core, Registry, Scripts, GPP Scheduled Tasks registered' })
        $Apply = @(Get-GPPermission -Name $Name -All -Server $Domain.PDC | Where-Object { "$($_.Permission)" -eq 'GpoApply' } | ForEach-Object { $_.Trustee.Name })
        Add-WdacResult $R $(if ($Apply -match 'Authenticated Users|Domain Computers') { 'OK' } else { 'WARN' }) "$Mode security filtering" "GpoApply: $($Apply -join ', ')"
        if ($G.WmiFilter) { Add-WdacResult $R 'WARN' "$Mode WMI filter" "$($G.WmiFilter.Name)" }
        try { $Sync = Get-GPRegistryValue -Name $Name -Server $Domain.PDC -Key 'HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'SyncForegroundPolicy' -ErrorAction Stop; Add-WdacResult $R $(if ($Sync.Value -eq 1) { 'OK' } else { 'WARN' }) "$Mode wait for network" "SyncForegroundPolicy = $($Sync.Value)" }
        catch { Add-WdacResult $R 'WARN' "$Mode wait for network" 'SyncForegroundPolicy not set' }

        # ------------------------------------------------------------ manifest + payload on every DC
        $Man = Read-WdacManifest (Join-Path $Paths.SysvolPdc $Paths.PayloadRel)
        if (-not $Man) { Add-WdacResult $R 'FAIL' "$Mode manifest" 'manifest.json missing in SYSVOL'; continue }
        Add-WdacResult $R $(if ($Man.Mode -eq $Mode) { 'OK' } else { 'FAIL' }) "$Mode manifest" "Mode $($Man.Mode), built $($Man.BuiltAt) on $($Man.BuiltOn) from $($Man.SourceXml)"
        $Base = $Man.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1
        $Ver[$Mode] = [version]$Base.Version; $Ver["$Mode-Guid"] = $Base.PolicyGuid
        foreach ($DC in $DCs) {
            $Dir = "\\$DC\SYSVOL\$($Domain.DnsRoot)\Policies\$($Paths.Id)\$($Paths.PayloadRel)"
            $Bad = New-Object System.Collections.Generic.List[string]
            foreach ($P in @($Man.Policies)) { $F = Join-Path $Dir $P.File; if (-not (Test-Path -LiteralPath $F)) { $Bad.Add("$($P.File) missing") } elseif ((Get-FileHash -LiteralPath $F -Algorithm SHA256).Hash -ne $P.Sha256) { $Bad.Add("$($P.File) hash differs") } }
            $Ds = Join-Path $Dir 'Deploy-WDACPolicy.ps1'
            if (-not (Test-Path -LiteralPath $Ds)) { $Bad.Add('Deploy-WDACPolicy.ps1 missing') } elseif ($Man.DeployScriptSha256 -and (Get-FileHash -LiteralPath $Ds -Algorithm SHA256).Hash -ne $Man.DeployScriptSha256) { $Bad.Add('Deploy-WDACPolicy.ps1 hash differs') }
            Add-WdacResult $R $(if ($Bad.Count) { 'FAIL' } else { 'OK' }) "$Mode payload on $DC" $(if ($Bad.Count) { $Bad -join '; ' } else { "$(@($Man.Policies).Count) policy file(s) + deploy script, hashes match: " + ((@($Man.Policies) | ForEach-Object { "$($_.Type) v$($_.Version)" }) -join ', ') })
        }

        # ------------------------------------------------------------ startup script + scheduled task definitions
        $Ini = Join-Path $Paths.SysvolPdc 'Machine\Scripts\scripts.ini'
        $IniText = if (Test-Path -LiteralPath $Ini) { [IO.File]::ReadAllText($Ini) } else { '' }
        $IniOk = ($IniText -match '\[Startup\]' -and $IniText -match 'powershell\.exe' -and $IniText -match [regex]::Escape("$($Paths.Id)\$($Paths.PayloadRel)\Deploy-WDACPolicy.ps1") -and $IniText -match "-Mode $Mode")
        Add-WdacResult $R $(if ($IniOk) { 'OK' } else { 'FAIL' }) "$Mode startup script" $(if ($IniOk) { (($IniText -split "`r?`n") | Where-Object { $_ -match 'Parameters=' }) -join '' } else { "scripts.ini missing or wrong ($Ini)" })
        $TaskFile = Join-Path $Paths.SysvolPdc 'Machine\Preferences\ScheduledTasks\ScheduledTasks.xml'
        if (Test-Path -LiteralPath $TaskFile) {
            $T = New-Object System.Xml.XmlDocument; $T.Load($TaskFile)
            $Tv = $T.ScheduledTasks.TaskV2
            $TaskArgs = $Tv.Properties.Task.Actions.Exec.Arguments
            $Int = $Tv.Properties.Task.Triggers.TimeTrigger.Repetition.Interval
            $TOk = ($Tv.name -eq "WDAC-GPO-Deploy-$Mode" -and $Tv.removePolicy -eq '1' -and $Tv.Properties.runAs -eq 'NT AUTHORITY\System' -and $TaskArgs -match "-Mode $Mode" -and $TaskArgs -match [regex]::Escape($Paths.Id))
            Add-WdacResult $R $(if ($TOk) { 'OK' } else { 'FAIL' }) "$Mode scheduled task" "$($Tv.name) runAs $($Tv.Properties.runAs), every $Int + at creation, removePolicy=$($Tv.removePolicy)"
        }
        else { Add-WdacResult $R 'FAIL' "$Mode scheduled task" "ScheduledTasks.xml missing ($TaskFile)" }

        # ------------------------------------------------------------ link
        $L = $Links | Where-Object { $_.DisplayName -eq $Name }
        Add-WdacResult $R $(if ($L) { 'OK' } else { 'FAIL' }) "$Mode link" $(if ($L) { "linked to $OU, enabled=$($L.Enabled), enforced=$($L.Enforced), order $($L.Order)" } else { "not linked to $OU" })
    }
    if ($Ver.Audit -and $Ver.Enforce) {
        Add-WdacResult $R $(if ($Ver['Audit-Guid'] -ieq $Ver['Enforce-Guid']) { 'OK' } else { 'FAIL' }) 'Same policy GUID' "$($Ver['Audit-Guid']) / $($Ver['Enforce-Guid'])"
        Add-WdacResult $R $(if ($Ver.Enforce -gt $Ver.Audit) { 'OK' } else { 'FAIL' }) 'Version order' "Audit v$($Ver.Audit) < Enforce v$($Ver.Enforce)"
    }
    $On = @($Links | Where-Object { $_.DisplayName -in $Cfg.AuditGpoName, $Cfg.EnforceGpoName -and $_.Enabled })
    $ModeNow = if ($On.Count -eq 0) { 'None' } elseif ($On.Count -gt 1) { 'BOTH' } elseif ($On[0].DisplayName -eq $Cfg.AuditGpoName) { 'Audit' } else { 'Enforce' }
    Add-WdacResult $R $(if ($ModeNow -eq 'BOTH') { 'FAIL' } else { 'OK' }) 'Active mode for the OU' $(if ($ModeNow -eq 'BOTH') { 'BOTH links are enabled - run 3_GPO_set_mode.ps1' } else { $ModeNow })
}
catch { Add-WdacResult $R 'FAIL' 'Unexpected error' $_.Exception.Message }
finally {
    $Failed = Write-WdacResults $R $Cfg 'GPO validation'
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
