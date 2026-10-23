# Step 6 - rollback / removal (elevated, Windows PowerShell 5.1 or PowerShell 7). Every action asks for confirmation.
#   -Action DisableLinks   both GPO links disabled. Devices KEEP their current policy (a GPO never removes a .cip).
#   -Action RemovePolicy   CiTool --remove-policy for the GPO policy GUID on -ComputerName (default: this computer).
#                          Refuses while a WDAC GPO link is enabled (the GPO would redeploy it) unless -Force.
#   -Action RemoveGpos     unlinks and deletes both GPOs (devices keep their policy; run RemovePolicy as well to clear them).
# To go back to AUDIT on enforced devices without removing anything, publish a new package pair instead (1_ + 2_ + 3_ -Mode Audit).
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('DisableLinks', 'RemovePolicy', 'RemoveGpos')][string]$Action,
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$TargetOU,
    [string]$AuditGpoName,
    [string]$EnforceGpoName,
    [switch]$Force
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '6_GPO_rollback' -Overrides @{ TargetOU = $TargetOU; AuditGpoName = $AuditGpoName; EnforceGpoName = $EnforceGpoName }
$R = New-WdacResults
try {
    Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
    $Domain = Get-WdacDomainInfo
    $OU = Resolve-WdacTargetOU $Cfg
    $Names = @($Cfg.AuditGpoName, $Cfg.EnforceGpoName)
    $Links = @((Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks | Where-Object { $_.DisplayName -in $Names })
    $Guid = $null
    foreach ($N in $Names) {
        $G = Get-GPO -Name $N -Server $Domain.PDC -ErrorAction SilentlyContinue
        if ($G -and -not $Guid) { $P = Get-WdacGpoPaths $G.Id $Domain; $M = Read-WdacManifest (Join-Path $P.SysvolPdc $P.PayloadRel); if ($M) { $Guid = ($M.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).PolicyGuid } }
    }
    if (-not $Guid) { $GuidFile = Join-Path $Cfg.WdacRoot 'Source\PolicyGuid.txt'; if (Test-Path $GuidFile) { $Guid = (Get-Content $GuidFile -Raw).Trim() } }

    switch ($Action) {
        'DisableLinks' {
            foreach ($L in $Links) {
                if ($PSCmdlet.ShouldProcess("$($L.DisplayName) on $OU", 'Disable GPO link')) { Set-GPLink -Name $L.DisplayName -Target $OU -LinkEnabled No -Server $Domain.PDC -ErrorAction Stop | Out-Null; Add-WdacResult $R 'OK' 'Link disabled' $L.DisplayName }
            }
            Add-WdacResult $R 'OK' 'Note' 'Devices keep their current App Control policy. Use -Action RemovePolicy to remove it.'
        }
        'RemovePolicy' {
            if (-not $Guid) { throw 'STOP: could not determine the policy GUID (no GPO manifest and no PolicyGuid.txt).' }
            $Enabled = @($Links | Where-Object { $_.Enabled })
            if ($Enabled -and -not $Force) { throw "STOP: $($Enabled.DisplayName -join ', ') is still ENABLED on $OU - the GPO would redeploy the policy. Run -Action DisableLinks first (or pass -Force for a deliberate test)." }
            foreach ($Computer in $ComputerName) {
                if (-not $PSCmdlet.ShouldProcess("$Computer", "CiTool --remove-policy $Guid")) { continue }
                $Remove = {
                    param($Guid)
                    $CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
                    $Before = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies) | Where-Object { $_.PolicyID -eq $Guid.Trim('{}').ToLower() } | Select-Object -First 1
                    $Out = & $CiTool --remove-policy $Guid -json
                    $Code = $LASTEXITCODE
                    $After = @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies) | Where-Object { $_.PolicyID -eq $Guid.Trim('{}').ToLower() } | Select-Object -First 1
                    $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
                    [pscustomobject]@{ Before = $(if ($Before) { "$($Before.FriendlyName) v$($Before.VersionString) active=$($Before.IsEnforced)" } else { 'not present' }); Output = ($Out -join ' '); Exit = $Code
                        After = $(if ($After) { "$($After.FriendlyName) v$($After.VersionString) active=$($After.IsEnforced)" } else { 'not present' }); Stig = "$($DG.CodeIntegrityPolicyEnforcementStatus) / $($DG.UsermodeCodeIntegrityPolicyEnforcementStatus)" }
                }
                $X = if ($Computer -eq $env:COMPUTERNAME) { & $Remove $Guid } else { Invoke-Command -ComputerName $Computer -ScriptBlock $Remove -ArgumentList $Guid -ErrorAction Stop }
                Add-WdacResult $R $(if ($X.Exit -eq 0) { 'OK' } else { 'FAIL' }) "$Computer remove $Guid" "before: $($X.Before) | CiTool: $($X.Output) | after: $($X.After) | STIG now $($X.Stig) (a reboot completes the removal)"
            }
        }
        'RemoveGpos' {
            foreach ($N in $Names) {
                $G = Get-GPO -Name $N -Server $Domain.PDC -ErrorAction SilentlyContinue
                if (-not $G) { continue }
                if ($PSCmdlet.ShouldProcess($N, 'Unlink and DELETE GPO')) {
                    if ($Links | Where-Object { $_.DisplayName -eq $N }) { Remove-GPLink -Name $N -Target $OU -Server $Domain.PDC -ErrorAction Stop | Out-Null }
                    Remove-GPO -Name $N -Server $Domain.PDC -ErrorAction Stop
                    Add-WdacResult $R 'OK' 'GPO deleted' $N
                }
            }
            Add-WdacResult $R 'OK' 'Note' 'Devices keep their current policy; the GPP tasks are removed at the next refresh. Use -Action RemovePolicy to clear devices.'
        }
    }
}
catch { Add-WdacResult $R 'FAIL' $Action $_.Exception.Message }
finally {
    $Failed = Write-WdacResults $R $Cfg "Rollback ($Action)"
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
