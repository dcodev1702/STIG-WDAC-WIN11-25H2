# Step 3 - switch the target OU between the two GPOs (elevated, Windows PowerShell 5.1 or PowerShell 7).
#   -Mode Audit    Audit GPO link ENABLED,  Enforce GPO link disabled
#   -Mode Enforce  Enforce GPO link ENABLED, Audit GPO link disabled
#   -Mode None     both links disabled (devices KEEP whatever policy they already have - see 6_GPO_rollback.ps1)
# Endpoints pick the change up at the next Group Policy refresh (or: gpupdate /target:computer /force) and the GPP task runs
# about a minute later; the startup script also applies it at the next boot.
param(
    [Parameter(Mandatory)][ValidateSet('Audit', 'Enforce', 'None')][string]$Mode,
    [string]$TargetOU,
    [string]$AuditGpoName,
    [string]$EnforceGpoName,
    # Run 'gpupdate /target:computer /force' on THIS computer afterwards (handy on the proving-ground device)
    [switch]$GpUpdate
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '3_GPO_set_mode' -Overrides @{ TargetOU = $TargetOU; AuditGpoName = $AuditGpoName; EnforceGpoName = $EnforceGpoName }
$R = New-WdacResults
$Failed = 1
try {
    Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
    $Domain = Get-WdacDomainInfo
    $OU = Resolve-WdacTargetOU $Cfg
    $Before = @{}
    $Man = @{}
    foreach ($M in 'Audit', 'Enforce') {
        $Name = if ($M -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
        $G = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $G) { throw "STOP: GPO '$Name' does not exist. Run 2_GPO_create_gpos.ps1 first." }
        $Paths = Get-WdacGpoPaths $G.Id $Domain
        $Man[$M] = Read-WdacManifest (Join-Path $Paths.SysvolPdc $Paths.PayloadRel)
        $Link = (Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks | Where-Object { $_.DisplayName -eq $Name }
        if (-not $Link) { New-GPLink -Name $Name -Target $OU -LinkEnabled No -Server $Domain.PDC -ErrorAction Stop | Out-Null; $Before[$M] = $false }
        else { $Before[$M] = [bool]$Link.Enabled }
    }
    $VA = [version]($Man.Audit.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).Version
    $VE = [version]($Man.Enforce.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).Version
    if ($Mode -eq 'Audit' -and $Before.Enforce) {
        Add-WdacResult $R 'WARN' 'Enforce -> Audit' "Devices that already run Enforce v$VE will NOT go back to Audit v$VA (the endpoint script never downgrades). NEXT, with the Audit link now enabled: build a new pair (1_GPO_build_packages.ps1) and publish it (2_GPO_create_gpos.ps1) - devices then move to the new Audit version, which is higher than v$VE."
    }
    $Want = @{ Audit = ($Mode -eq 'Audit'); Enforce = ($Mode -eq 'Enforce') }
    # Disable first, then enable, so both links are never enabled at the same time
    foreach ($M in @('Audit', 'Enforce') | Sort-Object { $Want[$_] }) {
        $Name = if ($M -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
        Set-GPLink -Name $Name -Target $OU -LinkEnabled $(if ($Want[$M]) { 'Yes' } else { 'No' }) -Server $Domain.PDC -ErrorAction Stop | Out-Null
    }
    foreach ($L in @((Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks | Where-Object { $_.DisplayName -in $Cfg.AuditGpoName, $Cfg.EnforceGpoName })) {
        $M = if ($L.DisplayName -eq $Cfg.AuditGpoName) { 'Audit' } else { 'Enforce' }
        $Ok = ([bool]$L.Enabled -eq $Want[$M])
        Add-WdacResult $R $(if ($Ok) { 'OK' } else { 'FAIL' }) "$M link" "$($L.DisplayName): enabled=$($L.Enabled) (was $($Before[$M])) - package v$(if ($M -eq 'Audit') { $VA } else { $VE })"
    }
    Add-WdacResult $R 'OK' 'Mode' "$OU is now in mode '$Mode'"
    if ($GpUpdate) {
        $Out = & gpupdate.exe /target:computer /force 2>&1
        Add-WdacResult $R $(if ($LASTEXITCODE -eq 0) { 'OK' } else { 'WARN' }) 'gpupdate (this computer)' (($Out | Where-Object { $_ -match '\S' }) -join ' ')
    }
    $Failed = 0
    Write-Host "Next: on an endpoint wait for the next refresh (or gpupdate /target:computer /force), give the task ~2 minutes, then .\5_GPO_validate_endpoint.ps1 -ExpectedMode $Mode" -ForegroundColor Cyan
}
catch { Add-WdacResult $R 'FAIL' 'Set mode' $_.Exception.Message }
finally {
    $Failed = [math]::Max($Failed, (Write-WdacResults $R $Cfg "Set mode $Mode"))
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
