# Step 0 - run on the fully configured WDAC REFERENCE device (elevated, Windows PowerShell 5.1 or PowerShell 7).
# Read-only. Proves the reference device, the domain and your rights are ready before any GPO is created.
param([string]$TargetOU)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '0_GPO_pre-flight' -Overrides @{ TargetOU = $TargetOU }
$R = New-WdacResults
try {
    # ---------------------------------------------------------------- session and tools
    Add-WdacResult $R 'OK' 'Session' "Elevated as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition))"
    $CS = Get-CimInstance Win32_ComputerSystem
    if ($CS.PartOfDomain) { Add-WdacResult $R 'OK' 'Domain membership' $CS.Domain } else { Add-WdacResult $R 'FAIL' 'Domain membership' 'This computer is not domain joined' }
    foreach ($M in 'GroupPolicy', 'ActiveDirectory', 'ConfigCI') {
        try { Import-WdacModule $M; Add-WdacResult $R 'OK' "Module $M" 'loaded' }
        catch { Add-WdacResult $R 'FAIL' "Module $M" "$($_.Exception.Message) - install RSAT: Get-WindowsCapability -Online -Name Rsat.GroupPolicy*, Rsat.ActiveDirectory* | Add-WindowsCapability -Online" }
    }
    $Groups = @(whoami /groups /fo csv | ConvertFrom-Csv | ForEach-Object { $_.'Group Name' })
    $Rights = @($Groups | Where-Object { $_ -match '\\(Domain Admins|Enterprise Admins|Group Policy Creator Owners)$' })
    if ($Rights) { Add-WdacResult $R 'OK' 'GPO rights' ($Rights -join ', ') } else { Add-WdacResult $R 'WARN' 'GPO rights' 'Not in Domain Admins / Group Policy Creator Owners - creating and linking GPOs needs delegated rights' }

    # ---------------------------------------------------------------- domain, DCs, SYSVOL
    $Domain = Get-WdacDomainInfo
    Add-WdacResult $R 'OK' 'Domain' "$($Domain.DnsRoot) ($($Domain.NetBIOS)) - PDC emulator $($Domain.PDC)"
    foreach ($DC in @(Get-ADDomainController -Filter * | Sort-Object HostName)) {
        $Path = "\\$($DC.HostName)\SYSVOL\$($Domain.DnsRoot)\Policies"
        if (Test-Path -LiteralPath $Path) { Add-WdacResult $R 'OK' "SYSVOL on $($DC.HostName)" "$Path reachable ($($DC.OperatingSystem))" } else { Add-WdacResult $R 'FAIL' "SYSVOL on $($DC.HostName)" "$Path not reachable" }
    }

    # ---------------------------------------------------------------- target OU and its members
    $OU = Resolve-WdacTargetOU $Cfg
    try {
        $OuObj = Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop
        Add-WdacResult $R 'OK' 'Target OU' "$($OuObj.Name) - $OU$(if (-not $Cfg.TargetOU) { ' (auto-detected from this computer)' })"
        $Members = @(Get-ADComputer -SearchBase $OU -Filter * -Properties OperatingSystem, OperatingSystemVersion)
        foreach ($C in $Members) {
            $Status = if ($C.OperatingSystem -match 'Windows 1[01] (Enterprise|Education|Pro)') { 'OK' } else { 'WARN' }
            Add-WdacResult $R $Status "OU member $($C.Name)" "$($C.OperatingSystem) $($C.OperatingSystemVersion)$(if ($Status -eq 'WARN') { ' - not a Windows client edition; the endpoint script will skip it' })"
        }
        if ($Members.Count -eq 0) { Add-WdacResult $R 'WARN' 'OU members' 'No computers in the OU yet' }
        $Links = @((Get-GPInheritance -Target $OU).GpoLinks | ForEach-Object { "$($_.DisplayName) (enabled=$($_.Enabled))" })
        Add-WdacResult $R 'OK' 'GPOs linked to OU' $(if ($Links) { $Links -join '; ' } else { '(none)' })
    }
    catch { Add-WdacResult $R 'FAIL' 'Target OU' "$OU : $($_.Exception.Message)" }
    foreach ($Name in $Cfg.AuditGpoName, $Cfg.EnforceGpoName) {
        $G = Get-GPO -Name $Name -ErrorAction SilentlyContinue
        Add-WdacResult $R 'OK' "GPO '$Name'" $(if ($G) { "exists ({$($G.Id)}) - 2_GPO_create_gpos.ps1 will UPDATE it" } else { 'does not exist yet - 2_GPO_create_gpos.ps1 will create it' })
    }

    # ---------------------------------------------------------------- reference policy (built with C:\WDAC\config\README.md)
    $GuidFile = Join-Path $Cfg.WdacRoot 'Source\PolicyGuid.txt'
    $EnforceXml = Join-Path $Cfg.WdacRoot 'Source\Base-Enforce.xml'
    if (-not (Test-Path -LiteralPath $GuidFile) -or -not (Test-Path -LiteralPath $EnforceXml)) { Add-WdacResult $R 'FAIL' 'Reference policy files' "Missing $GuidFile or $EnforceXml - finish C:\WDAC\config\README.md on this device first" }
    else {
        $Guid = (Get-Content -LiteralPath $GuidFile -Raw).Trim()
        $Doc = New-Object System.Xml.XmlDocument; $Doc.Load($EnforceXml)
        $S = $Doc.SiPolicy; $Opts = @($S.Rules.Rule.Option)
        if ($S.PolicyID -ieq $Guid -and $S.BasePolicyID -ieq $Guid -and $S.PolicyType -eq 'Base Policy') { Add-WdacResult $R 'OK' 'Base-Enforce.xml' "Base policy $Guid v$($S.VersionEx), Multiple Policy Format" } else { Add-WdacResult $R 'FAIL' 'Base-Enforce.xml' "PolicyID/BasePolicyID/type do not match PolicyGuid.txt ($Guid)" }
        if ($Opts -contains 'Enabled:Audit Mode') { Add-WdacResult $R 'FAIL' 'Base-Enforce.xml mode' 'Audit Mode is ON - the reference policy must be the enforced one' } else { Add-WdacResult $R 'OK' 'Base-Enforce.xml mode' 'Audit Mode OFF (enforced policy)' }
        Add-WdacResult $R $(if ($Opts -contains 'Enabled:Managed Installer') { 'OK' } else { 'WARN' }) 'Option 13 Managed Installer' $(if ($Opts -contains 'Enabled:Managed Installer') { 'ON (MECM / Intune)' } else { 'OFF' })
        $Plan = Get-WdacPackageVersions $Cfg $Guid $EnforceXml
        Add-WdacResult $R 'OK' 'Next package versions' "Audit $($Plan.Versions[0]) / Enforce $($Plan.Versions[1]) - $($Plan.Basis); highest known v$($Plan.Highest) ($($Plan.Sources))"
        $Active = @((& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies) | Where-Object { $_.PolicyID -ieq $Guid.Trim('{}') } | Select-Object -First 1
        # The reference device may itself be in the target OU and run a version published by one of the WDAC GPOs
        $FromGpo = @(Get-WdacPublishedPayloads $Cfg | ForEach-Object { $M = Read-WdacManifest $_; if ($M -and $Active) { @($M.Policies | Where-Object { $_.Type -eq 'Base' -and $_.PolicyGuid -ieq $Guid -and $_.Version -eq $Active.VersionString }) | ForEach-Object { "$($M.Mode) GPO package" } } })
        if ($Active -and $Active.VersionString -eq $S.VersionEx) { Add-WdacResult $R 'OK' 'Reference device active policy' "$($Active.FriendlyName) v$($Active.VersionString), IsAuthorized $($Active.IsAuthorized) - matches Base-Enforce.xml" }
        elseif ($Active -and $FromGpo) { Add-WdacResult $R 'OK' 'Reference device active policy' "$($Active.FriendlyName) v$($Active.VersionString), IsAuthorized $($Active.IsAuthorized) - deployed by the $($FromGpo -join ', ') (built from Base-Enforce.xml)" }
        elseif ($Active) { Add-WdacResult $R 'WARN' 'Reference device active policy' "Active v$($Active.VersionString) differs from Base-Enforce.xml v$($S.VersionEx)" }
        else { Add-WdacResult $R 'WARN' 'Reference device active policy' 'The reference policy is not active on this device' }
        $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        $St = "$($DG.CodeIntegrityPolicyEnforcementStatus) / $($DG.UsermodeCodeIntegrityPolicyEnforcementStatus)"
        Add-WdacResult $R $(if ($St -eq '2 / 2') { 'OK' } else { 'WARN' }) 'Reference device STIG (KMCI / UMCI)' $St
        $Supp = @((& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies | Where-Object { -not $_.IsSystemPolicy -and $_.BasePolicyID -ieq $Guid.Trim('{}') -and $_.PolicyID -ne $_.BasePolicyID })
        foreach ($Sp in $Supp) { Add-WdacResult $R 'OK' "Local supplemental $($Sp.FriendlyName)" "{$($Sp.PolicyID)} v$($Sp.VersionString) - NOT packaged unless passed to 1_GPO_build_packages.ps1 -SupplementalXml" }
    }
    $Build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    Add-WdacResult $R $(if ($Build -ge 22621 -and (Test-Path "$env:SystemRoot\System32\CiTool.exe")) { 'OK' } else { 'FAIL' }) 'CiTool.exe / build' "build $Build"
}
catch { Add-WdacResult $R 'FAIL' 'Unexpected error' $_.Exception.Message }
finally {
    $Failed = Write-WdacResults $R $Cfg 'GPO pre-flight'
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
