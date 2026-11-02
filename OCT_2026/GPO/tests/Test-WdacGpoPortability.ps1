# Portability test for the WDAC GPO flow: one policy kit, any domain and OU (enclave). Elevated; Windows PowerShell 5.1 and
# PowerShell 7. ASCII-only. It changes NOTHING in Active Directory, SYSVOL or App Control on this computer:
#   - every AD and Group Policy command the scripts call is replaced by an in-memory stand-in, and the test refuses to run the
#     scripts unless each of those names resolves to its stand-in;
#   - each simulated domain's SYSVOL is a folder under -WorkRoot, reached through the \\localhost\<drive>$ admin share;
#   - the real GPOs, OU links and active App Control policies are snapshotted before and after and must be identical.
#   .\Test-WdacGpoPortability.ps1                     # kit = ..\policy, scripts = ..\scripts
#   .\Test-WdacGpoPortability.ps1 -KitPath D:\kit     # a kit copied into an enclave
# What it proves for the kit (Base-Audit.xml, Base-Audit-Merged.xml, Base-Enforce.xml, PolicyGuid.txt, SHA256SUMS.txt):
#   1. Kit: hashes, one GUID, modes, Audit-Merged = Enforce except Audit Mode, every XML compiles, no user-profile rule.
#   2. Helpers: portability gate, OU-in-domain check, GPO paths per domain, FilePath folder check.
#   3. Steps 0, 1, 2, 4, 3 (and the new step 5 rows) run unchanged in two domains with different names and OUs: identical policy
#      content, each domain's own SYSVOL paths and OU links only. The target OU comes from this computer's account in one domain
#      (TargetOU empty) and from the settings file in the other (computer in another OU); -TargetOU typed without quotes works.
#      A TargetOU of the other domain or a container, a publish without confirmation and a policy with a user-profile rule are
#      refused with nothing changed.
# Results: console table + <WorkRoot>\Test-WdacGpoPortability.csv, transcript next to it; exit 1 on any FAIL.
param(
    [string]$KitPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'policy'),
    [string]$ScriptsPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'),
    [string]$WorkRoot = (Join-Path $env:TEMP ('WDAC-GPO-Portability-' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)
$ErrorActionPreference = 'Stop'
$Results = New-Object System.Collections.Generic.List[object]
function Add-TestResult([string]$Status, [string]$Check, [string]$Detail) { $Results.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail }) }
function Assert-That([bool]$Condition, [string]$Check, [string]$Detail) { Add-TestResult $(if ($Condition) { 'OK' } else { 'FAIL' }) $Check $Detail }

# Real state that must not change: GPOs of the domain, links on this computer's OU, App Control policies on this computer
function Get-WdacRealState([string]$OU) {
    $Lines = New-Object System.Collections.Generic.List[string]
    foreach ($G in @(GroupPolicy\Get-GPO -All | Sort-Object Id)) { $Lines.Add("GPO $($G.Id) '$($G.DisplayName)' modified $($G.ModificationTime.ToString('o')) ds $($G.Computer.DSVersion) sysvol $($G.Computer.SysvolVersion) $($G.GpoStatus)") }
    foreach ($L in @((GroupPolicy\Get-GPInheritance -Target $OU).GpoLinks)) { $Lines.Add("LINK '$($L.DisplayName)' enabled $($L.Enabled) order $($L.Order)") }
    foreach ($P in @((& (Join-Path $env:SystemRoot 'System32\CiTool.exe') --list-policies -json | ConvertFrom-Json).Policies | Sort-Object PolicyID)) { $Lines.Add("CI $($P.PolicyID) v$($P.VersionString) enforced $($P.IsEnforced)") }
    return , $Lines.ToArray()
}

# Kit Base-Enforce.xml plus one extra allow rule (FilePath in a named user profile, or a hash rule whose FriendlyName names one)
function New-WdacTestXml([string]$Source, [string]$Dest, [string]$FilePath, [string]$FriendlyName) {
    $NsUri = 'urn:schemas-microsoft-com:sipolicy'
    $D = New-Object System.Xml.XmlDocument; $D.Load($Source)
    $Rule = $D.CreateElement('Allow', $NsUri)
    $Rule.SetAttribute('ID', 'ID_ALLOW_PORTABILITY_TEST'); $Rule.SetAttribute('FriendlyName', $FriendlyName)
    if ($FilePath) { $Rule.SetAttribute('FilePath', $FilePath) } else { $Rule.SetAttribute('Hash', ('AB' * 32)) }
    [void]$D.SiPolicy.FileRules.AppendChild($Rule)
    $Ns = New-Object System.Xml.XmlNamespaceManager $D.NameTable; $Ns.AddNamespace('s', $NsUri)
    $Refs = $D.SelectSingleNode("/s:SiPolicy/s:SigningScenarios/s:SigningScenario[@Value='12']/s:ProductSigners/s:FileRulesRef", $Ns)
    $Ref = $D.CreateElement('FileRuleRef', $NsUri); $Ref.SetAttribute('RuleID', 'ID_ALLOW_PORTABILITY_TEST'); [void]$Refs.AppendChild($Ref)
    $D.Save($Dest)
}

# Runs one GPO script in this session (the stand-ins apply), returns exit code, output and the rows of its results CSV
function Invoke-WdacStep([string]$Script, [hashtable]$Arguments = @{}) {
    Start-Sleep -Milliseconds 1100   # results files are stamped to the second
    $ErrorActionPreference = 'Continue'   # as in an operator's console; the scripts must not inherit this test's 'Stop'
    $global:LASTEXITCODE = 0
    $Out = & $Script @Arguments *>&1 | Out-String -Width 4000
    $Code = $LASTEXITCODE
    $Csv = Get-ChildItem -LiteralPath (Join-Path $Global:WdacSim.GpoRoot 'Logs') -Filter "$([IO.Path]::GetFileNameWithoutExtension($Script))-*.csv" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    [pscustomobject]@{ ExitCode = $Code; Output = $Out; Rows = $(if ($Csv) { @(Import-Csv -LiteralPath $Csv.FullName) } else { @() }) }
}
function Format-Fails($Step) { (@($Step.Rows | Where-Object { $_.Status -eq 'FAIL' }) | ForEach-Object { "$($_.Check): $($_.Detail)" }) -join ' | ' }

# Commands the GPO scripts call that read or change AD / Group Policy / this computer's identity, plus ones they must never call
$Guarded = 'Get-ADDomain', 'Get-ADDomainController', 'Get-ADOrganizationalUnit', 'Get-ADComputer', 'Get-ADObject', 'Set-ADObject',
           'New-ADObject', 'Remove-ADObject', 'Get-GPO', 'New-GPO', 'Remove-GPO', 'Set-GPRegistryValue', 'Get-GPRegistryValue',
           'Get-GPPermission', 'Set-GPPermission', 'Get-GPInheritance', 'New-GPLink', 'Set-GPLink', 'Remove-GPLink', 'Invoke-GPUpdate',
           'Get-CimInstance', 'Read-Host'
$Started = $false
try {
    # ------------------------------------------------------------ preconditions (nothing is created before they pass)
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'STOP: run elevated - the GPO scripts refuse to start otherwise. Nothing was changed.' }
    $KitFiles = 'Base-Audit.xml', 'Base-Audit-Merged.xml', 'Base-Enforce.xml', 'PolicyGuid.txt'
    foreach ($F in $KitFiles + 'SHA256SUMS.txt') { if (-not (Test-Path -LiteralPath (Join-Path $KitPath $F))) { throw "STOP: kit file $F not found in $KitPath. Nothing was changed." } }
    foreach ($F in '0_GPO_pre-flight.ps1', '1_GPO_build_packages.ps1', '2_GPO_create_gpos.ps1', '3_GPO_set_mode.ps1', '4_GPO_validate_gpos.ps1', '5_GPO_validate_endpoint.ps1', 'WDAC-GPO-Common.ps1', 'GPO-Settings.psd1') {
        if (-not (Test-Path -LiteralPath (Join-Path $ScriptsPath $F))) { throw "STOP: $F not found in $ScriptsPath. Nothing was changed." }
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Import-Module GroupPolicy -SkipEditionCheck -WarningAction SilentlyContinue 3>$null
        Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue 3>$null
    }
    else { Import-Module GroupPolicy; Import-Module ConfigCI }
    Import-Module ActiveDirectory -WarningAction SilentlyContinue 3>$null
    . (Join-Path $ScriptsPath 'WDAC-GPO-Common.ps1')
    New-Item -Path $WorkRoot -ItemType Directory -Force | Out-Null
    $WorkRoot = (Resolve-Path -LiteralPath $WorkRoot).ProviderPath
    $Share = '\\localhost\' + $WorkRoot.Substring(0, 1) + '$' + $WorkRoot.Substring(2)
    if (-not (Test-Path -LiteralPath $Share)) { throw "STOP: $Share is not reachable - the simulated SYSVOL needs the administrative share of drive $($WorkRoot.Substring(0, 2))." }
    Start-Transcript -Path (Join-Path $WorkRoot 'Test-WdacGpoPortability.log') | Out-Null
    $Started = $true
    Add-TestResult 'OK' 'Session' "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) on $env:COMPUTERNAME; kit $KitPath; scripts $ScriptsPath; work $WorkRoot"

    # ------------------------------------------------------------ 1. the kit
    $Sums = @{}
    foreach ($Line in Get-Content -LiteralPath (Join-Path $KitPath 'SHA256SUMS.txt')) { if ($Line -match '^([0-9A-Fa-f]{64})\s+(\S.*)$') { $Sums[$Matches[2].Trim()] = $Matches[1].ToUpper() } }
    foreach ($F in $KitFiles) {
        $H = (Get-FileHash -LiteralPath (Join-Path $KitPath $F) -Algorithm SHA256).Hash
        Assert-That ($Sums[$F] -eq $H) "Kit hash $F" $(if ($Sums[$F] -eq $H) { $H } else { "$H - SHA256SUMS.txt says '$($Sums[$F])'" })
    }
    $KitEnforce = Join-Path $KitPath 'Base-Enforce.xml'
    $KitEnforceHash = (Get-FileHash -LiteralPath $KitEnforce -Algorithm SHA256).Hash
    $Guid = (Get-Content -LiteralPath (Join-Path $KitPath 'PolicyGuid.txt') -Raw).Trim()
    Assert-That ($Guid -match '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') 'Kit PolicyGuid.txt' $Guid
    $Docs = @{}
    foreach ($F in 'Base-Audit.xml', 'Base-Audit-Merged.xml', 'Base-Enforce.xml') {
        $X = Join-Path $KitPath $F
        $D = New-Object System.Xml.XmlDocument; $D.Load($X); $Docs[$F] = $D; $S = $D.SiPolicy
        $AuditOn = @($S.Rules.Rule.Option) -contains 'Enabled:Audit Mode'
        Assert-That ($S.PolicyID -ieq $Guid -and $S.BasePolicyID -ieq $Guid -and $S.PolicyType -eq 'Base Policy') "Kit $F identity" "v$($S.VersionEx), PolicyID = BasePolicyID = PolicyGuid.txt, $($S.PolicyType)"
        Assert-That ($AuditOn -eq ($F -ne 'Base-Enforce.xml')) "Kit $F mode" "Audit Mode $(if ($AuditOn) { 'ON' } else { 'OFF' })"
        foreach ($Row in (Get-WdacPortabilityFindings $X)) { Assert-That ($Row.Status -eq 'OK') "Kit $($Row.Check)" $Row.Detail }
        $Cip = Join-Path $WorkRoot ("kit-" + [IO.Path]::GetFileNameWithoutExtension($F) + '.cip')
        ConvertFrom-CIPolicy -XmlFilePath $X -BinaryFilePath $Cip | Out-Null
        $Bytes = [IO.File]::ReadAllBytes($Cip)
        Assert-That ($Bytes.Length -gt 0) "Kit $F compiles" "$($Bytes.Length) bytes"
    }
    $OA = @($Docs['Base-Audit-Merged.xml'].SiPolicy.Rules.Rule.Option); $OE = @($Docs['Base-Enforce.xml'].SiPolicy.Rules.Rule.Option)
    $OnlyA = @($OA | Where-Object { $OE -notcontains $_ }); $OnlyE = @($OE | Where-Object { $OA -notcontains $_ })
    $Ns = New-Object System.Xml.XmlNamespaceManager $Docs['Base-Enforce.xml'].NameTable; $Ns.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')
    $Differ = @('EKUs', 'FileRules', 'Signers', 'SigningScenarios', 'UpdatePolicySigners', 'CiSigners' | Where-Object { $Docs['Base-Audit-Merged.xml'].SelectSingleNode("/s:SiPolicy/s:$_", $Ns).OuterXml -cne $Docs['Base-Enforce.xml'].SelectSingleNode("/s:SiPolicy/s:$_", $Ns).OuterXml })
    Assert-That ($OnlyA.Count -eq 1 -and $OnlyA[0] -eq 'Enabled:Audit Mode' -and $OnlyE.Count -eq 0 -and $Differ.Count -eq 0) 'Kit Audit-Merged = Enforce except Audit Mode' "only in Audit-Merged: $($OnlyA -join ', '); only in Enforce: $(if ($OnlyE) { $OnlyE -join ', ' } else { '(none)' }); rule sections that differ: $(if ($Differ) { $Differ -join ', ' } else { '(none)' })"

    # ------------------------------------------------------------ 2. helpers
    $Dom2 = [pscustomobject]@{ DnsRoot = 'enclave2.example'; DN = 'DC=enclave2,DC=example'; PDC = 'dc01.enclave2.example'; NetBIOS = 'ENCLAVE2' }
    $V = Resolve-WdacTargetOU @{ TargetOU = 'OU=PAWs,DC=enclave2,DC=example' } $Dom2
    Assert-That ($V -eq 'OU=PAWs,DC=enclave2,DC=example') 'OU in its domain accepted' $V
    $V = Resolve-WdacTargetOU @{ TargetOU = 'OU=PAWs, DC=Enclave2, DC=Example' } $Dom2
    Assert-That ($V -eq 'OU=PAWs, DC=Enclave2, DC=Example') 'OU in its domain accepted (case, spaces)' $V
    foreach ($Bad in 'OU=PAWs,DC=enclave3,DC=mil', 'OU=PAWs,DC=xenclave2,DC=example', 'DC=enclave2,DC=example') {
        $Msg = try { [void](Resolve-WdacTargetOU @{ TargetOU = $Bad } $Dom2); '(accepted)' } catch { $_.Exception.Message }
        Assert-That ($Msg -like 'STOP: target OU*is not in domain enclave2.example*') 'OU outside the domain refused' "$Bad -> $Msg"
    }
    $P = Get-WdacGpoPaths '11111111-2222-3333-4444-555555555555' $Dom2
    Assert-That ($P.SysvolDomain -eq '\\enclave2.example\SysVol\enclave2.example\Policies\{11111111-2222-3333-4444-555555555555}' -and $P.SysvolPdc -like '\\dc01.enclave2.example\SYSVOL\enclave2.example\Policies\*' -and $P.AdPath -like '*,CN=Policies,CN=System,DC=enclave2,DC=example') 'GPO paths follow the domain' "$($P.SysvolDomain) | $($P.AdPath)"
    $NegRule = Join-Path $WorkRoot 'negative-user-profile-rule.xml'
    $NegText = Join-Path $WorkRoot 'negative-user-profile-text.xml'
    New-WdacTestXml $KitEnforce $NegRule '%OSDRIVE%\Users\testuser.TESTDOM\AppData\Local\Tool\*' 'portability test rule'
    New-WdacTestXml $KitEnforce $NegText '' 'C:\Users\testuser.TESTDOM\Downloads\tool.exe Hash Sha256'
    $F1 = Get-WdacPortabilityFindings $NegRule
    Assert-That (@($F1 | Where-Object { $_.Status -eq 'FAIL' -and $_.Detail -match 'ID_ALLOW_PORTABILITY_TEST' -and $_.Detail -match "'testuser\.TESTDOM'" -and $_.Detail -match 'Remove-CIPolicyRule' }).Count -eq 1) 'Gate: FilePath rule in a user profile = FAIL' ((@($F1) | ForEach-Object { "[$($_.Status)] $($_.Check)" }) -join '; ')
    $F2 = Get-WdacPortabilityFindings $NegText
    Assert-That (@($F2 | Where-Object { $_.Status -eq 'WARN' }).Count -eq 1 -and @($F2 | Where-Object { $_.Status -eq 'FAIL' }).Count -eq 0) 'Gate: user profile in rule text only = WARN' ((@($F2) | ForEach-Object { "[$($_.Status)] $($_.Check)" }) -join '; ')
    $Folders = @(& $WdacFilePathFolderCheck @('%OSDRIVE%\Program Files\*', (Join-Path $WorkRoot '*'), (Join-Path $WorkRoot 'missing\tool.exe')))
    $PF = $Folders | Where-Object { $_.Folder -eq (Join-Path $env:SystemDrive 'Program Files') }
    Assert-That ($PF -and $PF.Exists -and @($PF.Writers).Count -eq 0) 'Folder check: %OSDRIVE%\Program Files admin-only' "$($PF.Folder) writers: $(if (@($PF.Writers).Count) { @($PF.Writers) -join '; ' } else { '(none)' })"
    $WR = $Folders | Where-Object { $_.Folder -eq $WorkRoot }
    Assert-That ($WR -and $WR.Exists -and @($WR.Writers).Count -gt 0) 'Folder check: user-writable folder reported' "$($WR.Folder) writers: $(@($WR.Writers) -join '; ')"
    $MS = $Folders | Where-Object { $_.Folder -eq (Join-Path $WorkRoot 'missing') }
    Assert-That ($MS -and -not $MS.Exists) 'Folder check: missing folder reported' "$($MS.Folder) exists=$($MS.Exists)"

    # ------------------------------------------------------------ 3. two simulated enclaves
    $Settings = Import-PowerShellDataFile -LiteralPath (Join-Path $ScriptsPath 'GPO-Settings.psd1')
    $RealOU = Get-WdacComputerOU
    $BuildDomain = Get-WdacDomainInfo   # the real domain of this computer, read before the stand-ins exist
    $RealBefore = Get-WdacRealState $RealOU
    Add-TestResult 'OK' 'Real state snapshot (before)' "$($RealBefore.Count) lines: GPOs of the domain, links on $RealOU, App Control policies on $env:COMPUTERNAME"

    # Stand-ins. State lives in $Global:WdacSim (a stand-in called from a script resolves $script: to that script's scope).
    function global:Get-ADDomain { [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server, $Current) $D = $Global:WdacSim.Domain; [pscustomobject]@{ DNSRoot = $D.DnsRoot; DistinguishedName = $D.DN; PDCEmulator = $D.PDC; NetBIOSName = $D.NetBIOS } }
    function global:Get-ADDomainController { [CmdletBinding()] param($Filter, $Server) [pscustomobject]@{ HostName = $Global:WdacSim.Domain.PDC; OperatingSystem = 'Windows Server 2025 Datacenter (simulated)' } }
    function global:Get-ADOrganizationalUnit {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Server)
        if ($Global:WdacSim.OUs -notcontains "$Identity") { throw "Cannot find an object with identity: '$Identity' under: '$($Global:WdacSim.Domain.DN)'." }
        [pscustomobject]@{ Name = ("$Identity" -replace '^OU=((?:\\,|[^,])+),.*$', '$1'); DistinguishedName = "$Identity" }
    }
    function global:Get-ADComputer {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $SearchBase, $Filter, $Properties, $Server)
        # -Identity: this computer's account, which sits in $Global:WdacSim.ComputerOU of the simulated domain
        if ($Identity) { if ("$Identity" -ne $env:COMPUTERNAME) { throw "Cannot find an object with identity: '$Identity' under: '$($Global:WdacSim.Domain.DN)'." }; return [pscustomobject]@{ Name = "$Identity"; DistinguishedName = "CN=$Identity,$($Global:WdacSim.ComputerOU)" } }
        foreach ($N in 'PAW01', 'PAW02') { [pscustomobject]@{ Name = "$($Global:WdacSim.Key.ToUpper())-$N"; OperatingSystem = 'Windows 11 Enterprise'; OperatingSystemVersion = '10.0 (28000)'; DistinguishedName = "CN=$N,$SearchBase" } }
    }
    function global:Get-ADObject {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Properties, $Server)
        $O = $Global:WdacSim.Ad["$Identity"]
        if (-not $O) { throw "Cannot find an object with identity: '$Identity' (simulated domain)." }
        [pscustomobject]@{ DistinguishedName = "$Identity"; versionNumber = $O.versionNumber; gPCMachineExtensionNames = $O.gPCMachineExtensionNames }
    }
    function global:Set-ADObject {
        [CmdletBinding()] param([Parameter(Position = 0)]$Identity, [hashtable]$Replace, $Server)
        $O = $Global:WdacSim.Ad["$Identity"]
        if (-not $O) { throw "Cannot find an object with identity: '$Identity' (simulated domain)." }
        foreach ($K in @($Replace.Keys)) { $O[$K] = $Replace[$K] }
        $Global:WdacSim.Calls.Add("Set-ADObject $Identity $(@($Replace.Keys) -join ',')")
    }
    function global:Get-GPO {
        [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, $Server, [switch]$All, $Domain, $Guid)
        $G = $Global:WdacSim.Gpos[$Name]
        if (-not $G) { Write-Error "GPO '$Name' was not found in the simulated domain $($Global:WdacSim.Domain.DnsRoot)."; return }
        $Ini = Join-Path $Global:WdacSim.SysvolPolicies ('{' + $G.Id.ToString().ToUpper() + '}\GPT.INI')
        $SysV = 0
        if (Test-Path -LiteralPath $Ini) { foreach ($L in Get-Content -LiteralPath $Ini) { if ($L -match '^Version=(\d+)') { $SysV = [int]$Matches[1] } } }
        $G.Computer = [pscustomobject]@{ DSVersion = [int]$Global:WdacSim.Ad[$G.AdPath].versionNumber; SysvolVersion = $SysV }
        return $G
    }
    function global:New-GPO {
        [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, $Server, [string]$Comment)
        $Id = [guid]::NewGuid(); $IdText = '{' + $Id.ToString().ToUpper() + '}'
        $G = [pscustomobject]@{ DisplayName = $Name; Id = $Id; GpoStatus = 'AllSettingsEnabled'; ModificationTime = (Get-Date); WmiFilter = $null; Description = $Comment; Computer = $null; AdPath = "CN=$IdText,CN=Policies,CN=System,$($Global:WdacSim.Domain.DN)" }
        $Global:WdacSim.Gpos[$Name] = $G
        $Global:WdacSim.Ad[$G.AdPath] = @{ versionNumber = 0; gPCMachineExtensionNames = '' }
        $Dir = Join-Path $Global:WdacSim.SysvolPolicies $IdText
        New-Item -Path (Join-Path $Dir 'Machine') -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Dir 'GPT.INI'), "[General]`r`nVersion=0`r`n", [Text.Encoding]::ASCII)
        $Global:WdacSim.Calls.Add("New-GPO '$Name' $IdText")
        return $G
    }
    function global:Set-GPRegistryValue { [CmdletBinding()] param([string]$Name, $Server, [string]$Key, [string]$ValueName, $Type, $Value) $Global:WdacSim.Registry["$Name|$Key|$ValueName"] = $Value; $Global:WdacSim.Calls.Add("Set-GPRegistryValue '$Name' $ValueName=$Value") }
    function global:Get-GPRegistryValue {
        [CmdletBinding()] param([string]$Name, $Server, [string]$Key, [string]$ValueName)
        $K = "$Name|$Key|$ValueName"
        if (-not $Global:WdacSim.Registry.ContainsKey($K)) { throw "$ValueName is not set in '$Name' (simulated domain)." }
        [pscustomobject]@{ Value = $Global:WdacSim.Registry[$K] }
    }
    function global:Get-GPPermission { [CmdletBinding()] param([string]$Name, [switch]$All, $Server) [pscustomobject]@{ Permission = 'GpoApply'; Trustee = [pscustomobject]@{ Name = 'Authenticated Users' } } }
    function global:Get-GPInheritance { [CmdletBinding()] param([Parameter(Position = 0)]$Target, $Server) [pscustomobject]@{ Path = "$Target"; GpoLinks = @($Global:WdacSim.Links | Where-Object { $_.Target -eq "$Target" }) } }
    function global:New-GPLink {
        [CmdletBinding()] param([string]$Name, $Target, $LinkEnabled, $Server)
        if ($Global:WdacSim.OUs -notcontains "$Target") { throw "OU '$Target' does not exist in the simulated domain." }
        $Global:WdacSim.Links.Add([pscustomobject]@{ DisplayName = $Name; Target = "$Target"; Enabled = ("$LinkEnabled" -eq 'Yes'); Enforced = $false; Order = $Global:WdacSim.Links.Count + 1 })
        $Global:WdacSim.Calls.Add("New-GPLink '$Name' -> $Target enabled=$LinkEnabled")
    }
    function global:Set-GPLink {
        [CmdletBinding()] param([string]$Name, $Target, $LinkEnabled, $Server)
        $L = @($Global:WdacSim.Links | Where-Object { $_.DisplayName -eq $Name -and $_.Target -eq "$Target" })
        if (-not $L) { throw "'$Name' is not linked to '$Target' (simulated domain)." }
        $L[0].Enabled = ("$LinkEnabled" -eq 'Yes')
        $Global:WdacSim.Calls.Add("Set-GPLink '$Name' -> $Target enabled=$LinkEnabled")
    }
    # Never called by steps 0 - 5; a call would be a regression, so it fails loudly instead of reaching the real domain
    function global:New-ADObject { throw 'New-ADObject is not expected in this flow (simulated domain).' }
    function global:Remove-ADObject { throw 'Remove-ADObject is not expected in this flow (simulated domain).' }
    function global:Remove-GPO { throw 'Remove-GPO is not expected in this flow (simulated domain).' }
    function global:Set-GPPermission { throw 'Set-GPPermission is not expected in this flow (simulated domain).' }
    function global:Remove-GPLink { throw 'Remove-GPLink is not expected in this flow (simulated domain).' }
    function global:Invoke-GPUpdate { throw 'Invoke-GPUpdate is not expected in this flow (simulated domain).' }
    function global:Get-CimInstance {
        [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName, [string]$Namespace = 'root\cimv2', $ComputerName)
        if ($ClassName -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ Name = $env:COMPUTERNAME; PartOfDomain = $true; Domain = $Global:WdacSim.Domain.DnsRoot } }
        CimCmdlets\Get-CimInstance -ClassName $ClassName -Namespace $Namespace
    }
    function global:Read-Host { [CmdletBinding()] param([Parameter(Position = 0)]$Prompt) 'n' }
    foreach ($N in $Guarded) {
        $C = Get-Command -Name $N -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $C -or $C.CommandType -ne 'Function' -or $C.Module) { throw "STOP: $N resolves to $($C.CommandType) $($C.Source), not to the test stand-in - refusing to run the GPO scripts. Nothing was changed." }
    }
    Add-TestResult 'OK' 'Stand-ins in place' "$($Guarded.Count) AD / Group Policy / identity commands resolve to in-memory stand-ins"

    # enclave2: TargetOU empty, this computer's account sits in the PAW OU (auto-detected). enclave3: TargetOU set in the settings
    # file, this computer's account sits in ANOTHER OU (the setting wins).
    $Enclaves = @(
        [pscustomobject]@{ Key = 'enclave2'; DnsRoot = 'enclave2.example'; NetBIOS = 'ENCLAVE2'; DN = 'DC=enclave2,DC=example'; OU = 'OU=PAW Workstations,DC=enclave2,DC=example'
                           SettingsOU = ''; ComputerOU = 'OU=PAW Workstations,DC=enclave2,DC=example'; From = 'auto-detected: OU of this computer' },
        [pscustomobject]@{ Key = 'enclave3'; DnsRoot = 'ops.enclave3.mil'; NetBIOS = 'ENC3OPS'; DN = 'DC=ops,DC=enclave3,DC=mil'; OU = 'OU=Tier0,OU=PAWs,OU=Admin,DC=ops,DC=enclave3,DC=mil'
                           SettingsOU = 'OU=Tier0,OU=PAWs,OU=Admin,DC=ops,DC=enclave3,DC=mil'; ComputerOU = 'OU=Build Servers,DC=ops,DC=enclave3,DC=mil'; From = 'TargetOU in GPO-Settings.psd1' }
    )
    $Q = { param($Value) "'" + ("$Value" -replace "'", "''") + "'" }
    $Built = @{}
    foreach ($E in $Enclaves) {
        $K = $E.Key
        $Other = $Enclaves | Where-Object { $_.Key -ne $K } | Select-Object -First 1
        $Root = Join-Path $WorkRoot $K
        $Src = Join-Path $Root 'WDAC\Source'; $GpoRoot = Join-Path $Root 'GPO'; $Scr = Join-Path $Root 'scripts'
        New-Item -Path $Src, $GpoRoot, $Scr -ItemType Directory -Force | Out-Null
        foreach ($F in $KitFiles) { Copy-Item -LiteralPath (Join-Path $KitPath $F) -Destination $Src -Force }
        Get-ChildItem -LiteralPath $ScriptsPath -File | Copy-Item -Destination $Scr -Force
        @(
            '@{'
            "    TargetOU          = $(& $Q $E.SettingsOU)"
            "    AuditGpoName      = $(& $Q $Settings['AuditGpoName'])"
            "    EnforceGpoName    = $(& $Q $Settings['EnforceGpoName'])"
            "    PolicyNamePrefix  = $(& $Q $Settings['PolicyNamePrefix'])"
            "    TaskIntervalHours = $([int]$Settings['TaskIntervalHours'])"
            "    WdacRoot          = $(& $Q (Join-Path $Root 'WDAC'))"
            "    GpoRoot           = $(& $Q $GpoRoot)"
            '}'
        ) | Set-Content -LiteralPath (Join-Path $Scr 'GPO-Settings.psd1') -Encoding ASCII
        $Policies = Join-Path $Share "$K\dc\SYSVOL\$($E.DnsRoot)\Policies"
        New-Item -Path $Policies -ItemType Directory -Force | Out-Null
        $Global:WdacSim = @{
            Key = $K; OUs = @($E.OU, $E.ComputerOU | Select-Object -Unique); ComputerOU = $E.ComputerOU; SysvolPolicies = $Policies; GpoRoot = $GpoRoot
            Domain = [pscustomobject]@{ DnsRoot = $E.DnsRoot; DN = $E.DN; NetBIOS = $E.NetBIOS; PDC = (Join-Path $Share "$K\dc").Substring(2) }
            Gpos = @{}; Ad = @{}; Registry = @{}
            Links = New-Object System.Collections.Generic.List[object]; Calls = New-Object System.Collections.Generic.List[string]
        }
        Add-TestResult 'OK' "$K setup" "domain $($E.DnsRoot) ($($E.NetBIOS)), target OU $($E.OU), settings TargetOU '$($E.SettingsOU)', this computer's account in $($E.ComputerOU), kit copied to $Src"

        # step 0: pre-flight in this domain, then with the OTHER enclave's OU
        $S0 = Invoke-WdacStep (Join-Path $Scr '0_GPO_pre-flight.ps1')
        Assert-That ($S0.ExitCode -eq 0 -and -not (Format-Fails $S0)) "$K step 0 pre-flight" "exit $($S0.ExitCode); $(@($S0.Rows).Count) rows, $(@($S0.Rows | Where-Object { $_.Status -eq 'WARN' }).Count) WARN$(if (Format-Fails $S0) { '; FAIL: ' + (Format-Fails $S0) })"
        $Row = $S0.Rows | Where-Object { $_.Check -eq 'Domain' } | Select-Object -First 1
        Assert-That ("$($Row.Detail)" -like "$($E.DnsRoot) ($($E.NetBIOS))*") "$K step 0 domain read from AD" "$($Row.Detail)"
        $Row = $S0.Rows | Where-Object { $_.Check -eq 'Target OU' } | Select-Object -First 1
        Assert-That ($Row.Status -eq 'OK' -and "$($Row.Detail)" -like "* - $($E.OU) (from $($E.From)*") "$K step 0 target OU ($($E.From))" "$($Row.Detail)"
        $Row = $S0.Rows | Where-Object { $_.Check -eq 'Base-Enforce.xml portability' } | Select-Object -First 1
        Assert-That ($Row.Status -eq 'OK') "$K step 0 portability gate" "$($Row.Detail)"
        $Row = $S0.Rows | Where-Object { $_.Check -eq 'This device FilePath folders' } | Select-Object -First 1
        Assert-That ([bool]$Row) "$K step 0 FilePath folder check ran" "[$($Row.Status)] $($Row.Detail)"
        if ($K -eq $Enclaves[0].Key) { foreach ($W in @($S0.Rows | Where-Object { $_.Status -eq 'WARN' })) { Add-TestResult 'INFO' "$K step 0 warning" "$($W.Check): $($W.Detail)" } }
        $SN = Invoke-WdacStep (Join-Path $Scr '0_GPO_pre-flight.ps1') @{ TargetOU = $Other.OU }
        $Row = $SN.Rows | Where-Object { $_.Check -eq 'Target OU' } | Select-Object -First 1
        Assert-That ($SN.ExitCode -eq 1 -and $Row.Status -eq 'FAIL' -and "$($Row.Detail)" -like '*is not in domain*') "$K step 0 refuses the OU of $($Other.Key)" "exit $($SN.ExitCode): $($Row.Detail)"
        # -TargetOU typed without quotes reaches the script split at its commas; a container cannot hold GPO links
        $SU = Invoke-WdacStep (Join-Path $Scr '0_GPO_pre-flight.ps1') @{ TargetOU = [string[]]@($E.OU -split ',') }
        $Row = $SU.Rows | Where-Object { $_.Check -eq 'Target OU' } | Select-Object -First 1
        Assert-That ($Row.Status -eq 'OK' -and "$($Row.Detail)" -like "* - $($E.OU) (from -TargetOU parameter)") "$K step 0 -TargetOU without quotes" "$(@($E.OU -split ',').Count) pieces -> $($Row.Detail)"
        $SC = Invoke-WdacStep (Join-Path $Scr '0_GPO_pre-flight.ps1') @{ TargetOU = "CN=Computers,$($E.DN)" }
        $Row = $SC.Rows | Where-Object { $_.Check -eq 'Target OU' } | Select-Object -First 1
        Assert-That ($SC.ExitCode -eq 1 -and $Row.Status -eq 'FAIL' -and "$($Row.Detail)" -like '*is not an organizational unit*') "$K step 0 refuses a container" "exit $($SC.ExitCode): $($Row.Detail)"

        # step 1: build from the kit, then refuse a policy with a user-profile rule
        $S1 = Invoke-WdacStep (Join-Path $Scr '1_GPO_build_packages.ps1')
        Assert-That ($S1.ExitCode -eq 0 -and -not (Format-Fails $S1)) "$K step 1 build" "exit $($S1.ExitCode)$(if (Format-Fails $S1) { '; FAIL: ' + (Format-Fails $S1) })"
        $Pkg = (Get-Content -LiteralPath (Join-Path $GpoRoot 'Packages\latest.txt') -Raw).Trim()
        $MA = Read-WdacManifest (Join-Path $Pkg 'Audit'); $ME = Read-WdacManifest (Join-Path $Pkg 'Enforce')
        $VA = ($MA.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).Version; $VE = ($ME.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).Version
        Assert-That ($MA.SourceXmlSha256 -eq $KitEnforceHash -and $ME.SourceXmlSha256 -eq $KitEnforceHash -and [version]$VE -gt [version]$VA) "$K step 1 packages built from the kit" "Audit v$VA / Enforce v$VE, source SHA-256 $($ME.SourceXmlSha256)"
        $WantRules = (Get-WdacFilePathRules $KitEnforce) -join '|'
        Assert-That ((@($ME.FilePathRules) -join '|') -eq $WantRules -and (@($MA.FilePathRules) -join '|') -eq $WantRules) "$K step 1 manifest FilePathRules" "$(@($ME.FilePathRules).Count) FilePath rule(s) recorded"
        $Built[$K] = [pscustomobject]@{ Pkg = $Pkg; VA = $VA; VE = $VE }
        $Before = @(Get-ChildItem -LiteralPath (Join-Path $GpoRoot 'Packages') -Directory | ForEach-Object { $_.Name })
        $SB = Invoke-WdacStep (Join-Path $Scr '1_GPO_build_packages.ps1') @{ EnforceXml = $NegRule }
        $New = @(Get-ChildItem -LiteralPath (Join-Path $GpoRoot 'Packages') -Directory | Where-Object { $Before -notcontains $_.Name })
        $NewCip = @($New | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Recurse -Filter '*.cip' -File })
        $Gate = $SB.Rows | Where-Object { $_.Check -like '*user-profile rules' } | Select-Object -First 1
        $Latest = (Get-Content -LiteralPath (Join-Path $GpoRoot 'Packages\latest.txt') -Raw).Trim()
        Assert-That ($SB.ExitCode -eq 1 -and $Gate.Status -eq 'FAIL' -and $NewCip.Count -eq 0 -and $Latest -eq $Pkg) "$K step 1 refuses a user-profile rule" "exit $($SB.ExitCode), $($NewCip.Count) .cip compiled, latest.txt unchanged=$($Latest -eq $Pkg): $($Gate.Detail)"

        # step 2: refused without confirmation (Read-Host answers N / non-interactive), then published with -NoConfirm
        $S2N = Invoke-WdacStep (Join-Path $Scr '2_GPO_create_gpos.ps1')
        Assert-That ($S2N.ExitCode -eq 1 -and $Global:WdacSim.Gpos.Count -eq 0 -and $Global:WdacSim.Links.Count -eq 0 -and $Global:WdacSim.Calls.Count -eq 0) "$K step 2 without confirmation changes nothing" "exit $($S2N.ExitCode), GPOs $($Global:WdacSim.Gpos.Count), links $($Global:WdacSim.Links.Count): $(Format-Fails $S2N)"
        $S2 = Invoke-WdacStep (Join-Path $Scr '2_GPO_create_gpos.ps1') @{ NoConfirm = $true }
        Assert-That ($S2.ExitCode -eq 0 -and -not (Format-Fails $S2)) "$K step 2 publish" "exit $($S2.ExitCode); $($Global:WdacSim.Calls.Count) simulated AD/GPO change(s)$(if (Format-Fails $S2) { '; FAIL: ' + (Format-Fails $S2) })"
        $Row = $S2.Rows | Where-Object { $_.Check -eq 'Inputs' } | Select-Object -First 1
        Assert-That ("$($Row.Detail)" -like "*| OU $($E.OU) ($($E.From)*") "$K step 2 target OU ($($E.From))" "$($Row.Detail)"
        $Me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        foreach ($Mode in 'Audit', 'Enforce') {
            $Name = $Settings["${Mode}GpoName"]
            $G = $Global:WdacSim.Gpos[$Name]
            if (-not $G) { Assert-That $false "$K step 2 $Mode GPO" "'$Name' was not created"; continue }
            $Id = '{' + $G.Id.ToString().ToUpper() + '}'
            $Dir = Join-Path $Global:WdacSim.SysvolPolicies $Id
            $Unc = "\\$($E.DnsRoot)\SysVol\$($E.DnsRoot)\Policies\$Id\Machine\Scripts\Startup\WDAC\Deploy-WDACPolicy.ps1"
            $Ini = [IO.File]::ReadAllText((Join-Path $Dir 'Machine\Scripts\scripts.ini'))
            $T = New-Object System.Xml.XmlDocument; $T.Load((Join-Path $Dir 'Machine\Preferences\ScheduledTasks\ScheduledTasks.xml'))
            $Task = $T.ScheduledTasks.TaskV2.Properties.Task
            $Want = "-File `"$Unc`" -Mode $Mode -NoConfirm"
            Assert-That ($Ini.Contains($Want) -and "$($Task.Actions.Exec.Arguments)".Contains($Want)) "$K step 2 $Mode startup script + task" $Unc
            $L = @($Global:WdacSim.Links | Where-Object { $_.DisplayName -eq $Name })
            Assert-That ($L.Count -eq 1 -and $L[0].Target -eq $E.OU -and -not $L[0].Enabled) "$K step 2 $Mode link" "'$Name' -> $($L[0].Target) enabled=$($L[0].Enabled)"
            $PM = Read-WdacManifest (Join-Path $Dir 'Machine\Scripts\Startup\WDAC')
            $HashOk = @($PM.Policies | Where-Object { (Get-FileHash -LiteralPath (Join-Path $Dir "Machine\Scripts\Startup\WDAC\$($_.File)") -Algorithm SHA256).Hash -ne $_.Sha256 }).Count -eq 0
            Assert-That ($HashOk -and $PM.SourceXmlSha256 -eq $KitEnforceHash -and $PM.Mode -eq $Mode) "$K step 2 $Mode payload" "manifest $Mode, hashes match, source = kit Base-Enforce.xml"
            # What the endpoints of THIS domain read: only this domain's names - nothing from the real domain this test runs in,
            # the operator's profile, or the other enclave. BuiltBy / BuiltOn / SourceXml and the task Author record the operator and
            # build path - expected, not a dependency.
            $Json = $PM | Select-Object -Property * -ExcludeProperty BuiltBy, BuiltOn, SourceXml | ConvertTo-Json -Depth 6
            $Cips = (@($PM.Policies) | ForEach-Object { $B = [IO.File]::ReadAllBytes((Join-Path $Dir "Machine\Scripts\Startup\WDAC\$($_.File)")); [Text.Encoding]::Unicode.GetString($B) + [Text.Encoding]::ASCII.GetString($B) }) -join ''
            $Text = $Ini + "$($Task.Actions.Exec.Arguments)" + "$($Task.RegistrationInfo.Description)" + $Json + $Cips
            $Names = @([regex]::Escape($BuildDomain.DnsRoot), ('(?<![A-Za-z0-9])' + [regex]::Escape($BuildDomain.NetBIOS) + '(?![A-Za-z0-9])'), [regex]::Escape("\Users\$env:USERNAME"), [regex]::Escape($Other.DnsRoot), [regex]::Escape($Other.DN))
            $Leak = @($Names | Where-Object { $Text -match "(?i)$_" })
            Assert-That ($Leak.Count -eq 0) "$K step 2 $Mode only this domain's names" $(if ($Leak) { "found: $($Leak -join ', ')" } else { "SYSVOL payload, startup script, task and .cip name $($E.DnsRoot) only - not $($BuildDomain.DnsRoot), its NetBIOS name, the operator's profile or $($Other.DnsRoot)" })
            Assert-That ($PM.BuiltBy -eq $Me -and $Task.RegistrationInfo.Author -eq $Me) "$K step 2 $Mode operator recorded" "BuiltBy / task Author = $Me (whoever runs the build in that enclave)"
        }

        # steps 4 and 3: validate, then Audit -> Enforce, validating after each switch
        $S4 = Invoke-WdacStep (Join-Path $Scr '4_GPO_validate_gpos.ps1')
        $Row = $S4.Rows | Where-Object { $_.Check -eq 'Active mode for the OU' } | Select-Object -First 1
        Assert-That ($S4.ExitCode -eq 0 -and -not (Format-Fails $S4) -and $Row.Detail -eq 'None') "$K step 4 validate (links disabled)" "exit $($S4.ExitCode), active mode $($Row.Detail)$(if (Format-Fails $S4) { '; FAIL: ' + (Format-Fails $S4) })"
        foreach ($Mode in 'Audit', 'Enforce') {
            $S3 = Invoke-WdacStep (Join-Path $Scr '3_GPO_set_mode.ps1') @{ Mode = $Mode; NoConfirm = $true }
            $On = @($Global:WdacSim.Links | Where-Object { $_.Enabled } | ForEach-Object { $_.DisplayName })
            Assert-That ($S3.ExitCode -eq 0 -and $On.Count -eq 1 -and $On[0] -eq $Settings["${Mode}GpoName"]) "$K step 3 mode $Mode" "exit $($S3.ExitCode), enabled link: $($On -join ', ')$(if (Format-Fails $S3) { '; FAIL: ' + (Format-Fails $S3) })"
            $S4 = Invoke-WdacStep (Join-Path $Scr '4_GPO_validate_gpos.ps1')
            $Row = $S4.Rows | Where-Object { $_.Check -eq 'Active mode for the OU' } | Select-Object -First 1
            Assert-That ($S4.ExitCode -eq 0 -and $Row.Detail -eq $Mode) "$K step 4 validate ($Mode)" "exit $($S4.ExitCode), active mode $($Row.Detail)$(if (Format-Fails $S4) { '; FAIL: ' + (Format-Fails $S4) })"
        }

        # step 5 (first enclave): the new FilePath rows, from the published manifest, probed on this computer. Its other checks
        # FAIL by design here - nothing was deployed from a simulated domain - so only the new rows are asserted.
        if ($K -eq $Enclaves[0].Key) {
            $S5 = Invoke-WdacStep (Join-Path $Scr '5_GPO_validate_endpoint.ps1') @{ ExpectedMode = 'Enforce' }
            $Sum = $S5.Rows | Where-Object { $_.Check -eq "$env:COMPUTERNAME FilePath folders" } | Select-Object -First 1
            Assert-That ([bool]$Sum) "$K step 5 FilePath folder rows" "[$($Sum.Status)] $($Sum.Detail)"
            foreach ($W in @($S5.Rows | Where-Object { $_.Check -eq "$env:COMPUTERNAME FilePath folder" })) { Add-TestResult 'INFO' "$K step 5 FilePath folder" $W.Detail }
        }
    }

    # ------------------------------------------------------------ cross-enclave: the same policy everywhere
    $A = $Built[$Enclaves[0].Key]; $B = $Built[$Enclaves[1].Key]
    foreach ($Mode in 'Audit', 'Enforce') {
        $XA = Get-ChildItem -LiteralPath (Join-Path $A.Pkg 'xml') -Filter "$($Settings['PolicyNamePrefix'])-${Mode}_v*.xml" | Select-Object -First 1
        $XB = Get-ChildItem -LiteralPath (Join-Path $B.Pkg 'xml') -Filter "$($Settings['PolicyNamePrefix'])-${Mode}_v*.xml" | Select-Object -First 1
        $DA = New-Object System.Xml.XmlDocument; $DA.Load($XA.FullName); $DB = New-Object System.Xml.XmlDocument; $DB.Load($XB.FullName)
        $N2 = New-Object System.Xml.XmlNamespaceManager $DA.NameTable; $N2.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')
        $Diff = @('Rules', 'EKUs', 'FileRules', 'Signers', 'SigningScenarios', 'UpdatePolicySigners', 'CiSigners' | Where-Object { $DA.SelectSingleNode("/s:SiPolicy/s:$_", $N2).OuterXml -cne $DB.SelectSingleNode("/s:SiPolicy/s:$_", $N2).OuterXml })
        Assert-That ($Diff.Count -eq 0 -and $DA.SiPolicy.PolicyID -eq $DB.SiPolicy.PolicyID) "Both enclaves: identical $Mode policy" "same GUID $($DA.SiPolicy.PolicyID), options and rules; $($Enclaves[0].Key) v$($DA.SiPolicy.VersionEx), $($Enclaves[1].Key) v$($DB.SiPolicy.VersionEx)$(if ($Diff) { '; differ: ' + ($Diff -join ', ') })"
        $HA = (Get-FileHash -LiteralPath (Join-Path $A.Pkg "$Mode\$Guid.cip") -Algorithm SHA256).Hash; $HB = (Get-FileHash -LiteralPath (Join-Path $B.Pkg "$Mode\$Guid.cip") -Algorithm SHA256).Hash
        if ($DA.SiPolicy.VersionEx -eq $DB.SiPolicy.VersionEx) { Add-TestResult $(if ($HA -eq $HB) { 'OK' } else { 'WARN' }) "Both enclaves: $Mode .cip" $(if ($HA -eq $HB) { "byte-identical (same version): SHA-256 $HA" } else { "same version but different binaries: $HA / $HB" }) }
    }

    # ------------------------------------------------------------ the real domain and this computer are unchanged
    $RealAfter = Get-WdacRealState $RealOU
    $Changed = @(Compare-Object -ReferenceObject $RealBefore -DifferenceObject $RealAfter | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
    Assert-That ($Changed.Count -eq 0) 'Real state unchanged' $(if ($Changed.Count) { $Changed -join ' | ' } else { "$($RealAfter.Count) lines identical before and after: GPOs, links on $RealOU, App Control policies" })
}
catch { Add-TestResult 'FAIL' 'Stopped' $_.Exception.Message }
finally {
    foreach ($N in $Guarded) { if (Test-Path -LiteralPath "Function:\$N") { Remove-Item -LiteralPath "Function:\$N" -Force -ErrorAction SilentlyContinue } }
    $Left = @($Guarded | Where-Object { $C = Get-Command -Name $_ -ErrorAction SilentlyContinue | Select-Object -First 1; $C -and $C.CommandType -eq 'Function' -and -not $C.Module })
    if ($Left.Count) { Add-TestResult 'WARN' 'Stand-ins removed' "still defined in this session: $($Left -join ', ') - close this PowerShell window" }
    Remove-Variable -Name WdacSim -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $WorkRoot) {
        $Csv = Join-Path $WorkRoot 'Test-WdacGpoPortability.csv'
        $Results | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
    }
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $Fail = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count; $Warn = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($Fail) { Write-Host "Portability test: FAILED - $Fail fail, $Warn warning(s). Results: $Csv" -ForegroundColor Red }
    elseif ($Warn) { Write-Host "Portability test: PASSED with $Warn warning(s). Results: $Csv" -ForegroundColor Yellow }
    else { Write-Host "Portability test: PASSED. Results: $Csv" -ForegroundColor Green }
    if ($Started) { try { Stop-Transcript | Out-Null } catch { } }
}
if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count) { exit 1 }
