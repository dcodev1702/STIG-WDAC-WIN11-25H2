# Step 1 - run on the fully configured WDAC REFERENCE device (elevated, Windows PowerShell 5.1 or PowerShell 7).
# Builds the two GPO payloads from the reference device's ENFORCED policy XML (C:\WDAC\Source\Base-Enforce.xml):
#   Audit\   = the same rules + Enabled:Audit Mode, version N
#   Enforce\ = the same rules, Audit Mode OFF,       version N+1   (higher, so Audit -> Enforce replaces in place)
# Each folder gets {PolicyGUID}.cip, manifest.json (GUID, version, SHA-256, mode) and Deploy-WDACPolicy.ps1.
# Nothing is deployed and no GPO is touched.
param(
    [string]$EnforceXml,
    [string]$AuditVersion,
    [string]$EnforceVersion,
    # Optional supplemental policy XMLs to ship UNCHANGED in both packages (must supplement the same base policy)
    [string[]]$SupplementalXml = @()
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '1_GPO_build_packages'
$R = New-WdacResults
$Failed = 1
try {
    Import-WdacModule ConfigCI
    if (-not $EnforceXml) { $EnforceXml = Join-Path $Cfg.WdacRoot 'Source\Base-Enforce.xml' }
    $GuidFile = Join-Path $Cfg.WdacRoot 'Source\PolicyGuid.txt'
    foreach ($F in $EnforceXml, $GuidFile) { if (-not (Test-Path -LiteralPath $F)) { throw "STOP: $F not found. Finish C:\WDAC\config\README.md on this device first." } }
    $Guid = (Get-Content -LiteralPath $GuidFile -Raw).Trim()

    # ---------------------------------------------------------------- versions: higher than anything seen so far for this GUID
    if (-not $AuditVersion) {
        $Seen = New-Object System.Collections.Generic.List[version]
        $Src = New-Object System.Xml.XmlDocument; $Src.Load($EnforceXml); $Seen.Add([version]$Src.SiPolicy.VersionEx)
        $Act = @((& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies) | Where-Object { $_.PolicyID -ieq $Guid.Trim('{}') }
        foreach ($A in $Act) { $Seen.Add([version]$A.VersionString) }
        foreach ($M in @(Get-ChildItem -Path $Cfg.PackageRoot -Filter 'manifest.json' -Recurse -File -ErrorAction SilentlyContinue)) {
            foreach ($P in @((Get-Content -LiteralPath $M.FullName -Raw | ConvertFrom-Json).Policies | Where-Object { $_.PolicyGuid -ieq $Guid })) { $Seen.Add([version]$P.Version) }
        }
        $Max = ($Seen | Sort-Object | Select-Object -Last 1)
        if ($Max.Revision + 2 -gt 65535) { throw "STOP: the revision of v$Max is too high to auto-increment; pass -AuditVersion and -EnforceVersion." }
        $AuditVersion = "$($Max.Major).$($Max.Minor).$($Max.Build).$($Max.Revision + 1)"
        Add-WdacResult $R 'OK' 'Version source' "highest version seen for $Guid (XML, active, earlier packages): v$Max"
    }
    if (-not $EnforceVersion) { $V = [version]$AuditVersion; $EnforceVersion = "$($V.Major).$($V.Minor).$($V.Build).$($V.Revision + 1)" }
    if ([version]$EnforceVersion -le [version]$AuditVersion) { throw "STOP: EnforceVersion ($EnforceVersion) must be higher than AuditVersion ($AuditVersion)." }

    # ---------------------------------------------------------------- build both XMLs from the enforced source
    $Pkg = Join-Path $Cfg.PackageRoot $Cfg.Stamp
    $Work = Join-Path $Pkg 'xml'
    New-Item -Path $Work, (Join-Path $Pkg 'Audit'), (Join-Path $Pkg 'Enforce') -ItemType Directory -Force | Out-Null
    $Xml = @{ Audit = (Join-Path $Work 'GPO-Audit.xml'); Enforce = (Join-Path $Work 'GPO-Enforce.xml') }
    $Ver = @{ Audit = $AuditVersion; Enforce = $EnforceVersion }
    foreach ($Mode in 'Audit', 'Enforce') {
        Copy-Item -LiteralPath $EnforceXml -Destination $Xml[$Mode] -Force
        if ($Mode -eq 'Audit') { Set-RuleOption -FilePath $Xml[$Mode] -Option 3 -ErrorAction Stop } else { Set-RuleOption -FilePath $Xml[$Mode] -Option 3 -Delete -ErrorAction Stop }
        Set-CIPolicyIdInfo -FilePath $Xml[$Mode] -PolicyName "$($Cfg.PolicyNamePrefix)-$Mode" -PolicyId "GPO-$($Mode.ToUpper())-$($Ver[$Mode])" -ErrorAction Stop | Out-Null
        Set-CIPolicyVersion -FilePath $Xml[$Mode] -Version $Ver[$Mode] -ErrorAction Stop
    }

    # ---------------------------------------------------------------- gate: same GUID, only Audit Mode differs, identical rules
    $D = @{}
    foreach ($Mode in 'Audit', 'Enforce') { $D[$Mode] = New-Object System.Xml.XmlDocument; $D[$Mode].Load($Xml[$Mode]) }
    foreach ($Mode in 'Audit', 'Enforce') {
        $S = $D[$Mode].SiPolicy
        $Ok = ($S.PolicyID -ieq $Guid -and $S.BasePolicyID -ieq $Guid -and $S.PolicyType -eq 'Base Policy')
        Add-WdacResult $R $(if ($Ok) { 'OK' } else { 'FAIL' }) "$Mode GUID" "$($S.PolicyID) / base $($S.BasePolicyID) / $($S.PolicyType) / v$($S.VersionEx)"
    }
    $OA = @($D.Audit.SiPolicy.Rules.Rule.Option); $OE = @($D.Enforce.SiPolicy.Rules.Rule.Option)
    $OnlyInAudit = @($OA | Where-Object { $OE -notcontains $_ }); $OnlyInEnforce = @($OE | Where-Object { $OA -notcontains $_ })
    $OptOk = ($OnlyInAudit.Count -eq 1 -and $OnlyInAudit[0] -eq 'Enabled:Audit Mode' -and $OnlyInEnforce.Count -eq 0)
    Add-WdacResult $R $(if ($OptOk) { 'OK' } else { 'FAIL' }) 'Options differ only by Audit Mode' "only in Audit: $($OnlyInAudit -join ', '); only in Enforce: $(if ($OnlyInEnforce) { $OnlyInEnforce -join ', ' } else { '(none)' })"
    Add-WdacResult $R 'OK' 'Enforce options' (($OE | Sort-Object) -join ', ')
    $Ns = New-Object System.Xml.XmlNamespaceManager $D.Audit.NameTable; $Ns.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')
    foreach ($Node in 'EKUs', 'FileRules', 'Signers', 'SigningScenarios', 'UpdatePolicySigners', 'CiSigners') {
        $A = $D.Audit.SelectSingleNode("/s:SiPolicy/s:$Node", $Ns); $E = $D.Enforce.SelectSingleNode("/s:SiPolicy/s:$Node", $Ns)
        $Same = ("$($A.OuterXml)" -ceq "$($E.OuterXml)")
        Add-WdacResult $R $(if ($Same) { 'OK' } else { 'FAIL' }) "Identical <$Node>" $(if ($Same) { "$(@($A.ChildNodes).Count) child node(s)" } else { 'the two packages differ' })
    }
    $Counts = $D.Enforce.SiPolicy
    Add-WdacResult $R 'OK' 'Rule counts' "signers $(@($Counts.Signers.Signer | Where-Object { $_ }).Count), allow $(@($Counts.FileRules.Allow | Where-Object { $_ }).Count), deny $(@($Counts.FileRules.Deny | Where-Object { $_ }).Count), fileattrib $(@($Counts.FileRules.FileAttrib | Where-Object { $_ }).Count)"
    if (@($R | Where-Object { $_.Status -eq 'FAIL' }).Count) { throw 'STOP: the package gate failed (see the table above). Nothing was compiled.' }

    # ---------------------------------------------------------------- optional supplementals (shipped unchanged)
    $Supps = @()
    foreach ($SX in $SupplementalXml) {
        $SD = New-Object System.Xml.XmlDocument; $SD.Load($SX)
        if ($SD.SiPolicy.PolicyType -ne 'Supplemental Policy' -or $SD.SiPolicy.BasePolicyID -ine $Guid) { throw "STOP: $SX is not a supplemental policy of $Guid." }
        $Supps += [pscustomobject]@{ Xml = $SX; Guid = $SD.SiPolicy.PolicyID; Version = $SD.SiPolicy.VersionEx; Name = ($SD.SiPolicy.Settings.Setting | Where-Object { $_.ValueName -eq 'Name' }).Value.String }
    }

    # ---------------------------------------------------------------- compile and write manifests
    $SrcHash = (Get-FileHash -LiteralPath $EnforceXml -Algorithm SHA256).Hash
    foreach ($Mode in 'Audit', 'Enforce') {
        $Out = Join-Path $Pkg $Mode
        $Cip = Join-Path $Out "$Guid.cip"
        ConvertFrom-CIPolicy -XmlFilePath $Xml[$Mode] -BinaryFilePath $Cip -ErrorAction Stop | Out-Null
        $Policies = @([pscustomobject]@{ Type = 'Base'; PolicyGuid = $Guid; Version = $Ver[$Mode]; Name = "$($Cfg.PolicyNamePrefix)-$Mode"; File = "$Guid.cip"; Sha256 = (Get-FileHash -LiteralPath $Cip -Algorithm SHA256).Hash; Bytes = (Get-Item -LiteralPath $Cip).Length })
        foreach ($Sp in $Supps) {
            $SCip = Join-Path $Out "$($Sp.Guid).cip"
            ConvertFrom-CIPolicy -XmlFilePath $Sp.Xml -BinaryFilePath $SCip -ErrorAction Stop | Out-Null
            $Policies += [pscustomobject]@{ Type = 'Supplemental'; PolicyGuid = $Sp.Guid; Version = $Sp.Version; Name = $Sp.Name; File = "$($Sp.Guid).cip"; Sha256 = (Get-FileHash -LiteralPath $SCip -Algorithm SHA256).Hash; Bytes = (Get-Item -LiteralPath $SCip).Length }
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Deploy-WDACPolicy.ps1') -Destination $Out -Force
        [pscustomobject]@{
            Mode = $Mode; BuiltAt = (Get-Date).ToString('o'); BuiltOn = $env:COMPUTERNAME; BuiltBy = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            SourceXml = $EnforceXml; SourceXmlSha256 = $SrcHash; DeployScriptSha256 = (Get-FileHash -LiteralPath (Join-Path $Out 'Deploy-WDACPolicy.ps1') -Algorithm SHA256).Hash
            Policies = $Policies
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Out 'manifest.json') -Encoding UTF8
        foreach ($P in $Policies) { Add-WdacResult $R 'OK' "$Mode package" "$($P.Type) $($P.Name) v$($P.Version) - $($P.File) $($P.Bytes) bytes SHA-256 $($P.Sha256)" }
    }
    Set-Content -LiteralPath (Join-Path $Cfg.PackageRoot 'latest.txt') -Value $Pkg -Encoding Ascii
    Add-WdacResult $R 'OK' 'Package folder' "$Pkg (recorded in $(Join-Path $Cfg.PackageRoot 'latest.txt'))"
    $Failed = 0
}
catch { Add-WdacResult $R 'FAIL' 'Build' $_.Exception.Message }
finally {
    $Failed = [math]::Max($Failed, (Write-WdacResults $R $Cfg 'Package build'))
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
