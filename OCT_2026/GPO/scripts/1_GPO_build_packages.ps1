# Step 1 - run on the fully configured WDAC REFERENCE device (elevated, Windows PowerShell 5.1 or PowerShell 7).
# Builds the two GPO payloads from the reference device's ENFORCED policy XML (C:\WDAC\Source\Base-Enforce.xml):
#   Audit\   = the same rules + Enabled:Audit Mode, version YYYY.MM.DD.N
#   Enforce\ = the same rules, Audit Mode OFF,       version YYYY.MM.DD.N+1   (higher, so Audit -> Enforce replaces in place)
# Versions use today's (local) date with a daily counter, and are always above every version already known for the policy
# (WDAC-Version.ps1), including the packages already published in both GPOs.
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

    # ---------------------------------------------------------------- versions: YYYY.MM.DD.N (today), above everything known for this GUID
    #   known = source XML, this device's active policy, earlier packages AND what is already published in both GPOs (SYSVOL),
    #   so any reference device picks a version the endpoints will accept
    $Plan = Get-WdacPackageVersions $Cfg $Guid $EnforceXml
    Add-WdacResult $R 'OK' 'Version plan' "next pair $($Plan.Versions -join ' / ') - $($Plan.Basis); highest known v$($Plan.Highest) ($($Plan.Sources))"
    if (-not $AuditVersion) { $AuditVersion = $Plan.Versions[0] }
    elseif ($Plan.Highest -ne '(none)' -and [version]$AuditVersion -le [version]$Plan.Highest) { throw "STOP: -AuditVersion $AuditVersion is not higher than v$($Plan.Highest), which is already known for $Guid - endpoints would ignore it. Use $($Plan.Versions[0]) or higher (or omit -AuditVersion)." }
    if (-not $EnforceVersion) { $V = [version]$AuditVersion; $EnforceVersion = "$($V.Major).$($V.Minor).$($V.Build).$($V.Revision + 1)" }
    if ([version]$EnforceVersion -le [version]$AuditVersion) { throw "STOP: EnforceVersion ($EnforceVersion) must be higher than AuditVersion ($AuditVersion)." }

    # ---------------------------------------------------------------- build both XMLs from the enforced source
    #   Packages\<stamp>\xml\ (never published) keeps the exact XML behind each .cip, named like the policy and its version,
    #   plus a copy of the source XML with its own version, so every package can be traced and rebuilt
    $Pkg = Join-Path $Cfg.PackageRoot $Cfg.Stamp
    $Work = Join-Path $Pkg 'xml'
    New-Item -Path $Work, (Join-Path $Pkg 'Audit'), (Join-Path $Pkg 'Enforce') -ItemType Directory -Force | Out-Null
    $Ver = @{ Audit = $AuditVersion; Enforce = $EnforceVersion }
    $Xml = @{ Audit = (Join-Path $Work "$($Cfg.PolicyNamePrefix)-Audit_v$AuditVersion.xml"); Enforce = (Join-Path $Work "$($Cfg.PolicyNamePrefix)-Enforce_v$EnforceVersion.xml") }
    $SrcDoc = New-Object System.Xml.XmlDocument; $SrcDoc.Load($EnforceXml)
    Copy-Item -LiteralPath $EnforceXml -Destination (Join-Path $Work ("source_{0}_v{1}.xml" -f [IO.Path]::GetFileNameWithoutExtension($EnforceXml), $SrcDoc.SiPolicy.VersionEx)) -Force -ErrorAction Stop
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
