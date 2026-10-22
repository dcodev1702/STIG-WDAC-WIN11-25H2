$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()

# If the Wizard wrote a version-suffixed file (e.g., Base-Enforce_v*.xml), normalize it to Base-Enforce.xml
$LatestEnforceXml = Get-ChildItem -Path 'C:\WDAC\Source' -Filter 'Base-Enforce*.xml' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$EnforceXml = 'C:\WDAC\Source\Base-Enforce.xml'
if ($LatestEnforceXml.FullName -ne $EnforceXml) {
    Copy-Item -LiteralPath $LatestEnforceXml.FullName -Destination $EnforceXml -Force
}

# 1. Guarantee Enforce Mode options (Audit Mode OFF, Boot Audit ON, Supplemental ON, UMCI ON, Script Enforcement Disabled)
foreach ($OptOn in @(0, 2, 6, 9, 10, 11, 16, 17)) {
    Set-RuleOption -FilePath $EnforceXml -Option $OptOn
}
foreach ($OptOff in @(3, 13, 14, 15, 18, 19, 20)) {
    # Option 3 = Enabled:Audit Mode -> Deleting Option 3 guarantees ENFORCE MODE!
    Set-RuleOption -FilePath $EnforceXml -Option $OptOff -Delete
}

# 2. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.3) — DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $EnforceXml -PolicyName 'PAW-WDAC-Enforced' -PolicyId 'PAW-ENFORCED-v4'
Set-CIPolicyVersion -FilePath $EnforceXml -Version '2026.10.21.4'

# 3. Verify Multi-Policy Suitability & Enforce Readiness before compiling
[xml]$EnfDoc = Get-Content -LiteralPath $EnforceXml
$Opts = $EnfDoc.SiPolicy.Rules.Rule.Option
$Check = [pscustomobject]@{
    PolicyName              = ($EnfDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel           = ($EnfDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyType              = $EnfDoc.SiPolicy.PolicyType
    PolicyID_GUID           = $EnfDoc.SiPolicy.PolicyID
    BasePolicyID_GUID       = $EnfDoc.SiPolicy.BasePolicyID
    SameGuidAsAudit         = ($EnfDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    MultiPolicyFormatValid  = ($EnfDoc.SiPolicy.PolicyID -eq $EnfDoc.SiPolicy.BasePolicyID -and [bool]$EnfDoc.SiPolicy.PolicyID)
    VersionEx               = $EnfDoc.SiPolicy.VersionEx
    AuditModeRemoved        = ($Opts -notcontains 'Enabled:Audit Mode')
    UMCI_Enabled            = ($Opts -contains 'Enabled:UMCI')
    BootAuditEnabled        = ($Opts -contains 'Enabled:Boot Audit On Failure')
    AllowSupplemental       = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    ScriptEnforceDisabled   = ($Opts -contains 'Disabled:Script Enforcement')
    UpdateNoRebootEnabled   = ($Opts -contains 'Enabled:Update Policy No Reboot')
    NoFirefoxRules          = (-not ((Get-Content -LiteralPath $EnforceXml -Raw) -match 'Mozilla|Firefox'))
}
$Check | Format-List

if (-not ($Check.SameGuidAsAudit -and $Check.MultiPolicyFormatValid -and $Check.AuditModeRemoved -and $Check.UMCI_Enabled -and $Check.BootAuditEnabled -and $Check.AllowSupplemental -and $Check.NoFirefoxRules)) {
    throw 'STOP: Pre-deployment verification failed! Review the False property above before applying.'
}
Write-Host 'PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!' -ForegroundColor Green

# 4. Compile Base-Enforce.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $EnforceXml -BinaryFilePath $CipFile
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Enforced_v2026.10.21.4.cip' -Force

# Record SHA256 hash of the enforced .cip binary for your audit evidence
Get-FileHash -LiteralPath $CipFile -Algorithm SHA256 | Format-List

# 5. Apply the Enforced Policy live with CiTool.exe (no reboot required)
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
