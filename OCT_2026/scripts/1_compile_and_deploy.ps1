$BaseXml = 'C:\WDAC\Source\Base-Audit.xml'

# 1. Stamp helpful Name, ID label, and VersionEx (NEVER use -ResetPolicyID!)
Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'PAW-WDAC-Audit-Baseline' -PolicyId 'PAW-AUDIT-BASE-v1'
Set-CIPolicyVersion -FilePath $BaseXml -Version '2026.10.21.1'

# 2. Read the PolicyID GUID and verify rule options in the XML
[xml]$BaseDoc = Get-Content -LiteralPath $BaseXml
$PolicyGuid   = $BaseDoc.SiPolicy.PolicyID
$PolicyGuid | Set-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt'

[pscustomobject]@{
    PolicyType   = $BaseDoc.SiPolicy.PolicyType
    PolicyID     = $BaseDoc.SiPolicy.PolicyID
    BasePolicyID = $BaseDoc.SiPolicy.BasePolicyID
    VersionEx    = $BaseDoc.SiPolicy.VersionEx
    RuleOptions  = ($BaseDoc.SiPolicy.Rules.Rule.Option -join ', ')
} | Format-List


# 3. Compile Base-Audit.xml to C:\WDAC\Compiled\{PolicyID}.cip
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $BaseXml -BinaryFilePath $CipFile

# Save an archive copy of v2026.10.21.1 for our audit trail
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip' -Force

# 4. Deploy the Baseline Audit Policy live with CiTool.exe (no reboot required)
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json