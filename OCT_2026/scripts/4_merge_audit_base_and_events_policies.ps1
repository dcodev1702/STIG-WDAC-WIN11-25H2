$BaseXml   = 'C:\WDAC\Source\Base-Audit.xml'
$EventsXml = 'C:\WDAC\Source\Events-Allow.xml'
$MergedXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw).Trim()

# 1. Merge Base-Audit.xml (FIRST!) and Events-Allow.xml (SECOND)
Merge-CIPolicy -PolicyPaths $BaseXml, $EventsXml -OutputFilePath $MergedXml

# 2. Optional but Recommended for Azure CLI: Ensure the admin-only Program Files Azure CLI folder is covered
#    (Runs New-CIPolicyRule in Windows PowerShell 5.1 so Rule objects serialize cleanly into Merge-CIPolicy)
foreach ($AzFolder in @('C:\Program Files\Microsoft SDKs\Azure\CLI2\*', 'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\*')) {
    if (Test-Path (Split-Path $AzFolder -Parent)) {
        Write-Host "Adding admin-protected FilePath rule for Azure CLI: $AzFolder" -ForegroundColor Cyan
        powershell.exe -NoProfile -Command "
            Import-Module ConfigCI
            `$Rule = New-CIPolicyRule -FilePathRule '$AzFolder'
            Merge-CIPolicy -PolicyPaths '$MergedXml' -Rules `$Rule -OutputFilePath '$MergedXml.tmp' | Out-Null
            Move-Item -LiteralPath '$MergedXml.tmp' -Destination '$MergedXml' -Force
        "
    }
}

# 3. Clean up any extra rule options unioned from Events-Allow.xml and ensure Audit options remain set
#    Ensure REQUIRED options are ON:
#      0 = Enabled:UMCI
#      2 = Required:WHQL
#      3 = Enabled:Audit Mode
#      6 = Enabled:Unsigned System Integrity Policy
#      9 = Enabled:Advanced Boot Options Menu
#     10 = Enabled:Boot Audit On Failure
#     11 = Disabled:Script Enforcement
#     16 = Enabled:Update Policy No Reboot
#     17 = Enabled:Allow Supplemental Policies
foreach ($OptOn in @(0, 2, 3, 6, 9, 10, 11, 16, 17)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOn
}
#    Ensure UNWANTED options (often leaked by Wizard event policies) are OFF:
#     13 = Enabled:Managed Installer
#     14 = Enabled:Intelligent Security Graph Authorization
#     15 = Enabled:Invalidate EAs on Reboot
#     18 = Disabled:Runtime FilePath Rule Protection (deleting Option 18 keeps Runtime Protection ON!)
#     19 = Enabled:Dynamic Code Security
#     20 = Enabled:Revoked Expired As Unsigned
foreach ($OptOff in @(13, 14, 15, 18, 19, 20)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOff -Delete
}

# 4. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.2) — DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $MergedXml -PolicyName 'PAW-WDAC-Audit-Merged' -PolicyId 'PAW-AUDIT-MERGED-v2'
Set-CIPolicyVersion -FilePath $MergedXml -Version '2026.10.21.3'

# 5. Verify PolicyID GUID is unchanged, Audit Mode is still ON, and no Firefox/Mozilla rules exist
[xml]$MergedDoc = Get-Content -LiteralPath $MergedXml
$HasFirefox = (Get-Content -LiteralPath $MergedXml -Raw) -match 'Mozilla|Firefox'

[pscustomobject]@{
    PolicyName       = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel    = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyID_GUID    = $MergedDoc.SiPolicy.PolicyID
    MatchesBaseline  = ($MergedDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    VersionEx        = $MergedDoc.SiPolicy.VersionEx
    AuditModeOn      = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Audit Mode')
    SupplementalOn   = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Allow Supplemental Policies')
    BootAuditOn      = ($MergedDoc.SiPolicy.Rules.Rule.Option -contains 'Enabled:Boot Audit On Failure')
    FirefoxInPolicy  = $HasFirefox
} | Format-List


# 6. Compile Base-Audit-Merged.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
ConvertFrom-CIPolicy -XmlFilePath $MergedXml -BinaryFilePath $CipFile
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Merged_v2026.10.21.3.cip' -Force

# 7. Apply the updated Merged Audit Policy live with CiTool.exe
& "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json

# 8. Confirm STIG status is still 1 / 1 (Audit Mode) and FriendlyName updated to PAW-WDAC-Audit-Merged
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized
