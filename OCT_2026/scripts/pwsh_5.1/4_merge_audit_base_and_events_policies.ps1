#Requires -PSEdition Desktop
# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE (NOT pwsh 7).
# ConfigCI is a native Windows PowerShell 5.1 module, so no compatibility session or nested powershell.exe is needed.
# Step 5: merge Base-Audit.xml + Events-Allow.xml, keep Audit Mode, deploy, and start the screening window.
param(
    # Optional: admin-writable-only folders to allow with a FilePath rule, e.g. 'C:\Program Files\MyApp\*'.
    # A folder that does not exist on this machine is skipped with a warning; a folder standard users can write to is
    # skipped too (runtime FilePath rule protection would ignore the rule).
    [string[]]$AdditionalFolderRules = @(),
    # Optional: regex for an application that must NOT be allowed by this policy, e.g. 'MyBlockedApp' (empty = skip the check)
    [string]$ExcludedAppPattern = ''
)

$BaseXml        = 'C:\WDAC\Source\Base-Audit.xml'
$EventsXml      = 'C:\WDAC\Source\Events-Allow.xml'
$MergedXml      = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$PolicyGuidFile = 'C:\WDAC\Source\PolicyGuid.txt'

Import-Module ConfigCI -ErrorAction Stop

foreach ($RequiredFile in $BaseXml, $EventsXml, $PolicyGuidFile) {
    if (-not (Test-Path -LiteralPath $RequiredFile)) { throw "STOP: Required file not found: $RequiredFile" }
}
$PolicyGuid = (Get-Content -LiteralPath $PolicyGuidFile -Raw).Trim()

# 1. Merge Base-Audit.xml (FIRST!) and Events-Allow.xml (SECOND)
try { Merge-CIPolicy -PolicyPaths $BaseXml, $EventsXml -OutputFilePath $MergedXml -ErrorAction Stop | Out-Null }
catch { throw "STOP: Merge-CIPolicy failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (Step 4.3), then re-run this script." }

# 2. Optional: add FilePath allow rules for the admin-protected folders listed in $AdditionalFolderRules
foreach ($Folder in $AdditionalFolderRules) {
    $FolderPath = Split-Path $Folder -Parent
    if (-not (Test-Path -LiteralPath $FolderPath)) {
        Write-Warning "Skipping FilePath rule - folder not found: $Folder"
        continue
    }
    $UserWrite = @((Get-Acl -LiteralPath $FolderPath).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl|CreateFiles|AppendData|268435456|1073741824' -and
        "$($_.IdentityReference)" -notmatch 'SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER'
    })
    if ($UserWrite.Count -gt 0) {
        Write-Warning "Skipping FilePath rule - $FolderPath is writable by $((@($UserWrite.IdentityReference) | Select-Object -Unique) -join ', '). Runtime FilePath rule protection would ignore it; allow that application with Publisher or Hash rules instead."
        continue
    }
    Write-Host "Adding admin-protected FilePath rule: $Folder" -ForegroundColor Cyan
    $Rule = New-CIPolicyRule -FilePathRule $Folder -ErrorAction Stop
    Merge-CIPolicy -PolicyPaths $MergedXml -Rules $Rule -OutputFilePath "$MergedXml.tmp" -ErrorAction Stop | Out-Null
    Move-Item -LiteralPath "$MergedXml.tmp" -Destination $MergedXml -Force -ErrorAction Stop
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
#     13 = Enabled:Managed Installer (MECM / Intune is the managed installer in this environment)
#     16 = Enabled:Update Policy No Reboot
#     17 = Enabled:Allow Supplemental Policies
foreach ($OptOn in @(0, 2, 3, 6, 9, 10, 11, 13, 16, 17)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOn -ErrorAction Stop
}
#    Ensure UNWANTED options (often leaked by Wizard event policies) are OFF:
#     14 = Enabled:Intelligent Security Graph Authorization
#     15 = Enabled:Invalidate EAs on Reboot
#     18 = Disabled:Runtime FilePath Rule Protection (deleting Option 18 keeps Runtime Protection ON!)
#     19 = Enabled:Dynamic Code Security
#     20 = Enabled:Revoked Expired As Unsigned
foreach ($OptOff in @(14, 15, 18, 19, 20)) {
    Set-RuleOption -FilePath $MergedXml -Option $OptOff -Delete -ErrorAction Stop
}

# 4. Stamp helpful PolicyName, PolicyId, and the next version - YYYY.MM.DD.N, higher than the baseline and anything active
#    (WDAC-Version.ps1) - DO NOT use -ResetPolicyID!
. "$PSScriptRoot\WDAC-Version.ps1"
$Known = @(Get-WdacActivePolicyVersion $PolicyGuid) + @(Get-WdacVersionsFromXml $BaseXml) + @(Get-WdacVersionsFromArchive -Name 'PAW-WDAC-Audit-Baseline', 'PAW-WDAC-Audit-Merged', 'PAW-WDAC-Enforced')
$Next = Get-WdacNextVersion -Known $Known
$Version = $Next.Versions[0]
Write-Host "Policy version $Version ($($Next.Basis); highest known: $($Next.Highest))" -ForegroundColor Cyan
Set-CIPolicyIdInfo -FilePath $MergedXml -PolicyName 'PAW-WDAC-Audit-Merged' -PolicyId 'PAW-AUDIT-MERGED-v2' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $MergedXml -Version $Version -ErrorAction Stop

# 5. Verify the merged policy BEFORE compiling
#    (XmlDocument.Load honors the file's own encoding; Get-Content in 5.1 would assume ANSI for BOM-less UTF-8 files)
$MergedDoc = New-Object System.Xml.XmlDocument
$MergedDoc.Load($MergedXml)

#    5a. ConvertFrom-CIPolicy rejects any FileAttrib rule that has no name/hash/path attribute (typically a Wizard FilePublisher
#        rule for a file without version info) with: "There is invalid file rule with ID ID_FILEATTRIB_..."
$BadAttribs = @($MergedDoc.SiPolicy.FileRules.FileAttrib | Where-Object {
    -not ($_.HasAttribute('FileName') -or $_.HasAttribute('InternalName') -or $_.HasAttribute('FileDescription') -or
          $_.HasAttribute('ProductName') -or $_.HasAttribute('PackageFamilyName') -or $_.HasAttribute('Hash') -or $_.HasAttribute('FilePath'))
})
if ($BadAttribs.Count -gt 0) {
    foreach ($Bad in $BadAttribs) {
        $Signers = @($MergedDoc.SiPolicy.Signers.Signer | Where-Object { $_.FileAttribRef.RuleID -contains $Bad.ID } | ForEach-Object { "$($_.Name) [$($_.ID)]" })
        Write-Host "Invalid FileAttrib rule: $($Bad.ID)  (used by signer: $($Signers -join ', '))" -ForegroundColor Red
        Write-Host "    $($Bad.OuterXml)" -ForegroundColor DarkYellow
    }
    throw "STOP: $($BadAttribs.Count) FileAttrib rule(s) above cannot be compiled. Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (or re-add those files as Publisher or Hash rules in the Wizard), then re-run this script."
}

#    5b. PolicyID GUID is unchanged, Audit Mode is still ON, and the optional excluded application is not present
$HasExcludedApp = $false
if ($ExcludedAppPattern) { $HasExcludedApp = [IO.File]::ReadAllText($MergedXml) -match $ExcludedAppPattern }
$Opts = $MergedDoc.SiPolicy.Rules.Rule.Option

$Check = [pscustomobject]@{
    PolicyName          = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Name').Value.String
    PolicyIdLabel       = ($MergedDoc.SiPolicy.Settings.Setting | Where-Object ValueName -eq 'Id').Value.String
    PolicyID_GUID       = $MergedDoc.SiPolicy.PolicyID
    MatchesBaseline     = ($MergedDoc.SiPolicy.PolicyID -ieq $PolicyGuid)
    VersionEx           = $MergedDoc.SiPolicy.VersionEx
    AuditModeOn         = ($Opts -contains 'Enabled:Audit Mode')
    SupplementalOn      = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    BootAuditOn         = ($Opts -contains 'Enabled:Boot Audit On Failure')
    ExcludedAppInPolicy = $HasExcludedApp
}
$Check | Format-List

if (-not ($Check.MatchesBaseline -and $Check.AuditModeOn -and $Check.SupplementalOn -and $Check.BootAuditOn -and -not $Check.ExcludedAppInPolicy)) {
    throw 'STOP: Merged policy verification failed! Review the values above (MatchesBaseline/AuditModeOn/SupplementalOn/BootAuditOn must be True; ExcludedAppInPolicy must be False).'
}


# 6. Compile Base-Audit-Merged.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
try { ConvertFrom-CIPolicy -XmlFilePath $MergedXml -BinaryFilePath $CipFile -ErrorAction Stop }
catch { throw "STOP: Compiling $MergedXml failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml (Step 4.3), then re-run this script. Nothing was deployed." }
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }
Copy-Item -LiteralPath $CipFile -Destination "C:\WDAC\Compiled\PAW-WDAC-Audit-Merged_v$Version.cip" -Force -ErrorAction Stop

# 7. Apply the updated Merged Audit Policy live with CiTool.exe
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }

# 8. Start the screening window: every Event ID 3076 from now on is a gap in the merged rules (5_audit_merged_events.ps1 reads this file)
$ScreenStartFile = 'C:\WDAC\Events\ScreenStart.txt'
New-Item -Path (Split-Path -Parent $ScreenStartFile) -ItemType Directory -Force | Out-Null
$ScreenStart = Get-Date
$ScreenStart.ToString('o') | Set-Content -LiteralPath $ScreenStartFile -ErrorAction Stop

# 9. Confirm STIG status is still 1 / 1 (Audit Mode) and FriendlyName updated to PAW-WDAC-Audit-Merged
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

Write-Host "Screening window started at $($ScreenStart.ToString('o')). Reboot now, run every application you need, then run 5_audit_merged_events.ps1." -ForegroundColor Yellow
