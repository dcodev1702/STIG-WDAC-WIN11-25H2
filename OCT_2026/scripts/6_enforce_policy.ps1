# PowerShell 7 edition - run in an elevated "pwsh" window.
# Step 7: pre-deployment gate, stamp v3, compile, and apply the ENFORCED policy (Audit Mode is the only option turned off).
param(
    # Optional: regex for an application that must NOT be allowed by this policy, e.g. 'MyBlockedApp' (empty = skip the check)
    [string]$ExcludedAppPattern = ''
)

if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }

$PolicyGuid = (Get-Content -LiteralPath 'C:\WDAC\Source\PolicyGuid.txt' -Raw -ErrorAction Stop).Trim()

# If the Wizard wrote a version-suffixed file (e.g., Base-Enforce_v*.xml), normalize it to Base-Enforce.xml
$LatestEnforceXml = Get-ChildItem -Path 'C:\WDAC\Source' -Filter 'Base-Enforce*.xml' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $LatestEnforceXml) { throw 'STOP: No Base-Enforce*.xml found in C:\WDAC\Source. Run 5_audit_merged_events.ps1 first (it prepares Base-Enforce.xml once the screening is clean), then open it in the Wizard (Step 6).' }
$EnforceXml = 'C:\WDAC\Source\Base-Enforce.xml'
if ($LatestEnforceXml.FullName -ne $EnforceXml) {
    Copy-Item -LiteralPath $LatestEnforceXml.FullName -Destination $EnforceXml -Force -ErrorAction Stop
}

# The screened audit policy is the reference: enforcing must turn Audit Mode off and nothing else
$AuditXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
if (-not (Test-Path -LiteralPath $AuditXml)) { throw "STOP: $AuditXml not found. It is the reference that proves Audit Mode is the only option being turned off. Run 4_merge_audit_base_and_events_policies.ps1 first." }
[xml]$AuditDoc = Get-Content -LiteralPath $AuditXml
$AuditOptions = @($AuditDoc.SiPolicy.Rules.Rule.Option)

# 1. Guarantee Enforce Mode options (Audit Mode OFF, Boot Audit ON, Supplemental ON, UMCI ON, Script Enforcement Disabled)
foreach ($OptOn in @(0, 2, 6, 9, 10, 11, 13, 16, 17)) {
    Set-RuleOption -FilePath $EnforceXml -Option $OptOn -ErrorAction Stop
}
foreach ($OptOff in @(3, 14, 15, 18, 19, 20)) {
    # Option 3 = Enabled:Audit Mode -> Deleting Option 3 guarantees ENFORCE MODE!
    Set-RuleOption -FilePath $EnforceXml -Option $OptOff -Delete -ErrorAction Stop
}

# 2. Stamp helpful PolicyName, PolicyId, and bumped VersionEx (2026.10.21.3) - DO NOT use -ResetPolicyID!
Set-CIPolicyIdInfo -FilePath $EnforceXml -PolicyName 'PAW-WDAC-Enforced' -PolicyId 'PAW-ENFORCED-v3' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $EnforceXml -Version '2026.10.21.3' -ErrorAction Stop

# 3. Verify Multi-Policy Suitability & Enforce Readiness before compiling
[xml]$EnfDoc = Get-Content -LiteralPath $EnforceXml

#    3a. ConvertFrom-CIPolicy rejects any FileAttrib rule that has no name/hash/path attribute (typically a Wizard FilePublisher
#        rule for a file without version info) with: "There is invalid file rule with ID ID_FILEATTRIB_..."
$BadAttribs = @($EnfDoc.SiPolicy.FileRules.FileAttrib | Where-Object {
    -not ($_.HasAttribute('FileName') -or $_.HasAttribute('InternalName') -or $_.HasAttribute('FileDescription') -or
          $_.HasAttribute('ProductName') -or $_.HasAttribute('PackageFamilyName') -or $_.HasAttribute('Hash') -or $_.HasAttribute('FilePath'))
})
if ($BadAttribs.Count -gt 0) {
    foreach ($Bad in $BadAttribs) {
        $Signers = @($EnfDoc.SiPolicy.Signers.Signer | Where-Object { $_.FileAttribRef.RuleID -contains $Bad.ID } | ForEach-Object { "$($_.Name) [$($_.ID)]" })
        Write-Host "Invalid FileAttrib rule: $($Bad.ID)  (used by signer: $($Signers -join ', '))" -ForegroundColor Red
        Write-Host "    $($Bad.OuterXml)" -ForegroundColor DarkYellow
    }
    throw "STOP: $($BadAttribs.Count) FileAttrib rule(s) above cannot be compiled. Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml, re-run script 4, then repeat Step 6."
}

#    3b. Multi-policy format, enforce-mode options, and the optional excluded application
$Opts = @($EnfDoc.SiPolicy.Rules.Rule.Option)
#    Audit Mode must be the ONLY option that was enabled in the screened audit policy and is not enabled now
$OtherOptionsTurnedOff = @($AuditOptions | Where-Object { $_ -ne 'Enabled:Audit Mode' -and $Opts -notcontains $_ })
$OptionsAdded = @($Opts | Where-Object { $AuditOptions -notcontains $_ })
$HasExcludedApp = $false
if ($ExcludedAppPattern) { $HasExcludedApp = (Get-Content -LiteralPath $EnforceXml -Raw) -match $ExcludedAppPattern }
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
    OnlyAuditModeTurnedOff  = ($OtherOptionsTurnedOff.Count -eq 0)
    OtherOptionsTurnedOff   = ($OtherOptionsTurnedOff -join ', ')
    OptionsAdded            = ($OptionsAdded -join ', ')
    UMCI_Enabled            = ($Opts -contains 'Enabled:UMCI')
    BootAuditEnabled        = ($Opts -contains 'Enabled:Boot Audit On Failure')
    AllowSupplemental       = ($Opts -contains 'Enabled:Allow Supplemental Policies')
    ScriptEnforceDisabled   = ($Opts -contains 'Disabled:Script Enforcement')
    UpdateNoRebootEnabled   = ($Opts -contains 'Enabled:Update Policy No Reboot')
    ExcludedAppInPolicy     = $HasExcludedApp
}
$Check | Format-List

if (-not $Check.OnlyAuditModeTurnedOff) {
    Write-Host "Audit Mode must be the only option turned off, but these screened options are missing from Base-Enforce.xml: $($OtherOptionsTurnedOff -join ', ')" -ForegroundColor Red
    Write-Host 'Switch them back ON in the Wizard. If they are options this guide requires OFF (ISG, Invalidate EAs, Runtime FilePath Rule Protection, Dynamic Code Security, Revoked Expired As Unsigned), re-run script 4 to clean the audit policy and re-screen.' -ForegroundColor Red
}
if (-not ($Check.SameGuidAsAudit -and $Check.MultiPolicyFormatValid -and $Check.AuditModeRemoved -and $Check.OnlyAuditModeTurnedOff -and $Check.UMCI_Enabled -and $Check.BootAuditEnabled -and $Check.AllowSupplemental -and -not $Check.ExcludedAppInPolicy)) {
    throw 'STOP: Pre-deployment verification failed! Review the False property above before applying.'
}
Write-Host 'PRE-DEPLOYMENT CHECK PASSED: Policy is Enforce-ready and Multi-Policy compliant!' -ForegroundColor Green
Write-Host 'Audit Mode is the ONLY option turned off. Options that stay ENABLED in the enforced policy:' -ForegroundColor Green
$Opts | Sort-Object | ForEach-Object { Write-Host "  $_" }

# 4. Compile Base-Enforce.xml to C:\WDAC\Compiled\{PolicyID}.cip and archive a copy
$CipFile = Join-Path 'C:\WDAC\Compiled' "$PolicyGuid.cip"
try { ConvertFrom-CIPolicy -XmlFilePath $EnforceXml -BinaryFilePath $CipFile -ErrorAction Stop }
catch { throw "STOP: Compiling $EnforceXml failed: $($_.Exception.Message) Run 3_1_validate_winevent_rules.ps1 on Events-Allow.xml, re-run script 4, then repeat Step 6. Nothing was deployed." }
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Enforced_v2026.10.21.3.cip' -Force -ErrorAction Stop

# Record SHA256 hash of the enforced .cip binary for your audit evidence
Get-FileHash -LiteralPath $CipFile -Algorithm SHA256 | Format-List

# 5. Apply the Enforced Policy live with CiTool.exe (no reboot required)
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }
