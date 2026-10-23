if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }

$BaseXml = 'C:\WDAC\Source\Base-Audit.xml'
if (-not (Test-Path -LiteralPath $BaseXml)) { throw "STOP: $BaseXml not found. Create it with the App Control Policy Wizard first (Step 1)." }

# 1. Stamp helpful Name, ID label, and VersionEx (NEVER use -ResetPolicyID!)
Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'PAW-WDAC-Audit-Baseline' -PolicyId 'PAW-AUDIT-BASE-v1' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $BaseXml -Version '2026.10.21.1' -ErrorAction Stop

# 2. Read the PolicyID GUID and verify rule options in the XML
[xml]$BaseDoc = Get-Content -LiteralPath $BaseXml
$PolicyGuid   = $BaseDoc.SiPolicy.PolicyID
if (-not $PolicyGuid) { throw 'STOP: No PolicyID found. Base-Audit.xml must be created in Multiple Policy Format.' }
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
ConvertFrom-CIPolicy -XmlFilePath $BaseXml -BinaryFilePath $CipFile -ErrorAction Stop
if (-not (Test-Path -LiteralPath $CipFile)) { throw "STOP: Compile did not produce $CipFile." }

# Save an archive copy of v2026.10.21.1 for our audit trail
Copy-Item -LiteralPath $CipFile -Destination 'C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v2026.10.21.1.cip' -Force -ErrorAction Stop

# 4. Deploy the Baseline Audit Policy live with CiTool.exe (no reboot required)
$CiOut = & "$env:SystemRoot\System32\CiTool.exe" --update-policy $CipFile -json
$CiOut
$CiOp = try { ($CiOut -join "`n" | ConvertFrom-Json).OperationResult } catch { $null }
if ($LASTEXITCODE -ne 0 -or ($null -ne $CiOp -and $CiOp -ne 0)) { throw "STOP: CiTool.exe --update-policy failed (exit code $LASTEXITCODE, OperationResult $CiOp). The policy was NOT applied." }

# 5. Start the audit window: every Event ID 3076 from now on belongs to this round (3_capture_ciaudit_events.ps1 reads this file)
$AuditStartFile = 'C:\WDAC\Events\AuditRoundStart.txt'
New-Item -Path (Split-Path -Parent $AuditStartFile) -ItemType Directory -Force | Out-Null
if (Test-Path -LiteralPath $AuditStartFile) {
    $PreviousFile = Join-Path (Split-Path -Parent $AuditStartFile) "AuditRoundStart.previous-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    Copy-Item -LiteralPath $AuditStartFile -Destination $PreviousFile -ErrorAction Stop
    Write-Warning "An earlier audit window start existed and was replaced. The old value was kept as $PreviousFile"
}
$AuditRoundStart = Get-Date
$AuditRoundStart.ToString('o') | Set-Content -LiteralPath $AuditStartFile -ErrorAction Stop
Write-Host "Audit window started at $($AuditRoundStart.ToString('o')). Reboot now, then run every application you need (Step 3)." -ForegroundColor Green
