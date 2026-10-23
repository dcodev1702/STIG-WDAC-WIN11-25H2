#Requires -PSEdition Desktop
# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE (NOT pwsh 7).

Import-Module ConfigCI -WarningAction SilentlyContinue -ErrorAction Stop

$BaseXml = 'C:\WDAC\Source\Base-Audit.xml'
if (-not (Test-Path -LiteralPath $BaseXml)) { throw "STOP: $BaseXml not found. Create it with the App Control Policy Wizard first (Step 1)." }

# 1. Choose the version - YYYY.MM.DD.N (today, counter restarts daily), never lower than any version already known for this
#    policy (WDAC-Version.ps1) - then stamp helpful Name, ID label, and VersionEx (NEVER use -ResetPolicyID!)
. "$PSScriptRoot\WDAC-Version.ps1"
$PreDoc = New-Object System.Xml.XmlDocument
$PreDoc.Load($BaseXml)
$Known = @(Get-WdacActivePolicyVersion $PreDoc.SiPolicy.PolicyID) + @(Get-WdacVersionsFromArchive -Name 'PAW-WDAC-Audit-Baseline', 'PAW-WDAC-Audit-Merged', 'PAW-WDAC-Enforced')
$Next = Get-WdacNextVersion -Known $Known
$Version = $Next.Versions[0]
Write-Host "Policy version $Version ($($Next.Basis); highest known: $($Next.Highest))" -ForegroundColor Cyan
Set-CIPolicyIdInfo -FilePath $BaseXml -PolicyName 'PAW-WDAC-Audit-Baseline' -PolicyId 'PAW-AUDIT-BASE-v1' -ErrorAction Stop
Set-CIPolicyVersion -FilePath $BaseXml -Version $Version -ErrorAction Stop

# 2. Read the PolicyID GUID and verify rule options in the XML
#    (XmlDocument.Load honors the file's own encoding; Get-Content in 5.1 would assume ANSI for BOM-less UTF-8 files)
$BaseDoc = New-Object System.Xml.XmlDocument
$BaseDoc.Load($BaseXml)
$PolicyGuid = $BaseDoc.SiPolicy.PolicyID
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

# Save an archive copy of this version for our audit trail
Copy-Item -LiteralPath $CipFile -Destination "C:\WDAC\Compiled\PAW-WDAC-Audit-Baseline_v$Version.cip" -Force -ErrorAction Stop

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
