# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE.

$AuditStartFile = 'C:\WDAC\Events\AuditRoundStart.txt'
if (-not (Test-Path -LiteralPath $AuditStartFile)) { throw "STOP: $AuditStartFile not found. Run 1_compile_and_deploy.ps1 first (it records the start of the audit window)." }
$AuditRoundStart = [datetime]::Parse((Get-Content -LiteralPath $AuditStartFile -Raw).Trim())

# 1. Preview unique files that generated Event ID 3076 during our test window
$Events3076 = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $AuditRoundStart
} -ErrorAction SilentlyContinue)

if ($Events3076.Count -eq 0) { throw "STOP: No Event ID 3076 found since $AuditRoundStart. Confirm the audit policy is active (script 2), you are elevated, and you ran your applications after the audit window started." }

$Events3076 | ForEach-Object {
    $Xml = [xml]$_.ToXml()
    $File = ($Xml.Event.EventData.Data | Where-Object Name -in 'FileNameBuffer', 'FileName', 'File Name').'#text'
    [pscustomobject]@{
        TimeCreated = $_.TimeCreated
        FilePath    = $File
    }
} | Group-Object FilePath | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

# 2. Export ONLY 3076 + 3089 events since $AuditRoundStart to C:\WDAC\Events\PAW-Audit-3076.evtx
$StartUtc = $AuditRoundStart.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$EvtxPath = 'C:\WDAC\Events\PAW-Audit-3076.evtx'

& wevtutil.exe epl 'Microsoft-Windows-CodeIntegrity/Operational' $EvtxPath "/q:*[System[(EventID=3076 or EventID=3089) and TimeCreated[@SystemTime>='$StartUtc']]]" /ow:true
if ($LASTEXITCODE -ne 0) { throw "STOP: wevtutil.exe failed to export events (exit code $LASTEXITCODE). Run this from an elevated session." }
Get-Item -LiteralPath $EvtxPath -ErrorAction Stop | Select-Object FullName, Length, LastWriteTime

# 3. Read the export back: it must hold the same 3076 count as the live log, and one or more 3089 per 3076
#    (no 3089 for a 3076 means the Wizard can only offer a Hash rule for that file)
$Exported = @(Get-WinEvent -Path $EvtxPath -ErrorAction SilentlyContinue)
$Exported3076 = @($Exported | Where-Object Id -eq 3076).Count
Write-Host "Exported: $Exported3076 x 3076, $(@($Exported | Where-Object Id -eq 3089).Count) x 3089 (live log: $($Events3076.Count) x 3076 since $($AuditRoundStart.ToString('o')))" -ForegroundColor Cyan
if ($Exported3076 -ne $Events3076.Count) { Write-Warning 'The exported 3076 count differs from the live log. New events may have arrived during the export; re-run this script before Step 4.2.' }
Write-Host "Evidence (every event, with hashes and signer): .\Export-CIEventEvidence.ps1 -EvtxPath '$EvtxPath'" -ForegroundColor Cyan
