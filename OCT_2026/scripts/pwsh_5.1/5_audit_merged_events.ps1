# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE.
# Run AFTER rebooting and running every application you need (screening). When the screening is clean it also prepares
# Base-Enforce.xml (a copy of Base-Audit-Merged.xml) so the only manual step left before enforcing is the App Control Policy Wizard.
param(
    [switch]$AcceptRemaining,
    [switch]$Overwrite
)

# $ScreenStart is recorded by 4_merge_audit_base_and_events_policies.ps1 in C:\WDAC\Events\ScreenStart.txt so it survives the reboot
if (-not $ScreenStart) {
    $ScreenStartFile = 'C:\WDAC\Events\ScreenStart.txt'
    if (-not (Test-Path -LiteralPath $ScreenStartFile)) { throw "STOP: `$ScreenStart is not set and $ScreenStartFile was not found. Run 4_merge_audit_base_and_events_policies.ps1 first (it records the start of the screening window)." }
    $ScreenStart = [datetime]::Parse((Get-Content -LiteralPath $ScreenStartFile -Raw).Trim())
}

# 2. Check for any NEW 3076 events generated after $ScreenStart
$Remaining3076 = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $ScreenStart
} -ErrorAction SilentlyContinue)

Write-Host "New 3076 events since screening started: $($Remaining3076.Count)" -ForegroundColor Cyan
$Remaining3076 | Select-Object TimeCreated, Message | Format-List

# 3. Screening is clean (or the remaining events were reviewed with -AcceptRemaining): prepare Base-Enforce.xml for the Wizard (Step 6)
if ($Remaining3076.Count -gt 0 -and -not $AcceptRemaining) {
    Write-Host "NOT ready to enforce: $($Remaining3076.Count) new 3076 event(s). If any are for an application you need, repeat Steps 4 and 5. If every one is for an application you intend to keep blocked, re-run this script with -AcceptRemaining." -ForegroundColor Yellow
    return
}

$MergedXml = 'C:\WDAC\Source\Base-Audit-Merged.xml'
$EnforceXml = 'C:\WDAC\Source\Base-Enforce.xml'
if (-not (Test-Path -LiteralPath $MergedXml)) { throw "STOP: $MergedXml not found. Run 4_merge_audit_base_and_events_policies.ps1 first." }

$MergedTime = (Get-Item -LiteralPath $MergedXml).LastWriteTime
$Target = $EnforceXml
if (Test-Path -LiteralPath $EnforceXml) {
    if ((Get-FileHash -LiteralPath $EnforceXml).Hash -eq (Get-FileHash -LiteralPath $MergedXml).Hash) {
        Write-Host 'Base-Enforce.xml is already prepared (identical to Base-Audit-Merged.xml). Next: open it in the App Control Policy Wizard and turn Audit Mode OFF (Step 6).' -ForegroundColor Green
        return
    }

    # Base-Enforce.xml exists and differs: never overwrite silently. Ask; unless told otherwise, write a timestamped copy next to it.
    $Why = if ((Get-Item -LiteralPath $EnforceXml).LastWriteTime -gt $MergedTime) { 'was changed after it was prepared (for example in the Wizard)' } else { 'was prepared from an older merge' }
    $Stamped = Join-Path (Split-Path -Parent $EnforceXml) "Base-Enforce_$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    if ($Overwrite) { $Choice = 1 }
    elseif ([Environment]::UserInteractive -and -not ([Environment]::GetCommandLineArgs() -match '^[-/]noni') -and ($Host.Name -match 'ISE' -or -not [Console]::IsInputRedirected)) {
        $Options = @(
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Timestamped copy', "Keep Base-Enforce.xml and write $(Split-Path -Leaf $Stamped)"),
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Overwrite', 'Replace Base-Enforce.xml with the screened policy'),
            (New-Object System.Management.Automation.Host.ChoiceDescription '&Cancel', 'Change nothing')
        )
        try { $Choice = $Host.UI.PromptForChoice('Base-Enforce.xml already exists', "Base-Enforce.xml $Why. How should the screened policy be saved?", $Options, 0) }
        catch { $Choice = 0 }
    }
    else { $Choice = 0 }
    if ($Choice -eq 2) { Write-Host 'Cancelled - nothing was changed.' -ForegroundColor Yellow; return }
    if ($Choice -eq 0) { $Target = $Stamped; Write-Warning "Base-Enforce.xml $Why and was left untouched. The screened policy was written to $Target instead (use -Overwrite to replace Base-Enforce.xml)." }
}
Copy-Item -LiteralPath $MergedXml -Destination $Target -Force -ErrorAction Stop
# Keeping the copy's timestamp equal to its source lets a later save (the Wizard) be recognised as an edit
(Get-Item -LiteralPath $Target).LastWriteTime = $MergedTime
Write-Host "$(Split-Path -Leaf $Target) prepared from Base-Audit-Merged.xml. Next: open it in the App Control Policy Wizard and turn Audit Mode OFF (Step 6), then run 6_enforce_policy.ps1 (it uses the newest Base-Enforce*.xml)." -ForegroundColor Green
