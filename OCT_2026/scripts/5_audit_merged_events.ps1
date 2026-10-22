# 2. Check for any NEW 3076 events generated after $ScreenStart
$Remaining3076 = @(Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076
    StartTime = $ScreenStart
} -ErrorAction SilentlyContinue)

Write-Host "New 3076 events since screening started: $($Remaining3076.Count)" -ForegroundColor Cyan
$Remaining3076 | Select-Object TimeCreated, Message | Format-List
