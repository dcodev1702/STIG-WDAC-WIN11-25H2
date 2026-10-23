# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE.

# 1. Stage 1 STIG Check - Expect UMCI = 1 (Audit Mode). KMCI reads 1 on a clean OS, or stays 2 if Microsoft platform
#    policies (e.g. the vulnerable driver blocklist) already enforced kernel mode at pre-flight.
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 2. Verify CiTool shows PAW-WDAC-Audit-Baseline loaded and authorized
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, BasePolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

# 3. Confirm Event ID 3099 (Policy Loaded) in the CodeIntegrity Operational log
#    (retried for ~10 seconds: run straight after script 1, the event may not be flushed to the log yet)
$Events3099 = @()
for ($Try = 1; $Try -le 5 -and $Events3099.Count -eq 0; $Try++) {
    $Events3099 = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
        Id        = 3099
        StartTime = (Get-Date).AddMinutes(-10)
    } -MaxEvents 5 -ErrorAction SilentlyContinue)
    if ($Events3099.Count -eq 0) { Start-Sleep -Seconds 2 }
}
if ($Events3099.Count -eq 0) { Write-Warning 'No Event 3099 in the last 10 minutes. If script 1 ran earlier than that, query a wider window; otherwise re-run script 1.' }
$Events3099 | Select-Object TimeCreated, Id, Message | Format-List
