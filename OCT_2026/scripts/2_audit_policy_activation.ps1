# 1. Stage 1 STIG Check — Expect BOTH values to now be 1 (Audit Mode)!
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 2. Verify CiTool shows PAW-WDAC-Audit-Baseline loaded and authorized
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, BasePolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

# 3. Confirm Event ID 3099 (Policy Loaded) in the CodeIntegrity Operational log
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3099
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 | Select-Object TimeCreated, Id, Message | Format-List

