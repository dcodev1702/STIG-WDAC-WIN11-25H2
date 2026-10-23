# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE.

# 1. Confirm the active multi-policy binary exists under CiPolicies\Active\{PolicyID}.cip (and no legacy SiPolicy.p7b exists)
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.cip' -ErrorAction Stop |
    Select-Object Name, Length, LastWriteTime
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"   # Expect: False

# 2. Confirm CiTool reports PAW-WDAC-Enforced (the version script 6 stamped) with IsEnforced = True and IsAuthorized = True
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Where-Object { -not $_.IsSystemPolicy } |
    Format-List PolicyID, BasePolicyID, FriendlyName, Version, VersionString, IsEnforced, IsAuthorized

# 3. Confirm Event ID 3099 logged the activation of PAW-WDAC-Enforced
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3099
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List
