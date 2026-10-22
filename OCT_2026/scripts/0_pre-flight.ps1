# 1. Stage 0 STIG Check — Expect BOTH values to be 0 (Not Configured)
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 2. Confirm no legacy single-policy SiPolicy.p7b exists (Expect: False)
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"

# 3. List existing policies in CiTool — Expect ONLY built-in Microsoft Platform policies (IsSystemPolicy = true)
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Select-Object PolicyID, FriendlyName, IsSystemPolicy, IsEnforced, IsAuthorized |
    Format-Table -AutoSize

# 4. Verify our 3 Approved Apps + 1 Proof-of-Block App (Firefox) are installed on the PAW
[pscustomobject]@{
    WinDirStat = (Get-ChildItem "$env:ProgramFiles\WinDirStat\WinDirStat.exe", "${env:ProgramFiles(x86)}\WinDirStat\WinDirStat.exe" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    AzureCLI   = (Get-Command az.cmd -ErrorAction SilentlyContinue).Source
    VSCode     = (@("$env:ProgramFiles\Microsoft VS Code\Code.exe", "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1)
    Firefox    = (@("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1)
} | Format-List
