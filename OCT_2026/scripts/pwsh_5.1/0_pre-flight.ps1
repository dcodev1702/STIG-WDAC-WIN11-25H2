#Requires -PSEdition Desktop
# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE (NOT pwsh 7).

# 1. Verify this Windows PowerShell 5.1 session is running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'STOP: Open Windows PowerShell 5.1 with "Run as Administrator".' }

# 2. Create the clean directory structure
$Folders = @(
    'C:\WDAC\Source',
    'C:\WDAC\Compiled',
    'C:\WDAC\Events',
    'C:\WDAC\Logs'
)
New-Item -Path $Folders -ItemType Directory -Force -ErrorAction Stop | Out-Null

# 3. Start an audit log transcript of all commands and outputs
Start-Transcript -Path "C:\WDAC\Logs\WDAC-Manual-Run-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

# 4. Import ConfigCI (native in Windows PowerShell 5.1) and confirm CiTool.exe exists (Windows 11 22H2+ / Server 2025)
Import-Module ConfigCI -WarningAction SilentlyContinue -ErrorAction Stop
Get-Command -Module ConfigCI
if (-not (Test-Path -LiteralPath "$env:SystemRoot\System32\CiTool.exe")) { throw 'STOP: CiTool.exe was not found. Multiple-policy deployment requires Windows 11 22H2 or later.' }

# 5. Stage 0 STIG Check - Expect BOTH values to be 0 (Not Configured)
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Format-List CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus

# 6. Confirm no legacy single-policy SiPolicy.p7b exists (Expect: False)
Test-Path "$env:SystemRoot\System32\CodeIntegrity\SiPolicy.p7b"

# 7. List existing policies in CiTool - Expect ONLY built-in Microsoft Platform policies (IsSystemPolicy = true)
(& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies |
    Select-Object PolicyID, FriendlyName, IsSystemPolicy, IsEnforced, IsAuthorized |
    Format-Table -AutoSize

# 8. Install every application you need on this PAW NOW (before any audit policy is loaded).
#    Do NOT launch any application you intend to keep blocked.
