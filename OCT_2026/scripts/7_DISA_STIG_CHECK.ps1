# Official DISA STIG Check (must be run in an elevated PowerShell session)
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'Run the STIG check in an elevated PowerShell session (Run as administrator).' }

$DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$DG | Format-List *codeintegrity*

Write-Host "V-243450 (CodeIntegrityPolicyEnforcementStatus)         : $($DG.CodeIntegrityPolicyEnforcementStatus) $(if ($DG.CodeIntegrityPolicyEnforcementStatus -eq 2) { '[PASS - NOT A FINDING]' } else { '[OPEN FINDING]' })" -ForegroundColor $(if ($DG.CodeIntegrityPolicyEnforcementStatus -eq 2) { 'Green' } else { 'Red' })
Write-Host "V-243451 (UsermodeCodeIntegrityPolicyEnforcementStatus) : $($DG.UsermodeCodeIntegrityPolicyEnforcementStatus) $(if ($DG.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) { '[PASS - NOT A FINDING]' } else { '[OPEN FINDING]' })" -ForegroundColor $(if ($DG.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) { 'Green' } else { 'Red' })
