# PowerShell 7 edition - run in an elevated "pwsh" window (ConfigCI loads through the Windows PowerShell compatibility layer).
# Step 1.1: run right AFTER the App Control Policy Wizard saved Base-Audit.xml (Step 1) and BEFORE 1_compile_and_deploy.ps1.
# Checks the Wizard output against this guide (multiple-policy format, rule options including Option 13 Managed Installer,
# both recommended block lists) and fixes what it safely can. A backup is saved before any change, the result is proven
# with a real compile, and CiTool.exe is never called (nothing is deployed).
param(
    [string]$BaseXml = 'C:\WDAC\Source\Base-Audit.xml',
    # Remove the 6 WSL deny rules that the Recommended User Mode Block Rules add (bash.exe, lxrun.exe, LxssManager.dll,
    # wsl.exe, wslconfig.exe, wslhost.exe). Deny always beats allow, so without this switch WSL is blocked once enforced.
    [switch]$AllowWSL,
    # Optional: regex for the application you intend to keep BLOCKED. Warns if the base policy text already matches it,
    # because scripts 4 and 6 would then stop on a false positive.
    [string]$ExcludedAppPattern = '',
    [switch]$ReportOnly
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Module ConfigCI)) { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop }
if (-not (Test-Path -LiteralPath $BaseXml)) { throw "STOP: $BaseXml not found. Create it with the App Control Policy Wizard first (Step 1)." }

# Options this guide requires ON / OFF. Option 13 (Managed Installer) is ON: MECM / Intune is the managed installer.
$RequiredOn = @(
    [pscustomobject]@{ Rule = 0;  Option = 'Enabled:UMCI' }
    [pscustomobject]@{ Rule = 2;  Option = 'Required:WHQL' }
    [pscustomobject]@{ Rule = 3;  Option = 'Enabled:Audit Mode' }
    [pscustomobject]@{ Rule = 6;  Option = 'Enabled:Unsigned System Integrity Policy' }
    [pscustomobject]@{ Rule = 9;  Option = 'Enabled:Advanced Boot Options Menu' }
    [pscustomobject]@{ Rule = 10; Option = 'Enabled:Boot Audit On Failure' }
    [pscustomobject]@{ Rule = 11; Option = 'Disabled:Script Enforcement' }
    [pscustomobject]@{ Rule = 13; Option = 'Enabled:Managed Installer' }
    [pscustomobject]@{ Rule = 16; Option = 'Enabled:Update Policy No Reboot' }
    [pscustomobject]@{ Rule = 17; Option = 'Enabled:Allow Supplemental Policies' }
)
$RequiredOff = @(
    [pscustomobject]@{ Rule = 14; Option = 'Enabled:Intelligent Security Graph Authorization' }
    [pscustomobject]@{ Rule = 15; Option = 'Enabled:Invalidate EAs on Reboot' }
    [pscustomobject]@{ Rule = 18; Option = 'Disabled:Runtime FilePath Rule Protection' }
    [pscustomobject]@{ Rule = 19; Option = 'Enabled:Dynamic Code Security' }
    [pscustomobject]@{ Rule = 20; Option = 'Enabled:Revoked Expired As Unsigned' }
)
$WslDenyFiles = 'bash.exe', 'lxrun.exe', 'LxssManager.dll', 'wsl.exe', 'wslconfig.exe', 'wslhost.exe'

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Status, [string]$Check, [string]$Detail) {
    $Findings.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail })
}

[xml]$Doc = Get-Content -LiteralPath $BaseXml -Raw
$Si = $Doc.SiPolicy
$Ns = New-Object System.Xml.XmlNamespaceManager $Doc.NameTable
$Ns.AddNamespace('s', 'urn:schemas-microsoft-com:sipolicy')

# 1. Multiple-policy format base policy (cannot be fixed here - recreate it in the Wizard)
if ($Si.PolicyType -ne 'Base Policy') { Add-Finding 'FAIL' 'PolicyType' "is '$($Si.PolicyType)'; it must be 'Base Policy'" }
elseif (-not $Si.PolicyID -or $Si.PolicyID -ne $Si.BasePolicyID) { Add-Finding 'FAIL' 'Multiple Policy Format' "PolicyID '$($Si.PolicyID)' must equal BasePolicyID '$($Si.BasePolicyID)' (choose Multiple Policy Format in the Wizard)" }
else { Add-Finding 'OK' 'Multiple Policy Format' "Base Policy, PolicyID = BasePolicyID = $($Si.PolicyID)" }

# 2. Rule options
$Opts = @($Si.Rules.Rule.Option)
$ToEnable = @($RequiredOn | Where-Object { $Opts -notcontains $_.Option })
$ToDisable = @($RequiredOff | Where-Object { $Opts -contains $_.Option })
foreach ($O in $ToEnable) { Add-Finding 'FIX' "Option $($O.Rule)" "$($O.Option) is missing - will be turned ON" }
foreach ($O in $ToDisable) { Add-Finding 'FIX' "Option $($O.Rule)" "$($O.Option) is present - will be turned OFF" }
if ($ToEnable.Count + $ToDisable.Count -eq 0) { Add-Finding 'OK' 'Rule options' 'all 10 required options ON (incl. 13 Managed Installer); all 5 forbidden options OFF' }

# 3. Both recommended block lists merged (Step 1, File Rules screen)
$DenyIds = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($D in @($Doc.SelectNodes('//s:FileRules/s:Deny', $Ns))) { [void]$DenyIds.Add($D.GetAttribute('ID')) }
foreach ($Scenario in @(@{ Value = '12'; Name = 'Recommended User Mode Block Rules' }, @{ Value = '131'; Name = 'Recommended Kernel Mode Block Rules' })) {
    $Refs = @($Doc.SelectNodes("//s:SigningScenario[@Value='$($Scenario.Value)']//s:FileRuleRef", $Ns) | Where-Object { $DenyIds.Contains($_.GetAttribute('RuleID')) })
    $DeniedSigners = @($Doc.SelectNodes("//s:SigningScenario[@Value='$($Scenario.Value)']//s:DeniedSigner", $Ns))
    if ($Refs.Count + $DeniedSigners.Count -gt 0) { Add-Finding 'OK' $Scenario.Name "$($Refs.Count) deny file rule(s), $($DeniedSigners.Count) denied signer(s) in scenario $($Scenario.Value)" }
    else { Add-Finding 'WARN' $Scenario.Name "no deny rules in scenario $($Scenario.Value) - re-check the merge box on the Wizard's File Rules screen" }
}

# 4. WSL deny rules from the Recommended User Mode Block Rules
$WslRules = @($Doc.SelectNodes('//s:FileRules/s:Deny', $Ns) | Where-Object { $WslDenyFiles -contains $_.GetAttribute('FileName') })
if ($WslRules.Count -eq 0) { Add-Finding 'OK' 'WSL deny rules' 'none present' }
elseif ($AllowWSL) { foreach ($R in $WslRules) { Add-Finding 'FIX' "Deny $($R.GetAttribute('ID'))" "$($R.GetAttribute('FileName')) - will be removed (-AllowWSL)" } }
else { Add-Finding 'WARN' 'WSL deny rules' "$($WslRules.Count) present ($(($WslRules | ForEach-Object { $_.GetAttribute('FileName') }) -join ', ')) - WSL will be BLOCKED once enforced. Re-run with -AllowWSL if WSL must keep working." }

# 5. The block-test application must not already match the base policy (scripts 4 and 6 would stop on a false positive)
if ($ExcludedAppPattern) {
    if ((Get-Content -LiteralPath $BaseXml -Raw) -match $ExcludedAppPattern) { Add-Finding 'WARN' 'ExcludedAppPattern' "'$ExcludedAppPattern' already matches text in $BaseXml - pick a more specific pattern" }
    else { Add-Finding 'OK' 'ExcludedAppPattern' "'$ExcludedAppPattern' does not match the base policy" }
}

# ---------------------------------------------------------------- report
$Findings | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
$LogDir = 'C:\WDAC\Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
$LogFile = Join-Path $LogDir "Base-Audit-Validate-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Findings | Export-Csv -LiteralPath $LogFile -NoTypeInformation
Write-Host "Findings log: $LogFile" -ForegroundColor Cyan

if (@($Findings | Where-Object Status -eq 'FAIL').Count -gt 0) { throw "STOP: $BaseXml is not a Multiple-Policy-Format base policy. Recreate it in the Wizard (Step 1) and re-run." }

function Test-Compile([string]$XmlPath) {
    $Work = Join-Path ([IO.Path]::GetTempPath()) ('wdac_validate_' + [guid]::NewGuid().ToString('N'))
    New-Item -Path $Work -ItemType Directory -Force | Out-Null
    try { ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath (Join-Path $Work 'test.cip') -ErrorAction Stop | Out-Null }
    finally { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
}

$Fixes = @($Findings | Where-Object Status -eq 'FIX')
$Warnings = @($Findings | Where-Object Status -eq 'WARN').Count
$WarnText = if ($Warnings) { " Review the $Warnings WARN finding(s) above before continuing." } else { '' }
if ($Fixes.Count -eq 0 -or $ReportOnly) {
    try { Test-Compile $BaseXml } catch { throw "STOP: $BaseXml does not compile: $($_.Exception.Message)" }
    if ($Fixes.Count -eq 0 -and -not $Warnings) { Write-Host "PASSED: $BaseXml matches this guide and compiles. No changes were needed." -ForegroundColor Green }
    elseif ($Fixes.Count -eq 0) { Write-Host "PASSED with warnings: $BaseXml compiles and was not changed.$WarnText" -ForegroundColor Yellow }
    else { Write-Host "PASSED (-ReportOnly): $BaseXml compiles; $($Fixes.Count) fix(es) above were NOT applied.$WarnText" -ForegroundColor Yellow }
    return
}

$Backup = Join-Path (Split-Path -Parent $BaseXml) ([IO.Path]::GetFileNameWithoutExtension($BaseXml) + ".wizard-original-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml")
Copy-Item -LiteralPath $BaseXml -Destination $Backup -ErrorAction Stop
foreach ($O in $ToEnable) { Set-RuleOption -FilePath $BaseXml -Option $O.Rule -ErrorAction Stop }
foreach ($O in $ToDisable) { Set-RuleOption -FilePath $BaseXml -Option $O.Rule -Delete -ErrorAction Stop }
if ($AllowWSL) { foreach ($R in $WslRules) { Remove-CIPolicyRule -FilePath $BaseXml -Id $R.GetAttribute('ID') -ErrorAction Stop | Out-Null } }

try { Test-Compile $BaseXml }
catch {
    Copy-Item -LiteralPath $Backup -Destination $BaseXml -Force
    throw "STOP: the fixed policy does not compile ($($_.Exception.Message)). $BaseXml was restored from $Backup."
}
Write-Host "PASSED: $($Fixes.Count) fix(es) applied to $BaseXml and it compiles. Original saved as $Backup.$WarnText" -ForegroundColor $(if ($Warnings) { 'Yellow' } else { 'Green' })
