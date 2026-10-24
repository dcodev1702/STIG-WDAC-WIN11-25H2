# Official DISA STIG Check (must be run in an elevated PowerShell session)
# Microsoft Windows PAW STIG - App Control for Business (WDAC):
#   V-243450 (STIG ID WPAW-00-001050, CAT II)  Win32_DeviceGuard CodeIntegrityPolicyEnforcementStatus         = 2
#   V-243451 (STIG ID WPAW-00-001060, CAT II)  Win32_DeviceGuard UsermodeCodeIntegrityPolicyEnforcementStatus = 2
# Values: 0 = OFF, 1 = AUDIT, 2 = ENFORCING (DISA: Not Configured / Audit / Enforced); only 2 passes. The report also shows the
# system, the active App Control policies (CiTool) and, per finding, which policy produces the value and what to do next.
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) { throw 'Run the STIG check in an elevated PowerShell session (Run as administrator).' }

$DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
if (-not $DG) { throw 'Win32_DeviceGuard returned no data on this system.' }
$Kmci = [int]$DG.CodeIntegrityPolicyEnforcementStatus
$Umci = [int]$DG.UsermodeCodeIntegrityPolicyEnforcementStatus

# ---------------------------------------------------------------- output helpers
$Width = 120
try { $Cols = $Host.UI.RawUI.WindowSize.Width; if ($Cols -ge 100) { $Width = [math]::Min($Cols, 160) } } catch { }
function Get-CiModeText([int]$Value) { switch ($Value) { 0 { 'OFF' } 1 { 'AUDIT' } 2 { 'ENFORCING' } default { 'UNKNOWN' } } }
function Get-CiModeColor([int]$Value) { switch ($Value) { 2 { 'Green' } 1 { 'Yellow' } default { 'Red' } } }
function Write-Line([string]$Char = '-', [string]$Color = 'DarkGray') { Write-Host ($Char * ($Width - 1)) -ForegroundColor $Color }
function Write-Section([string]$Title, [string]$Note = '') {
    Write-Host ''
    Write-Host " $Title" -ForegroundColor Cyan -NoNewline
    if ($Note) { Write-Host "   $Note" -ForegroundColor DarkGray } else { Write-Host '' }
    Write-Line
}
# Writes $Tokens joined by spaces, wrapped to the window; continuation lines are indented to the end of $Prefix
function Write-Wrapped([string]$Prefix, [string[]]$Tokens, [string]$Color = 'Gray', [string]$PrefixColor = '') {
    $Lines = New-Object System.Collections.Generic.List[string]; $Line = ''
    $Room = [math]::Max(30, $Width - 1 - $Prefix.Length)
    foreach ($Token in $Tokens) {
        if (-not $Token) { continue }
        if ($Line -and ($Line.Length + 1 + $Token.Length) -gt $Room) { $Lines.Add($Line); $Line = $Token }
        else { $Line = if ($Line) { "$Line $Token" } else { $Token } }
    }
    if ($Line -or $Lines.Count -eq 0) { $Lines.Add($Line) }
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $Lead = if ($i -eq 0) { $Prefix } else { ' ' * $Prefix.Length }
        if ($i -eq 0 -and $PrefixColor) { Write-Host $Lead -ForegroundColor $PrefixColor -NoNewline; Write-Host $Lines[$i] -ForegroundColor $Color }
        else { Write-Host ($Lead + $Lines[$i]) -ForegroundColor $Color }
    }
}
# One "label  value" row; the value wraps under itself
function Write-KV([string]$Label, [string]$Value, [string]$Color = 'Gray') { Write-Wrapped ('   ' + $Label.PadRight(16)) ($Value -split ' ') $Color 'DarkGray' }
# A table: column widths fit the longest cell. -RowColorKey colours a whole row (written as ONE line, so transcripts keep it);
# otherwise -ColorColumn / -ColorKey colour one cell per row.
function Write-Table($Data, [string[]]$Header, [string[]]$Keys, [string]$RowColorKey = '', [int]$ColorColumn = -1, [string]$ColorKey = '') {
    $Rows = @($Data | ForEach-Object { $_ })
    $W = @(); for ($c = 0; $c -lt $Keys.Count; $c++) { $Max = $Header[$c].Length; foreach ($R in $Rows) { $L = "$($R.($Keys[$c]))".Length; if ($L -gt $Max) { $Max = $L } }; $W += $Max }
    $Cells = { param($Values) $Out = ''; for ($c = 0; $c -lt $Values.Count; $c++) { $Out += $(if ($c -lt $Values.Count - 1) { "$($Values[$c])".PadRight($W[$c]) + '  ' } else { "$($Values[$c])" }) }; $Out }
    Write-Host ('   ' + (& $Cells $Header)) -ForegroundColor White
    Write-Host ('   ' + (& $Cells @($W | ForEach-Object { '-' * $_ }))) -ForegroundColor DarkGray
    foreach ($R in $Rows) {
        $Values = @($Keys | ForEach-Object { $R.$_ })
        if ($RowColorKey) { Write-Host ('   ' + (& $Cells $Values)) -ForegroundColor $R.$RowColorKey; continue }
        Write-Host '   ' -NoNewline
        for ($c = 0; $c -lt $Values.Count; $c++) {
            $Text = if ($c -lt $Values.Count - 1) { "$($Values[$c])".PadRight($W[$c]) + '  ' } else { "$($Values[$c])" }
            Write-Host $Text -ForegroundColor $(if ($c -eq $ColorColumn -and $ColorKey -and $R.$ColorKey) { $R.$ColorKey } else { 'Gray' }) -NoNewline
        }
        Write-Host ''
    }
}

# ---------------------------------------------------------------- system facts
$OS = Get-CimInstance -ClassName Win32_OperatingSystem
$CS = Get-CimInstance -ClassName Win32_ComputerSystem
$Release = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
$Now = Get-Date
$Up = $Now - $OS.LastBootUpTime
# Interactive users from quser (console, RDP, Hyper-V enhanced session); the domain comes from the owner of explorer.exe in the
# same session. A session name can start with a digit, and a disconnected session has none.
$Sessions = @()
$Owners = @{}
foreach ($Pr in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
    try { $O = Invoke-CimMethod -InputObject $Pr -MethodName GetOwner -ErrorAction Stop; if ($O.User) { $Owners["$($Pr.SessionId)"] = "$($O.Domain)\$($O.User)" } } catch { }
}
try { $Quser = @(& "$env:SystemRoot\System32\quser.exe" 2>$null) } catch { $Quser = @() }
foreach ($L in @($Quser | Select-Object -Skip 1)) {
    if ($L -match '^\s*>?(?<user>\S+)\s+(?:(?<session>\S+)\s+)?(?<id>\d+)\s+(?<state>\S+)\s+(?<idle>\S+)\s+(?<logon>.+?)\s*$') {
        $Who = if ($Owners.ContainsKey($Matches.id)) { $Owners[$Matches.id] } else { $Matches.user }
        $Sessions += "$Who ($($Matches.state), since $($Matches.logon))"
    }
}
if (-not $Sessions -and $CS.UserName) { $Sessions = @("$($CS.UserName) (console)") }
if (-not $Sessions) { $Sessions = @('nobody (no interactive session)') }
$PsExe = try { (Get-Process -Id $PID).Path } catch { '' }
$System = @(
    @(@('Computer', "$env:COMPUTERNAME$(if ($CS.PartOfDomain) { " ($($CS.Domain))" })"), @('Checked', ('{0} (UTC{1})' -f $Now.ToString('yyyy-MM-dd HH:mm:ss'), $Now.ToString('zzz')))),
    @(@('Windows', "$($OS.Caption -replace '^Microsoft ', '') $Release ($($OS.BuildNumber))"), @('Uptime', ('{0} d {1} h {2} min (boot {3})' -f $Up.Days, $Up.Hours, $Up.Minutes, $OS.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')))),
    @(@('Logged on', ($Sessions -join '; ')), @('PowerShell', "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))$(if ($PsExe) { " $PsExe" })")),
    @(@('Run by', "$([Security.Principal.WindowsIdentity]::GetCurrent().Name) (elevated)"), $null)
)

# ---------------------------------------------------------------- policies loaded on this device (CiTool)
$CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
$ActiveDir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
$All = @(); $CiError = ''
if (Test-Path -LiteralPath $CiTool) {
    try { $All = @(((& $CiTool --list-policies -json) -join "`n" | ConvertFrom-Json).Policies) }
    catch { $CiError = "CiTool --list-policies failed: $($_.Exception.Message)" }
}
else { $CiError = 'CiTool.exe was not found (Windows 11 22H2 or later) - policy details are not available.' }
$Rows = @(foreach ($P in $All) {
    $Opts = @($P.PolicyOptions | Where-Object { $_ })
    $Audit = $Opts -contains 'Enabled:Audit Mode'
    [pscustomobject]@{
        Name = $(if ($P.FriendlyName) { [string]$P.FriendlyName } else { "{$(([string]$P.PolicyID).ToUpper())}" }); Version = [string]$P.VersionString
        Id = "{$(([string]$P.PolicyID).ToUpper())}"; BaseId = "{$(([string]$P.BasePolicyID).ToUpper())}"; IsBase = ($P.PolicyID -eq $P.BasePolicyID)
        IsSystem = [bool]$P.IsSystemPolicy; Active = [bool]$P.IsEnforced; Authorized = [bool]$P.IsAuthorized
        Options = $Opts; Umci = ($Opts -contains 'Enabled:UMCI'); Audit = $Audit; Mode = $(if ($Audit) { 1 } else { 2 })
    }
})
# CiTool's IsEnforced means "loaded and in effect"; the audit/enforce mode comes from the Enabled:Audit Mode option
$OrgBases = @($Rows | Where-Object { $_.Active -and -not $_.IsSystem -and $_.IsBase })
$OrgSupps = @($Rows | Where-Object { $_.Active -and -not $_.IsSystem -and -not $_.IsBase })
$OrgInactive = @($Rows | Where-Object { -not $_.Active -and -not $_.IsSystem })
$SysBases = @($Rows | Where-Object { $_.Active -and $_.IsSystem -and $_.IsBase } | Sort-Object @{ Expression = 'Mode'; Descending = $true }, Name)
$SysSupps = @($Rows | Where-Object { $_.Active -and $_.IsSystem -and -not $_.IsBase })
$OrgUmEnf = @($OrgBases | Where-Object { $_.Umci -and -not $_.Audit })
$OrgUmAud = @($OrgBases | Where-Object { $_.Umci -and $_.Audit })
$OrgKmEnf = @($OrgBases | Where-Object { -not $_.Audit })
$SysKmEnf = @($SysBases | Where-Object { -not $_.Audit })
$Sac = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$SacText = switch ($Sac) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation' } default { '' } }
function Get-Scope($Row) { if ($Row.Umci) { 'kernel + user' } else { 'kernel only' } }
function Get-Label($Row) { "$($Row.Name) v$($Row.Version)" }
$OptionNumber = @{
    'Enabled:UMCI' = 0; 'Enabled:Boot Menu Protection' = 1; 'Required:WHQL' = 2; 'Enabled:Audit Mode' = 3; 'Disabled:Flight Signing' = 4
    'Enabled:Inherit Default Policy' = 5; 'Enabled:Unsigned System Integrity Policy' = 6; 'Allowed:Debug Policy Augmented' = 7; 'Required:EV Signers' = 8
    'Enabled:Advanced Boot Options Menu' = 9; 'Enabled:Boot Audit On Failure' = 10; 'Disabled:Script Enforcement' = 11; 'Required:Enforce Store Applications' = 12
    'Enabled:Managed Installer' = 13; 'Enabled:Intelligent Security Graph Authorization' = 14; 'Enabled:Invalidate EAs on Reboot' = 15
    'Enabled:Update Policy No Reboot' = 16; 'Enabled:Allow Supplemental Policies' = 17; 'Disabled:Runtime FilePath Rule Protection' = 18
    'Enabled:Dynamic Code Security' = 19; 'Enabled:Revoked Expired As Unsigned' = 20
}

# ================================================================ header + system
Write-Host ''
Write-Line '='
Write-Host ' DISA STIG CHECK - App Control for Business (WDAC)' -ForegroundColor Cyan -NoNewline
Write-Host '   Microsoft Windows PAW STIG  V-243450 / V-243451' -ForegroundColor DarkGray
Write-Line '='
Write-Section 'SYSTEM'
$LeftW = [math]::Min(58, [int](@($System | ForEach-Object { $_[0][1].Length }) | Measure-Object -Maximum).Maximum)
foreach ($Pair in $System) {
    $Left = '   ' + $Pair[0][0].PadRight(12) + $Pair[0][1]
    $Two = ($Pair[1] -and $Width -ge 120 -and $Pair[0][1].Length -le $LeftW)
    if ($Two) {
        Write-Host ('   ' + $Pair[0][0].PadRight(12)) -ForegroundColor DarkGray -NoNewline; Write-Host $Pair[0][1].PadRight($LeftW + 4) -NoNewline
        Write-Host $Pair[1][0].PadRight(12) -ForegroundColor DarkGray -NoNewline; Write-Host $Pair[1][1]
    }
    else {
        foreach ($Item in @($Pair | Where-Object { $_ })) { Write-Wrapped ('   ' + $Item[0].PadRight(12)) ($Item[1] -split ' ') 'Gray' 'DarkGray' }
    }
}

# ================================================================ STIG results (one row per finding)
Write-Section 'STIG RESULTS' 'Win32_DeviceGuard: 0 = OFF, 1 = AUDIT, 2 = ENFORCING - only 2 passes'
$Results = @(
    [pscustomobject]@{ Vuln = 'V-243450'; Stig = 'WPAW-00-001050'; Cat = 'II'; Scope = 'Kernel mode'; Property = 'CodeIntegrityPolicyEnforcementStatus'; Value = "$Kmci ($(Get-CiModeText $Kmci))"; Result = $(if ($Kmci -eq 2) { 'PASS (Not a Finding)' } else { 'OPEN FINDING' }); Color = $(if ($Kmci -eq 2) { 'Green' } else { 'Red' }) }
    [pscustomobject]@{ Vuln = 'V-243451'; Stig = 'WPAW-00-001060'; Cat = 'II'; Scope = 'User mode'; Property = 'UsermodeCodeIntegrityPolicyEnforcementStatus'; Value = "$Umci ($(Get-CiModeText $Umci))"; Result = $(if ($Umci -eq 2) { 'PASS (Not a Finding)' } else { 'OPEN FINDING' }); Color = $(if ($Umci -eq 2) { 'Green' } else { 'Red' }) }
)
Write-Table $Results @('Vuln ID', 'STIG ID', 'CAT', 'Checks', 'Win32_DeviceGuard property', 'Value', 'Result') @('Vuln', 'Stig', 'Cat', 'Scope', 'Property', 'Value', 'Result') -RowColorKey 'Color'

# ================================================================ findings, grouped by STIG ID
function Write-FindingHeader([string]$Head, [int]$Value) {
    $Tail = '{0,-14} {1,-12}' -f "$Value ($(Get-CiModeText $Value))", $(if ($Value -eq 2) { 'PASS' } else { 'OPEN FINDING' })
    Write-Host ''
    Write-Host (' ' + $Head.PadRight([math]::Max($Head.Length + 2, $Width - 2 - $Tail.Length)) + $Tail) -ForegroundColor $(if ($Value -eq 2) { 'Green' } else { 'Red' })
    Write-Line
}
Write-Section 'FINDINGS' 'which policies produce each value, and what to do next'
Write-FindingHeader 'V-243450 | WPAW-00-001050 | CAT II | Kernel-mode code integrity' $Kmci
Write-KV 'Checks' 'CodeIntegrityPolicyEnforcementStatus - which drivers and other kernel-mode code may load'
Write-KV 'Passes when' 'an active base policy enforces kernel mode (option 3, Enabled:Audit Mode, OFF). Every App Control policy covers kernel mode.'
if ($Rows) {
    $KmList = @($OrgKmEnf | ForEach-Object { "$(Get-Label $_) (organization)" }) + @($SysKmEnf | ForEach-Object { "$($_.Name) (Windows built-in)" })
    if (-not $KmList) { $KmList = @('none') }
    $First = $true; foreach ($K in $KmList) { Write-KV $(if ($First) { 'Enforced by' } else { '' }) $K 'White'; $First = $false }
    if ($Kmci -eq 2 -and -not $OrgKmEnf) { Write-KV 'Note' "Windows' built-in policies enforce kernel mode, so this value often reads 2 before an organization policy exists." }
    if ($Kmci -ne 2 -and $OrgKmEnf) { Write-KV 'WARNING' "an organization policy enforces kernel mode but Win32_DeviceGuard reports $Kmci ($(Get-CiModeText $Kmci)). Restart the device to complete activation, then run this check again." 'Yellow' }
}
if ($Kmci -eq 1) { Write-KV 'Next step' 'kernel mode is only audited. Deploy the organization base policy with option 3 (Enabled:Audit Mode) OFF.' 'Yellow' }
if ($Kmci -eq 0) { Write-KV 'Next step' 'no App Control policy is in effect. Deploy the organization base policy with option 3 (Enabled:Audit Mode) OFF.' 'Yellow' }

Write-FindingHeader 'V-243451 | WPAW-00-001060 | CAT II | User-mode code integrity (UMCI)' $Umci
Write-KV 'Checks' 'UsermodeCodeIntegrityPolicyEnforcementStatus - which applications, DLLs and installers may run'
Write-KV 'Passes when' 'a base policy with option 0 (Enabled:UMCI) ON and option 3 (Enabled:Audit Mode) OFF is active'
Write-KV 'Effect now' $(switch ($Umci) { 2 { 'ENFORCING - files the policy does not allow are blocked (Event 3077)' } 1 { 'AUDIT - Event 3076 records what would be blocked; nothing is blocked' } default { 'OFF - user-mode code is not checked' } }) (Get-CiModeColor $Umci)
if ($Rows) {
    $First = $true; foreach ($B in $OrgUmEnf) { Write-KV $(if ($First) { 'Delivered by' } else { '' }) "$(Get-Label $B) $($B.Id) - organization base policy, ENFORCING" 'White'; $First = $false }
    $First = $true; foreach ($B in $OrgUmAud) { Write-KV $(if ($First) { 'In AUDIT' } else { '' }) "$(Get-Label $B) $($B.Id) - organization base policy, Audit Mode ON" 'Yellow'; $First = $false }
    if ($Umci -ne 2 -and $OrgUmEnf) { Write-KV 'WARNING' "an organization policy enforces user mode but Win32_DeviceGuard reports $Umci ($(Get-CiModeText $Umci)). Restart the device to complete activation, then run this check again." 'Yellow' }
    if ($Umci -eq 2 -and -not $OrgUmEnf) { Write-KV 'Note' 'no organization base policy enforces user mode, so the value comes from another policy (for example a Windows built-in one) or from a change that is not in effect yet. Deploy the enforced organization policy so the result does not depend on Windows defaults.' 'Yellow' }
    if ($Umci -eq 1 -and -not $OrgUmAud -and $Sac -eq 2) { Write-KV 'Source' 'no organization policy covers user mode. Smart App Control is in Evaluation, which audits user mode - the usual reason for a starting value of 1.' 'Yellow' }
}
if ($Umci -ne 2 -and -not $OrgUmEnf) {
    Write-KV 'Next step' $(if ($OrgUmAud) { 'turn option 3 (Enabled:Audit Mode) OFF in the organization base policy and deploy the enforced version.' } else { 'deploy an organization base policy with option 0 (Enabled:UMCI) ON and option 3 (Enabled:Audit Mode) OFF.' }) 'Yellow'
}

# ================================================================ policies in effect
Write-Section 'ORGANIZATION POLICIES' 'deployed by your organization (CiTool --list-policies)'
if ($CiError) { Write-KV 'Not available' $CiError 'Yellow' }
else {
    $OrgTable = New-Object System.Collections.Generic.List[object]
    foreach ($B in $OrgBases) {
        $OrgTable.Add([pscustomobject]@{ Type = 'Base'; Name = $B.Name; Version = $B.Version; Mode = (Get-CiModeText $B.Mode); Scope = (Get-Scope $B); Status = $(if ($B.Authorized) { 'active' } else { 'NOT AUTHORIZED' }); Id = $B.Id; Color = (Get-CiModeColor $B.Mode) })
        foreach ($S in @($OrgSupps | Where-Object { $_.BaseId -eq $B.Id })) { $OrgTable.Add([pscustomobject]@{ Type = 'Supplemental'; Name = $S.Name; Version = $S.Version; Mode = "(base's)"; Scope = 'adds allow rules'; Status = $(if ($S.Authorized) { 'active' } else { 'NOT AUTHORIZED' }); Id = $S.Id; Color = 'Gray' }) }
    }
    $OrgBaseIds = @($OrgBases | ForEach-Object { $_.Id })
    foreach ($S in @($OrgSupps | Where-Object { $OrgBaseIds -notcontains $_.BaseId })) { $OrgTable.Add([pscustomobject]@{ Type = 'Supplemental'; Name = $S.Name; Version = $S.Version; Mode = '-'; Scope = "base $($S.BaseId) not active"; Status = 'orphan'; Id = $S.Id; Color = 'Yellow' }) }
    foreach ($I in $OrgInactive) { $OrgTable.Add([pscustomobject]@{ Type = $(if ($I.IsBase) { 'Base' } else { 'Supplemental' }); Name = $I.Name; Version = $I.Version; Mode = '-'; Scope = '-'; Status = 'NOT IN EFFECT (restart?)'; Id = $I.Id; Color = 'Yellow' }) }
    if ($OrgTable.Count) { Write-Table $OrgTable @('Type', 'Name', 'Version', 'Mode', 'Scope', 'Status', 'Policy ID') @('Type', 'Name', 'Version', 'Mode', 'Scope', 'Status', 'Id') -ColorColumn 3 -ColorKey 'Color' }
    else { Write-Host '   none - only the Windows built-in policies below are in effect' -ForegroundColor Yellow }
    foreach ($B in $OrgBases) {
        # Rule options as a numbered grid, two columns, sorted by option number
        $Opt = @($B.Options | ForEach-Object { [pscustomobject]@{ N = $(if ($OptionNumber.ContainsKey($_)) { $OptionNumber[$_] } else { 99 }); Text = $_ } } | Sort-Object N, Text)
        Write-Host ''
        Write-Host "   $(Get-Label $B)  -  $($Opt.Count) rule options" -ForegroundColor White
        $File = Get-Item -LiteralPath (Join-Path $ActiveDir "$($B.Id).cip") -ErrorAction SilentlyContinue
        if ($File) { Write-KV 'Policy file' "CiPolicies\Active\$($File.Name) (written $($File.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))" }
        $Half = [int][math]::Ceiling($Opt.Count / 2)
        $Cell = { param($O) if ($O) { '{0,2}  {1}' -f $(if ($O.N -eq 99) { '-' } else { $O.N }), $O.Text } else { '' } }
        $ColW = [int](@($Opt | ForEach-Object { (& $Cell $_).Length }) + 0 | Measure-Object -Maximum).Maximum + 4
        for ($i = 0; $i -lt $Half; $i++) {
            $L = & $Cell $Opt[$i]; $R = if ($i + $Half -lt $Opt.Count) { & $Cell $Opt[$i + $Half] } else { '' }
            Write-Host ('   ' + $(if ($i -eq 0) { 'Rule options'.PadRight(16) } else { ''.PadRight(16) })) -ForegroundColor DarkGray -NoNewline
            Write-Host ($L.PadRight($ColW) + $R)
        }
    }
}
Write-Section 'WINDOWS BUILT-IN POLICIES' 'Microsoft-signed system policies (IsSystemPolicy)'
if ($CiError) { Write-KV 'Not available' $CiError 'Yellow' }
else {
    $SysTable = @($SysBases | ForEach-Object { [pscustomobject]@{ Mode = (Get-CiModeText $_.Mode); Scope = (Get-Scope $_); Version = $_.Version; Name = "$($_.Name)$(if ($_.Name -like 'VerifiedAndReputableDesktop*') { " (Smart App Control$(if ($SacText) { ": $SacText" }))" })"; Color = (Get-CiModeColor $_.Mode) } })
    if ($SysTable) { Write-Table $SysTable @('Mode', 'Scope', 'Version', 'Name') @('Mode', 'Scope', 'Version', 'Name') -ColorColumn 0 -ColorKey 'Color' } else { Write-Host '   none' }
    if ($SysSupps) { Write-KV 'Supplementals' "$((@($SysSupps | ForEach-Object { $_.Name })) -join ', ') ($($SysSupps.Count))" 'DarkGray' }
}

# ================================================================ result
$Pass = ($Kmci -eq 2 -and $Umci -eq 2)
$Open = @(@($Kmci, $Umci) | Where-Object { $_ -ne 2 }).Count
Write-Host ''
Write-Line '='
Write-Host (' RESULT   {0} / {1} = {2} / {3}   V-243450 {4}   V-243451 {5}   ({6})' -f $Kmci, $Umci, (Get-CiModeText $Kmci), (Get-CiModeText $Umci), $(if ($Kmci -eq 2) { 'PASS' } else { 'OPEN FINDING' }), $(if ($Umci -eq 2) { 'PASS' } else { 'OPEN FINDING' }), $(if ($Open) { "$Open open finding$(if ($Open -gt 1) { 's' })" } else { 'no open findings' })) -ForegroundColor $(if ($Pass) { 'Green' } else { 'Red' })
if ($OrgBases) {
    $First = $true
    foreach ($B in $OrgBases) { Write-Wrapped $(if ($First) { ' Policy   ' } else { '          ' }) ("$(Get-Label $B) ($(Get-CiModeText $B.Mode)) $($B.Id)" -split ' ') 'White' 'DarkGray'; $First = $false }
    foreach ($S in $OrgSupps) { Write-Wrapped '          ' ("+ supplemental $(Get-Label $S)" -split ' ') 'Gray' }
    if ($OrgBases.Count -gt 1) { Write-Wrapped '          ' ("$($OrgBases.Count) organization base policies are active: a file must be allowed by EVERY base policy to run." -split ' ') 'Yellow' }
}
elseif (-not $CiError) { Write-Host ' Policy   none (Windows built-in policies only)' -ForegroundColor Yellow }
Write-Line '='
Write-Host ''
