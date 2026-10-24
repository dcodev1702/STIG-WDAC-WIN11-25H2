# Works in PowerShell 7 and Windows PowerShell 5.1 (no ConfigCI needed) - run elevated, after (or during) the workflow.
# Builds ONE self-contained HTML run report (inline CSS, no scripts, no external resources) from the guide's working folders
# and the live system. No application names are hard-coded.
#   - STIG values: current, plus every value found in C:\WDAC\Logs transcripts (= the stage-by-stage progression)
#   - active custom policies (CiTool), each policy XML stage, compiled .cip hashes
#   - every FilePath rule and whether Windows will honor it (admin-writable-only check)
#   - managed installer (MECM / Intune) readiness
#   - latest 0_1 / 3_1 findings, and EVERY 3076 / 3077 event (via Export-CIEventEvidence.ps1)
#
#   .\New-WDACRunReport.ps1
#   .\New-WDACRunReport.ps1 -BlockTestPattern 'MyBlockedApp' -NotesMarkdown 'C:\WDAC\Logs\My-Run-Notes.md'
param(
    [string]$OutHtml,
    [string]$Title = 'App Control (WDAC) STIG Run Report',
    # Optional regex for the application you intend to keep BLOCKED; its 3077 rows are labeled "expected".
    [string]$BlockTestPattern = '',
    # Optional Markdown file (for example your own run notes) rendered at the end of the report.
    [string]$NotesMarkdown,
    # Start of the enforced window for 3077 events (default: time the enforced .cip archive was written).
    [datetime]$EnforcedSince
)

$ErrorActionPreference = 'Stop'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -Path 'C:\WDAC\Logs' -ItemType Directory -Force | Out-Null
if (-not $OutHtml) { $OutHtml = "C:\WDAC\Logs\WDAC-Run-Report-$Stamp.html" }
$OutDir = Split-Path -Parent $OutHtml
$OutBase = Join-Path $OutDir ([IO.Path]::GetFileNameWithoutExtension($OutHtml))
$Exporter = Join-Path $PSScriptRoot 'Export-CIEventEvidence.ps1'

function Esc([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }
function Badge([string]$Kind, [string]$Text) { "<span class=`"badge $Kind`">$(Esc $Text)</span>" }
function Get-Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

# Renders objects as a table; columns whose name matches -Mono are monospaced (hashes, paths)
function ConvertTo-HtmlTable($Objects, [string[]]$Columns, [string]$Mono = 'SHA|Hash|GUID|PolicyID|ActivityId|File|Process|Path', [switch]$Raw) {
    $Rows = @($Objects | Where-Object { $_ })
    if ($Rows.Count -eq 0) { return '<p class="muted">None.</p>' }
    if (-not $Columns) { $Columns = @($Rows[0].PSObject.Properties.Name) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(Esc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = "$($r.$c)"
            $cls = if ($c -match $Mono) { ' class="mono"' } else { '' }
            $cell = if ($Raw -and $v -match '^<span class="badge') { $v } else { Esc $v }
            [void]$sb.Append("<td$cls>$cell</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

# ---------------------------------------------------------------- minimal Markdown -> HTML (headings, tables, lists, code, inline)
$Sep = [string][char]1
function Convert-Inline([string]$Text) {
    $Codes = New-Object System.Collections.Generic.List[string]
    $Text = [regex]::Replace($Text, '`([^`]+)`', { param($m) $Codes.Add($m.Groups[1].Value); [string][char]2 + ($Codes.Count - 1) + [string][char]3 })
    $Text = (Esc $Text) -replace '\\\|', '|'
    $Text = [regex]::Replace($Text, '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2">$1</a>')
    $Text = [regex]::Replace($Text, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    $Text = [regex]::Replace($Text, '(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])', '<em>$1</em>')
    $Text = [regex]::Replace($Text, [string][char]2 + '(\d+)' + [string][char]3, { param($m) '<code>' + (Esc ($Codes[[int]$m.Groups[1].Value] -replace '\\\|', '|')) + '</code>' })
    return $Text
}
function Split-Row([string]$Line) {
    $t = $Line.Trim()
    if ($t.StartsWith('|')) { $t = $t.Substring(1) }
    if ($t.EndsWith('|')) { $t = $t.Substring(0, $t.Length - 1) }
    $t = $t.Replace('\|', $Sep)
    return @($t.Split('|') | ForEach-Object { $_.Replace($Sep, '\|').Trim() })
}
function Convert-Markdown([string[]]$Lines) {
    $sb = New-Object System.Text.StringBuilder
    $Open = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $Lines.Count) {
        $line = $Lines[$i]
        $isList = $line -match '^(\s*)([-*]|\d+\.)\s+(.*)$'
        if (-not $isList -and -not ($line -match '^\s{2,}\S' -and $Open.Count -gt 0)) { while ($Open.Count -gt 0) { [void]$sb.Append("</li></$($Open[$Open.Count - 1])>"); $Open.RemoveAt($Open.Count - 1) } }
        if ($line -match '^```') {
            $i++; $code = New-Object System.Collections.Generic.List[string]
            while ($i -lt $Lines.Count -and $Lines[$i] -notmatch '^```') { $code.Add($Lines[$i]); $i++ }
            [void]$sb.AppendLine("<pre><code>$(Esc ($code -join "`n"))</code></pre>"); $i++; continue
        }
        if ($line -match '^(#{1,4})\s+(.*)$') { $lvl = [math]::Min($Matches[1].Length + 1, 5); [void]$sb.AppendLine("<h$lvl>$(Convert-Inline $Matches[2])</h$lvl>"); $i++; continue }
        if ($line -match '^\s*\|' -and $i + 1 -lt $Lines.Count -and $Lines[$i + 1] -match '^\s*\|[\s:|-]+\|\s*$') {
            $head = Split-Row $line
            [void]$sb.Append('<div class="tw"><table><thead><tr>')
            foreach ($h in $head) { [void]$sb.Append("<th>$(Convert-Inline $h)</th>") }
            [void]$sb.Append('</tr></thead><tbody>'); $i += 2
            while ($i -lt $Lines.Count -and $Lines[$i] -match '^\s*\|') {
                $cells = Split-Row $Lines[$i]; [void]$sb.Append('<tr>')
                for ($c = 0; $c -lt $head.Count; $c++) { $v = if ($c -lt $cells.Count) { $cells[$c] } else { '' }; [void]$sb.Append("<td>$(Convert-Inline $v)</td>") }
                [void]$sb.Append('</tr>'); $i++
            }
            [void]$sb.AppendLine('</tbody></table></div>'); continue
        }
        if ($isList) {
            $depth = [math]::Floor($Matches[1].Length / 2) + 1
            $tag = if ($Matches[2] -match '\d') { 'ol' } else { 'ul' }
            $content = Convert-Inline $Matches[3]
            if ($Open.Count -lt $depth) {
                while ($Open.Count -lt $depth) { [void]$sb.Append("<$tag>"); $Open.Add($tag); if ($Open.Count -lt $depth) { [void]$sb.Append('<li>') } }
                [void]$sb.Append("<li>$content")
            }
            else {
                while ($Open.Count -gt $depth) { [void]$sb.Append("</li></$($Open[$Open.Count - 1])>"); $Open.RemoveAt($Open.Count - 1) }
                [void]$sb.Append("</li><li>$content")
            }
            $i++; continue
        }
        if ($line -match '^\s{2,}\S' -and $Open.Count -gt 0) { [void]$sb.Append(' ' + (Convert-Inline $line.Trim())); $i++; continue }
        if ($line -match '^---+\s*$') { [void]$sb.AppendLine('<hr>'); $i++; continue }
        if ($line -match '^\s*$') { $i++; continue }
        $para = New-Object System.Collections.Generic.List[string]
        while ($i -lt $Lines.Count -and $Lines[$i] -notmatch '^\s*$' -and $Lines[$i] -notmatch '^(#|```|\s*\||\s*([-*]|\d+\.)\s|---+\s*$)') { $para.Add($Lines[$i]); $i++ }
        [void]$sb.AppendLine("<p>$(Convert-Inline ($para -join ' '))</p>")
    }
    while ($Open.Count -gt 0) { [void]$sb.Append("</li></$($Open[$Open.Count - 1])>"); $Open.RemoveAt($Open.Count - 1) }
    return $sb.ToString()
}

# ---------------------------------------------------------------- live system state
$DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$Kmci = [int]$DG.CodeIntegrityPolicyEnforcementStatus
$Umci = [int]$DG.UsermodeCodeIntegrityPolicyEnforcementStatus
$Pass = ($Kmci -eq 2 -and $Umci -eq 2)
$OS = Get-CimInstance Win32_OperatingSystem
$Sac = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$SacText = switch ($Sac) { 0 { 'Off' } 1 { 'On' } 2 { 'Evaluation' } default { 'Not reported' } }
$Policies = @((& "$env:SystemRoot\System32\CiTool.exe" --list-policies -json | ConvertFrom-Json).Policies | Where-Object { -not $_.IsSystemPolicy } | ForEach-Object {
    [pscustomobject]@{ FriendlyName = $_.FriendlyName; Type = $(if ($_.PolicyID -eq $_.BasePolicyID) { 'Base' } else { 'Supplemental' }); VersionString = $_.VersionString; PolicyID = $_.PolicyID; BasePolicyID = $_.BasePolicyID; IsEnforced = $_.IsEnforced; IsAuthorized = $_.IsAuthorized }
})
function StigText([int]$v) { switch ($v) { 0 { 'OFF' } 1 { 'AUDIT' } 2 { 'ENFORCING' } default { 'UNKNOWN' } } }

# ---------------------------------------------------------------- STIG values recorded in transcripts
$History = New-Object System.Collections.Generic.List[object]
foreach ($T in @(Get-ChildItem -Path 'C:\WDAC\Logs' -Filter '*.log' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)) {
    $Lines = @(Get-Content -LiteralPath $T.FullName -ErrorAction SilentlyContinue)
    $Start = ''; $Cmd = '(script output)'
    for ($n = 0; $n -lt $Lines.Count; $n++) {
        if ($Lines[$n] -match '^Start time:\s*(\d{14})') { $Start = [datetime]::ParseExact($Matches[1], 'yyyyMMddHHmmss', $null).ToString('yyyy-MM-dd HH:mm:ss') }
        elseif ($Lines[$n] -match '^PS[^>]*>\s*(\S.*)$') { $Cmd = $Matches[1] }
        elseif ($Lines[$n] -match '^\s+V-243450\s+WPAW-00-001050\s.*?\s(\d) \((?:OFF|AUDIT|ENFORCING|UNKNOWN)\)') {
            # 7_DISA_STIG_CHECK.ps1 results table: one row per finding
            $K = $Matches[1]
            for ($m = $n + 1; $m -le [math]::Min($n + 3, $Lines.Count - 1); $m++) {
                if ($Lines[$m] -match '^\s+V-243451\s+WPAW-00-001060\s.*?\s(\d) \((?:OFF|AUDIT|ENFORCING|UNKNOWN)\)') { $U = $Matches[1]; $History.Add([pscustomobject]@{ Seq = $History.Count; Transcript = $T.Name; TranscriptStart = $Start; Command = $Cmd; KMCI = "$K ($(StigText $K))"; UMCI = "$U ($(StigText $U))" }); break }
            }
        }
        elseif ($Lines[$n] -match '^CodeIntegrityPolicyEnforcementStatus\s*:\s*(\d)') {
            $K = $Matches[1]
            for ($m = $n + 1; $m -le [math]::Min($n + 3, $Lines.Count - 1); $m++) {
                if ($Lines[$m] -match '^UsermodeCodeIntegrityPolicyEnforcementStatus\s*:\s*(\d)') { $U = $Matches[1]; $History.Add([pscustomobject]@{ Seq = $History.Count; Transcript = $T.Name; TranscriptStart = $Start; Command = $Cmd; KMCI = "$K ($(StigText $K))"; UMCI = "$U ($(StigText $U))" }); break }
            }
        }
    }
}
# Order by transcript start, then by position inside the transcript; the live reading always comes last
$History = @($History | Sort-Object TranscriptStart, Seq) + @([pscustomobject]@{ Transcript = '(live, report time)'; TranscriptStart = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Command = 'Win32_DeviceGuard'; KMCI = "$Kmci ($(StigText $Kmci))"; UMCI = "$Umci ($(StigText $Umci))" })

# ---------------------------------------------------------------- policy XML stages + supplemental XMLs
function Get-PolicySummary([string]$Path) {
    $Doc = New-Object System.Xml.XmlDocument
    $Doc.Load($Path)
    $S = $Doc.SiPolicy
    $Opts = @($S.Rules.Rule.Option)
    [pscustomobject]@{
        File = Split-Path -Leaf $Path; PolicyType = $S.PolicyType; PolicyID = $S.PolicyID; VersionEx = $S.VersionEx
        Name = ($S.Settings.Setting | Where-Object { $_.ValueName -eq 'Name' }).Value.String
        AuditMode = $(if ($Opts -contains 'Enabled:Audit Mode') { 'ON' } else { 'OFF' })
        ManagedInstaller = $(if ($Opts -contains 'Enabled:Managed Installer') { 'ON' } else { 'OFF' })
        Signers = @($S.Signers.Signer | Where-Object { $_ }).Count; Allow = @($S.FileRules.Allow | Where-Object { $_ }).Count
        Deny = @($S.FileRules.Deny | Where-Object { $_ }).Count; FileAttrib = @($S.FileRules.FileAttrib | Where-Object { $_ }).Count
        Options = ($Opts | Sort-Object) -join ', '; SHA256 = Get-Sha $Path; Doc = $Doc
    }
}
$StageFiles = @('Base-Audit.xml', 'Base-Audit-Merged.xml', 'Base-Enforce.xml') | ForEach-Object { Join-Path 'C:\WDAC\Source' $_ } | Where-Object { Test-Path -LiteralPath $_ }
$SuppFiles = @(Get-ChildItem -Path 'C:\WDAC\Source' -Filter '*.xml' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(Base-|Events-Allow)' } | Where-Object {
    $d = New-Object System.Xml.XmlDocument; try { $d.Load($_.FullName); $d.SiPolicy.PolicyType -eq 'Supplemental Policy' } catch { $false } } | ForEach-Object { $_.FullName })
$Stages = @(foreach ($f in @($StageFiles) + @($SuppFiles)) { Get-PolicySummary $f })
$Compiled = @(Get-ChildItem -Path 'C:\WDAC\Compiled' -Filter '*.cip' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | ForEach-Object {
    [pscustomobject]@{ File = $_.Name; Bytes = '{0:N0}' -f $_.Length; Written = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); SHA256 = Get-Sha $_.FullName } })

# ---------------------------------------------------------------- FilePath rules and whether they are honored
function Test-AdminOnly([string]$Folder) {
    if (-not (Test-Path -LiteralPath $Folder)) { return $null }
    $W = @((Get-Acl -LiteralPath $Folder).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl|CreateFiles|AppendData|268435456|1073741824' -and
        "$($_.IdentityReference)" -notmatch 'SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER' })
    return ($W.Count -eq 0)
}
$PathRules = New-Object System.Collections.Generic.List[object]
$Latest = $Stages | Where-Object { $_.PolicyType -eq 'Base Policy' } | Select-Object -Last 1
foreach ($P in @($Latest) + @($Stages | Where-Object { $_.PolicyType -eq 'Supplemental Policy' })) {
    if (-not $P) { continue }
    $NoRuntimeCheck = @($P.Doc.SiPolicy.Rules.Rule.Option) -contains 'Disabled:Runtime FilePath Rule Protection'
    foreach ($R in @($P.Doc.SiPolicy.FileRules.Allow | Where-Object { $_ -and $_.FilePath })) {
        $Expanded = $R.FilePath -replace '%OSDRIVE%', $env:SystemDrive -replace '%WINDIR%', $env:windir -replace '%SYSTEM32%', "$env:windir\System32"
        $Probe = if ($Expanded.Contains('*')) { $Expanded.Substring(0, $Expanded.IndexOf('*')) } else { $Expanded }
        $Folder = if ($Probe.EndsWith('\')) { $Probe.TrimEnd('\') } else { Split-Path -Parent $Probe }
        $AdminOnly = Test-AdminOnly $Folder
        $Status = if ($null -eq $AdminOnly) { Badge 'warn' 'Folder not found' } elseif ($AdminOnly) { Badge 'ok' 'Honored (admin-only)' } elseif ($NoRuntimeCheck) { Badge 'warn' 'Honored (runtime check disabled in this policy)' } else { Badge 'bad' 'NOT honored (user-writable)' }
        $PathRules.Add([pscustomobject]@{ Policy = $P.File; Rule = $R.ID; FilePath = $R.FilePath; CheckedFolder = $Folder; Status = $Status })
    }
}

# ---------------------------------------------------------------- managed installer readiness
function Get-ServiceState([string]$Name) { $S = Get-Service -Name $Name -ErrorAction SilentlyContinue; if ($S) { "$($S.Status) / $($S.StartType)" } else { 'Not installed' } }
$AppLockerDoc = try { [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) } catch { $null }
$MiCollection = if ($AppLockerDoc) { @($AppLockerDoc.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' }) | Select-Object -First 1 }
$MiRules = if ($MiCollection) { @($MiCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | ForEach-Object { $_.GetAttribute('Name') }) -join '; ' } else { '' }
$Fltr = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='AppLockerFltr'" -ErrorAction SilentlyContinue
$Mi = @(
    [pscustomobject]@{ Component = 'MECM client (CcmExec)'; State = Get-ServiceState 'CcmExec' }
    [pscustomobject]@{ Component = 'Intune Management Extension'; State = Get-ServiceState 'IntuneManagementExtension' }
    [pscustomobject]@{ Component = 'AppLocker ManagedInstaller collection'; State = $(if ($MiCollection) { "Present ($($MiCollection.EnforcementMode)): $MiRules" } else { 'Not configured' }) }
    [pscustomobject]@{ Component = 'Application Identity (AppIDSvc)'; State = Get-ServiceState 'AppIDSvc' }
    [pscustomobject]@{ Component = 'AppLocker filter driver (AppLockerFltr)'; State = $(if ($Fltr) { "$($Fltr.State) / $($Fltr.StartMode)" } else { 'Not installed' }) }
)

# ---------------------------------------------------------------- script findings (latest of each)
function Get-LatestCsv([string]$Filter) { $F = Get-ChildItem -Path 'C:\WDAC\Logs' -Filter $Filter -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1; if ($F) { @{ Name = $F.Name; Rows = @(Import-Csv -LiteralPath $F.FullName) } } }
$Validate = Get-LatestCsv 'Base-Audit-Validate-*.csv'
$Sanitize = Get-LatestCsv 'Events-Allow-Sanitize-*.csv'

# ---------------------------------------------------------------- events (every 3076 / 3077), via the exporter
function Get-Evidence([hashtable]$ExporterArgs, [string]$Suffix) {
    if (-not (Test-Path -LiteralPath $Exporter)) { return $null }
    $Csv = "$OutBase-$Suffix.csv"
    & $Exporter @ExporterArgs -OutCsv $Csv -OutMd "$OutBase-$Suffix.md" 6>$null | Out-Null
    # The unary comma keeps an empty result an (empty) array instead of $null, so "0 events" is not reported as "no data"
    if ((Test-Path -LiteralPath $Csv) -and (Get-Item -LiteralPath $Csv).Length -gt 0) { return , @(Import-Csv -LiteralPath $Csv) } else { return , @() }
}
$EvCols = 'TimeCreated', 'RecordId', 'Location', 'File', 'Process', 'Publisher', 'Issuer', 'OriginalFileName', 'FileVersion', 'ValidatedSigningLevel', 'Status', 'SHA256Authenticode', 'SHA256Flat', 'PolicyName', 'ActivityId'
$AuditEvtx = 'C:\WDAC\Events\PAW-Audit-3076.evtx'
$Audit = if (Test-Path -LiteralPath $AuditEvtx) { Get-Evidence @{ EvtxPath = $AuditEvtx; EventId = 3076 } 'audit-3076' } else { $null }
$ScreenFile = 'C:\WDAC\Events\ScreenStart.txt'
$ScreenStart = if (Test-Path -LiteralPath $ScreenFile) { [datetime]::Parse((Get-Content -LiteralPath $ScreenFile -Raw).Trim()) } else { $null }
$Screen = if ($ScreenStart) { Get-Evidence @{ StartTime = $ScreenStart; EventId = 3076 } 'screen-3076' } else { $null }
if (-not $PSBoundParameters.ContainsKey('EnforcedSince')) {
    $Enf = Get-ChildItem -Path 'C:\WDAC\Compiled' -Filter 'PAW-WDAC-Enforced_v*.cip' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($Enf) { $EnforcedSince = $Enf.LastWriteTime }
}
$Blocks = if ($EnforcedSince) { Get-Evidence @{ StartTime = $EnforcedSince; EventId = 3077 } 'enforced-3077' } else { $null }
$Expected = @(); $Unexpected = @()
if ($Blocks) {
    foreach ($B in $Blocks) {
        $IsExpected = $BlockTestPattern -and ("$($B.File) $($B.Process) $($B.Publisher) $($B.ProductName)" -match $BlockTestPattern)
        $B | Add-Member -NotePropertyName Verdict -NotePropertyValue $(if ($IsExpected) { 'Expected (block-test app)' } else { 'Review' }) -Force
        if ($IsExpected) { $Expected += $B } else { $Unexpected += $B }
    }
}

# ---------------------------------------------------------------- artifacts
$Inventory = foreach ($Dir in 'C:\WDAC\Source', 'C:\WDAC\Events') { Get-ChildItem -Path $Dir -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { [pscustomobject]@{ File = $_.FullName; Bytes = '{0:N0}' -f $_.Length; Written = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); SHA256 = Get-Sha $_.FullName } } }
$LogFiles = @(Get-ChildItem -Path 'C:\WDAC\Logs' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { [pscustomobject]@{ File = $_.Name; Bytes = '{0:N0}' -f $_.Length; Written = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } })
$NotesHtml = if ($NotesMarkdown -and (Test-Path -LiteralPath $NotesMarkdown)) { Convert-Markdown ([IO.File]::ReadAllLines($NotesMarkdown, [Text.Encoding]::UTF8)) } else { '' }

# ---------------------------------------------------------------- HTML
$KCls = if ($Kmci -eq 2) { 'ok' } else { 'bad' }; $UCls = if ($Umci -eq 2) { 'ok' } else { 'bad' }
$Verdict = if ($Pass) { Badge 'ok' 'V-243450 & V-243451 PASS' } else { Badge 'bad' 'STIG OPEN' }
$BlockCard = if ($null -eq $Blocks) { '<p class="v">&ndash;</p><p class="d">No enforced policy compiled yet</p>' } else { "<p class=`"v $(if ($Unexpected.Count) { 'bad' } else { 'ok' })`">$($Unexpected.Count)</p><p class=`"d`">3077 to review &middot; $($Expected.Count) expected (block-test app)</p>" }
$ScreenCard = if ($null -eq $Screen) { '<p class="v">&ndash;</p><p class="d">No screening window yet</p>' } else { "<p class=`"v $(if ($Screen.Count) { 'bad' } else { 'ok' })`">$($Screen.Count)</p><p class=`"d`">new 3076 since $($ScreenStart.ToString('yyyy-MM-dd HH:mm:ss'))</p>" }
$Css = @'
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1b1f24;--muted:#5b6470;--line:#dfe3e8;--accent:#0f6cbd;--ok:#107c10;--ok-bg:#e8f5e8;--bad:#b10e1c;--bad-bg:#fde7e9;--warn:#8a5300;--warn-bg:#fff4ce;--code-bg:#f0f2f5;--th:#eef1f5}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#111418;--panel:#1a1f25;--ink:#e6e9ed;--muted:#9aa4b1;--line:#2c333c;--accent:#4aa3ff;--ok:#6ccb5f;--ok-bg:#16301a;--bad:#ff7b84;--bad-bg:#3a1a1e;--warn:#ffd166;--warn-bg:#3a3014;--code-bg:#232a32;--th:#222931}}
:root[data-theme="dark"]{--bg:#111418;--panel:#1a1f25;--ink:#e6e9ed;--muted:#9aa4b1;--line:#2c333c;--accent:#4aa3ff;--ok:#6ccb5f;--ok-bg:#16301a;--bad:#ff7b84;--bad-bg:#3a1a1e;--warn:#ffd166;--warn-bg:#3a3014;--code-bg:#232a32;--th:#222931}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,Roboto,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
header,section{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-bottom:20px}
.eyebrow{color:var(--muted);font-size:13px;letter-spacing:.04em;text-transform:uppercase;margin:0 0 6px}h1{font-size:26px;line-height:1.25;margin:0 0 8px}
h2{font-size:20px;margin:0 0 10px}h3{font-size:17px;margin:20px 0 8px}h4,h5{font-size:15px;margin:16px 0 6px}a{color:var(--accent)}
.muted,.sub{color:var(--muted)}.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-weight:600;font-size:12.5px;white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok)}.badge.bad{background:var(--bad-bg);color:var(--bad)}.badge.warn{background:var(--warn-bg);color:var(--warn)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-top:16px}
.card{background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:14px}.card .k{color:var(--muted);font-size:12.5px;margin:0 0 4px}
.card .v{font-size:28px;font-weight:700;margin:0;line-height:1.1}.card .d{font-size:13px;color:var(--muted);margin:6px 0 0}.v.ok{color:var(--ok)}.v.bad{color:var(--bad)}
code{font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px;background:var(--code-bg);padding:1px 5px;border-radius:5px;word-break:break-word}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:10px;padding:12px 14px;overflow-x:auto}pre code{background:none;padding:0;white-space:pre}
.tw{overflow-x:auto;margin:10px 0 14px;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}th{background:var(--th);font-weight:600;white-space:nowrap}
tbody tr:last-child td{border-bottom:none}td.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;white-space:nowrap}
details{border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin:12px 0}details>summary{cursor:pointer;font-weight:600}
nav ol{columns:2;column-gap:32px;margin:6px 0 0}@media (max-width:640px){nav ol{columns:1}}footer{color:var(--muted);font-size:12.5px;text-align:center}
@media print{body{background:#fff}details:not([open])>*:not(summary){display:none}}
'@
$Html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(Esc $Title)</title><style>$Css</style></head>
<body><div class="wrap">
<header>
<p class="eyebrow">App Control for Business (WDAC) &middot; DISA PAW STIG &middot; $(Esc $env:COMPUTERNAME)</p>
<h1>$(Esc $Title) $Verdict</h1>
<p class="sub">$(Esc $OS.Caption) $(Esc $OS.Version) &middot; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $(Esc ([Security.Principal.WindowsIdentity]::GetCurrent().Name)) &middot; Smart App Control: $(Esc $SacText)</p>
<div class="cards">
<div class="card"><p class="k">V-243450 &middot; Kernel-mode CI</p><p class="v $KCls">$Kmci</p><p class="d">$(StigText $Kmci) &middot; $(if ($Kmci -eq 2) { 'PASS' } else { 'OPEN FINDING' })</p></div>
<div class="card"><p class="k">V-243451 &middot; User-mode CI</p><p class="v $UCls">$Umci</p><p class="d">$(StigText $Umci) &middot; $(if ($Umci -eq 2) { 'PASS' } else { 'OPEN FINDING' })</p></div>
<div class="card"><p class="k">Screening</p>$ScreenCard</div>
<div class="card"><p class="k">Enforced blocks</p>$BlockCard</div>
</div></header>
<nav><section><strong>Contents</strong><ol>
<li><a href="#stig">STIG values</a></li><li><a href="#policies">Active policies</a></li><li><a href="#stages">Policy stages and binaries</a></li>
<li><a href="#paths">FilePath rules</a></li><li><a href="#mi">Managed installer</a></li><li><a href="#findings">Script findings</a></li>
<li><a href="#audit">Audit events (3076)</a></li><li><a href="#screen">Screening (3076)</a></li><li><a href="#blocks">Enforced blocks (3077)</a></li>
<li><a href="#artifacts">Artifacts</a></li>$(if ($NotesHtml) { '<li><a href="#notes">Run notes</a></li>' })
</ol></section></nav>
<section id="stig"><h2>STIG values</h2><p class="muted">Every <code>Win32_DeviceGuard</code> reading found in the transcripts under <code>C:\WDAC\Logs</code>, in order, plus the live value now. 0 = not configured, 1 = audit, 2 = enforced.</p>
$(ConvertTo-HtmlTable $History @('TranscriptStart', 'Transcript', 'Command', 'KMCI', 'UMCI'))</section>
<section id="policies"><h2>Active custom policies (CiTool)</h2>$(ConvertTo-HtmlTable $Policies)</section>
<section id="stages"><h2>Policy stages and binaries</h2>
$(ConvertTo-HtmlTable ($Stages | Select-Object File, PolicyType, Name, VersionEx, AuditMode, ManagedInstaller, Signers, Allow, Deny, FileAttrib, PolicyID, SHA256) @('File', 'PolicyType', 'Name', 'VersionEx', 'AuditMode', 'ManagedInstaller', 'Signers', 'Allow', 'Deny', 'FileAttrib', 'PolicyID', 'SHA256'))
<details><summary>Rule options per stage</summary>$(ConvertTo-HtmlTable ($Stages | Select-Object File, Options) @('File', 'Options') -Mono 'File')</details>
<h3>Compiled binaries (C:\WDAC\Compiled)</h3>$(ConvertTo-HtmlTable $Compiled)</section>
<section id="paths"><h2>FilePath rules and whether they are honored</h2><p class="muted">Runtime FilePath rule protection only honors FilePath rules on folders that standard users cannot write to (checked against the current ACL). Policy: latest base stage plus supplemental XMLs in <code>C:\WDAC\Source</code>.</p>
$(ConvertTo-HtmlTable $PathRules @('Policy', 'Rule', 'FilePath', 'CheckedFolder', 'Status') -Raw)</section>
<section id="mi"><h2>Managed installer (MECM / Intune)</h2><p class="muted">Option 13 only takes effect when a managed installer is designated through an AppLocker ManagedInstaller rule collection and the AppLocker components run.</p>$(ConvertTo-HtmlTable $Mi)</section>
<section id="findings"><h2>Script findings</h2>
<h3>0_1_validate_base_policy.ps1 $(if ($Validate) { "&middot; <code>$(Esc $Validate.Name)</code>" })</h3>$(if ($Validate) { ConvertTo-HtmlTable $Validate.Rows } else { '<p class="muted">No findings log.</p>' })
<h3>3_1_validate_winevent_rules.ps1 $(if ($Sanitize) { "&middot; <code>$(Esc $Sanitize.Name)</code>" })</h3>$(if ($Sanitize) { ConvertTo-HtmlTable $Sanitize.Rows } else { '<p class="muted">No findings log.</p>' })</section>
<section id="audit"><h2>Audit capture &mdash; Event 3076 $(if ($Audit) { "($($Audit.Count))" })</h2><p class="muted">From <code>$(Esc $AuditEvtx)</code>, the exact file the Wizard parses; each event is joined to its 3089 signature record.</p>$(if ($null -eq $Audit) { '<p class="muted">No export yet.</p>' } else { ConvertTo-HtmlTable $Audit $EvCols })</section>
<section id="screen"><h2>Screening &mdash; new Event 3076 $(if ($Screen) { "($($Screen.Count))" })</h2>$(if ($null -eq $Screen) { '<p class="muted">No screening window yet.</p>' } elseif ($Screen.Count -eq 0) { Badge 'ok' '0 new 3076 events - allow list complete' } else { ConvertTo-HtmlTable $Screen $EvCols })</section>
<section id="blocks"><h2>Enforced blocks &mdash; Event 3077 $(if ($Blocks) { "($($Blocks.Count))" })</h2><p class="muted">$(if ($EnforcedSince) { "Since $($EnforcedSince.ToString('yyyy-MM-dd HH:mm:ss'))." }) $(if ($BlockTestPattern) { "Rows matching <code>$(Esc $BlockTestPattern)</code> are expected." } else { 'No -BlockTestPattern given: every row is marked for review.' })</p>
$(if ($null -eq $Blocks) { '<p class="muted">No enforced policy compiled yet.</p>' } elseif ($Blocks.Count -eq 0) { Badge 'ok' 'No blocks' } else { ConvertTo-HtmlTable $Blocks (@('Verdict') + $EvCols) })</section>
<section id="artifacts"><h2>Artifacts</h2>$(ConvertTo-HtmlTable $Inventory)<details><summary>Logs in C:\WDAC\Logs ($($LogFiles.Count))</summary>$(ConvertTo-HtmlTable $LogFiles)</details></section>
$(if ($NotesHtml) { "<section id=`"notes`"><h2>Run notes</h2><p class=`"muted`">Rendered from <code>$(Esc $NotesMarkdown)</code>.</p>$NotesHtml</section>" })
<footer>Self-contained report &middot; no external resources &middot; New-WDACRunReport.ps1</footer>
</div></body></html>
"@
Set-Content -LiteralPath $OutHtml -Value $Html -Encoding UTF8
Write-Host "Report: $OutHtml ($('{0:N0}' -f (Get-Item -LiteralPath $OutHtml).Length) bytes)" -ForegroundColor Green
Write-Host "STIG $Kmci / $Umci | screening 3076: $(if ($null -eq $Screen) { 'n/a' } else { $Screen.Count }) | 3077: $(if ($null -eq $Blocks) { 'n/a' } else { "$($Blocks.Count) ($($Unexpected.Count) to review)" })" -ForegroundColor Cyan
