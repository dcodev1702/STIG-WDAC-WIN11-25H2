# Works in PowerShell 7 and Windows PowerShell 5.1 (no ConfigCI needed) - run elevated.
# Audit-trail helper: writes EVERY CodeIntegrity audit (3076) or enforced-block (3077) event, joined to its 3089 signature
# record(s), to a CSV and a Markdown table: time, record ID, file, process, signer/issuer, signing levels, hashes, policy.
#
#   .\Export-CIEventEvidence.ps1 -EvtxPath 'C:\WDAC\Events\PAW-Audit-3076.evtx'      # exactly what the Wizard parses (Step 4.1)
#   .\Export-CIEventEvidence.ps1                                                     # live log since AuditRoundStart.txt
#   .\Export-CIEventEvidence.ps1 -StartTime (Get-Content C:\WDAC\Events\ScreenStart.txt)   # screening window (Step 5)
#   .\Export-CIEventEvidence.ps1 -EventId 3077 -StartTime (Get-Date).AddMinutes(-30)       # enforced blocks (Step 8)
param(
    [string]$EvtxPath,
    [datetime]$StartTime,
    [ValidateSet(3076, 3077)][int]$EventId = 3076,
    [string]$OutCsv,
    [string]$OutMd
)

$ErrorActionPreference = 'Stop'
if (-not $EvtxPath -and -not $PSBoundParameters.ContainsKey('StartTime')) {
    $AuditStartFile = 'C:\WDAC\Events\AuditRoundStart.txt'
    if (-not (Test-Path -LiteralPath $AuditStartFile)) { throw "STOP: pass -EvtxPath or -StartTime ($AuditStartFile was not found)." }
    $StartTime = [datetime]::Parse((Get-Content -LiteralPath $AuditStartFile -Raw).Trim())
}
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -Path 'C:\WDAC\Logs' -ItemType Directory -Force | Out-Null
if (-not $OutCsv) { $OutCsv = "C:\WDAC\Logs\CI-Evidence-$EventId-$Stamp.csv" }
if (-not $OutMd) { $OutMd = [IO.Path]::ChangeExtension($OutCsv, '.md') }

$Filter = @{ Id = @($EventId, 3089) }
if ($EvtxPath) { $Filter.Path = $EvtxPath } else { $Filter.LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; $Filter.StartTime = $StartTime }
$All = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Sort-Object RecordId)

# Signing level names (Microsoft Learn: "Understanding App Control event tags")
$SigningLevel = @{ 0 = 'Not checked'; 1 = 'Unsigned'; 2 = 'Enterprise'; 3 = 'Custom 1'; 4 = 'Authenticode'; 5 = 'Custom 2'; 6 = 'Store'; 7 = 'Antimalware'; 8 = 'Microsoft'; 9 = 'Custom 4'; 10 = 'Custom 5'; 11 = 'Dynamic Code Generation'; 12 = 'Windows'; 13 = 'Windows PPL'; 14 = 'Windows TCB'; 15 = 'Custom 6' }

# Map \Device\HarddiskVolumeN\... to drive letters
Add-Type -Namespace WdacEvidence -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);' -ErrorAction SilentlyContinue
$DeviceMap = @{}
foreach ($Drive in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' })) {
    $Sb = New-Object System.Text.StringBuilder 512
    if ([WdacEvidence.Dos]::QueryDosDevice($Drive.Name + ':', $Sb, 512)) { $DeviceMap[$Sb.ToString()] = $Drive.Name + ':' }
}
function ConvertTo-DosPath([string]$Path) {
    foreach ($Device in $DeviceMap.Keys) { if ($Path.StartsWith($Device + '\', [StringComparison]::OrdinalIgnoreCase)) { return $DeviceMap[$Device] + $Path.Substring($Device.Length) } }
    return $Path
}
function Get-Data($Record) {
    $Map = @{}
    foreach ($D in ([xml]$Record.ToXml()).Event.EventData.Data) { $Map[$D.Name] = "$($D.'#text')" }
    return $Map
}
# Groups a file by where it is installed - no application names are hard-coded
function Get-Location([string]$File) {
    switch -Regex ($File) {
        '^[A-Z]:\\Program Files( \(x86\))?\\([^\\]+)'                      { return $Matches[2] }
        '^[A-Z]:\\Users\\[^\\]+\\\.vscode\\extensions\\([^\\]+?)-\d'       { return "VS Code extension: $($Matches[1])" }
        '^[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\Programs\\([^\\]+)'       { return $Matches[1] }
        '^[A-Z]:\\Users\\'                                                 { return 'User profile' }
        '^[A-Z]:\\ProgramData\\([^\\]+)'                                   { return "ProgramData\$($Matches[1])" }
        '^[A-Z]:\\Windows\\'                                               { return 'Windows' }
        default                                                            { return (Split-Path -Parent $File) }
    }
}

$Signatures = @{}
foreach ($E in ($All | Where-Object Id -eq 3089)) {
    $Key = "$($E.ActivityId)"
    if (-not $Signatures.ContainsKey($Key)) { $Signatures[$Key] = New-Object System.Collections.Generic.List[object] }
    $Signatures[$Key].Add((Get-Data $E))
}

$Rows = @(foreach ($E in ($All | Where-Object Id -eq $EventId)) {
    $D = Get-Data $E
    $Sig = @($Signatures["$($E.ActivityId)"] | Where-Object { $_ })
    $File = ConvertTo-DosPath $D['File Name']
    $Requested = [int]$D['Requested Signing Level']
    $Validated = [int]$D['Validated Signing Level']
    [pscustomobject]@{
        TimeCreated           = $E.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff')
        EventId               = $E.Id
        RecordId              = $E.RecordId
        Location              = Get-Location $File
        File                  = $File
        Process               = ConvertTo-DosPath $D['Process Name']
        # 3089 reports an unsigned file as PublisherName/IssuerName 'Unknown'
        Publisher             = (@($Sig | ForEach-Object { $_['PublisherName'] } | Where-Object { $_ -and $_ -ne 'Unknown' } | Select-Object -Unique) -join ' | ')
        Issuer                = (@($Sig | ForEach-Object { $_['IssuerName'] } | Where-Object { $_ -and $_ -ne 'Unknown' } | Select-Object -Unique) -join ' | ')
        CertNotValidAfter     = (@($Sig | ForEach-Object { $_['NotValidAfter'] } | Where-Object { $_ } | Select-Object -Unique) -join ' | ')
        SignatureCount        = $Sig.Count
        RequestedSigningLevel = "$Requested ($($SigningLevel[$Requested]))"
        ValidatedSigningLevel = "$Validated ($($SigningLevel[$Validated]))"
        Status                = $D['Status']
        SigningScenario       = $(if ($D['SI Signing Scenario'] -eq '1') { 'User mode' } elseif ($D['SI Signing Scenario'] -eq '0') { 'Kernel mode' } else { $D['SI Signing Scenario'] })
        OriginalFileName      = $D['OriginalFileName']
        ProductName           = $D['ProductName']
        FileVersion           = $D['FileVersion']
        SHA256Authenticode    = $D['SHA256 Hash']
        SHA256Flat            = $D['SHA256 Flat Hash']
        SHA1Authenticode      = $D['SHA1 Hash']
        UserWriteable         = $D['UserWriteable']
        PolicyName            = $D['PolicyName']
        PolicyId              = $D['PolicyID']
        PolicyGUID            = $D['PolicyGUID']
        PolicyHash            = $D['PolicyHash']
        ActivityId            = "$($E.ActivityId)"
    }
})
$Rows | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8

$Md = New-Object System.Text.StringBuilder
[void]$Md.AppendLine("| # | Time | Record | Location | File | Process | Signer (3089) | Validated level | SHA-256 (Authenticode) |")
[void]$Md.AppendLine("|---:|---|---:|---|---|---|---|---|---|")
$i = 0
foreach ($R in $Rows) {
    $i++
    $Signer = if ($R.Publisher) { "$($R.Publisher) - *$($R.Issuer)*" } else { '*unsigned*' }
    [void]$Md.AppendLine("| $i | $($R.TimeCreated) | $($R.RecordId) | $($R.Location) | ``$($R.File)`` | ``$(Split-Path -Leaf $R.Process)`` | $Signer | $($R.ValidatedSigningLevel) | ``$($R.SHA256Authenticode)`` |")
}
Set-Content -LiteralPath $OutMd -Value $Md.ToString() -Encoding UTF8

$Source = if ($EvtxPath) { $EvtxPath } else { "live log since $($StartTime.ToString('o'))" }
Write-Host "$($Rows.Count) x $EventId event(s), $(@($All | Where-Object Id -eq 3089).Count) x 3089 from $Source" -ForegroundColor Cyan
if ($Rows.Count -gt 0) {
    Write-Host "Time range: $($Rows[0].TimeCreated) -> $($Rows[-1].TimeCreated) | unsigned: $(@($Rows | Where-Object { -not $_.Publisher }).Count) | status: $((@($Rows | Group-Object Status | ForEach-Object { "$($_.Name) x$($_.Count)" })) -join ', ')"
    $Rows | Group-Object Location, { if ($_.Publisher) { $_.Publisher } else { '(unsigned)' } } | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
}
Write-Host "CSV: $OutCsv"
Write-Host "Markdown: $OutMd"
