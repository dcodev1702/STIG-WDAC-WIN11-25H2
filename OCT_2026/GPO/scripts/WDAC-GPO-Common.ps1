# Shared helpers for the WDAC GPO scripts (dot-sourced by 0_ to 6_). Works in Windows PowerShell 5.1 and PowerShell 7.

# Date-based policy versions (YYYY.MM.DD.N, never lower than any known version) - same file as in C:\WDAC\config\scripts
. "$PSScriptRoot\WDAC-Version.ps1"
# Yellow Y/N confirmation before App Control changes (-NoConfirm for automation) - same file as in C:\WDAC\config\scripts
. "$PSScriptRoot\WDAC-Confirm.ps1"

# Loads a Windows module in either edition (ConfigCI goes through the compatibility session in PowerShell 7)
function Import-WdacModule([string]$Name) {
    if (Get-Module -Name $Name) { return }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        if ($Name -eq 'ConfigCI') { Import-Module ConfigCI -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop 3>$null }
        else { Import-Module $Name -SkipEditionCheck -WarningAction SilentlyContinue -ErrorAction Stop 3>$null }
    }
    else { Import-Module $Name -WarningAction SilentlyContinue -ErrorAction Stop }
}

# Admin check, settings (GPO-Settings.psd1 + overrides), log folder and transcript
function Initialize-WdacGpo([string]$ScriptName, [hashtable]$Overrides = @{}, [switch]$NoTranscript) {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) { throw 'STOP: run this script in an elevated PowerShell window ("Run as administrator").' }
    $Cfg = @{}
    $SettingsFile = Join-Path $PSScriptRoot 'GPO-Settings.psd1'
    if (Test-Path -LiteralPath $SettingsFile) { $Cfg = Import-PowerShellDataFile -LiteralPath $SettingsFile }
    foreach ($Key in @($Overrides.Keys)) { if ($Overrides[$Key]) { $Cfg[$Key] = $Overrides[$Key] } }
    foreach ($Key in 'AuditGpoName', 'EnforceGpoName', 'PolicyNamePrefix', 'WdacRoot', 'GpoRoot') { if (-not $Cfg[$Key]) { throw "STOP: setting '$Key' is empty (GPO-Settings.psd1)." } }
    if (-not $Cfg.TaskIntervalHours) { $Cfg.TaskIntervalHours = 4 }
    $Cfg.LogDir = Join-Path $Cfg.GpoRoot 'Logs'
    $Cfg.PackageRoot = Join-Path $Cfg.GpoRoot 'Packages'
    New-Item -Path $Cfg.LogDir, $Cfg.PackageRoot -ItemType Directory -Force | Out-Null
    $Cfg.Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Cfg.ScriptName = $ScriptName
    if (-not $NoTranscript) {
        $Cfg.Transcript = Join-Path $Cfg.LogDir "$ScriptName-$($Cfg.Stamp).log"
        Start-Transcript -Path $Cfg.Transcript | Out-Null
    }
    return $Cfg
}

function Stop-WdacTranscript { try { Stop-Transcript | Out-Null } catch { } }

# Distinguished name of the OU that holds a computer (default: this computer)
function Get-WdacComputerOU([string]$ComputerName = $env:COMPUTERNAME) {
    $Searcher = [adsisearcher]"(&(objectCategory=computer)(sAMAccountName=$ComputerName`$))"
    $Found = $Searcher.FindOne()
    if (-not $Found) { throw "STOP: computer '$ComputerName' was not found in Active Directory." }
    $Dn = [string]$Found.Properties.distinguishedname
    return ($Dn -replace '^CN=(?:\\,|[^,])+,', '')
}

function Resolve-WdacTargetOU($Cfg) { if ($Cfg.TargetOU) { return $Cfg.TargetOU } else { return Get-WdacComputerOU } }

function Get-WdacDomainInfo {
    Import-WdacModule ActiveDirectory
    $D = Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ DnsRoot = $D.DNSRoot; DN = $D.DistinguishedName; PDC = $D.PDCEmulator; NetBIOS = $D.NetBIOSName }
}

# AD and SYSVOL locations of a GPO (writes go to the PDC emulator, endpoints read through the domain namespace)
function Get-WdacGpoPaths($GpoId, $Domain) {
    $Id = '{' + ("$GpoId".Trim('{}')).ToUpper() + '}'
    [pscustomobject]@{
        Id           = $Id
        AdPath       = "CN=$Id,CN=Policies,CN=System,$($Domain.DN)"
        SysvolPdc    = "\\$($Domain.PDC)\SYSVOL\$($Domain.DnsRoot)\Policies\$Id"
        SysvolDomain = "\\$($Domain.DnsRoot)\SysVol\$($Domain.DnsRoot)\Policies\$Id"
        PayloadRel   = 'Machine\Scripts\Startup\WDAC'
    }
}

# Merges client-side-extension entries ([{CSE}{Tool}...]) into gPCMachineExtensionNames, sorted the way GPMC writes them
function Merge-WdacExtensionNames([string]$Existing, [string[]]$Add) {
    $Map = @{}
    foreach ($Block in [regex]::Matches("$Existing$($Add -join '')", '\[([^\]]+)\]')) {
        $Guids = @([regex]::Matches($Block.Groups[1].Value, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($Guids.Count -eq 0) { continue }
        if (-not $Map.ContainsKey($Guids[0])) { $Map[$Guids[0]] = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
        foreach ($Tool in @($Guids | Select-Object -Skip 1)) { [void]$Map[$Guids[0]].Add($Tool) }
    }
    return (@($Map.Keys | Sort-Object | ForEach-Object { '[' + $_ + (@($Map[$_]) -join '') + ']' }) -join '')
}

# Raises the computer-side version of a GPO by one in AD and GPT.INI so endpoints reprocess it
function Step-WdacGpoVersion($Paths, $Domain) {
    $Obj = Get-ADObject -Identity $Paths.AdPath -Properties versionNumber -Server $Domain.PDC -ErrorAction Stop
    $New = [int]$Obj.versionNumber + 1
    Set-ADObject -Identity $Paths.AdPath -Replace @{ versionNumber = $New } -Server $Domain.PDC -ErrorAction Stop
    $Ini = Join-Path $Paths.SysvolPdc 'GPT.INI'
    $Lines = if (Test-Path -LiteralPath $Ini) { @(Get-Content -LiteralPath $Ini) } else { @('[General]') }
    if ($Lines -match '^Version=') { $Lines = @($Lines | ForEach-Object { if ($_ -match '^Version=') { "Version=$New" } else { $_ } }) } else { $Lines += "Version=$New" }
    Set-Content -LiteralPath $Ini -Value $Lines -Encoding Ascii
    return $New
}

# SYSVOL payload folders of both WDAC GPOs (what endpoints can already see); nothing when the GPOs do not exist yet
function Get-WdacPublishedPayloads($Cfg) {
    try {
        Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
        $Domain = Get-WdacDomainInfo
        foreach ($Name in $Cfg.AuditGpoName, $Cfg.EnforceGpoName) {
            $G = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
            if ($G) { $P = Get-WdacGpoPaths $G.Id $Domain; Join-Path $P.SysvolPdc $P.PayloadRel }
        }
    }
    catch { }
}

# Next Audit/Enforce version pair for a policy GUID: today's date + counter, above every version known from the source XML,
# this device's active policy, earlier packages in Packages\ and the packages already PUBLISHED in both GPOs
function Get-WdacPackageVersions($Cfg, [string]$Guid, [string]$EnforceXml) {
    $Published = @(Get-WdacPublishedPayloads $Cfg)
    $Known = @(Get-WdacVersionsFromXml $EnforceXml) + @(Get-WdacActivePolicyVersion $Guid) + @(Get-WdacVersionsFromManifests (@($Cfg.PackageRoot) + $Published) $Guid)
    $Plan = Get-WdacNextVersion -Known $Known -Count 2
    $Plan | Add-Member -NotePropertyName Sources -NotePropertyValue "source XML, this device's active policy, earlier packages, $($Published.Count) published GPO payload(s)"
    return $Plan
}

# Reads manifest.json from a package folder or a GPO payload folder
function Read-WdacManifest([string]$Folder) {
    $File = Join-Path $Folder 'manifest.json'
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    return (Get-Content -LiteralPath $File -Raw | ConvertFrom-Json)
}

# Win32_DeviceGuard values as people read them: 0 = OFF, 1 = AUDIT, 2 = ENFORCING (only 2 passes the STIG)
function Format-WdacCiStatus([int]$Value) { "$Value ($(switch ($Value) { 0 { 'OFF' } 1 { 'AUDIT' } 2 { 'ENFORCING' } default { 'UNKNOWN' } }))" }
function Format-WdacStig([int]$Kmci, [int]$Umci) { "V-243450 kernel $(Format-WdacCiStatus $Kmci) / V-243451 user $(Format-WdacCiStatus $Umci)" }

# PASS / WARN / FAIL result tables
function New-WdacResults { return , (New-Object System.Collections.Generic.List[object]) }
function Add-WdacResult($List, [string]$Status, [string]$Check, [string]$Detail) { $List.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail }) }
function Write-WdacResults($List, $Cfg, [string]$Title) {
    $Csv = Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp).csv"
    $List | Format-Table -AutoSize -Wrap | Out-String -Width 230 | Write-Host
    $List | Export-Csv -LiteralPath $Csv -NoTypeInformation
    $Fail = @($List | Where-Object { $_.Status -eq 'FAIL' }).Count
    $Warn = @($List | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($Fail) { Write-Host "$($Title): FAILED - $Fail fail, $Warn warning(s). Results: $Csv" -ForegroundColor Red }
    elseif ($Warn) { Write-Host "$($Title): PASSED with $Warn warning(s). Results: $Csv" -ForegroundColor Yellow }
    else { Write-Host "$($Title): PASSED. Results: $Csv" -ForegroundColor Green }
    return $Fail
}
