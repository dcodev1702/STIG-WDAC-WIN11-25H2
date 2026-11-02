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

# Target OU: the TargetOU setting, or the OU of this computer. With -Domain, an OU of another domain (for example a settings file
# copied from another enclave) stops here, before anything is read from or written to the wrong place.
function Resolve-WdacTargetOU($Cfg, $Domain) {
    $OU = if ($Cfg.TargetOU) { "$($Cfg.TargetOU)".Trim() } else { Get-WdacComputerOU }
    if ($Domain -and $Domain.DN) {
        $Norm = { param($Dn) ("$Dn" -replace '\s*,\s*', ',').ToLowerInvariant() }
        if (-not (& $Norm $OU).EndsWith(',' + (& $Norm $Domain.DN))) {
            throw "STOP: target OU '$OU' is not in domain $($Domain.DnsRoot) ($($Domain.DN)). Set TargetOU in GPO-Settings.psd1 (or pass -TargetOU) to an OU of this domain, or leave it empty to use the OU of this computer. Nothing was changed."
        }
    }
    return $OU
}

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

# Portability gate for a policy XML that is published to other OUs and domains (enclaves). A FilePath rule under a named user
# profile (C:\Users\<name>\...) works for that one user only, carries the user name - and the domain, in a <user>.<DOMAIN> profile
# folder - into every enclave, and runtime FilePath rule protection ignores user-writable folders anyway: FAIL. The same text in
# any other attribute or value (a FriendlyName copied from an event, for example) only discloses the name: WARN.
function Get-WdacPortabilityFindings([string]$XmlPath) {
    $Rows = New-Object System.Collections.Generic.List[object]
    $Name = Split-Path -Leaf $XmlPath
    $Doc = New-Object System.Xml.XmlDocument
    try { $Doc.Load($XmlPath) }
    catch { $Rows.Add([pscustomobject]@{ Status = 'FAIL'; Check = "$Name portability"; Detail = "cannot read the XML: $($_.Exception.Message)" }); return , $Rows.ToArray() }
    $ProfileRx = '(?i)\\Users\\(?!(?:Public|Default|Default User|All Users)(?:\\|$))([^\\*]+)'
    $RuleIds = New-Object System.Collections.Generic.List[string]
    $Named = New-Object System.Collections.Generic.List[string]
    $TextHits = New-Object System.Collections.Generic.List[string]
    foreach ($Node in @($Doc.SelectNodes('//@*')) + @($Doc.SelectNodes('//text()'))) {
        $M = [regex]::Match("$($Node.Value)", $ProfileRx)
        if (-not $M.Success) { continue }
        $Named.Add($M.Groups[1].Value)
        $Owner = if ($Node.NodeType -eq 'Attribute') { $Node.OwnerElement } else { $Node.ParentNode }
        $Id = if ($Owner -and $Owner.GetAttribute('ID')) { $Owner.GetAttribute('ID') } else { $Owner.LocalName }
        if ($Node.NodeType -eq 'Attribute' -and $Node.LocalName -eq 'FilePath') { if (-not $RuleIds.Contains($Id)) { $RuleIds.Add($Id) } }
        elseif (-not $RuleIds.Contains($Id)) { $TextHits.Add("$Id.$($Node.LocalName)") }
    }
    $Profiles = (@($Named | Sort-Object -Unique) | ForEach-Object { "'$_'" }) -join ', '
    if ($RuleIds.Count) {
        $Fix = "foreach (`$Id in '$($RuleIds -join "', '")') { Remove-CIPolicyRule -FilePath '$($XmlPath.Replace("'", "''"))' -Id `$Id }"
        $Rows.Add([pscustomobject]@{ Status = 'FAIL'; Check = "$Name user-profile rules"; Detail = "$($RuleIds.Count) FilePath rule(s) name the user profile $Profiles ($($RuleIds -join ', ')). They allow files for that one user only, carry the user and domain name into every enclave, and runtime FilePath rule protection ignores user-writable folders. Remove them on the reference device (Windows PowerShell 5.1, ConfigCI): $Fix - or in the App Control Wizard - then run this step again." })
    }
    $TextOnly = @($TextHits | Where-Object { $RuleIds -notcontains ($_ -replace '\.[^.]+$', '') } | Sort-Object -Unique)
    if ($TextOnly.Count) { $Rows.Add([pscustomobject]@{ Status = 'WARN'; Check = "$Name user-profile text"; Detail = "rule text names the user profile $Profiles ($($TextOnly -join ', ')). It changes nothing on the devices but discloses the name in every enclave - edit the text in the App Control Wizard." }) }
    if (-not $RuleIds.Count -and -not $TextOnly.Count) { $Rows.Add([pscustomobject]@{ Status = 'OK'; Check = "$Name portability"; Detail = 'no rule or rule text names a user profile (C:\Users\<name>)' }) }
    return , $Rows.ToArray()
}

# FilePath values of the policy's allow rules: what runtime FilePath rule protection checks on every device
function Get-WdacFilePathRules([string]$XmlPath) {
    $Doc = New-Object System.Xml.XmlDocument; $Doc.Load($XmlPath)
    return , @($Doc.SiPolicy.FileRules.ChildNodes | Where-Object { $_.LocalName -eq 'Allow' -and $_.GetAttribute('FilePath') } | ForEach-Object { $_.GetAttribute('FilePath') } | Sort-Object -Unique)
}

# Runtime FilePath rule protection: Windows ignores a FilePath rule whose folder standard users can write to, so the files there are
# BLOCKED under Enforce. Checks each rule folder (and its parents, not the drive root, where users may create folders by default) on
# the computer it runs on - locally with &, or remotely with Invoke-Command, so it is self-contained. Write = write data/add file,
# append data/add folder, delete, change permissions, take ownership, GENERIC_WRITE or GENERIC_ALL, granted to anyone other than
# SYSTEM, TrustedInstaller, CREATOR OWNER and the administrator groups (the same rule 4_merge_audit_base_and_events_policies.ps1
# applies to -AdditionalFolderRules). Returns one row per folder: Folder, Rules, Exists, Writers.
$WdacFilePathFolderCheck = {
    param([string[]]$RulePaths)
    $WriteMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $Admins = '(^|\\)(SYSTEM|TrustedInstaller|CREATOR OWNER|Administrators|Domain Admins|Enterprise Admins)$'
    $ByFolder = [ordered]@{}
    foreach ($Rule in @($RulePaths | Where-Object { $_ })) {
        $Path = $Rule
        foreach ($Macro in @(@('%OSDRIVE%', $env:SystemDrive), @('%WINDIR%', $env:SystemRoot), @('%SYSTEM32%', (Join-Path $env:SystemRoot 'System32')))) {
            if ($Path.StartsWith($Macro[0], [StringComparison]::OrdinalIgnoreCase)) { $Path = $Macro[1] + $Path.Substring($Macro[0].Length) }
        }
        $Star = $Path.IndexOf('*')
        $Folder = if ($Star -ge 0) { $Prefix = $Path.Substring(0, $Star); if ($Prefix.EndsWith('\')) { $Prefix.TrimEnd('\') } else { [IO.Path]::GetDirectoryName($Prefix) } }
                  elseif (Test-Path -LiteralPath $Path -PathType Container) { $Path.TrimEnd('\') }
                  else { [IO.Path]::GetDirectoryName($Path) }
        if (-not $Folder) { $Folder = $Path }
        if (-not $ByFolder.Contains($Folder)) { $ByFolder[$Folder] = New-Object System.Collections.Generic.List[string] }
        $ByFolder[$Folder].Add($Rule)
    }
    foreach ($Folder in $ByFolder.Keys) {
        $Exists = [bool](Test-Path -LiteralPath $Folder -PathType Container)
        $Writers = New-Object System.Collections.Generic.List[string]
        if ($Exists) {
            $Root = ([IO.Path]::GetPathRoot($Folder)).TrimEnd('\')
            $Dir = $Folder
            while ($Dir -and $Dir.TrimEnd('\') -ne $Root) {
                try {
                    foreach ($Ace in (Get-Acl -LiteralPath $Dir -ErrorAction Stop).Access) {
                        if ("$($Ace.AccessControlType)" -ne 'Allow' -or "$($Ace.IdentityReference)" -match $Admins) { continue }
                        if (([int]$Ace.FileSystemRights -band $WriteMask) -ne 0 -and -not $Writers.Contains("$($Ace.IdentityReference) on $Dir")) { $Writers.Add("$($Ace.IdentityReference) on $Dir") }
                    }
                }
                catch { $Writers.Add("ACL of $Dir unreadable: $($_.Exception.Message)") }
                $Dir = [IO.Path]::GetDirectoryName($Dir)
            }
        }
        [pscustomobject]@{ Folder = $Folder; Rules = $ByFolder[$Folder].ToArray(); Exists = $Exists; Writers = $Writers.ToArray() }
    }
}

# Result rows for $WdacFilePathFolderCheck: one WARN per folder that is missing or user-writable, then one summary row
function Add-WdacFolderCheckResults($List, $Rows, [string]$Prefix) {
    $Rows = @($Rows | Where-Object { $_ })
    $Bad = 0
    foreach ($F in $Rows) {
        $What = "$($F.Folder) ($(@($F.Rules).Count) rule(s), e.g. $(@($F.Rules)[0]))"
        if (-not $F.Exists) { $Bad++; Add-WdacResult $List 'WARN' ("$Prefix FilePath folder").Trim() "$What does not exist on this computer - the rule allows nothing here" }
        elseif (@($F.Writers).Count) { $Bad++; Add-WdacResult $List 'WARN' ("$Prefix FilePath folder").Trim() "$What is writable by $(@($F.Writers) -join '; ') - runtime FilePath rule protection ignores the rule, so files there are BLOCKED under Enforce. Remove write access for standard users in the image, or allow those files by publisher or hash." }
    }
    Add-WdacResult $List $(if ($Bad) { 'WARN' } else { 'OK' }) ("$Prefix FilePath folders").Trim() $(if ($Rows.Count) { "$($Rows.Count - $Bad) of $($Rows.Count) rule folder(s) admin-only$(if ($Bad) { "; $Bad need attention (rows above)" })" } else { 'the policy has no FilePath allow rules' })
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
