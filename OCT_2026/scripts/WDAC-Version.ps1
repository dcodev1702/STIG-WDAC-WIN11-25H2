# Date-based App Control policy versions. IDENTICAL copy in C:\WDAC\config\scripts, C:\WDAC\config\scripts\pwsh_5.1 and
# C:\WDAC\GPO\scripts (each folder is copied and used on its own). Dot-source it. Windows PowerShell 5.1 and PowerShell 7.
#
#   Scheme:  YYYY.MM.DD.N   (local date; the counter N starts at 1 every day)
#            e.g. 2026.10.23.1, 2026.10.23.2 ... then 2026.10.24.1
#   Windows compares the four parts in order, so the date always outranks the counter.
#   Rule:    a new version is NEVER lower than the highest version already known for the policy (another reference device,
#            clock skew, a build "in the future"): CiTool and the GPO endpoint script only ever move a policy forward.
#   Note:    each part is a number, so CiTool / Event 3099 show 9 October as 2026.10.9.1 (no leading zeros).

# Version(s) stamped in policy XML file(s)
function Get-WdacVersionsFromXml([string[]]$Path) {
    foreach ($P in $Path) {
        if (-not $P -or -not (Test-Path -LiteralPath $P)) { continue }
        $Doc = New-Object System.Xml.XmlDocument
        try { $Doc.Load($P); [version]$Doc.SiPolicy.VersionEx } catch { }
    }
}

# Version of the policy GUID as CiTool reports it on this computer (active or on disk)
function Get-WdacActivePolicyVersion([string]$PolicyGuid) {
    $CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
    if (-not $PolicyGuid -or -not (Test-Path -LiteralPath $CiTool)) { return }
    $Guid = $PolicyGuid.Trim('{}').ToLower()
    foreach ($P in @((& $CiTool --list-policies -json | ConvertFrom-Json).Policies | Where-Object { $_.PolicyID -eq $Guid })) { try { [version]$P.VersionString } catch { } }
}

# Versions in archived binaries named <name>_v<a.b.c.d>.cip (C:\WDAC\Compiled). Pass -Name to count only one policy's archives
# (other policies, such as local supplementals, are archived in the same folder).
function Get-WdacVersionsFromArchive([string]$Folder = 'C:\WDAC\Compiled', [string[]]$Name = @('*')) {
    foreach ($F in @(Get-ChildItem -Path $Folder -Filter '*_v*.cip' -File -ErrorAction SilentlyContinue)) {
        if ($F.Name -notmatch '^(.+)_v(\d+\.\d+\.\d+\.\d+)\.cip$') { continue }
        $Base = $Matches[1]; $Ver = $Matches[2]
        if (@($Name | Where-Object { $Base -like $_ }).Count) { [version]$Ver }
    }
}

# Versions of the policy GUID in manifest.json files under the given folders (GPO packages and GPO SYSVOL payloads)
function Get-WdacVersionsFromManifests([string[]]$Folder, [string]$PolicyGuid) {
    foreach ($Root in $Folder) {
        if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { continue }
        foreach ($M in @(Get-ChildItem -Path $Root -Filter 'manifest.json' -Recurse -File -ErrorAction SilentlyContinue)) {
            try { foreach ($P in @((Get-Content -LiteralPath $M.FullName -Raw | ConvertFrom-Json).Policies | Where-Object { "$($_.PolicyGuid)".Trim('{}') -ieq $PolicyGuid.Trim('{}') })) { [version]$P.Version } } catch { }
        }
    }
}

# Versions of the policy GUID in the GPO packages built on THIS device (C:\WDAC\GPO\Packages\<stamp>\Audit|Enforce\manifest.json).
# The config scripts count them too: a version that a published Audit or Enforce package already uses must never be reused for
# a different policy, or an endpoint holding that package would treat the new policy as "already active".
function Get-WdacVersionsFromGpoPackages([string]$PolicyGuid, [string]$Root = 'C:\WDAC\GPO\Packages') {
    if ($PolicyGuid -and (Test-Path -LiteralPath $Root)) { Get-WdacVersionsFromManifests -Folder $Root -PolicyGuid $PolicyGuid }
}

# Returns $Count consecutive versions starting at today's date + counter, always above every known version
function Get-WdacNextVersion([version[]]$Known = @(), [int]$Count = 1, [datetime]$Date = (Get-Date)) {
    $Today = New-Object version $Date.Year, $Date.Month, $Date.Day, 1
    $Highest = @($Known | Where-Object { $_ } | Sort-Object) | Select-Object -Last 1
    $First = $Today
    $Basis = "today $($Date.ToString('yyyy-MM-dd')), counter 1"
    if ($Highest -and $Highest -ge $Today) {
        $First = New-Object version $Highest.Major, $Highest.Minor, $Highest.Build, ($Highest.Revision + 1)
        $SameDay = ($Highest.Major -eq $Today.Major -and $Highest.Minor -eq $Today.Minor -and $Highest.Build -eq $Today.Build)
        $Basis = if ($SameDay) { "today $($Date.ToString('yyyy-MM-dd')), next counter after v$Highest" } else { "v$Highest is later than today's date (clock skew or a future build) - continuing after it" }
    }
    if ($First.Revision + $Count - 1 -gt 65535) { throw "STOP: the daily counter would pass 65535 after v$Highest. Pass an explicit version." }
    [pscustomobject]@{
        Versions = @(for ($i = 0; $i -lt $Count; $i++) { "$($First.Major).$($First.Minor).$($First.Build).$($First.Revision + $i)" })
        Highest  = $(if ($Highest) { "$Highest" } else { '(none)' })
        Basis    = $Basis
    }
}
