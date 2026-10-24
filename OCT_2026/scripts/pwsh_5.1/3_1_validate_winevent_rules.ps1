#Requires -PSEdition Desktop
# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE (NOT pwsh 7).
# Run AFTER the App Control Policy Wizard created Events-Allow.xml (Step 4.2) and BEFORE the merge (script 4).
# Sanitizes every rule so Merge-CIPolicy / ConvertFrom-CIPolicy (and therefore CiTool.exe) accept the file.
# It only edits Events-Allow.xml after a successful compile + merge test; CiTool.exe is never called and no policy is applied.
# It also removes unsigned file-name rules ("Allow <file> by file attributes"), which match in any folder (-KeepFileNameRules).
param(
    [string]$EventsXml = 'C:\WDAC\Source\Events-Allow.xml',
    [string]$BaseXml = 'C:\WDAC\Source\Base-Audit.xml',
    [switch]$ReportOnly,
    [switch]$AllowPublisherFallback,
    # Keep unsigned file-name rules (FileName / InternalName / FileDescription / ProductName only) instead of removing them
    [switch]$KeepFileNameRules
)

$ErrorActionPreference = 'Stop'
Import-Module ConfigCI -WarningAction SilentlyContinue -ErrorAction Stop

$SiNs = 'urn:schemas-microsoft-com:sipolicy'
$IdentityAttrs = 'Hash', 'FilePath', 'FileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName'
$IdPattern = @{
    Allow      = '^(ID_ALLOW_[A-Z][_A-Z0-9]*|ID_FILE_[A-Z][_A-Z0-9]*)$'
    Deny       = '^(ID_DENY_[A-Z][_A-Z0-9]*|ID_FILE_[A-Z][_A-Z0-9]*)$'
    FileAttrib = '^(ID_FILEATTRIB_[A-Z][_A-Z0-9]*|ID_FILE_[A-Z][_A-Z0-9]*)$'
    Signer     = '^ID_SIGNER_[A-Z][_A-Z0-9]*$'
}
$IdPrefix = @{ Allow = 'ID_ALLOW_'; Deny = 'ID_DENY_'; FileAttrib = 'ID_FILEATTRIB_'; Signer = 'ID_SIGNER_' }

$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Action, [string]$Item, [string]$Detail) {
    $Findings.Add([pscustomobject]@{ Action = $Action; Item = $Item; Detail = $Detail })
}

function Get-Label($El) {
    foreach ($Name in 'ID', 'RuleID', 'SignerId') {
        $Value = $El.GetAttribute($Name)
        if ($Value) { return "$($El.LocalName) $Value" }
    }
    return $El.LocalName
}

function Get-SiNode([string]$XPath) { $Doc.SelectNodes($XPath, $Ns) }
function Remove-SiNode($Node) { [void]$Node.ParentNode.RemoveChild($Node) }
function New-IdSet { New-Object 'System.Collections.Generic.HashSet[string]' }

function Remove-DuplicateRefs($Parent, [string]$Attr) {
    $Seen = New-IdSet
    foreach ($Child in @($Parent.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.HasAttribute($Attr) })) {
        if (-not $Seen.Add($Child.LocalName + '|' + $Child.GetAttribute($Attr))) {
            Remove-SiNode $Child
            Add-Finding 'FIXED' (Get-Label $Child) 'duplicate reference removed'
        }
    }
}

# Returns a normalized a.b.c.d string, or $null when the value is not a valid 4-part (0-65535) version
function ConvertTo-SiVersion([string]$Text) {
    if ($Text -notmatch '^\d{1,5}(\.\d{1,5}){0,3}$') { return $null }
    $Parts = @($Text.Split('.') | ForEach-Object { [int]$_ })
    foreach ($Part in $Parts) { if ($Part -gt 65535) { return $null } }
    while ($Parts.Count -lt 4) { $Parts += 0 }
    return ($Parts -join '.')
}

# Returns the reason a file rule cannot be compiled/merged, or $null when it is valid (may normalize versions in place)
function Get-RuleProblem([System.Xml.XmlElement]$R) {
    $Present = @($IdentityAttrs | Where-Object { $R.HasAttribute($_) })
    if ($R.LocalName -eq 'FileAttrib') {
        if ($Present.Count -eq 0) { return 'FileAttrib has none of FileName, InternalName, FileDescription, ProductName, PackageFamilyName, Hash or FilePath' }
    }
    else {
        if ($Present.Count -eq 0) { return "$($R.LocalName) rule has no Hash, FilePath or FileName attribute" }
        if ($R.HasAttribute('Hash') -and $Present.Count -gt 1) { return 'Hash is combined with other file attributes' }
    }
    if ($R.HasAttribute('Hash')) {
        $Hash = $R.GetAttribute('Hash')
        if ($Hash -notmatch '^[0-9A-Fa-f]+$') { return 'Hash is not hexadecimal' }
        if ($Hash.Length -ne 40 -and $Hash.Length -ne 64) { return "Hash is $($Hash.Length) hex characters long (SHA-1 is 40, SHA-256 is 64)" }
    }
    $Versions = @{}
    foreach ($Attr in 'MinimumFileVersion', 'MaximumFileVersion') {
        if (-not $R.HasAttribute($Attr)) { continue }
        $Normalized = ConvertTo-SiVersion $R.GetAttribute($Attr)
        if (-not $Normalized) { return "$Attr '$($R.GetAttribute($Attr))' is not a valid a.b.c.d version (each part 0-65535)" }
        if ($Normalized -cne $R.GetAttribute($Attr)) {
            $R.SetAttribute($Attr, $Normalized)
            Add-Finding 'FIXED' (Get-Label $R) "$Attr normalized to $Normalized"
        }
        $Versions[$Attr] = $Normalized
    }
    if ($Versions.Count -eq 2 -and ([version]$Versions['MinimumFileVersion']) -gt ([version]$Versions['MaximumFileVersion'])) { return 'MinimumFileVersion is greater than MaximumFileVersion' }
    return $null
}

function Save-SiDoc([System.Xml.XmlDocument]$D, [string]$Path) {
    $Settings = New-Object System.Xml.XmlWriterSettings
    $Settings.Indent = $true
    $Settings.IndentChars = '  '
    $Settings.Encoding = New-Object System.Text.UTF8Encoding($true)
    $Writer = [System.Xml.XmlWriter]::Create($Path, $Settings)
    try { $D.Save($Writer) } finally { $Writer.Close() }
}

# Same schema the compiler uses; returns the validation messages (empty list = valid)
function Test-SiSchema([System.Xml.XmlDocument]$D, [string]$XsdPath) {
    $Messages = New-Object System.Collections.Generic.List[string]
    $Set = New-Object System.Xml.Schema.XmlSchemaSet
    $Reader = [System.Xml.XmlReader]::Create($XsdPath)
    try { [void]$Set.Add($SiNs, $Reader) } finally { $Reader.Close() }
    $Set.Compile()
    $script:SchemaMessages = $Messages
    $Handler = [System.Xml.Schema.ValidationEventHandler] { param($Sender, $Args2) $script:SchemaMessages.Add($Args2.Message) }
    $Copy = $D.CloneNode($true)
    $Copy.Schemas = $Set
    $Copy.Validate($Handler)
    return , $Messages
}

function Test-Toolchain([string]$XmlPath, [string]$Work) {
    $Errors = New-Object System.Collections.Generic.List[string]
    try { ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath (Join-Path $Work 'events.cip') -ErrorAction Stop | Out-Null }
    catch { $Errors.Add("Compiling Events-Allow.xml failed: $($_.Exception.Message)") }
    if (Test-Path -LiteralPath $BaseXml) {
        try {
            $Merged = Join-Path $Work 'merged.xml'
            Merge-CIPolicy -PolicyPaths $BaseXml, $XmlPath -OutputFilePath $Merged -ErrorAction Stop | Out-Null
            ConvertFrom-CIPolicy -XmlFilePath $Merged -BinaryFilePath (Join-Path $Work 'merged.cip') -ErrorAction Stop | Out-Null
        }
        catch { $Errors.Add("Merging with $BaseXml (or compiling the merged result) failed: $($_.Exception.Message)") }
    }
    return , $Errors
}

# ---------------------------------------------------------------- load
if (-not (Test-Path -LiteralPath $EventsXml)) { throw "STOP: $EventsXml not found. Create it with the App Control Policy Wizard first (Step 4.2)." }
$Doc = New-Object System.Xml.XmlDocument
try { $Doc.Load($EventsXml) } catch { throw "STOP: $EventsXml is not well-formed XML: $($_.Exception.Message)" }
if ($Doc.DocumentElement.LocalName -ne 'SiPolicy' -or $Doc.DocumentElement.NamespaceURI -ne $SiNs) { throw "STOP: $EventsXml is not an App Control policy (the root element must be SiPolicy in $SiNs)." }
$Ns = New-Object System.Xml.XmlNamespaceManager $Doc.NameTable
$Ns.AddNamespace('s', $SiNs)

$XsdPath = Join-Path $env:SystemRoot 'schemas\CodeIntegrity\cipolicy.xsd'
$XsdFound = Test-Path -LiteralPath $XsdPath
$AllowedOptions = @()
if ($XsdFound) {
    $Xsd = New-Object System.Xml.XmlDocument
    $Xsd.Load($XsdPath)
    $XsNs = New-Object System.Xml.XmlNamespaceManager $Xsd.NameTable
    $XsNs.AddNamespace('xs', 'http://www.w3.org/2001/XMLSchema')
    $AllowedOptions = @($Xsd.SelectNodes("//xs:simpleType[@name='OptionType']/xs:restriction/xs:enumeration", $XsNs) | ForEach-Object { $_.GetAttribute('value') })
}

# ---------------------------------------------------------------- 1. normalize values (empty attributes compile alone but break the merge)
$Normalized = 0
foreach ($R in @(Get-SiNode '//s:FileRules/*')) {
    foreach ($A in @($R.Attributes | Where-Object { $_.Name -ne 'ID' -and $_.Name -ne 'FriendlyName' })) {
        $Trimmed = $A.Value.Trim()
        if ($Trimmed.Length -eq 0) {
            [void]$R.Attributes.Remove($A)
            Add-Finding 'FIXED' (Get-Label $R) "removed empty $($A.Name) attribute"
        }
        elseif ($Trimmed -cne $A.Value) { $A.Value = $Trimmed; $Normalized++ }
    }
    if ($R.HasAttribute('Hash') -and $R.GetAttribute('Hash') -cne $R.GetAttribute('Hash').ToUpperInvariant()) {
        $R.SetAttribute('Hash', $R.GetAttribute('Hash').ToUpperInvariant())
        $Normalized++
    }
}
if ($Normalized -gt 0) { Add-Finding 'FIXED' 'FileRules' "$Normalized value(s) normalized (trimmed whitespace / upper-case hashes)" }

# ---------------------------------------------------------------- 2. duplicate IDs (keep the first)
foreach ($XPath in '//s:FileRules/*', '//s:Signers/s:Signer') {
    $Seen = New-IdSet
    foreach ($E in @(Get-SiNode $XPath)) {
        $Id = $E.GetAttribute('ID')
        if ($Id -and -not $Seen.Add($Id)) {
            Remove-SiNode $E
            Add-Finding 'REMOVED' (Get-Label $E) 'duplicate ID (the first occurrence was kept)'
        }
    }
}

# ---------------------------------------------------------------- 3. IDs that do not match the schema pattern are renamed (references follow)
$UsedIds = New-IdSet
foreach ($E in @(Get-SiNode '//s:FileRules/* | //s:Signers/s:Signer')) { [void]$UsedIds.Add($E.GetAttribute('ID')) }
$Counter = 0
foreach ($E in @(Get-SiNode '//s:FileRules/* | //s:Signers/s:Signer')) {
    if (-not $IdPattern.ContainsKey($E.LocalName)) { continue }
    $Old = $E.GetAttribute('ID')
    if ($Old -cmatch $IdPattern[$E.LocalName]) { continue }
    do { $Counter++; $New = $IdPrefix[$E.LocalName] + 'SAN_' + $Counter } while ($UsedIds.Contains($New))
    [void]$UsedIds.Add($New)
    $E.SetAttribute('ID', $New)
    if ($Old) {
        foreach ($Ref in @(Get-SiNode '//*[@RuleID or @SignerId or @DenyRuleID or @AllowRuleID]')) {
            foreach ($AttrName in 'RuleID', 'SignerId', 'DenyRuleID', 'AllowRuleID') {
                if ($Ref.GetAttribute($AttrName) -ceq $Old) { $Ref.SetAttribute($AttrName, $New) }
            }
        }
    }
    Add-Finding 'FIXED' "$($E.LocalName) '$Old'" "ID does not match the schema pattern; renamed to $New"
}

# ---------------------------------------------------------------- 4. file rules the compiler/merge would reject
foreach ($R in @(Get-SiNode '//s:FileRules/*')) {
    if ('Allow', 'Deny', 'FileAttrib' -cnotcontains $R.LocalName) { continue }
    $Problem = Get-RuleProblem $R
    if ($Problem) {
        Remove-SiNode $R
        Add-Finding 'REMOVED' (Get-Label $R) $Problem
    }
}

# ---------------------------------------------------------------- 4b. unsigned file-name rules ("Allow <file> by file attributes")
#     An Allow rule with only FileName / InternalName / FileDescription / ProductName - no signer, no path, no hash - matches a
#     file with those names in ANY folder, and these version-resource values are easy to fake. Removed by default: cover the file
#     with a FilePath / folder rule (script 4 -AdditionalFolderRules) or a Publisher rule. -KeepFileNameRules keeps them (WARN).
#     Packaged-app rules (PackageFamilyName) and Deny rules are not affected.
foreach ($R in @(Get-SiNode '//s:FileRules/s:Allow')) {
    if ($R.HasAttribute('Hash') -or $R.HasAttribute('FilePath') -or $R.HasAttribute('PackageFamilyName')) { continue }
    $Attrs = @(@('FileName', 'InternalName', 'FileDescription', 'ProductName') | Where-Object { $R.HasAttribute($_) } | ForEach-Object { "$_='$($R.GetAttribute($_))'" })
    if ($Attrs.Count -eq 0) { continue }
    $What = ($R.GetAttribute('FriendlyName') -replace ';\s*Correlation Id.*$', '')
    if ($KeepFileNameRules) { Add-Finding 'WARN' (Get-Label $R) "unsigned file-name rule kept (-KeepFileNameRules): $What - $($Attrs -join ', ') matches in ANY folder and can be faked" }
    else {
        Remove-SiNode $R
        Add-Finding 'REMOVED' (Get-Label $R) "unsigned file-name rule: $What - $($Attrs -join ', ') would allow a file with these names in ANY folder, and they can be faked. Cover it with a FilePath/folder rule (script 4 -AdditionalFolderRules) or a Publisher rule (-KeepFileNameRules keeps it)"
    }
}

# ---------------------------------------------------------------- 5. signers (a signer that loses every FileAttrib would silently become a whole-publisher rule)
$FileAttribIds = New-IdSet
foreach ($F in @(Get-SiNode '//s:FileRules/s:FileAttrib')) { [void]$FileAttribIds.Add($F.GetAttribute('ID')) }
$EkuIds = New-IdSet
foreach ($K in @(Get-SiNode '//s:EKUs/s:EKU')) { [void]$EkuIds.Add($K.GetAttribute('ID')) }

foreach ($S in @(Get-SiNode '//s:Signers/s:Signer')) {
    $Problem = $null
    $Roots = @($S.SelectNodes('s:CertRoot', $Ns))
    if ($Roots.Count -eq 0) { $Problem = 'signer has no CertRoot' }
    else {
        $Type = $Roots[0].GetAttribute('Type')
        $Value = $Roots[0].GetAttribute('Value')
        if ('TBS', 'Wellknown' -cnotcontains $Type) { $Problem = "CertRoot Type '$Type' is not TBS or Wellknown" }
        elseif ($Value -notmatch '^([0-9A-Fa-f]{2})+$') { $Problem = 'CertRoot Value is empty or not valid hexadecimal' }
        elseif ($Type -ceq 'TBS' -and 40, 64, 96, 128 -notcontains $Value.Length) { Add-Finding 'WARN' (Get-Label $S) "CertRoot TBS hash is $($Value.Length) hex characters (expected 40, 64, 96 or 128)" }
    }
    if (-not $Problem) {
        foreach ($C in @($S.SelectNodes('s:CertPublisher | s:CertIssuer', $Ns))) {
            if ([string]::IsNullOrWhiteSpace($C.GetAttribute('Value'))) { $Problem = "$($C.LocalName) is empty (an empty publisher would not restrict the signer safely)" }
        }
        foreach ($C in @($S.SelectNodes('s:CertEKU', $Ns))) {
            if (-not $EkuIds.Contains($C.GetAttribute('ID'))) { $Problem = "CertEKU '$($C.GetAttribute('ID'))' does not exist in EKUs" }
        }
    }
    if ($Problem) {
        Remove-SiNode $S
        Add-Finding 'REMOVED' (Get-Label $S) $Problem
        continue
    }

    if ([string]::IsNullOrWhiteSpace($S.GetAttribute('Name'))) {
        $S.SetAttribute('Name', $S.GetAttribute('ID'))
        Add-Finding 'FIXED' (Get-Label $S) 'Name was missing; set to the signer ID'
    }

    $Refs = @($S.SelectNodes('s:FileAttribRef', $Ns))
    if ($Refs.Count -gt 0) {
        $Kept = 0
        $DroppedRefs = New-Object System.Collections.Generic.List[string]
        $SeenRefs = New-IdSet
        foreach ($Ref in $Refs) {
            $RefId = $Ref.GetAttribute('RuleID')
            if (-not $FileAttribIds.Contains($RefId)) { Remove-SiNode $Ref; $DroppedRefs.Add($RefId) }
            elseif (-not $SeenRefs.Add($RefId)) { Remove-SiNode $Ref; Add-Finding 'FIXED' "FileAttribRef $RefId" 'duplicate reference removed' }
            else { $Kept++ }
        }
        if ($DroppedRefs.Count -gt 0) { Add-Finding 'REMOVED' "FileAttribRef (signer $($S.GetAttribute('ID')))" "reference(s) to missing or removed FileAttrib: $($DroppedRefs -join ', ')" }
        if ($Kept -eq 0) {
            if ($AllowPublisherFallback) {
                Add-Finding 'WARN' (Get-Label $S) 'all of its FileAttrib restrictions were invalid - the signer now trusts EVERY file from this publisher (-AllowPublisherFallback)'
            }
            else {
                Remove-SiNode $S
                Add-Finding 'REMOVED' (Get-Label $S) 'all of its FileAttrib rules were invalid; kept out of the policy so it does not widen to a whole-publisher rule (re-add the file as Hash/Publisher in the Wizard, or use -AllowPublisherFallback)'
            }
        }
    }
}

# ---------------------------------------------------------------- 6. references
$SignerIds = New-IdSet
foreach ($S in @(Get-SiNode '//s:Signers/s:Signer')) { [void]$SignerIds.Add($S.GetAttribute('ID')) }
foreach ($Ref in @(Get-SiNode '//*[@SignerId]')) {
    if (-not $SignerIds.Contains($Ref.GetAttribute('SignerId'))) {
        Remove-SiNode $Ref
        Add-Finding 'REMOVED' (Get-Label $Ref) 'reference to a missing or removed signer'
    }
}
foreach ($P in @(Get-SiNode '//*[*[@SignerId]]')) { Remove-DuplicateRefs $P 'SignerId' }

$RuleIds = New-IdSet
foreach ($R in @(Get-SiNode '//s:FileRules/s:Allow | //s:FileRules/s:Deny')) { [void]$RuleIds.Add($R.GetAttribute('ID')) }
foreach ($Ref in @(Get-SiNode '//s:FileRuleRef')) {
    if (-not $RuleIds.Contains($Ref.GetAttribute('RuleID'))) {
        Remove-SiNode $Ref
        Add-Finding 'REMOVED' (Get-Label $Ref) 'reference to a missing or removed Allow/Deny rule'
    }
}
foreach ($P in @(Get-SiNode '//*[s:FileRuleRef]')) { Remove-DuplicateRefs $P 'RuleID' }

foreach ($C in @(Get-SiNode '//s:AllowedSigners | //s:DeniedSigners | //s:FileRulesRef')) {
    if (-not $C.HasChildNodes) { Remove-SiNode $C }
}

# ---------------------------------------------------------------- 7. policy options
$SeenOptions = New-IdSet
foreach ($O in @(Get-SiNode '//s:Rules/s:Rule/s:Option')) {
    $Text = $O.InnerText.Trim()
    if ($AllowedOptions -and $AllowedOptions -cnotcontains $Text) {
        Remove-SiNode $O.ParentNode
        Add-Finding 'REMOVED' "Option '$Text'" 'not a valid policy option for this Windows version'
    }
    elseif (-not $SeenOptions.Add($Text)) {
        Remove-SiNode $O.ParentNode
        Add-Finding 'FIXED' "Option '$Text'" 'duplicate option removed'
    }
    elseif ($Text -cne $O.InnerText) { $O.InnerText = $Text }
}

# ---------------------------------------------------------------- 8. rules that are valid but have no effect
$ReferencedRules = New-IdSet
foreach ($Ref in @(Get-SiNode '//s:FileRuleRef')) { [void]$ReferencedRules.Add($Ref.GetAttribute('RuleID')) }
foreach ($R in @(Get-SiNode '//s:FileRules/s:Allow | //s:FileRules/s:Deny')) {
    if (-not $ReferencedRules.Contains($R.GetAttribute('ID'))) { Add-Finding 'WARN' (Get-Label $R) 'not referenced by any signing scenario, so it has no effect' }
}
$ReferencedSigners = New-IdSet
foreach ($Ref in @(Get-SiNode '//*[@SignerId]')) { [void]$ReferencedSigners.Add($Ref.GetAttribute('SignerId')) }
foreach ($S in @(Get-SiNode '//s:Signers/s:Signer')) {
    if (-not $ReferencedSigners.Contains($S.GetAttribute('ID'))) { Add-Finding 'WARN' (Get-Label $S) 'not referenced by any signing scenario or signer list, so it has no effect' }
}

# ---------------------------------------------------------------- 9. whatever the schema still rejects
if (-not (Test-Path -LiteralPath $BaseXml)) { Add-Finding 'WARN' 'Merge test' "$BaseXml not found - the merge test will be skipped (only the compile test runs)" }
if ($XsdFound) {
    try {
        $SchemaMessages = Test-SiSchema $Doc $XsdPath
        foreach ($Message in ($SchemaMessages | Select-Object -First 10)) { Add-Finding 'WARN' 'Schema' $Message }
    }
    catch { Add-Finding 'WARN' 'Schema' "schema validation could not run: $($_.Exception.Message)" }
}
else { Add-Finding 'WARN' 'Schema' "$XsdPath not found - schema validation was skipped" }

# ---------------------------------------------------------------- report
$Changed = @($Findings | Where-Object { $_.Action -eq 'FIXED' -or $_.Action -eq 'REMOVED' }).Count -gt 0
$Fixed = @($Findings | Where-Object Action -eq 'FIXED').Count
$Removed = @($Findings | Where-Object Action -eq 'REMOVED').Count
$Warned = @($Findings | Where-Object Action -eq 'WARN').Count

if ($Findings.Count -gt 0) { $Findings | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host }
$LogDir = 'C:\WDAC\Logs'
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
$LogFile = Join-Path $LogDir "Events-Allow-Sanitize-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Findings | Export-Csv -LiteralPath $LogFile -NoTypeInformation
Write-Host "Findings: $Fixed fixed, $Removed removed, $Warned warning(s). Log: $LogFile" -ForegroundColor Cyan

# ---------------------------------------------------------------- prove the result compiles and merges before touching the file
$Work = Join-Path ([IO.Path]::GetTempPath()) ('wdac_sanitize_' + [guid]::NewGuid().ToString('N'))
New-Item -Path $Work -ItemType Directory -Force | Out-Null
try {
    $Candidate = $EventsXml
    if ($Changed) {
        $Candidate = Join-Path $Work 'Events-Allow.sanitized.xml'
        Save-SiDoc $Doc $Candidate
    }
    $Errors = Test-Toolchain $Candidate $Work
    if ($Errors.Count -gt 0) {
        $Errors | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        throw "STOP: $EventsXml still fails Merge-CIPolicy/ConvertFrom-CIPolicy after sanitizing. It was NOT modified. Review the messages above and the findings log, fix the rule in the Wizard, then re-run."
    }

    if (-not $Changed) {
        Write-Host "PASSED: every rule in $EventsXml is valid; it compiles and merges as-is. No changes were needed." -ForegroundColor Green
    }
    elseif ($ReportOnly) {
        Write-Host "PASSED (-ReportOnly): the sanitized policy compiles and merges. $EventsXml was NOT modified." -ForegroundColor Yellow
    }
    else {
        $Backup = Join-Path (Split-Path -Parent $EventsXml) ([IO.Path]::GetFileNameWithoutExtension($EventsXml) + ".original-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml")
        Copy-Item -LiteralPath $EventsXml -Destination $Backup -ErrorAction Stop
        Copy-Item -LiteralPath $Candidate -Destination $EventsXml -Force -ErrorAction Stop
        Write-Host "PASSED: $EventsXml was sanitized and now compiles and merges. Original saved as $Backup" -ForegroundColor Green
    }
}
finally { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
