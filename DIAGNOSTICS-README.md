# App Control Diagnostics and Troubleshooting

[Main walkthrough](README.md) | [Policy reset runbook](POLICY-RESET-README.md)

Use three separate checks: **what the source XML configures**, **which policy the PAW has loaded**, and **what happened when an application ran**. None of these checks replaces the other two.

## Troubleshooting Order

| Symptom | Check first | Follow-through |
|---|---|---|
| New rules appear to have no effect | Source version/options, GPO source path, binary hash, CiTool inventory, 3099 details | Confirm the intended revision loaded; investigate 3095/3097/3100 before changing rules again |
| Old 3076s still appear | Recorded post-activation time boundary and event policy ID | Historical records persist; reproduce the workload and examine only fresh events from the intended policy |
| Fresh 3076/3077 for an approved application | Exact file/component, policy ID, 3089 signature details, explicit denies | Check DLLs/drivers and update-specific hashes; another enforced base may still block |
| Supplemental exists on disk but does not extend trust | Base option 17, policy format, BasePolicyID, signer authorization, CiTool authorization | Confirm supported deployment and loading; existence on disk is insufficient |
| GPO looks applied but the wrong policy runs | Resultant GPO path and competing deployment sources | Verify the actual endpoint binary and activation; do not equate `gpupdate` with loading |
| MSI starts but fails later | AppLocker MSI/Script events plus CodeIntegrity 3077 for extracted DLLs | Installer publisher trust does not automatically authorize unsigned custom-action DLLs |
| PowerShell behaves differently by session/script | Host/version, current LanguageMode, script/module trust, all active policies | Do not infer a Domain Admin exemption or the whole policy state from one session |

> [!IMPORTANT]
> These commands inspect configuration; they do not merge, deploy, refresh, or remove policies.
>
> - Run the ConfigCI examples in **Windows PowerShell 5.1** on the authoring workstation. PowerShell 7 compatibility remoting can change how ConfigCI collections are returned.
> - Run endpoint checks in an **elevated session on the target PAW**, not just on the workstation running the Wizard.
> - Replace the example `C:\WDAC\...` paths with your actual files.
> - `Get-CIPolicy` and `Get-CIPolicyIdInfo` inspect **source XML**. Do not pass a compiled `.p7b` or `.cip` file to them or assume they report the active endpoint policy.

## Inspect the Source XML: Identity, Version, and Rule Options

Confirm the commands are available, then select the editable source XML associated with the policy binary you are investigating:

```powershell
Get-Command Get-CIPolicy, Get-CIPolicyIdInfo -ErrorAction Stop
$PolicyXml = 'C:\WDAC\Source\YourPolicy.xml'

Get-CIPolicyIdInfo -FilePath $PolicyXml -ErrorAction Stop |
    Select-Object ValueName, Value |
    Format-Table -AutoSize
```

`Get-CIPolicyIdInfo` reports the friendly PolicyInfo name and identifier. A date-like identifier such as `2026-03-27v3` is **not** the multiple-policy GUID and does not set `VersionEx`.

Read the XML's actual identity fields and configured options:

```powershell
[xml]$PolicyDocument = Get-Content -LiteralPath $PolicyXml -Raw -ErrorAction Stop
$RuleOptions = @($PolicyDocument.SiPolicy.Rules.Rule.Option)

[pscustomobject]@{
    VersionEx = $PolicyDocument.SiPolicy.VersionEx
    PolicyID = $PolicyDocument.SiPolicy.PolicyID
    BasePolicyID = $PolicyDocument.SiPolicy.BasePolicyID
    LegacyPolicyTypeID = $PolicyDocument.SiPolicy.PolicyTypeID
    AuditModeConfigured = $RuleOptions -contains 'Enabled:Audit Mode'
    UMCIConfigured = $RuleOptions -contains 'Enabled:UMCI'
    SupplementalPoliciesAllowed = $RuleOptions -contains 'Enabled:Allow Supplemental Policies'
    ISGConfigured = $RuleOptions -contains 'Enabled:Intelligent Security Graph Authorization'
} | Format-List

$RuleOptions | Sort-Object
```

**Interpretation:**

- `AuditModeConfigured = True` means this XML requests audit mode. `False` means it requests enforcement; it does not prove that this file is deployed.
- Legacy authoring XML uses `PolicyTypeID`; empty `PolicyID` and `BasePolicyID` fields are expected in that layout. Do not mistake `PolicyTypeID` for a unique modern policy identity.
- In multiple-policy format, a base has matching `PolicyID` and `BasePolicyID` values. A supplemental policy has its own `PolicyID` and a `BasePolicyID` identifying the base it expands.
- Allowing supplemental policies is a configuration prerequisite, not proof that a supplemental policy is correctly associated, deployed, or active. Signed bases also require the appropriate supplemental signer authorization.
- Check the complete option list for Managed Installer, WHQL, script enforcement, and other settings. A filename containing `Enforce`, `UMCI`, or `AllowSupplemental` is not evidence of those settings.

## Inspect Allow and Deny Rules with Get-CIPolicy

```powershell
$Rules = Get-CIPolicy -FilePath $PolicyXml -ErrorAction Stop

$Rules |
    Group-Object TypeId |
    Select-Object Name, Count |
    Format-Table -AutoSize

$Rules |
    Where-Object { $_.TypeId -eq 'Deny' } |
    Select-Object -First 25 Name, Id, TypeId, UserMode |
    Format-Table -AutoSize

$Rules |
    Where-Object { $_.Name -match 'WSL|Docker|7-Zip' } |
    Select-Object Name, Id, TypeId, UserMode |
    Format-Table -AutoSize
```

The last query searches rule names for convenience; it is **not** a complete rule evaluator. A missing name match does not prove the application is untrusted, and a matching rule does not prove it will run. Inspect signer/file-attribute references and explicit denies, then test the actual application. Merging an allow rule or deploying a supplemental allow does not override an explicit deny.

## Identify Policies on the Target PAW with CiTool

On Windows 11 25H2, use the built-in CiTool from an elevated session:

```powershell
$PolicyInventoryJson = & "$env:SystemRoot\System32\CiTool.exe" -lp -json
if ($LASTEXITCODE -ne 0) {
    throw "CiTool policy inventory failed with exit code $LASTEXITCODE. Check elevation. Output: $PolicyInventoryJson"
}

($PolicyInventoryJson | ConvertFrom-Json -ErrorAction Stop).Policies |
    Format-List *
```

Review the policy ID, base policy ID, friendly name, version, authorization, and active/enforcement indicators. Preserve the full output when troubleshooting; filtering only on a friendly name can hide other policies that affect the result. CiTool may display the version as a packed integer rather than the dotted `VersionEx` string.

For a numeric packed version, decode the four 16-bit components if needed:

```powershell
$PackedVersion = [uint64](Read-Host 'Paste the numeric Version reported by CiTool')
'{0}.{1}.{2}.{3}' -f (($PackedVersion -shr 48) -band 0xFFFF),
    (($PackedVersion -shr 32) -band 0xFFFF),
    (($PackedVersion -shr 16) -band 0xFFFF),
    ($PackedVersion -band 0xFFFF)
```

Correlate this inventory with the intended source XML and activation events. A file on disk, a familiar friendly name, or a single inventory flag does not by itself establish the intended audit/enforce behavior. Leave Microsoft platform policies alone.

## Inspect Deployed Files, Binary Hashes, and GPO Application

These are **different deployment layouts**:

| Deployment layout | Expected policy location |
|---|---|
| Legacy single-policy deployment | `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` |
| Multiple-policy deployment | `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyID}.cip` |

The built-in **Deploy App Control for Business** GPO setting supports single-policy format only. A GPO-delivered script that deploys multiple-policy files is a different deployment workflow.

```powershell
Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity" -Filter '*.p7b' -File -ErrorAction Stop |
    Select-Object Name, Length, LastWriteTime

Get-ChildItem -LiteralPath "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.cip' -File -ErrorAction Stop |
    Select-Object Name, Length, LastWriteTime

gpresult /r /scope computer
if ($LASTEXITCODE -ne 0) {
    throw "Computer-scope GPO reporting failed with exit code $LASTEXITCODE."
}

Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ErrorAction Stop |
    Select-Object DeployConfigCIPolicy, ConfigCIPolicyFilePath |
    Format-List
```

A missing directory/registry key, empty listing, or GPO listed by `gpresult` is not sufficient to determine policy activation. Use CiTool and event evidence as well. `DeployConfigCIPolicy = 1` plus `ConfigCIPolicyFilePath` identifies this built-in GPO setting's configured source, not every other policy deployment method.

To fingerprint a particular compiled artifact:

```powershell
$PolicyBinary = 'C:\WDAC\Compiled\YourPolicy.p7b'
Get-FileHash -LiteralPath $PolicyBinary -Algorithm SHA256 -ErrorAction Stop |
    Format-List Algorithm, Hash, Path
```

Compare the deployment-source binary with the corresponding endpoint binary when verifying distribution. Do not compare an XML hash with a binary hash; matching binary hashes establish byte identity, not activation or correctness of the allowlist.

## Check Effective CI/UMCI Status and the Current PowerShell Session

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop |
    Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus |
    Format-List

$PSVersionTable.PSVersion
$ExecutionContext.SessionState.LanguageMode
```

For each CI/UMCI status, `0` means not configured, `1` means audit, and `2` means enforced. Both must be `2` for the two numeric [STIG checks in the main guide](README.md#1--why-this-matters--the-two-stig-cat-ii-findings); the values do not identify the policy or approve its rules.

`LanguageMode` describes **this PowerShell session**. `FullLanguage` alone does not prove App Control is disabled or establish script behavior for every host, script, or active policy.

## Query Activation, Audit, and Block Events Separately

Run these queries on the PAW where you reproduced the behavior. Set the start time to cover the deployment and test:

```powershell
$Since = (Get-Date).AddDays(-1)

$ActivationEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3095, 3096, 3097, 3099, 3100, 3102, 3103
    StartTime = $Since
} -MaxEvents 20 -ErrorAction Stop)

$ActivationEvents |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

**3099** indicates a policy loaded; inspect its Details/XML for policy identity and options. **3095** indicates a reboot is required for the refresh, **3097** indicates refresh failure, and **3100** indicates unsuccessful activation. A refresh-finished event alone is not proof of successful activation.

To view the structured data for the most recent retained 3099 in that time window:

```powershell
$LoadedEvent = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3099
    StartTime = $Since
} -MaxEvents 1 -ErrorAction Stop

$LoadedEvent.ToXml()
```

The most recent 3099 may belong to another policy. Match the identity and deployment time, rather than accepting the event ID alone.

To decode selected **3099 Options bit addresses** after choosing the correct event:

```powershell
$OptionsHex = Read-Host 'Paste the Options hexadecimal value from the matching 3099 event'
$OptionsValue = [Convert]::ToUInt32(($OptionsHex -replace '^0x', ''), 16)
[pscustomobject]@{
    UMCI = ($OptionsValue -band (1 -shl 2)) -ne 0
    ISG = ($OptionsValue -band (1 -shl 4)) -ne 0
    AllowSupplementalPolicies = ($OptionsValue -band (1 -shl 10)) -ne 0
    AuditMode = ($OptionsValue -band (1 -shl 16)) -ne 0
} | Format-List
```

These are event **bit addresses**, not the numeric `Set-RuleOption` indices. For example, Audit Mode is option 3 but event bit 16. See [Microsoft's activation event option mapping](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#policy-activation-event-options).

For executable, DLL, and driver decisions:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3076, 3077, 3089
    StartTime = $Since
} -MaxEvents 50 -ErrorAction Stop |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

- **3076:** the file would have been blocked by an audit policy. Review whether it should be approved; do not automatically allow everything logged.
- **3077:** an enforced policy blocked the file.
- **3089:** associated signature information; correlate it using the event's System/Correlation ActivityID.

For MSI and script decisions on Windows 11:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
    Id = 8028, 8029, 8038
    StartTime = $Since
} -MaxEvents 50 -ErrorAction Stop |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

**8028** is an audit decision, **8029** is an enforcement decision, and **8038** provides correlated signature information. Script hosts control the final behavior: an 8029 does not always mean the script stopped entirely; PowerShell can run an unapproved script in Constrained Language Mode. These AppLocker MSI/Script events are not available on Windows Server Core.

Filtering happens at the event source, before `-MaxEvents` limits the results. If PowerShell reports **no events found**, that means no retained records matched the query; it does not prove successful activation, application approval, or compliance. Check the time range, log retention, target computer, and whether the workload actually ran.

If the Wizard runs on a different computer, export the PAW's relevant logs and parse those exported logs. Parsing the authoring workstation's local Event Viewer does not collect the PAW's telemetry.

## Inspect Fresh Audit Events by Policy

Set `$AuditRoundStart` after verifying activation and **before** the workload run, as in [Step 4 of the main walkthrough](README.md#step-4--confirm-policy-activation-event-id-3099-). If using a new session, restore the timestamp you recorded rather than using the current time:

```powershell
$AuditRoundStart = [datetimeoffset]::Parse(
    (Read-Host 'Paste the recorded audit-round start timestamp, including offset')
).LocalDateTime
$ExpectedPolicyId = [guid](Read-Host 'Paste the intended policy GUID verified with CiTool')
```

Then query the PAW. This example reads named fields rather than relying on an event Properties index:

```powershell
$FreshAuditEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3076
    StartTime = $AuditRoundStart
} -ErrorAction Stop)

$AuditRows = @(
    foreach ($Event in $FreshAuditEvents) {
        [xml]$EventXml = $Event.ToXml()
        $Fields = @{}
        foreach ($Field in $EventXml.Event.EventData.Data) {
            $Fields[[string]$Field.Name] = $Field.InnerText
        }
        if (-not $Fields.ContainsKey('PolicyID')) {
            Write-Warning "Event record $($Event.RecordId) has no PolicyID field. Inspect its XML manually; it has not been attributed to the intended policy."
            continue
        }
        [pscustomobject]@{
            TimeCreated = $Event.TimeCreated
            RecordId = $Event.RecordId
            PolicyID = [guid]$Fields['PolicyID']
            FileName = $Fields['FileName']
            Message = $Event.Message
        }
    }
)

$AuditRows |
    Where-Object { $_.PolicyID -eq $ExpectedPolicyId } |
    Select-Object TimeCreated, RecordId, PolicyID, FileName, Message |
    Format-List
```

Do not use absence of displayed rows as a pass without confirming the query completed, no records were left unattributed, and the workload ran. Events from other policy IDs explain why a file can still produce an audit record after the intended base was updated. If a fresh event remains for the updated identity, inspect its exact file, rule coverage, signature, denies, and actual loaded version.

## Diagnostic References

- [Get-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/get-cipolicy)
- [Get-CIPolicyIdInfo](https://learn.microsoft.com/en-us/powershell/module/configci/get-cipolicyidinfo)
- [CiTool commands and output](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [App Control event explanations](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [Group Policy deployment limitations](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy)
- [Activation event option-bit mapping](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#policy-activation-event-options)
- [Supported policy removal and recovery](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies)
