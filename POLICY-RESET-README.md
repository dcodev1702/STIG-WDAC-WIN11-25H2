# App Control Policy Reset - Windows 11 Enterprise 25H2

This runbook removes **selected custom App Control policies** so you can start a new, controlled audit deployment. It does not remove Windows' built-in code-integrity protections, vulnerable-driver policies, HVCI, Credential Guard, AppLocker, or antivirus.

**Sequence:** identify and back up -> stop deployment -> complete signed-base prerequisites if applicable -> remove each approved identity -> verify immediately -> refresh/restart -> verify again.

For ordinary rule corrections, prefer a forward policy update rather than a reset. See the [main guide](README.md#recovery-rollback-and-starting-over).

> [!WARNING]
> Policy removal reduces protection and can interrupt compliance. Use an approved maintenance window and an isolated pilot first. Have recovery access, known-good policy sources/binaries, and BitLocker recovery material available.
>
> **Do not delete a signed base directly.** It first needs an authorized signed replacement and a reboot. Skipping that sequence can cause boot failure.
>
> Do not delete the CodeIntegrity directory, use wildcard policy deletion, remove Microsoft platform policies, or disable Secure Boot as a routine reset step. If the machine cannot boot, use [Microsoft's separate boot-recovery procedure](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies#remove-app-control-policies-causing-boot-stop-failures).

## What Counts as a Successful Reset?

All of the following must hold:

- Every policy ID in your **reviewed removal plan** is absent from successful CiTool inventories immediately after removal and again after management refresh and restart.
- The deployment sources for those identities remain disabled or retargeted, so the removed policy is not restored.
- No unexplained matching OS/EFI deployment copies remain.
- Remaining policies are identified and intentionally retained, including Microsoft platform policies and custom policies outside the reset scope.
- You saved before/after evidence, the removal results, and the restart/management verification.

**Do not require CI/UMCI status values to become `0`, CiTool to return no policies, PowerShell to enter FullLanguage, or every application to run.** Other controls can remain active. Historical 3076, 3077, and 3099 records also remain; their existence does not mean removal failed.

## 1. Prepare an Elevated Session and Evidence Folder

Run the endpoint steps in **Windows PowerShell 5.1 as administrator on the PAW you are resetting**. Authoring/signing steps in Section 5 belong on the authorized authoring workstation instead.

```powershell
$ErrorActionPreference = 'Stop'
$Principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as administrator on the target PAW.'
}
$CiTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $CiTool -PathType Leaf)) {
    throw "CiTool was not found: $CiTool"
}
```

Define this read-only inventory helper. You will reuse it after removal and after restarting:

```powershell
function Get-AppControlPolicyInventory {
    $RawInventory = & "$env:SystemRoot\System32\CiTool.exe" -lp -json
    if ($LASTEXITCODE -ne 0) {
        throw "CiTool inventory failed ($LASTEXITCODE). Output: $RawInventory"
    }
    $Inventory = $RawInventory | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $Inventory -or
        $Inventory.PSObject.Properties.Name -notcontains 'Policies' -or
        $null -eq $Inventory.Policies) {
        throw 'CiTool did not return the expected Policies collection. Do not interpret this as a cleared device.'
    }
    foreach ($Policy in $Inventory.Policies) {
        if (-not $Policy.PolicyID) {
            throw 'An inventory entry has no PolicyID. Inspect the raw CiTool output before proceeding.'
        }
        $null = [guid]::Parse([string]$Policy.PolicyID)
    }
    $Inventory.Policies
}
```

Create a unique local evidence folder; retain its path outside the PAW for recovery. Store evidence in an access-controlled location, not in the public repository:

```powershell
$ResetStarted = Get-Date
$EvidenceFolder = Join-Path 'C:\WDAC\ResetEvidence' (
    $ResetStarted.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $EvidenceFolder -ErrorAction Stop | Out-Null
$Before = @(Get-AppControlPolicyInventory)
ConvertTo-Json -InputObject $Before -Depth 10 |
    Set-Content -LiteralPath (Join-Path $EvidenceFolder 'Before-Policies.json') -Encoding UTF8
$Before | Format-List *
$EvidenceFolder
```

## 2. Identify the Exact Policy and Its Signing State

Also run the readable inventory and review **Policy ID**, **Base Policy ID**, **Friendly Name**, **Version**, **Platform Policy**, **Policy is Signed**, authorization, and active-state indicators:

```powershell
& $CiTool -lp
if ($LASTEXITCODE -ne 0) { throw "Readable CiTool inventory failed: $LASTEXITCODE" }
```

An XML option named `Enabled:Unsigned System Integrity Policy` permits unsigned operation; it does **not** prove the deployed artifact is unsigned. The extension `.p7b` also does not prove the policy is signed. Use the actual inventory and authorized source/signing records.

The previously reviewed `10.0.5.9` artifact used the legacy identity `{A244370E-44C9-4C06-B551-F6016E563076}`. **Do not paste that ID merely because it appears here**; match the actual target's inventory. Friendly dates/labels from `Get-CIPolicyIdInfo` are not policy GUIDs.

Enter the verified custom base or individual supplemental ID:

```powershell
$TargetPolicyId = [guid](Read-Host 'Enter the custom policy GUID verified on this PAW')
if ($TargetPolicyId -eq [guid]::Empty) { throw 'The empty GUID is not a valid reset target.' }
$Target = @($Before | Where-Object { [guid]$_.PolicyID -eq $TargetPolicyId })
if ($Target.Count -ne 1) { throw 'Expected exactly one matching policy. Recheck the target identity.' }
$Target | Format-List *

$LinkedSupplementals = @($Before | Where-Object {
    $_.BasePolicyID -and
    [guid]$_.BasePolicyID -eq $TargetPolicyId -and
    [guid]$_.PolicyID -ne $TargetPolicyId
})
$LinkedSupplementals | Format-List *
```

**Stop if the target is a Microsoft platform policy, ownership is uncertain, or signing state cannot be established.** Do not identify policies solely by a filename or friendly-name substring.

For a base reset, review its linked supplementals and plan to remove the in-scope supplementals **before** the base. Removing a supplemental alone does not require removing its base. Keep other independent bases outside the plan unless their removal is separately approved.

Save a deliberate list of the approved IDs; this does not remove anything:

```powershell
$RemovalIds = @(
    (Read-Host 'Enter ONLY the reviewed custom policy GUIDs to remove, separated by commas').Split(',') |
        ForEach-Object { [guid]::Parse($_.Trim()) }
)
if (@($RemovalIds | Select-Object -Unique).Count -ne $RemovalIds.Count) {
    throw 'Duplicate removal IDs were entered. Correct the list before proceeding.'
}
foreach ($Id in $RemovalIds) {
    if ($Id -eq [guid]::Empty -or
        @($Before | Where-Object { [guid]$_.PolicyID -eq $Id }).Count -ne 1) {
        throw "The removal plan contains an empty or unverified ID: $Id"
    }
}
if ($RemovalIds -notcontains $TargetPolicyId) {
    throw 'The selected target is not in the reviewed removal plan.'
}
$ResetPlan = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Started = $ResetStarted.ToString('o')
    PolicyIDs = @($RemovalIds | ForEach-Object { $_.ToString('B') })
}
$ResetPlan | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $EvidenceFolder 'Reset-Plan.json') -Encoding UTF8
$ResetPlan | Format-List
```

Copy the associated authoring XML and compiled deployment binaries into your protected change/backup location. Record their SHA256 values and current versions. Use [source XML inspection](README.md#inspect-the-source-xml-identity-version-and-rule-options) and `Get-FileHash` for each artifact. Do not assume a decoded binary export is a build-ready source.

## 3. Stop Every Deployment Source before Removing Anything

Record how **each** planned identity reaches this PAW:

| Source | Required action |
|---|---|
| Built-in GPO deployment | In GPMC, change the effective `Computer Configuration\Administrative Templates\System\Device Guard\Deploy App Control for Business` setting to **Disabled** for the approved reset scope. Resolve any other GPO configuring it. |
| GPO startup script / scheduled deployment | Disable or retarget the specific policy deployment action for the reset device. Preserve unrelated startup tasks and GPO settings. |
| ConfigMgr / other management agent | Remove or suspend the policy assignment/remediation that would reinstall the selected identity. |
| Intune / MDM | Use the product's supported policy unassignment/removal process and synchronize the device. Coordinate ownership; CSP removal can have broader effects. |
| Manual CiTool deployment | Confirm there is no task, script, or management agent that periodically registers the same policy again. |

Do not disable an entire shared GPO or delete its share indiscriminately. Disabling a deployment source is not, by itself, evidence that the already loaded policy is gone.

On the PAW:

```powershell
gpupdate /force
if ($LASTEXITCODE -ne 0) { throw "gpupdate failed: $LASTEXITCODE" }
gpresult /r /scope computer
if ($LASTEXITCODE -ne 0) { throw "gpresult failed: $LASTEXITCODE" }

$DeviceGuardKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
if (Test-Path -LiteralPath $DeviceGuardKey) {
    Get-ItemProperty -LiteralPath $DeviceGuardKey -ErrorAction Stop |
        Select-Object DeployConfigCIPolicy, ConfigCIPolicyFilePath |
        Format-List
} else {
    Write-Host 'No DeviceGuard policy registry key is present; verify other deployment sources separately.'
}
```

For the disabled built-in GPO path, investigate if `DeployConfigCIPolicy` is still `1`. An old path string alone does not establish that delivery remains enabled, and absence of this registry setting does not exclude other deployment methods. Save resultant-policy evidence and management synchronization results.

## 4. Select the Correct Removal Branch

| Actual deployed policy | Next step |
|---|---|
| Unsigned custom base or unsigned supplemental | Proceed to Section 6 after backing up and stopping its deployment sources. |
| Signed supplemental | Microsoft permits removal through the same procedure as unsigned policies; proceed to Section 6. |
| Signed custom base | Complete **every** prerequisite in Section 5, including reboot, before Section 6. |
| Unknown state or Microsoft platform policy | Stop. Resolve identity/ownership/signing; do not attempt deletion. |

## 5. Signed Base Only: Deploy an Authorized Removal-Ready Replacement

**Skip this section for a verified unsigned policy.** A signed base is protected against tampering; neither administrator rights nor simply disabling GPO is sufficient to bypass its update authorization.

On the authorized authoring/signing workstation:

1. Copy the current, known-good base XML to a separate removal-staging source. Preserve the policy's actual identity, rule coverage, and existing `UpdatePolicySigners`. **Do not use `-ResetPolicyID`.**
2. Enable option **6**, `Enabled:Unsigned System Integrity Policy`, in that replacement.
3. Set `VersionEx` to **equal to or greater than** the installed version; prefer a forward version. For a deployed `10.0.5.9`, `10.0.5.10` is an example, not a universal value.
4. Confirm the replacement still has `UpdatePolicySigners`, and that the signing certificate is authorized by the **existing deployed policy**. Adding a new certificate only to the replacement cannot authorize an otherwise untrusted update.
5. Compile and sign the replacement using that authorized certificate/private key. **The replacement must still be signed**, even though option 6 is now enabled.

Example preparation using a copy of the existing authoring XML (create the output directories first):

```powershell
$RemovalXml = 'C:\WDAC\Source\Base-Removal-Ready.xml'
if (Test-Path -LiteralPath $RemovalXml) { throw 'Use a new staging path; do not overwrite existing removal evidence.' }
Copy-Item -LiteralPath 'C:\WDAC\Source\Current-Signed-Base.xml' -Destination $RemovalXml -ErrorAction Stop
Set-RuleOption -FilePath $RemovalXml -Option 6 -ErrorAction Stop
Set-CIPolicyVersion -FilePath $RemovalXml -Version '10.0.5.10' -ErrorAction Stop
ConvertFrom-CIPolicy -XmlFilePath $RemovalXml `
    -BinaryFilePath 'C:\WDAC\Compiled\Base-Removal-Ready.bin' -ErrorAction Stop
```

Review the XML identity, version, and signer references **before** signing. The version must be adjusted upward if your deployed revision is newer. Do not overwrite your only original source.

For an authorized certificate already in the signing operator's **CurrentUser personal certificate store**, Microsoft's SignTool signing pattern is:

```powershell
$SignTool = (Get-Command signtool.exe -ErrorAction Stop).Source
$Thumbprint = Read-Host 'Enter the thumbprint of the signing certificate authorized by the deployed base'
$SigningCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
if (-not $SigningCertificate.HasPrivateKey) { throw 'The authorized signing private key is unavailable.' }
& $SignTool sign -v -sha1 $Thumbprint -s My -p7 'C:\WDAC\Signed' `
    -p7co 1.3.6.1.4.1.311.79.1 -fd sha256 'C:\WDAC\Compiled\Base-Removal-Ready.bin'
if ($LASTEXITCODE -ne 0) { throw "App Control policy signing failed: $LASTEXITCODE" }
Get-ChildItem -LiteralPath 'C:\WDAC\Signed' -File -ErrorAction Stop
```

Use your organization's authorized signing workflow instead if the key is in another store or managed signing service. Do not create a new certificate to work around missing authorization. Verify the resulting signed output and signing certificate using [Microsoft's signed-policy instructions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering#verify-and-deploy-the-signed-policy); do not deploy the unsigned `.bin` by mistake.

Then:

6. Stage the **signed** output using the existing policy format/name convention: legacy single-policy binary or `{PolicyID}.cip` for multiple-policy format. Do not convert format or identity during removal staging.
7. Deploy the authorized replacement to the target using your supported update mechanism, with the old automatic deployment sources still disabled. A deliberate CiTool update on the PAW is:

   ```powershell
   $SignedReplacement = Read-Host 'Enter the full path to the verified signed removal-ready policy binary'
   if (-not (Test-Path -LiteralPath $SignedReplacement -PathType Leaf)) {
       throw 'The signed replacement file was not found.'
   }
   & $CiTool --update-policy $SignedReplacement -json
   if ($LASTEXITCODE -ne 0) { throw "Removal-ready replacement deployment failed: $LASTEXITCODE" }
   ```

8. **Restart the PAW before removal.** Verify the same identity and intended version loaded, and confirm option 6 is present in the matching 3099 Options evidence. In that event, option 6 corresponds to **bit address 19**, not bit 6. Use the [event-option mapping](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#policy-activation-event-options).
9. Save that evidence and restore your endpoint session/plan using **only the session-restoration portion of Section 8**. The base is still present at this stage; do not run the post-removal absence assertion yet. Proceed to Section 6 only after the authorized replacement and required restart are confirmed.

The replacement artifact may still report as signed: that is expected. The removal prerequisite is the authorized option-6 update **plus restart**, not making the signature indicator say false. If the signer/key, deployment, or activation cannot be verified, stop and use the approved recovery/escalation path.

## 6. Remove One Reviewed Custom Policy at a Time

**This section changes endpoint protection. Run it only after Sections 1-4 and any required signed-base staging.** For a base reset, remove its reviewed supplementals first; do not leave orphaned supplemental deployment assignments.

The code checks the saved plan, refreshes inventory, refuses base removal while linked policies remain, and requires the exact confirmation text. It does not determine whether a signed-base prerequisite has been completed; that is the mandatory Section 5 gate.

```powershell
$PolicyIdToRemove = [guid](Read-Host 'Enter ONE reviewed policy GUID to remove now')
if ($RemovalIds -notcontains $PolicyIdToRemove) {
    throw 'This policy ID is outside the reviewed removal plan.'
}
$Current = @(Get-AppControlPolicyInventory)
$Selected = @($Current | Where-Object { [guid]$_.PolicyID -eq $PolicyIdToRemove })
if ($Selected.Count -ne 1) { throw 'The selected policy is not uniquely present. Recheck inventory.' }
$Selected | Format-List *
$Children = @($Current | Where-Object {
    $_.BasePolicyID -and
    [guid]$_.BasePolicyID -eq $PolicyIdToRemove -and
    [guid]$_.PolicyID -ne $PolicyIdToRemove
})
if ($Children.Count -gt 0) {
    $Children | Format-List *
    throw 'Linked supplementals remain. Review/remove their deployments and policies before this base.'
}
$RequiredConfirmation = 'REMOVE ' + $PolicyIdToRemove.ToString('B')
if ((Read-Host "Type exactly $RequiredConfirmation after checking signing/removal prerequisites") -cne $RequiredConfirmation) {
    throw 'Confirmation did not match. Nothing was removed.'
}
$RemovalOutput = & $CiTool -rp $PolicyIdToRemove.ToString('B') -json
$RemovalExitCode = $LASTEXITCODE
$RemovalOutput | Set-Content -LiteralPath (
    Join-Path $EvidenceFolder ($PolicyIdToRemove.ToString('D') + '-Removal.json')
) -Encoding UTF8
if ($RemovalExitCode -ne 0) {
    throw "Policy removal failed ($RemovalExitCode). Output: $RemovalOutput"
}
$RemovalOutput
$AfterOne = @(Get-AppControlPolicyInventory)
if (@($AfterOne | Where-Object { [guid]$_.PolicyID -eq $PolicyIdToRemove }).Count -gt 0) {
    throw 'The policy is still listed. Inspect status/reboot requirements; do not claim a cleared state.'
}
```

Repeat for each approved identity, then complete the whole-plan verification below. Windows 11 25H2 supports unsigned-policy removal without a required reboot, but this runbook still verifies persistence across a controlled restart. If a record remains, it may need further supported processing; do not hide it by filtering only on an enforcement flag.

## 7. Verify the Entire Removal Plan Immediately

```powershell
$After = @(Get-AppControlPolicyInventory)
ConvertTo-Json -InputObject $After -Depth 10 |
    Set-Content -LiteralPath (Join-Path $EvidenceFolder 'After-Policies.json') -Encoding UTF8
$RemainingTargets = @($After | Where-Object { $RemovalIds -contains [guid]$_.PolicyID })
if ($RemainingTargets.Count -gt 0) {
    $RemainingTargets | Format-List *
    throw 'At least one planned identity remains. The reset is not verified.'
}
$After | Format-List *
Write-Host 'All planned identities are absent from this successful inventory. Persistence verification is still required.'
```

Review all remaining entries against the before inventory. A successful reset does not imply every remaining custom policy was in scope; record intentional exclusions. Inventory absence is stronger evidence than an old event log or missing desktop toast, but still needs deployment/persistence checks.

## 8. Refresh Management, Restart, and Verify the Cleared State Again

1. With deployment sources still disabled, refresh GPO and synchronize any other applicable management agent.
2. Restart the PAW in the approved window. Do not re-enable the old deployment source.
3. Open a **new elevated Windows PowerShell 5.1 session** on the same PAW.
4. Re-run the **elevation/CiTool check and inventory helper definition** from Section 1. Do **not** create a replacement evidence folder/plan.
5. Restore the existing plan:

```powershell
$EvidenceFolder = Read-Host 'Enter the original reset evidence folder path'
$ResetPlan = Get-Content -LiteralPath (Join-Path $EvidenceFolder 'Reset-Plan.json') -Raw -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
if ($ResetPlan.ComputerName -ne $env:COMPUTERNAME) {
    throw 'This reset plan belongs to a different computer.'
}
if (-not $ResetPlan.PolicyIDs -or @($ResetPlan.PolicyIDs).Count -eq 0) {
    throw 'The saved removal plan is empty or invalid.'
}
$RemovalIds = @($ResetPlan.PolicyIDs | ForEach-Object { [guid]::Parse([string]$_) })
if ($RemovalIds -contains [guid]::Empty -or
    @($RemovalIds | Select-Object -Unique).Count -ne $RemovalIds.Count) {
    throw 'The saved removal plan contains an empty or duplicate identity.'
}
```

The restoration block above is also used after the **signed-base staging reboot**, before Section 6. It does not assert that the staged base is absent.

**After the actual removals and the persistence-test restart**, run this separate check:

```powershell
$PostRestart = @(Get-AppControlPolicyInventory)
ConvertTo-Json -InputObject $PostRestart -Depth 10 |
    Set-Content -LiteralPath (Join-Path $EvidenceFolder 'PostRestart-Policies.json') -Encoding UTF8
$RestoredTargets = @($PostRestart | Where-Object { $RemovalIds -contains [guid]$_.PolicyID })
if ($RestoredTargets.Count -gt 0) {
    $RestoredTargets | Format-List *
    throw 'A removed identity is present after restart. Check redeployment and OS/EFI copies.'
}
$PostRestart | Format-List *
Write-Host 'The saved removal-plan identities are absent after restart. Complete the source/file checks before final sign-off.'
```

6. Repeat Section 3's GPO/registry checks and confirm any ConfigMgr/MDM/script assignments remain stopped. If a scheduled agent has a later deployment cycle, verify again after that cycle; a GPO refresh alone does not exercise every management source.
7. Inspect exact deployment locations as described in Section 9.
8. Save the results and sign off only when the [success criteria](#what-counts-as-a-successful-reset) are met.

For contextual status, not a target-removal pass/fail:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop |
    Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus |
    Format-List
$ExecutionContext.SessionState.LanguageMode
```

`0 = not configured`, `1 = audit`, and `2 = enforced` describe the effective CI/UMCI posture. Other policies can keep either field enforced. Conversely, losing your PAW enforcement baseline may reopen STIG findings even though the targeted reset succeeded. Restore a validated baseline before returning the PAW to service.

## 9. Check OS/EFI Copies without Broad Deletion

Relevant locations from Microsoft's removal procedure:

| Format | OS volume | EFI system partition |
|---|---|---|
| Legacy single-policy | `C:\Windows\System32\CodeIntegrity\SiPolicy.p7b` | `\EFI\Microsoft\Boot\SiPolicy.p7b` |
| Multiple-policy | `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyID}.cip` | `\EFI\Microsoft\Boot\CiPolicies\Active\{PolicyID}.cip` |

The legacy reserved GUID may have both `SiPolicy.p7b` and corresponding `.cip` copies. Check exact approved identities, not every `.p7b` on the system. OS paths below use `$env:SystemRoot` to support nonstandard Windows locations.

```powershell
$ExactOsPaths = @(
    foreach ($Id in $RemovalIds) {
        Join-Path "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active" ($Id.ToString('B') + '.cip')
        if ($Id -eq [guid]'A244370E-44C9-4C06-B551-F6016E563076') {
            Join-Path "$env:SystemRoot\System32\CodeIntegrity" 'SiPolicy.p7b'
        }
    }
)
$OsCopyStatus = @(
    foreach ($Path in $ExactOsPaths) {
        [pscustomobject]@{ Path = $Path; Exists = Test-Path -LiteralPath $Path -PathType Leaf }
    }
)
$OsCopyStatus | Format-Table -AutoSize
if (@($OsCopyStatus | Where-Object Exists).Count -gt 0) {
    throw 'Matching OS policy copies remain. Investigate before declaring the reset cleared.'
}
```

For EFI inspection on a UEFI PAW, choose an **unused** drive letter first. The example uses `W:`. Mounting/dismounting is an administrative action; the inspection itself does not delete anything:

```powershell
if (Get-PSDrive | Where-Object { $_.Name -eq 'W' }) { throw 'W: is already in use. Choose another unused letter.' }
& "$env:SystemRoot\System32\mountvol.exe" W: /S
if ($LASTEXITCODE -ne 0) { throw "EFI mount failed: $LASTEXITCODE" }
try {
    $EfiCopyStatus = @(
        foreach ($Id in $RemovalIds) {
            $EfiPolicyPath = Join-Path 'W:\EFI\Microsoft\Boot\CiPolicies\Active' ($Id.ToString('B') + '.cip')
            [pscustomobject]@{ Path = $EfiPolicyPath; Exists = Test-Path -LiteralPath $EfiPolicyPath -PathType Leaf }
            if ($Id -eq [guid]'A244370E-44C9-4C06-B551-F6016E563076') {
                $EfiLegacyPath = 'W:\EFI\Microsoft\Boot\SiPolicy.p7b'
                [pscustomobject]@{ Path = $EfiLegacyPath; Exists = Test-Path -LiteralPath $EfiLegacyPath -PathType Leaf }
            }
        }
    )
} finally {
    & "$env:SystemRoot\System32\mountvol.exe" W: /D
    $EfiDismountExitCode = $LASTEXITCODE
    if ($EfiDismountExitCode -ne 0) { Write-Warning "EFI dismount failed: $EfiDismountExitCode. Resolve the remaining mount." }
}
if ($EfiDismountExitCode -ne 0) { throw 'EFI inspection did not finish cleanly; the mount needs attention.' }
$EfiCopyStatus | Format-Table -AutoSize
if (@($EfiCopyStatus | Where-Object Exists).Count -gt 0) {
    throw 'Matching EFI policy copies remain. Investigate before declaring the reset cleared.'
}
```

If you change the letter, change **all** references in the block. Save the output. If an unexplained target copy remains, or access/mounting fails, record the incomplete check rather than claiming all copies are cleared. Follow the [official exact-policy file-removal procedure](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies#remove-app-control-policies-using-script) only after signing prerequisites and deployment-source checks. Do not substitute a recursive or wildcard delete.

## 10. Starting Fresh and Versioning

- The number of past enforcement revisions does not prevent a reset. Active identity, signing/update authorization, deployed version, and management sources are what matter.
- **Update/rollback in place:** preserve identity and move `VersionEx` forward, including when restoring older known-good rules. For a signed removal-ready update, Microsoft's explicit requirement is equal-or-higher; a lower signed version can cause boot failure.
- **Fresh design:** deliberately choose single-policy GPO or multiple-policy deployment and create the appropriate audit source. A new identity is a separate policy, not an update to an existing one.
- There is no need to reset a friendly date/version label to `1.0.0.0`. Keep the change history and avoid collisions or accidental redeployment of old artifacts.
- Deploy the new audit baseline to the pilot, verify its identity/options/version, record a new audit-round time boundary, and run approved workloads. Historical 3076s still belong to earlier rounds.
- Restore the approved enforcement baseline and confirm CI/UMCI posture before returning a production PAW to normal service.

Continue with the [main audit/merge/enforcement walkthrough](README.md#3--step-by-step-walkthrough) and [diagnostics](README.md#8-diagnostics-and-troubleshooting).

## Troubleshooting Stop Conditions

| Observation | Action |
|---|---|
| CiTool fails, JSON is incomplete, or access is denied | Stop; fix elevation/output handling. An inventory error is not an empty policy set. |
| Target returns after refresh/restart | Find the active deployment source or remaining OS/EFI copy; do not repeatedly delete files. |
| Policy record remains after removal | Inspect CiTool output, signing prerequisites, and restart requirements. Do not claim success based only on the command exit code. |
| Signed-base signer/private key unavailable | Stop; use the authorized policy owner/recovery process. Do not invent a new signer or delete the signed base. |
| CI/UMCI stays at `2` | Identify remaining policies. This alone does not mean the selected custom policy remains. |
| Old block/activation events remain | Expected history. Compare identities and timestamps with the new inventory and test boundary. |
| Applications remain blocked | Check other WDAC bases, AppLocker, Defender/ASR, Smart App Control where applicable, and OS permissions. Do not remove unrelated controls as part of this reset. |

## Microsoft References

- [Remove App Control policies, including signed-base prerequisites](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/disable-appcontrol-policies)
- [CiTool policy inventory and removal](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [Signed-policy preparation, signing, and deployment](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering)
- [Activation event option bits](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations#policy-activation-event-options)
- [Built-in GPO deployment scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy)
