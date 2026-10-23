# Step 2 - run on the REFERENCE device (elevated, Windows PowerShell 5.1 or PowerShell 7) as a Domain Admin / GPO creator.
# Creates (or updates = publishes a new package to) the Audit and Enforce GPOs and links BOTH to the target OU with the links
# DISABLED. Nothing reaches an endpoint until 3_GPO_set_mode.ps1 enables one link.
# Each GPO gets, in its own SYSVOL folder:
#   Machine\Scripts\Startup\WDAC\   Deploy-WDACPolicy.ps1 + manifest.json + {PolicyGUID}.cip   (from 1_GPO_build_packages.ps1)
#   Machine\Scripts\scripts.ini     startup script: powershell.exe -ExecutionPolicy Bypass -File <UNC>\Deploy-WDACPolicy.ps1 -Mode <mode>
#   Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
#                                   GPP task 'WDAC-GPO-Deploy-<mode>' (SYSTEM, at creation + every N hours, removed when the GPO no longer applies)
#   Registry.pol                    'Always wait for the network at computer startup and logon' = Enabled
param(
    [string]$PackagePath,
    [string]$TargetOU,
    [string]$AuditGpoName,
    [string]$EnforceGpoName,
    [int]$TaskIntervalHours
)

. "$PSScriptRoot\WDAC-GPO-Common.ps1"
$Cfg = Initialize-WdacGpo -ScriptName '2_GPO_create_gpos' -Overrides @{ TargetOU = $TargetOU; AuditGpoName = $AuditGpoName; EnforceGpoName = $EnforceGpoName; TaskIntervalHours = $TaskIntervalHours }
$R = New-WdacResults
$Failed = 1
# Client-side extensions used (GPMC format): GPP core, Registry, Scripts, GPP Scheduled Tasks
$Cse = @(
    '[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'
    '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
    '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    '[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'
)
try {
    Import-WdacModule GroupPolicy; Import-WdacModule ActiveDirectory
    $Domain = Get-WdacDomainInfo
    $OU = Resolve-WdacTargetOU $Cfg
    Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
    if (-not $PackagePath) {
        $Latest = Join-Path $Cfg.PackageRoot 'latest.txt'
        if (-not (Test-Path -LiteralPath $Latest)) { throw 'STOP: no package yet. Run 1_GPO_build_packages.ps1 first.' }
        $PackagePath = (Get-Content -LiteralPath $Latest -Raw).Trim()
    }
    Add-WdacResult $R 'OK' 'Inputs' "package $PackagePath | OU $OU | PDC $($Domain.PDC) | task every $($Cfg.TaskIntervalHours) h"

    $Versions = @{}
    foreach ($Mode in 'Audit', 'Enforce') {
        $Name = if ($Mode -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
        $Src = Join-Path $PackagePath $Mode
        $Man = Read-WdacManifest $Src
        if (-not $Man -or $Man.Mode -ne $Mode) { throw "STOP: $Src has no $Mode manifest.json. Run 1_GPO_build_packages.ps1." }
        foreach ($P in @($Man.Policies)) {
            $Hash = (Get-FileHash -LiteralPath (Join-Path $Src $P.File) -Algorithm SHA256).Hash
            if ($Hash -ne $P.Sha256) { throw "STOP: $($P.File) in $Src does not match its manifest hash." }
        }
        $Versions[$Mode] = [version]($Man.Policies | Where-Object { $_.Type -eq 'Base' } | Select-Object -First 1).Version

        # ------------------------------------------------------------ GPO object
        $Gpo = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $Gpo) {
            $Gpo = New-GPO -Name $Name -Server $Domain.PDC -Comment "App Control for Business (multiple policy format) - $Mode mode. Managed by C:\WDAC\GPO\scripts; deploys with CiTool.exe via startup script + scheduled task." -ErrorAction Stop
            Add-WdacResult $R 'OK' "$Mode GPO" "created '$Name' {$($Gpo.Id)}"
        }
        else { Add-WdacResult $R 'OK' "$Mode GPO" "updating existing '$Name' {$($Gpo.Id)}" }
        $Gpo.GpoStatus = 'UserSettingsDisabled'
        Set-GPRegistryValue -Name $Name -Server $Domain.PDC -Key 'HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'SyncForegroundPolicy' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
        $Paths = Get-WdacGpoPaths $Gpo.Id $Domain
        $Machine = Join-Path $Paths.SysvolPdc 'Machine'
        for ($i = 0; $i -lt 30 -and -not (Test-Path -LiteralPath $Machine); $i++) { Start-Sleep -Seconds 2 }
        if (-not (Test-Path -LiteralPath $Machine)) { New-Item -Path $Machine -ItemType Directory -Force | Out-Null }

        # ------------------------------------------------------------ payload (replace whatever an earlier publish left)
        $Payload = Join-Path $Paths.SysvolPdc $Paths.PayloadRel
        if (Test-Path -LiteralPath $Payload) { Get-ChildItem -LiteralPath $Payload -File | Remove-Item -Force }
        New-Item -Path $Payload -ItemType Directory -Force | Out-Null
        Get-ChildItem -LiteralPath $Src -File | Copy-Item -Destination $Payload -Force
        $ScriptUnc = Join-Path (Join-Path $Paths.SysvolDomain $Paths.PayloadRel) 'Deploy-WDACPolicy.ps1'
        $PsArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptUnc`" -Mode $Mode"

        # ------------------------------------------------------------ startup script (scripts.ini is UTF-16 LE, as GPMC writes it)
        $Ini = Join-Path $Machine 'Scripts\scripts.ini'
        $IniText = "`r`n[Startup]`r`n0CmdLine=powershell.exe`r`n0Parameters=$PsArgs`r`n"
        [IO.File]::WriteAllText($Ini, $IniText, [Text.Encoding]::Unicode)

        # ------------------------------------------------------------ GPP scheduled task
        $TaskName = "WDAC-GPO-Deploy-$Mode"
        $Esc = { param($s) [System.Security.SecurityElement]::Escape($s) }
        $Changed = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $Start = (Get-Date).Date.ToString('yyyy-MM-ddTHH:mm:ss')
        $TaskXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="$TaskName" image="2" changed="$Changed" uid="{$([guid]::NewGuid().ToString().ToUpper())}" userContext="0" removePolicy="1">
    <Properties action="R" name="$TaskName" runAs="NT AUTHORITY\System" logonType="S4U">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>$(& $Esc ([Security.Principal.WindowsIdentity]::GetCurrent().Name))</Author>
          <Description>$(& $Esc "App Control for Business ($Mode): deploys the policy in '$Name' with CiTool.exe when the GPO carries a newer version. Managed by C:\WDAC\GPO\scripts.")</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\System</UserId>
            <LogonType>S4U</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <IdleSettings>
            <Duration>PT10M</Duration>
            <WaitTimeout>PT1H</WaitTimeout>
            <StopOnIdleEnd>false</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
          </IdleSettings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <RunOnlyIfIdle>false</RunOnlyIfIdle>
          <WakeToRun>false</WakeToRun>
          <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
          <Priority>7</Priority>
        </Settings>
        <Triggers>
          <RegistrationTrigger>
            <Enabled>true</Enabled>
            <Delay>PT1M</Delay>
          </RegistrationTrigger>
          <TimeTrigger>
            <StartBoundary>$Start</StartBoundary>
            <Enabled>true</Enabled>
            <Repetition>
              <Interval>PT$($Cfg.TaskIntervalHours)H</Interval>
              <StopAtDurationEnd>false</StopAtDurationEnd>
            </Repetition>
          </TimeTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
            <Arguments>$(& $Esc $PsArgs)</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
"@
        $TaskDir = Join-Path $Machine 'Preferences\ScheduledTasks'
        New-Item -Path $TaskDir -ItemType Directory -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $TaskDir 'ScheduledTasks.xml'), $TaskXml, (New-Object Text.UTF8Encoding($false)))

        # ------------------------------------------------------------ register the CSEs and raise the version
        $AdObj = Get-ADObject -Identity $Paths.AdPath -Properties gPCMachineExtensionNames -Server $Domain.PDC -ErrorAction Stop
        $Ext = Merge-WdacExtensionNames ([string]$AdObj.gPCMachineExtensionNames) $Cse
        Set-ADObject -Identity $Paths.AdPath -Replace @{ gPCMachineExtensionNames = $Ext } -Server $Domain.PDC -ErrorAction Stop
        $NewVer = Step-WdacGpoVersion $Paths $Domain
        Add-WdacResult $R 'OK' "$Mode SYSVOL" "$Payload <- $(@(Get-ChildItem -LiteralPath $Payload -File).Name -join ', ')"
        Add-WdacResult $R 'OK' "$Mode startup script" "powershell.exe $PsArgs"
        Add-WdacResult $R 'OK' "$Mode scheduled task" "$TaskName - SYSTEM, at creation (+1 min) and every $($Cfg.TaskIntervalHours) h, removed when no longer applied"
        Add-WdacResult $R 'OK' "$Mode GPO version" "computer version $NewVer; CSEs $Ext"

        # ------------------------------------------------------------ link to the OU, disabled (3_GPO_set_mode.ps1 enables one)
        $Link = (Get-GPInheritance -Target $OU -Server $Domain.PDC).GpoLinks | Where-Object { $_.DisplayName -eq $Name }
        if (-not $Link) { New-GPLink -Name $Name -Target $OU -LinkEnabled No -Server $Domain.PDC -ErrorAction Stop | Out-Null; Add-WdacResult $R 'OK' "$Mode link" "linked to $OU (DISABLED)" }
        else { Add-WdacResult $R 'OK' "$Mode link" "already linked to $OU (enabled=$($Link.Enabled)) - left as is" }
    }
    if ($Versions.Enforce -le $Versions.Audit) { Add-WdacResult $R 'FAIL' 'Version order' "Enforce v$($Versions.Enforce) must be higher than Audit v$($Versions.Audit)" }
    else { Add-WdacResult $R 'OK' 'Version order' "Audit v$($Versions.Audit) < Enforce v$($Versions.Enforce)" }
    $Inventory = foreach ($Name in $Cfg.AuditGpoName, $Cfg.EnforceGpoName) { $G = Get-GPO -Name $Name -Server $Domain.PDC; [pscustomobject]@{ Name = $Name; Id = "{$($G.Id)}"; Sysvol = (Get-WdacGpoPaths $G.Id $Domain).SysvolDomain; Package = $PackagePath } }
    $Inventory | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Cfg.LogDir 'GPO-Inventory.json') -Encoding UTF8
    $Failed = 0
    Write-Host 'Next: .\4_GPO_validate_gpos.ps1, then .\3_GPO_set_mode.ps1 -Mode Audit' -ForegroundColor Cyan
}
catch { Add-WdacResult $R 'FAIL' 'Create / update' $_.Exception.Message }
finally {
    $Failed = [math]::Max($Failed, (Write-WdacResults $R $Cfg 'GPO create / update'))
    Stop-WdacTranscript
}
if ($Failed) { exit 1 }
