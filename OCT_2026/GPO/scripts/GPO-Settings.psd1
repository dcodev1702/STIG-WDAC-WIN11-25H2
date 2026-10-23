# Settings shared by every script in this folder. Edit them once here; a script parameter with the same name overrides them.
@{
    # Target OU (distinguished name). Leave empty to use the OU of the computer that runs the scripts.
    TargetOU          = ''

    # The two GPOs. Both are linked to the target OU; only one link is enabled at a time (3_GPO_set_mode.ps1).
    AuditGpoName      = 'JMSC-WDAC-PAWS - AppControl Audit'
    EnforceGpoName    = 'JMSC-WDAC-PAWS - AppControl Enforce'

    # Friendly-name prefix stamped into the packaged policies (shown by CiTool and Event 3099 on the endpoints).
    PolicyNamePrefix  = 'PAW-WDAC-GPO'

    # The endpoint scheduled task re-runs the deployment every N hours (it also runs right after Group Policy creates it).
    TaskIntervalHours = 4

    # Working folders of the fully configured reference device (layout of C:\WDAC\config\README.md).
    WdacRoot          = 'C:\WDAC'

    # This effort's folder: scripts, packages and logs.
    GpoRoot           = 'C:\WDAC\GPO'
}
