# Confirmation gate for scripts that change App Control for Business (WDAC) on a device or in the domain.
# Identical copy in C:\WDAC\config\scripts, C:\WDAC\config\scripts\pwsh_5.1 and C:\WDAC\GPO\scripts. Windows PowerShell 5.1 and PowerShell 7.
#   Interactive session:      the change is shown in yellow, then 'Continue? [Y/N]'. Y (or Yes) continues; N (or No) stops with
#                             nothing changed. Any other answer is asked again (3 tries, then stop).
#   -NoConfirm:               no prompt (MECM, scheduled tasks, GPO startup scripts); the change is still shown and transcribed.
#   Non-interactive session:  without -NoConfirm the script stops before changing anything - it never waits for an answer.

# True when a person can answer Read-Host: an interactive desktop session, not started with -NonInteractive, stdin not redirected
function Test-WdacInteractive {
    if (-not [Environment]::UserInteractive) { return $false }
    if (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }).Count -gt 0) { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return $true
}

function Confirm-WdacChange {
    param(
        # What is about to change, e.g. 'ENFORCE PAW-WDAC-Enforced v2026.10.24.1 on PAW01'
        [Parameter(Mandatory)][string]$Action,
        # Extra lines: scope, effect, how to undo
        [string[]]$Detail = @(),
        [switch]$NoConfirm
    )
    Write-Host ''
    Write-Host "WARNING: this changes App Control - $Action" -ForegroundColor Yellow
    foreach ($Line in $Detail) { if ($Line) { Write-Host "  $Line" -ForegroundColor Yellow } }
    if ($NoConfirm) { Write-Host '  -NoConfirm: continuing without a prompt.' -ForegroundColor Yellow; return }
    if (-not (Test-WdacInteractive)) {
        throw 'STOP: this change needs a Y/N confirmation, but the session is non-interactive. Nothing was changed. Run the script in an interactive console, or add -NoConfirm for automation.'
    }
    for ($Try = 1; $Try -le 3; $Try++) {
        $Answer = "$(Read-Host 'Continue? [Y/N]')".Trim()
        if ($Answer -match '^(y|yes)$') { Write-Host '  Confirmed.' -ForegroundColor Yellow; return }
        if ($Answer -match '^(n|no)$') { break }
        Write-Host '  Please answer Y or N.' -ForegroundColor Yellow
    }
    throw 'STOP: not confirmed - nothing was changed.'
}
