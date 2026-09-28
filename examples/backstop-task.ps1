<#
.SYNOPSIS
  Independent failsafe: unconditionally revoke the scan credential, whatever else has happened.

.DESCRIPTION
  Invoke-GvmJitScan revokes in a finally block, which covers errors, timeouts and crashes of the
  scan itself. It does NOT cover the process being killed or the machine rebooting mid-scan -- in
  those cases finally never runs and the account is left enabled with a live password.

  This script closes that gap. It assumes nothing about current state, is safe to run when no scan
  has run, and is idempotent. Schedule it to fire after your longest plausible scan window.

  It exits non-zero if the revoke did not fully succeed, so the task shows failure and you find out.
  That matters: a backstop that reports success when it failed is worse than no backstop, because
  you stop looking.

  Register with (adjust to taste):

    # -Command, NOT -File: with -File, everything after the script path is passed to the script as
    # arguments and '*>' is never parsed as redirection, so the task fails every single run. For the
    # backstop that means the one mitigation covering kill/reboot would never actually fire.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -ExecutionPolicy AllSigned -Command ' +
        '"& ''C:\GvmJit\examples\backstop-task.ps1'' -ConfigPath ''C:\GvmJit\config.psd1'' ' +
        '*> ''C:\GvmJit\backstop-last-run.log''"')
    Register-ScheduledTask -TaskName 'GVM JIT credential backstop' -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 10:30) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'EXAMPLE\gvm-runner$' -LogonType Password -RunLevel Limited)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    # Name the event source explicitly. The module's default is 'GvmJitCredential', which an
    # existing deployment may never have created -- in which case the audit trail for this task
    # goes to the log file only, and you find out by reading a warning rather than by noticing.
    [string]$LogSource = 'GvmJitCredential',
    [string]$ModulePath = (Join-Path $PSScriptRoot '..\GvmJitCredential\GvmJitCredential.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module $ModulePath -Force
$cfg = Import-PowerShellDataFile -Path $ConfigPath

# Read config keys through a helper. Under Set-StrictMode -Version Latest, $cfg.Missing on a hashtable
# raises PropertyNotFoundStrict, so a single omitted key turned a config typo into "this task throws
# before doing anything" -- for the backstop, that means it never revokes. Required keys are named
# explicitly so the error says which one is missing.
function Get-Cfg {
    param([string]$Key, $Default = $null, [switch]$Required)
    if ($cfg.ContainsKey($Key) -and $null -ne $cfg[$Key] -and "$($cfg[$Key])" -ne '') { return $cfg[$Key] }
    if ($Required) { throw "Config '$ConfigPath' is missing required key '$Key'." }
    return $Default
}

# -Strict: here we DO want a throw, so the scheduled task reports failure.
# Assigned rather than left on the pipeline: emitting the result object dumps a Format-List with
# blank lines into the task log, burying the event lines that actually matter.
$r = Revoke-GvmScanCredential -Identity (Get-Cfg 'Identity' -Required) -CredentialId (Get-Cfg 'CredentialId' -Required) `
    -ScannerHost (Get-Cfg 'ScannerHost' -Required) -GmpHelper (Get-Cfg 'GmpHelper' -Required) -IdentityFile (Get-Cfg 'IdentityFile' '') `
    -LogSource $LogSource -Strict

"Backstop revoke for '$($r.Identity)' via $($r.Server)"
"  disabled         : $($r.Disabled)"
"  passwordReset    : $($r.PasswordReset)"
"  greenboneBlanked : $($r.GreenboneBlanked)"
if ($r.Warnings.Count -gt 0) { $r.Warnings | ForEach-Object { "  warning: $_" } }
