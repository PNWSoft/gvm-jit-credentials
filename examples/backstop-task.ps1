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

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -ExecutionPolicy AllSigned -File "C:\GvmJit\examples\backstop-task.ps1" ' +
        '-ConfigPath "C:\GvmJit\config.psd1" *> "C:\GvmJit\backstop-last-run.log"')
    Register-ScheduledTask -TaskName 'GVM JIT credential backstop' -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 10:30) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'EXAMPLE\gvm-runner$' -LogonType Password -RunLevel Limited)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$ModulePath = (Join-Path $PSScriptRoot '..\GvmJitCredential\GvmJitCredential.psd1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module $ModulePath -Force
$cfg = Import-PowerShellDataFile -Path $ConfigPath

# -Strict: here we DO want a throw, so the scheduled task reports failure.
Revoke-GvmScanCredential -Identity $cfg.Identity -CredentialId $cfg.CredentialId `
    -ScannerHost $cfg.ScannerHost -GmpHelper $cfg.GmpHelper -IdentityFile $cfg.IdentityFile `
    -Strict
