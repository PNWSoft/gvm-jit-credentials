<#
.SYNOPSIS
  Entry point for the scheduled scan task: reads config.psd1 and runs one JIT scan.

.DESCRIPTION
  Register this as a scheduled task running as your runner account. That account needs:
    * the delegated rights from bootstrap\Initialize-GvmScanAccount.ps1
    * an SSH key to the Greenbone host, IN ITS OWN PROFILE
    * the Greenbone host in ITS OWN known_hosts (BatchMode ssh fails silently otherwise)

  Register with (adjust paths, account and schedule):

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -ExecutionPolicy AllSigned -File "C:\GvmJit\examples\scan-task.ps1" ' +
        '-ConfigPath "C:\GvmJit\config.psd1" *> "C:\GvmJit\scan-last-run.log"')
    Register-ScheduledTask -TaskName 'GVM JIT scan' -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 01:00) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'EXAMPLE\gvm-runner$' -LogonType Password -RunLevel Limited)

  -ExecutionPolicy AllSigned in the task action is worth keeping even if the machine policy is
  laxer: process scope wins, so a tampered or unsigned script cannot run under this task. It fails
  closed. Note that it also means THIS file and the module must be signed with a certificate the
  machine trusts.
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

$result = Invoke-GvmJitScan -Identity $cfg.Identity -CredentialId $cfg.CredentialId `
    -TaskId $cfg.TaskId -ScannerHost $cfg.ScannerHost -GmpHelper $cfg.GmpHelper `
    -IdentityFile $cfg.IdentityFile `
    -ReplicationDelaySeconds $cfg.ReplicationDelaySeconds `
    -PollSeconds $cfg.PollSeconds -MaxScanMinutes $cfg.MaxScanMinutes

"Scan status : $($result.Status)"
"Report id   : $($result.ReportId)"
"Duration    : $($result.Duration)"
"Revoked     : disabled=$($result.Revoke.Disabled) passwordReset=$($result.Revoke.PasswordReset)"

# Make the task's exit code mean something, rather than leaving it to inference.
if ($result.Revoke.Errors.Count -gt 0) {
    $result.Revoke.Errors | ForEach-Object { Write-Error $_ }
    exit 2          # scan may be fine, but the credential did not fully revoke: investigate NOW
}
if ($result.Status -ne 'Done') { exit 1 }
exit 0
