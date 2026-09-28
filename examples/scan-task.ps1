<#
.SYNOPSIS
  Entry point for the scheduled scan task: reads config.psd1 and runs one JIT scan.

.DESCRIPTION
  Register this as a scheduled task running as your runner account. That account needs:
    * the delegated rights from bootstrap\Initialize-GvmScanAccount.ps1
    * an SSH key to the Greenbone host, IN ITS OWN PROFILE
    * the Greenbone host in ITS OWN known_hosts -- with BatchMode, ssh gives no prompt and exits
      255; this module reports that, but anything calling raw ssh will not

  Register with (adjust paths, account and schedule):

    # -Command, NOT -File. With -File, everything after the script path is passed to the script
    # as arguments and '*>' is never parsed as redirection: the task fails with
    # "A positional parameter cannot be found that accepts argument '*>'" and writes no log.
    #
    # The try/catch and the explicit re-exit are NOT boilerplate. powershell.exe -Command does not
    # propagate a called script's exit code -- MEASURED on Windows PowerShell 5.1:
    #     -Command "& 'x.ps1' *> 'log'"           exit 3 arrives as 1
    #     -Command "& { & 'x.ps1' } *> 'log'"     exit 3 arrives as 0, and so does a MISSING script
    # So every exit code below collapses to 0/1, and the worst case -- a wrong path, or AllSigned
    # refusing the file -- reports SUCCESS. 'exit $LASTEXITCODE' fixes the first; only the catch
    # fixes the second, because $LASTEXITCODE is untouched when the script never ran at all. Use
    # -File instead if you do not need the redirection: it propagates exit codes on its own.
    $inner = "& 'C:\GvmJit\examples\scan-task.ps1' -ConfigPath 'C:\GvmJit\config.psd1' " +
             "*> 'C:\GvmJit\scan-last-run.log'"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy AllSigned -Command ' +
        "`"`$ErrorActionPreference='Stop'; try { $inner; exit `$LASTEXITCODE } " +
        "catch { `$_ | Out-File 'C:\GvmJit\scan-last-run.log' -Append; exit 1 }`"")
    Register-ScheduledTask -TaskName 'GVM JIT scan' -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 01:00) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'EXAMPLE\gvm-runner$' -LogonType Password -RunLevel Limited)

  Exit codes:
    0  scanned, and the credential fully revoked.
    1  anything else. Usually the scan: it did not reach Done, or it threw. Also an exception before
       the scan -- a missing config key, a failed Import-Module, or a Grant that failed and rolled
       itself back cleanly. None of those leave a usable credential behind.
    2  the account may still be usable: investigate NOW. Either the revoke reported errors, or Grant
       enabled the account and its own rollback then failed (event 1903), in which case Greenbone may
       still hold the live password.
    3  scanned and revoked, but the scanner's stored copy was not overwritten (event 1010). Nothing
       usable is left behind; it points at a broken GMP path.

  backstop-task.ps1 shares 0 and 3, but NOT 1 and 2. It has no 2 -- its 1 is this script's 2, a
  revoke that failed. Do not carry a single reading of "1" between the two.

  -ExecutionPolicy AllSigned in the task action is worth keeping even if the machine policy is laxer:
  the process scope beats the LocalMachine scope, so a tampered or unsigned script cannot run under
  this task. It fails closed. It also means THIS file and the module must be signed with a certificate
  the machine trusts.

  The exception, which is exactly the case this is meant to cover: if execution policy comes from GROUP
  POLICY, the MachinePolicy/UserPolicy scope overrides the command-line flag and it does nothing but
  emit a warning. Check with Get-ExecutionPolicy -List; if a policy scope is set, AllSigned has to be
  set there instead of here.
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

# Wrapped because a failing SCAN throws, and the revoke outcome rides out on the exception rather than
# in a return value. Without this, "the scan died AND the account is still enabled" was reported as a
# plain 1 -- the code documented below as not a security problem.
try {
    $result = Invoke-GvmJitScan -Identity (Get-Cfg 'Identity' -Required) -CredentialId (Get-Cfg 'CredentialId' -Required) `
        -TaskId (Get-Cfg 'TaskId' -Required) -ScannerHost (Get-Cfg 'ScannerHost' -Required) -GmpHelper (Get-Cfg 'GmpHelper' -Required) `
        -IdentityFile (Get-Cfg 'IdentityFile' '') `
        -ReplicationDelaySeconds (Get-Cfg 'ReplicationDelaySeconds' 45) `
        -PollSeconds (Get-Cfg 'PollSeconds' 30) -MaxScanMinutes (Get-Cfg 'MaxScanMinutes' 300) `
        -LogSource $LogSource
}
catch {
    # The scan failed. Whether that is merely a scan problem or a security one depends entirely on
    # whether the revoke in its finally block succeeded, which is why that result is attached here.
    $revoke = $_.Exception.Data['GvmJitRevoke']
    Write-Warning "Scan failed: $($_.Exception.Message)"
    if ($revoke -and $revoke.Errors.Count -gt 0) {
        $revoke.Errors | ForEach-Object { Write-Error $_ -ErrorAction Continue }
        exit 2      # the account may still be usable: this outranks the scan failure
    }
    if ($_.Exception.Data['GvmJitRollbackFailed']) {
        # Grant enabled the account, its own rollback failed (event 1903), and Greenbone may hold the
        # live password. The worst state there is, so it gets the loudest code rather than a 1.
        Write-Error "Grant rolled back and the rollback FAILED: the account may still be ENABLED. See event 1903." -ErrorAction Continue
        exit 2
    }
    # Otherwise the credential was revoked, or was never granted and Grant rolled itself back cleanly.
    $_ | Out-String | Write-Host
    exit 1
}

"Scan status : $($result.Status)"
"Report id   : $($result.ReportId)"
"Duration    : $($result.Duration)"
"Revoked     : disabled=$($result.Revoke.Disabled) passwordReset=$($result.Revoke.PasswordReset)"
if ($result.Revoke.Warnings.Count -gt 0) { $result.Revoke.Warnings | ForEach-Object { Write-Warning $_ } }

# Make the task's exit code mean something, rather than leaving it to inference. Checked in order of
# severity: a run can qualify for more than one of these, and the scheduler shows you only one number.
if ($result.Revoke.Errors.Count -gt 0) {
    # -ErrorAction Continue is load-bearing, not noise. This script sets $ErrorActionPreference =
    # 'Stop', under which Write-Error TERMINATES -- so the script died here and exited 1, and the
    # 'exit 2' below was unreachable. The one outcome meaning "the account may still be usable"
    # was therefore indistinguishable from an ordinary failed scan.
    $result.Revoke.Errors | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 2          # scan may be fine, but the credential did not fully revoke: investigate NOW
}
if ($result.Status -ne 'Done') { exit 1 }   # credential revoked; it is the scan that failed
# Revoked and scanned, but the scanner's stored copy was not overwritten -- same meaning as the
# backstop's 3: nothing usable is left behind, and the GMP path needs a look before the next grant.
if ($result.Revoke.Warnings.Count -gt 0) { exit 3 }
exit 0
