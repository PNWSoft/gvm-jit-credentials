<#
.SYNOPSIS
  Independent failsafe: unconditionally revoke the scan credential, whatever else has happened.

.DESCRIPTION
  Invoke-GvmJitScan revokes in a finally block, which covers errors, timeouts and crashes of the
  scan itself. It does NOT cover the process being killed or the machine rebooting mid-scan -- in
  those cases finally never runs and the account is left enabled with a live password.

  This script closes that gap. It assumes nothing about current state, is safe to run when no scan
  has run, and is idempotent. Schedule it to fire after your longest plausible scan window.

  Exit codes, because "did it work" has to be answerable from the scheduler alone:

    0  account disabled, password invalidated, and the scanner's stored copy overwritten.
    1  the AD revoke failed -- the account may still be usable with a known password. This is the one
       that means NOT SAFE; -Strict throws, so the task reports failure. It is also what an exception
       before the revoke produces (a missing Identity in the config, a failed Import-Module), which
       leaves the account in whatever state it was already in -- still unrevoked, so still read it as
       "look now".
    3  the account is secured, but overwriting the scanner's stored copy was skipped or failed
       (event 1010, Warning) -- the GMP settings are absent or malformed, or the scanner rejected the
       write. The AD reset has already invalidated that value, so nothing usable is left behind. What
       this signals is a broken GMP path, worth knowing before the next grant needs it.

  There is deliberately no 2 here. scan-task.ps1 uses 2 for "the account may still be usable" because
  its 1 already means "the scan failed"; this script has no scan, so that case IS its 1. The two share
  0 and 3 only -- do not carry a single reading of "1" between them.

  A backstop that reports success when part of it failed is worse than no backstop, because you stop
  looking. But one that screams NOT SAFE over a hygiene failure trains you to ignore it, which ends
  the same way -- so the two get different codes rather than one undifferentiated alarm. Treat a 3 as
  "look this week", a 1 as "look now".

  Register with (adjust to taste):

    # -Command, NOT -File: with -File, everything after the script path is passed to the script as
    # arguments and '*>' is never parsed as redirection, so the task fails every single run. For the
    # backstop that means the one mitigation covering kill/reboot would never actually fire.
    #
    # The try/catch and the explicit re-exit are load-bearing for exactly the reason this script
    # exists. powershell.exe -Command does not propagate a called script's exit code -- MEASURED on
    # Windows PowerShell 5.1:
    #     -Command "& 'x.ps1' *> 'log'"           exit 3 arrives as 1
    #     -Command "& { & 'x.ps1' } *> 'log'"     exit 3 arrives as 0, and so does a MISSING script
    # Without this, the codes documented above collapse to 0/1, and a backstop whose path is wrong
    # -- or whose file AllSigned refuses -- reports SUCCESS every week while never revoking anything.
    # 'exit $LASTEXITCODE' recovers the code; only the catch covers "the script never ran at all",
    # because $LASTEXITCODE is left untouched in that case.
    $inner = "& 'C:\GvmJit\examples\backstop-task.ps1' -ConfigPath 'C:\GvmJit\config.psd1' " +
             "*> 'C:\GvmJit\backstop-last-run.log'"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy AllSigned -Command ' +
        "`"`$ErrorActionPreference='Stop'; try { $inner; exit `$LASTEXITCODE } " +
        "catch { `$_ | Out-File 'C:\GvmJit\backstop-last-run.log' -Append; exit 1 }`"")
    Register-ScheduledTask -TaskName 'GVM JIT credential backstop' -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 10:30) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'EXAMPLE\gvm-runner$' -LogonType Password -RunLevel Limited) `
        -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable)

  -StartWhenAvailable is not decoration. A mid-scan REBOOT is the main case this task exists for, and
  a task without it is simply skipped if the machine is still down at the trigger time -- leaving the
  account enabled until the following week. With it, the task runs once the machine is back.

  What "independent" does and does not mean here: this is a separate task, so it survives the scan
  process dying, hanging or being killed. It runs on the same host, under the same account, through
  the same scheduler, so it is not independent of that host being broken.
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
# Only Identity is -Required. The three GMP keys are NOT, deliberately: they are needed solely for
# step 3, the best-effort overwrite of the copy Greenbone stores. Requiring them meant one missing or
# malformed key threw here, in Get-Cfg, before the account was disabled -- so the backstop failed every
# week while leaving the very thing it exists to revoke untouched. Missing keys now skip step 3 and
# surface as a warning (exit 3), with the AD revoke already done.
$r = Revoke-GvmScanCredential -Identity (Get-Cfg 'Identity' -Required) -CredentialId (Get-Cfg 'CredentialId' '') `
    -ScannerHost (Get-Cfg 'ScannerHost' '') -GmpHelper (Get-Cfg 'GmpHelper' '') -IdentityFile (Get-Cfg 'IdentityFile' '') `
    -LogSource $LogSource -Strict

"Backstop revoke for '$($r.Identity)' via $($r.Server)"
"  disabled         : $($r.Disabled)"
"  passwordReset    : $($r.PasswordReset)"
"  greenboneBlanked : $($r.GreenboneBlanked)"
if ($r.Warnings.Count -gt 0) {
    $r.Warnings | ForEach-Object { "  warning: $_" }
    # Distinct from both outcomes above. -Strict has already thrown if the AD revoke failed, so
    # reaching here means the account IS secured and this is not an emergency -- but the scheduler
    # must not show a clean run when part of the job did not happen.
    exit 3
}
exit 0
