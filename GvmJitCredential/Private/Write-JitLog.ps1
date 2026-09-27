function Write-JitLog {
    <#
    .SYNOPSIS
      Writes an audit line to the Windows Application event log and to the host's output.

    .DESCRIPTION
      The event log is the durable audit trail for credential grant and revoke: harder to tamper
      with than a text file, and it survives the scheduled task's console being discarded.

      It ALSO always writes to the host stream, because a scheduled task redirecting with `*>`
      captures that. Previously the host line appeared only when the event source was MISSING, so a
      correctly configured deployment produced a task log containing no sequence of events at all --
      exactly backwards.

      It deliberately does NOT use Write-Error or Write-Warning. PowerShell attributes those to the
      function that raised them, so a failure surfaced here rendered as

          Write-JitLog : DISABLE FAILED for 'x' - investigate: Cannot find an object...
          At C:\...\Revoke-GvmScanCredential.ps1:129 char:9

      which reads as though the logger broke rather than the disable, and points at the logging line
      instead of the failure. Failures are already reported in the caller's return value and, with
      -Strict, as a thrown exception; duplicating them into the error stream added noise and
      misdirection.

      NEVER pass a password into this function.

      Registering a new event source needs administrator rights, which the runner deliberately does
      not have. Create the source once during setup (see bootstrap/), after which the low-privilege
      runner can write to it. If it is missing, the host-stream line still appears, so a run is never
      silent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [int]$EventId = 1000,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level = 'Information',
        [string]$Source = 'GvmJitCredential'
    )
    # Resolve the source ONCE per session and remember the answer. SourceExists is not cheap and,
    # more importantly, it THROWS for a source that does not exist when the caller cannot enumerate
    # every event log -- which a low-privilege runner cannot ("Inaccessible logs: Security, State").
    # A source that DOES exist is found in Application before the search reaches those, which is why
    # a configured deployment never sees this. Warning per call turned one missing source into a
    # warning on every single line, which is worse than the silence it replaced.
    if ($script:JitLogSourceChecked -ne $Source) {
        $script:JitLogSourceChecked = $Source
        $script:JitLogSourceUsable = $false
        try {
            $script:JitLogSourceUsable = [System.Diagnostics.EventLog]::SourceExists($Source)
            if (-not $script:JitLogSourceUsable) {
                Write-Host ("[Warning] event log source '{0}' does not exist; this run is logged to output only. Create it once as an administrator: New-EventLog -LogName Application -Source '{0}'" -f $Source)
            }
        }
        catch {
            Write-Host ("[Warning] cannot verify event log source '{0}' ({1}); this run is logged to output only. Create it once as an administrator: New-EventLog -LogName Application -Source '{0}'" -f $Source, $_.Exception.Message)
        }
    }

    if ($script:JitLogSourceUsable) {
        try {
            Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $EventId -Message $Message
        }
        catch {
            # Losing a log line must never abort a revoke; the host line below still records it.
            $script:JitLogSourceUsable = $false
            Write-Host ("[Warning] event log write failed, continuing with output only: {0}" -f $_.Exception.Message)
        }
    }
    Write-Host ("[{0}] {1}" -f $Level, $Message)
}
