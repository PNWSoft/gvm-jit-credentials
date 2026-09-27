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
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
            Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $EventId -Message $Message
        }
    }
    catch {
        # SourceExists can itself throw under a restricted token, and Write-EventLog fails if the
        # source was never registered. Never let logging break the caller -- but do not swallow it
        # silently either: a missing audit trail is exactly the kind of quiet degradation this
        # module exists to avoid, so say so on the stream that IS being captured.
        Write-Host ("[Warning] event log write to source '{0}' failed; host output only: {1}" -f $Source, $_.Exception.Message)
    }
    Write-Host ("[{0}] {1}" -f $Level, $Message)
}
