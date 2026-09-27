function Write-JitLog {
    <#
    .SYNOPSIS
      Writes to the Windows Application event log, falling back to the verbose stream.

    .DESCRIPTION
      The event log is the audit trail for credential grant/revoke, so it is deliberately the
      primary sink rather than a text file: it is harder to tamper with and survives the
      scheduled task's console being discarded.

      NEVER pass a password into this function.

      Registering a new event source needs administrator rights, which the runner account
      deliberately does not have. Create the source once during setup (see bootstrap/), then
      the low-privilege runner can write to it. If it is missing we degrade to -Verbose rather
      than failing the run, because losing a log line must never abort a revoke.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [int]$EventId = 1000,
        [ValidateSet('Information','Warning','Error')][string]$Level = 'Information',
        [string]$Source = 'GvmJitCredential'
    )
    $written = $false
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
            Write-EventLog -LogName Application -Source $Source -EntryType $Level -EventId $EventId -Message $Message
            $written = $true
        }
    } catch {
        # SourceExists can itself throw under a restricted token; never let logging break the caller.
        $written = $false
    }
    if (-not $written) { Write-Verbose ("[{0}] {1}" -f $Level, $Message) }
    if ($Level -eq 'Error')   { Write-Error   $Message -ErrorAction Continue }
    elseif ($Level -eq 'Warning') { Write-Warning $Message }
}
