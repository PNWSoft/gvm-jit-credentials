function Invoke-GvmJitScan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId',
        Justification = 'CredentialId is a Greenbone object UUID, not a secret. The rule matches on the parameter name containing "Credential".')]
    <#
    .SYNOPSIS
      Runs an authenticated scan with the credential live only for its duration.

    .DESCRIPTION
      Convenience composition of Grant-GvmScanCredential and Revoke-GvmScanCredential. Use it when
      you want the whole lifecycle in one call; use the two primitives directly when you already
      have your own scan orchestration.

      Sequence:
        1. grant  -- enable the account, rotate the password, push it to Greenbone
        2. wait   -- let the AD reset replicate (see -ReplicationDelaySeconds)
        3. scan   -- start a Greenbone task and poll it, or run your own -ScanAction
        4. revoke -- ALWAYS, in a finally block, whatever happened above

      WHAT THIS CANNOT PROTECT AGAINST: if the process is killed outright, or the machine reboots
      mid-scan, the finally block never runs and the account is left enabled with a live password.
      That is not a hypothetical -- it is the normal outcome of a reboot during a long scan. Deploy
      the independent backstop as well (examples/backstop-task.ps1): a scheduled task that calls
      Revoke-GvmScanCredential unconditionally, timed to fire after your longest plausible scan.
      A finally block cannot outlive its own process, so the backstop is the only thing covering those.

    .PARAMETER TaskId
      UUID of an existing Greenbone task to start and poll.

    .PARAMETER ScanAction
      A script block to run instead, for callers who build their own target/task each run or who
      trigger scanning some other way. It receives the grant record as $args[0]. The credential is
      live for its duration and revoked when it returns or throws.

    .PARAMETER MaxScanMinutes
      Safety timeout for the poll loop. On expiry the function throws -- and therefore revokes.
      A scan that hangs must not hold the credential open indefinitely.

    .OUTPUTS
      A result record: Status, TaskId, ReportId, StartedAt, FinishedAt, Duration, Revoke.

    .EXAMPLE
      Invoke-GvmJitScan -Identity gvm-scan -CredentialId $cfg.CredentialId -TaskId $cfg.TaskId `
          -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh

    .EXAMPLE
      # Bring your own orchestration: build a fresh target and task from current inventory.
      Invoke-GvmJitScan -Identity gvm-scan -CredentialId $cfg.CredentialId `
          -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh `
          -ScanAction { param($grant) New-MyDailyTarget; Start-MyTask -Wait }
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByTaskId')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$CredentialId,
        [Parameter(Mandatory)][string]$ScannerHost,
        [Parameter(Mandatory)][string]$GmpHelper,

        [Parameter(Mandatory, ParameterSetName = 'ByTaskId')][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TaskId,
        [Parameter(Mandatory, ParameterSetName = 'ByScanAction')][scriptblock]$ScanAction,

        [string]$IdentityFile = '',
        [string]$Server = '',
        [ValidateRange(14, 127)][int]$PasswordLength = 24,
        [int]$ReplicationDelaySeconds = 45,
        [int]$PollSeconds = 30,
        [int]$MaxScanMinutes = 300,
        [string]$LogSource = 'GvmJitCredential'
    )

    $gmp = @{
        ScannerHost  = $ScannerHost
        GmpHelper    = $GmpHelper
        IdentityFile = $IdentityFile
    }

    if (-not $PSCmdlet.ShouldProcess("scan account '$Identity'", 'Grant credential, run scan, revoke credential')) {
        return
    }

    $result = [pscustomobject]@{
        Status     = 'NotRun'
        TaskId     = if ($PSCmdlet.ParameterSetName -eq 'ByTaskId') { $TaskId } else { '' }
        ReportId   = ''
        StartedAt  = (Get-Date)
        FinishedAt = $null
        Duration   = $null
        Revoke     = $null
    }

    # Grant is INSIDE the try: if it throws after enabling the account, the finally must still get
    # a chance to run. Grant rolls itself back in that case, so $grant stays $null and the finally
    # skips -- but a future change to either function must not reintroduce an unprotected window.
    $grant = $null
    try {
        $grant = Grant-GvmScanCredential -Identity $Identity -CredentialId $CredentialId `
            -ScannerHost $ScannerHost -GmpHelper $GmpHelper -IdentityFile $IdentityFile `
            -Server $Server -PasswordLength $PasswordLength `
            -ReplicationDelaySeconds $ReplicationDelaySeconds -LogSource $LogSource

        # The reset was written to the PDC emulator; give it time to reach the DCs the targets will
        # actually authenticate against. Skipping this produces a scan that silently falls back to
        # unauthenticated results, which looks like a clean scan rather than a failed one.
        if ($ReplicationDelaySeconds -gt 0) {
            Write-JitLog "Waiting ${ReplicationDelaySeconds}s for the password reset to replicate" 1004 'Information' $LogSource
            Start-Sleep -Seconds $ReplicationDelaySeconds
        }

        if ($PSCmdlet.ParameterSetName -eq 'ByScanAction') {
            Write-JitLog 'Running caller-supplied ScanAction' 1005 'Information' $LogSource
            & $ScanAction $grant
            $result.Status = 'ScanActionCompleted'
        }
        else {
            # start_task answers 202 Accepted, not 200.
            $null = Invoke-GmpRequest @gmp -ExpectStatus @('200', '202') `
                        -Xml ('<start_task task_id="{0}"/>' -f $TaskId)
            Write-JitLog "Greenbone task $TaskId started" 1005 'Information' $LogSource

            $deadline = (Get-Date).AddMinutes($MaxScanMinutes)
            $terminal = @('Done', 'Stopped', 'Interrupted')
            $status   = 'Unknown'
            do {
                Start-Sleep -Seconds $PollSeconds
                if ((Get-Date) -gt $deadline) {
                    throw "Scan exceeded MaxScanMinutes ($MaxScanMinutes); revoking the credential rather than waiting longer."
                }
                $doc = Invoke-GmpRequest @gmp -Xml ('<get_tasks task_id="{0}"/>' -f $TaskId)
                $node = $doc.SelectSingleNode('//task/status')
                $status = if ($node) { $node.InnerText } else { 'Unknown' }
            } until ($terminal -contains $status)

            $report = $doc.SelectSingleNode('//task/last_report/report')
            if ($report) { $result.ReportId = $report.GetAttribute('id') }
            $result.Status = $status
            Write-JitLog "Scan reached terminal state: $status" 1020 'Information' $LogSource
        }
    }
    finally {
        # Not inside a try/catch of its own: Revoke-GvmScanCredential does not throw by default, so
        # it cannot mask an exception already propagating from the scan.
        # $grant is null only when Grant itself failed, and Grant rolls back its own partial state.
        if ($grant) { $result.Revoke = Revoke-GvmScanCredential -Grant $grant }
        $result.FinishedAt = Get-Date
        $result.Duration   = $result.FinishedAt - $result.StartedAt
    }

    return $result
}
