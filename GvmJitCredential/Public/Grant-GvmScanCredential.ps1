function Grant-GvmScanCredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId',
        Justification = 'CredentialId is a Greenbone object UUID, not a secret. The rule matches on the parameter name containing "Credential".')]
    <#
    .SYNOPSIS
      Brings the scan account to life for one scan: enable, rotate to a fresh random password,
      push that password into the Greenbone credential object.

    .DESCRIPTION
      Half of the just-in-time model. Between scans the AD account is DISABLED and the password
      stored in Greenbone is invalid, so the credential is useless to anyone who obtains it.
      This grant makes it briefly usable; Revoke-GvmScanCredential puts it back.

      Order matters. The password is set in AD FIRST and pushed to Greenbone SECOND, and the
      function throws if Greenbone rejects it. If it were done the other way round, a failure
      would leave Greenbone holding a password that AD does not have, and the scan would
      authenticate nowhere -- with authentication failures across every target, which looks
      exactly like an attack in progress.

      The reset is written to the PDC emulator so it replicates promptly. Callers MUST still wait
      -- see -ReplicationDelaySeconds -- before starting a scan, or targets may authenticate
      against a domain controller that has not caught up and the scan silently falls back to
      unauthenticated results.

      ALWAYS pair this with Revoke-GvmScanCredential in a finally block, and deploy the
      independent backstop (examples/backstop-task.ps1) for the cases where finally never runs:
      the process being killed, or the machine rebooting mid-scan.

    .PARAMETER Identity
      sAMAccountName of the dedicated scan account, e.g. "greenbone-scan".

    .PARAMETER CredentialId
      UUID of the Greenbone credential object to push the password into. Get it from
      bootstrap/Initialize-GvmScanCredential.ps1.

    .OUTPUTS
      A grant record (Identity, CredentialId, Server, GrantedAt) to pass to
      Revoke-GvmScanCredential as -Grant. It deliberately does NOT contain the password.
      It is a PSCustomObject, so it cannot be splatted -- use -Grant, not @grant.

    .EXAMPLE
      $grant = Grant-GvmScanCredential -Identity greenbone-scan -CredentialId $cfg.CredentialId `
                 -ScannerHost scanner@scanner.example.local -GmpHelper /opt/gvm/gmp.sh
      try { Start-MyScan } finally { Revoke-GvmScanCredential -Grant $grant }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Identity,
        # Interpolated into a GMP request body; validated so it cannot inject XML.
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$CredentialId,
        [Parameter(Mandatory)][string]$ScannerHost,
        [Parameter(Mandatory)][string]$GmpHelper,
        [string]$IdentityFile = '',
        # Domain controller to write to. Defaults to the PDC emulator, which is where an admin
        # password reset should go for prompt replication.
        [string]$Server = '',
        [ValidateRange(14,127)][int]$PasswordLength = 24,
        # Callers should Start-Sleep this long between the grant and starting the scan. Exposed
        # here so the value travels with the grant record rather than being reinvented.
        [int]$ReplicationDelaySeconds = 45,
        [string]$LogSource = 'GvmJitCredential'
    )

    if (-not $Server) { $Server = Resolve-JitDomainController }

    $target = "scan account '$Identity' on $Server"
    if (-not $PSCmdlet.ShouldProcess($target, 'Enable, rotate password, push to Greenbone')) {
        return
    }

    Write-JitLog "JIT grant starting for '$Identity'" 1000 'Information' $LogSource

    Set-JitAccountEnabled -Identity $Identity -Enabled $true -Server $Server
    Write-JitLog "Account '$Identity' ENABLED" 1001 'Information' $LogSource

    # From here on the account is ENABLED. Any failure below must undo that before rethrowing:
    # an enabled account with a live (or unknown) password is the exact state this module exists to
    # prevent, and the caller cannot clean up because it never received a grant record.
    $password = $null
    $body = $null
    try {
        $password = New-EphemeralPassword -Length $PasswordLength
        Set-JitAccountPassword -Identity $Identity -Password $password -Server $Server
        Write-JitLog 'Password rotated in AD' 1002 'Information' $LogSource

        $body = '<modify_credential credential_id="{0}"><password>{1}</password></modify_credential>' -f `
            $CredentialId, (ConvertTo-GmpText $password)
        $null = Invoke-GmpRequest -Xml $body -ScannerHost $ScannerHost -GmpHelper $GmpHelper `
            -IdentityFile $IdentityFile
        Write-JitLog 'Greenbone credential updated for this scan window' 1003 'Information' $LogSource
    }
    catch {
        Write-JitLog ("Grant FAILED after enabling '$Identity'; rolling back. " + $_.Exception.Message) 1009 'Error' $LogSource
        try {
            # -Strict so a rollback that fails THROWS and lands in the catch below, producing the
            # 1903 event. Without it Revoke returns normally with its failures only in .Errors, and
            # the "rollback also failed" branch is effectively unreachable.
            $null = Revoke-GvmScanCredential -Identity $Identity -CredentialId $CredentialId `
                -ScannerHost $ScannerHost -GmpHelper $GmpHelper -IdentityFile $IdentityFile `
                -Server $Server -LogSource $LogSource -Strict
        }
        catch {
            # Rollback failing is the worst case: enabled account, nobody cleaning up. Say so loudly.
            Write-JitLog ("ROLLBACK ALSO FAILED for '$Identity' - the account may still be ENABLED. Investigate immediately: " + $_.Exception.Message) 1903 'Error' $LogSource
        }
        throw
    }
    finally {
        # Drops our references. It does NOT zero the strings -- see CAVEATS in the README. $body is
        # cleared too: it carries the same plaintext as $password.
        $password = $null
        $body = $null
        Remove-Variable password, body -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        Identity                = $Identity
        CredentialId            = $CredentialId
        ScannerHost             = $ScannerHost
        GmpHelper               = $GmpHelper
        IdentityFile            = $IdentityFile
        Server                  = $Server
        LogSource               = $LogSource
        GrantedAt               = (Get-Date)
        ReplicationDelaySeconds = $ReplicationDelaySeconds
    }
}
