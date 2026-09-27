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
      A grant record (Identity, CredentialId, Server, GrantedAt) suitable for splatting into
      Revoke-GvmScanCredential. It deliberately does NOT contain the password.

    .EXAMPLE
      $grant = Grant-GvmScanCredential -Identity greenbone-scan -CredentialId $cfg.CredentialId `
                 -ScannerHost scanner@scanner.example.local -GmpHelper /opt/gvm/gmp.sh
      try { Start-MyScan } finally { Revoke-GvmScanCredential @grant }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$CredentialId,
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

    $password = New-EphemeralPassword -Length $PasswordLength
    try {
        Set-JitAccountPassword -Identity $Identity -Password $password -Server $Server
        Write-JitLog 'Password rotated in AD' 1002 'Information' $LogSource

        $body = '<modify_credential credential_id="{0}"><password>{1}</password></modify_credential>' -f
                    $CredentialId, (ConvertTo-GmpText $password)
        $null = Invoke-GmpRequest -Xml $body -ScannerHost $ScannerHost -GmpHelper $GmpHelper `
                    -IdentityFile $IdentityFile
        Write-JitLog 'Greenbone credential updated for this scan window' 1003 'Information' $LogSource
    }
    finally {
        # Drop our reference promptly. This does not zero the string -- see CAVEATS in the README.
        $password = $null
        Remove-Variable password -ErrorAction SilentlyContinue
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
