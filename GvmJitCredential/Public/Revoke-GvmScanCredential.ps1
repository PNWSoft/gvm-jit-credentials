function Revoke-GvmScanCredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId',
        Justification = 'CredentialId is a Greenbone object UUID, not a secret. The rule matches on the parameter name containing "Credential".')]
    <#
    .SYNOPSIS
      Returns the scan account to its dormant state: disabled, with a password nobody holds.

    .DESCRIPTION
      The other half of the just-in-time model, and the half that must not fail. Two independent
      layers are restored:

        1. the AD account is DISABLED, and
        2. its password is reset to a fresh random value that is never recorded anywhere.

      Either alone would suffice; doing both means a mistake in one does not expose the credential.

      DESIGN: every step is independently try/caught and the function does NOT rethrow by default.
      This is deliberate. It is normally called from a finally block, often while another exception
      is already in flight, and throwing here would replace the original error with this one --
      losing the reason the scan failed. Worse, an early throw would skip the remaining revoke
      steps, which is the opposite of what a cleanup routine should do. Failures are logged as
      errors and reported in the return value; pass -Strict to throw after attempting everything.

      IDEMPOTENT and safe to run at any time, including when no scan ran and when the account is
      already disabled. That is what makes it usable as an unconditional scheduled backstop.

    .PARAMETER Grant
      The record returned by Grant-GvmScanCredential, supplying identity, credential and scanner
      details in one object.

    .PARAMETER Strict
      Throw if any step failed, after attempting all of them. Appropriate for the scheduled
      backstop, where the task SHOULD report failure. Leave it off inside a finally block.

    .OUTPUTS
      A record of what succeeded: Disabled, PasswordReset, GreenboneBlanked, Errors.

    .EXAMPLE
      $grant = Grant-GvmScanCredential @params
      try     { Start-MyScan }
      finally { Revoke-GvmScanCredential -Grant $grant }

    .EXAMPLE
      # Unconditional backstop: no grant record, nothing assumed about the current state.
      Revoke-GvmScanCredential -Identity greenbone-scan -Strict
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByIdentity')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByGrant', Position = 0)]
        [ValidateNotNull()]
        [psobject]$Grant,

        [Parameter(Mandatory, ParameterSetName = 'ByIdentity')]
        [string]$Identity,

        [Parameter(ParameterSetName = 'ByIdentity')][string]$CredentialId = '',
        [Parameter(ParameterSetName = 'ByIdentity')][string]$ScannerHost  = '',
        [Parameter(ParameterSetName = 'ByIdentity')][string]$GmpHelper    = '',
        [Parameter(ParameterSetName = 'ByIdentity')][string]$IdentityFile = '',
        [Parameter(ParameterSetName = 'ByIdentity')][string]$Server       = '',

        # Valid in both sets: these are policy, not identity.
        [ValidateRange(14, 127)][int]$PasswordLength = 32,
        [bool]$BlankGreenboneCredential = $true,
        [switch]$Strict,
        [string]$LogSource = 'GvmJitCredential'
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByGrant') {
        $Identity     = [string](Get-ObjectProperty $Grant 'Identity' '')
        $CredentialId = [string](Get-ObjectProperty $Grant 'CredentialId' '')
        $ScannerHost  = [string](Get-ObjectProperty $Grant 'ScannerHost' '')
        $GmpHelper    = [string](Get-ObjectProperty $Grant 'GmpHelper' '')
        $IdentityFile = [string](Get-ObjectProperty $Grant 'IdentityFile' '')
        $Server       = [string](Get-ObjectProperty $Grant 'Server' '')
        $LogSource    = [string](Get-ObjectProperty $Grant 'LogSource' $LogSource)
        if (-not $Identity) {
            throw 'The supplied -Grant object has no Identity. Pass -Identity explicitly instead.'
        }
    }

    if (-not $Server) {
        try { $Server = Resolve-JitDomainController }
        catch { $Server = $env:USERDNSDOMAIN }
    }

    if (-not $PSCmdlet.ShouldProcess("scan account '$Identity' on $Server", 'Disable and invalidate password')) {
        return
    }

    $result = [pscustomobject]@{
        Identity         = $Identity
        Server           = $Server
        Disabled         = $false
        PasswordReset    = $false
        GreenboneBlanked = $false
        Errors           = [System.Collections.Generic.List[string]]::new()
        RevokedAt        = (Get-Date)
    }

    # --- 1) disable
    try {
        Set-JitAccountEnabled -Identity $Identity -Enabled $false -Server $Server
        $result.Disabled = $true
        Write-JitLog "Account '$Identity' DISABLED" 1006 'Information' $LogSource
    }
    catch {
        $msg = "DISABLE FAILED for '$Identity' - investigate: $($_.Exception.Message)"
        $result.Errors.Add($msg)
        Write-JitLog $msg 1901 'Error' $LogSource
    }

    # --- 2) invalidate the password, regardless of whether the disable worked
    $garbage = $null
    try {
        $garbage = New-EphemeralPassword -Length $PasswordLength
        Set-JitAccountPassword -Identity $Identity -Password $garbage -Server $Server
        $result.PasswordReset = $true
        Write-JitLog 'Password reset to an unrecorded random value' 1007 'Information' $LogSource
    }
    catch {
        $msg = "PASSWORD INVALIDATION FAILED for '$Identity' - investigate: $($_.Exception.Message)"
        $result.Errors.Add($msg)
        Write-JitLog $msg 1902 'Error' $LogSource
    }

    # --- 3) best-effort: overwrite the value Greenbone stores as well
    if ($BlankGreenboneCredential -and $CredentialId -and $ScannerHost -and $GmpHelper) {
        try {
            $filler = if ($garbage) { $garbage } else { New-EphemeralPassword -Length $PasswordLength }
            $body = '<modify_credential credential_id="{0}"><password>{1}</password></modify_credential>' -f `
                $CredentialId, (ConvertTo-GmpText $filler)
            $null = Invoke-GmpRequest -Xml $body -ScannerHost $ScannerHost -GmpHelper $GmpHelper `
                -IdentityFile $IdentityFile
            $result.GreenboneBlanked = $true
            Write-JitLog 'Greenbone-stored credential overwritten' 1008 'Information' $LogSource
        }
        catch {
            # Warning, not Error: the AD reset above already made the stored value useless.
            $msg = "Greenbone credential blanking failed (the AD reset already invalidated it): $($_.Exception.Message)"
            $result.Errors.Add($msg)
            Write-JitLog $msg 1010 'Warning' $LogSource
        }
    }

    $garbage = $null
    Remove-Variable garbage, filler -ErrorAction SilentlyContinue

    if ($Strict -and $result.Errors.Count -gt 0) {
        throw ("Revoke incomplete for '{0}': {1}" -f $Identity, ($result.Errors -join ' | '))
    }
    return $result
}
