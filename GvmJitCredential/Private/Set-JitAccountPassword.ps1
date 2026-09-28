function Set-JitAccountPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Both Set-ADAccountPassword and the GMP payload require the plaintext, so a SecureString here would only be unwrapped immediately. Documented under the README, under "Threat model -- What this does NOT fix".')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Same: the value originates as plaintext by necessity.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private seam. The public callers (Grant/Revoke) implement ShouldProcess; adding it here would prompt twice for one action.')]
    <#
    .SYNOPSIS
      Performs an administrative password reset on the scan account.

    .DESCRIPTION
      Uses -Reset, an administrative reset, which bypasses minimum password age. Without it, a
      second grant on the same day fails wherever a minimum age is configured.

      A thin seam over Set-ADAccountPassword so the module is testable without a domain. Takes
      plaintext because both AD and the GMP payload need it; see the README, under "Threat model -- What this does NOT fix".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Password,
        # See Set-JitAccountEnabled: empty means "let the AD cmdlets discover a DC".
        [AllowEmptyString()][string]$Server = ''
    )
    Assert-JitAdModule
    $p = @{
        Identity    = $Identity
        Reset       = $true
        NewPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
        ErrorAction = 'Stop'
    }
    if ($Server) { $p['Server'] = $Server }
    Set-ADAccountPassword @p
}
