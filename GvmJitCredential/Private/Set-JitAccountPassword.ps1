function Set-JitAccountPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
        Justification = 'Both Set-ADAccountPassword and the GMP payload require the plaintext, so a SecureString here would only be unwrapped immediately. Documented under CAVEATS in the README.')]
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
      plaintext because both AD and the GMP payload need it; see CAVEATS in the README.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Server
    )
    Assert-JitAdModule
    Set-ADAccountPassword -Identity $Identity -Reset `
        -NewPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
        -Server $Server -ErrorAction Stop
}
