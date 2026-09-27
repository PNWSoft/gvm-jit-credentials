function Set-JitAccountEnabled {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Private seam. The public callers implement ShouldProcess; adding it here would prompt twice for one action.')]
    <#
    .SYNOPSIS
      Enables or disables the scan account.

    .DESCRIPTION
      A thin seam over Enable-ADAccount / Disable-ADAccount. It exists so the module can be unit
      tested on a machine with no RSAT and no domain, which includes GitHub Actions runners.
      Mock this in tests rather than the AD cmdlets, which cannot be mocked when absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][bool]$Enabled,
        # Optional and allowed to be empty: an empty value means "let the AD cmdlets discover a DC".
        # Passing -Server '' through would throw a binding error, so it is omitted instead.
        [AllowEmptyString()][string]$Server = ''
    )
    Assert-JitAdModule
    $p = @{ Identity = $Identity; ErrorAction = 'Stop' }
    if ($Server) { $p['Server'] = $Server }
    if ($Enabled) { Enable-ADAccount @p } else { Disable-ADAccount @p }
}
