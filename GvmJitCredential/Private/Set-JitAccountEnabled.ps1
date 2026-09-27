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
        [Parameter(Mandatory)][string]$Server
    )
    Assert-JitAdModule
    if ($Enabled) { Enable-ADAccount  -Identity $Identity -Server $Server -ErrorAction Stop }
    else          { Disable-ADAccount -Identity $Identity -Server $Server -ErrorAction Stop }
}
