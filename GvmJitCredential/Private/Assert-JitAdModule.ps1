function Assert-JitAdModule {
    <#
    .SYNOPSIS
      Loads the ActiveDirectory module, with an actionable error if RSAT is missing.
    #>
    [CmdletBinding()]
    param()
    if (Get-Module -Name ActiveDirectory) { return }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module is not installed. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}
