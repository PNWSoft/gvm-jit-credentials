function Assert-JitAdModule {
    <#
    .SYNOPSIS
      Loads the ActiveDirectory module, with an actionable error if RSAT is missing.
    #>
    [CmdletBinding()]
    param()
    if (Get-Module -Name ActiveDirectory) { return }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        # Both routes, because the right one depends on the SKU and the runner is usually a server:
        #   Windows Server      -> Install-WindowsFeature
        #   Windows client      -> Add-WindowsCapability, which needs the FULL capability name
        #                          (Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0); the wildcard form
        #                          below avoids having to know the version suffix.
        throw @'
The ActiveDirectory module is not installed. Install RSAT:
  Windows Server: Install-WindowsFeature RSAT-AD-PowerShell
  Windows client: Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools*' | Add-WindowsCapability -Online
'@
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}
