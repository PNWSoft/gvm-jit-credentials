function Resolve-JitDomainController {
    <#
    .SYNOPSIS
      Returns the PDC emulator hostname.

    .DESCRIPTION
      Administrative password resets are written to the PDC emulator so they replicate promptly.
      Wrapped in its own function so tests can mock it without a domain, and so the fallback
      behaviour lives in one place.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Assert-JitAdModule
    return [string](Get-ADDomainController -Discover -Service PrimaryDC).HostName[0]
}
