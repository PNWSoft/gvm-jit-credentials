function Get-ObjectProperty {
    <#
    .SYNOPSIS
      Reads a property that may be absent, without tripping Set-StrictMode.

    .DESCRIPTION
      Under Set-StrictMode -Version Latest, touching a property a PSCustomObject does not have
      throws PropertyNotFoundException. Grant records come from callers and may be hand-built or
      produced by an older version of this module, so every read of one goes through here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}
