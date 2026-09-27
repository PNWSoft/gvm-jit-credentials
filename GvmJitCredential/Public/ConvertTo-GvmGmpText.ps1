function ConvertTo-GvmGmpText {
    <#
    .SYNOPSIS
      XML-escapes a value for interpolation into a GMP request body.

    .DESCRIPTION
      Public counterpart to the module's internal escaping. Any caller-supplied value going into a
      request -- a target name, a hostname, a login -- must pass through this. An unescaped '&' or
      '<' produces malformed XML, and the failure mode is a request that is silently rejected or,
      worse, one that stores a truncated value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    return ConvertTo-GmpText -Text $Text
}
