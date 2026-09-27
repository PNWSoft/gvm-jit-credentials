function ConvertTo-GmpText {
    <#
    .SYNOPSIS
      XML-escapes a value for interpolation into a GMP request body.

    .DESCRIPTION
      Passwords are generated from a set that includes & < > and quotes, so escaping is not
      optional -- an unescaped '&' produces malformed XML and the credential push fails, or
      worse, silently stores a truncated password that then fails to authenticate mid-scan.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Security.SecurityElement]::Escape($Text)
}
