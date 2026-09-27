function ConvertTo-GmpText {
    <#
    .SYNOPSIS
      XML-escapes a value for interpolation into a GMP request body.

    .DESCRIPTION
      The generated password alphabet includes '&', so escaping is not optional; login names and
      object names supplied by the caller may contain any of & < > too -- an unescaped '&' produces malformed XML and the credential push fails, or
      worse, silently stores a truncated password that then fails to authenticate mid-scan.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Security.SecurityElement]::Escape($Text)
}
