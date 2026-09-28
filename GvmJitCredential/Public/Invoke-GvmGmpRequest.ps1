function Invoke-GvmGmpRequest {
    <#
    .SYNOPSIS
      Sends one GMP request to the scanner and returns the parsed response.

    .DESCRIPTION
      Public wrapper over the module's GMP transport. It exists for callers using
      Invoke-GvmJitScan -ScanAction, or the Grant/Revoke primitives directly, who build their own
      targets and tasks each run: without it there is no way to talk to Greenbone from inside a
      -ScanAction block except by reimplementing the transport, which would duplicate the parts that
      are easy to get wrong -- keeping secrets off the command line, capturing ssh's stderr, and
      checking the status attribute by parsing rather than by regex.

      The request travels over SSH stdin and never appears on a command line. Always use
      ConvertTo-GvmGmpText on any value you interpolate into a request body.

    .PARAMETER ExpectStatus
      Statuses treated as success. Defaults to 200. GMP answers 201 to most create_* commands and
      202 to start_task, so pass those explicitly when you use them.

    .EXAMPLE
      $doc = Invoke-GvmGmpRequest -Xml '<get_version/>' -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh

    .EXAMPLE
      $doc = Invoke-GvmGmpRequest -ScannerHost $h -GmpHelper $g -ExpectStatus 200,201 `
                 -Xml ('<create_target><name>{0}</name><hosts>{1}</hosts></create_target>' -f
                       (ConvertTo-GvmGmpText $name), (ConvertTo-GvmGmpText $hosts))
      $targetId = $doc.DocumentElement.GetAttribute('id')
    #>
    [CmdletBinding()]
    [OutputType([xml])]
    param(
        [Parameter(Mandatory)][string]$Xml,
        [Parameter(Mandatory)][string]$ScannerHost,
        [Parameter(Mandatory)][string]$GmpHelper,
        [string]$IdentityFile = '',
        [int]$ConnectTimeoutSeconds = 15,
        [string[]]$ExpectStatus = @('200')
    )
    return Invoke-GmpRequest -Xml $Xml -ScannerHost $ScannerHost -GmpHelper $GmpHelper `
        -IdentityFile $IdentityFile -ConnectTimeoutSeconds $ConnectTimeoutSeconds `
        -ExpectStatus $ExpectStatus
}
