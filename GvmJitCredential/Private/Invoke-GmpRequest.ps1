function Invoke-GmpRequest {
    <#
    .SYNOPSIS
      Sends one GMP request to the scanner over SSH stdin and returns the parsed response.

    .DESCRIPTION
      The request travels on STDIN, never on the command line, so a password in a
      <modify_credential> payload never appears in argv, in `ps` output on the scanner, or in
      shell history on either end. This is the whole reason for the host-side helper script
      (host/gmp.sh) instead of calling `gvm-cli --gmp-password` directly.

      The response is parsed as XML and the status attribute is checked. Regex-matching the raw
      text for status="200" happens to work but is fragile: a nested element can carry the same
      attribute, so a failed call whose body quotes a successful one would read as success.

    .PARAMETER IdentityFile
      Explicit SSH private key. Strongly recommended: without it, ssh resolves the key from the
      CALLING account's ~/.ssh, so the same code succeeds under the scheduled task and fails when
      a human runs it by hand -- a confusing difference to debug.
    #>
    [CmdletBinding()]
    [OutputType([xml])]
    param(
        [Parameter(Mandatory)][string]$Xml,
        # Validated, because both end up on ssh's command line. A value beginning with '-' would
        # otherwise be parsed as an option: -oProxyCommand=<payload> runs arbitrary code as the
        # CALLING account, which is the runner holding the AD delegation and the SSH key.
        # The user@ part is optional: a bare host relying on an ssh_config User directive is valid.
        [Parameter(Mandatory)]
        [ValidatePattern('^([A-Za-z0-9._-]+@)?[A-Za-z0-9._-]+$')]
        [string]$ScannerHost,

        [Parameter(Mandatory)]
        [ValidatePattern('^/[A-Za-z0-9._/-]+$')]
        [string]$GmpHelper,
        [string]$IdentityFile = '',
        [int]$ConnectTimeoutSeconds = 15,
        [int]$ServerAliveIntervalSeconds = 15,
        [int]$ServerAliveCountMax = 4,
        # Accepted statuses. 200 = OK; start_task answers 202 Accepted.
        [string[]]$ExpectStatus = @('200')
    )

    if ($IdentityFile -and -not (Test-Path -LiteralPath $IdentityFile)) {
        throw "IdentityFile not found: $IdentityFile"
    }

    # ServerAliveInterval/CountMax are load-bearing, not tuning. ConnectTimeout bounds only the
    # CONNECTION; if the scanner crashes or a stateful firewall drops the flow mid-poll, ssh blocks on
    # read (Windows TCP keepalive defaults to hours), and -MaxScanMinutes cannot save us because its
    # deadline check lives inside the poll loop that is itself blocked. The account would stay ENABLED
    # with a live password until the backstop task fires. 15s x 4 bounds that at about a minute.
    $sshArgs = @(
        '-o', 'BatchMode=yes'
        '-o', "ConnectTimeout=$ConnectTimeoutSeconds"
        '-o', "ServerAliveInterval=$ServerAliveIntervalSeconds"
        '-o', "ServerAliveCountMax=$ServerAliveCountMax"
    )
    if ($IdentityFile) { $sshArgs += @('-o','IdentitiesOnly=yes','-i',$IdentityFile) }
    # '--' terminates option parsing, so even if the validation above is ever loosened a
    # leading-dash value cannot become an ssh option. Verified: ssh accepts '--' and then rejects
    # '-oProxyCommand=...' as an invalid hostname rather than honouring it.
    $sshArgs += @('--', $ScannerHost, $GmpHelper)

    # STDERR goes to a file rather than $null. With BatchMode=yes ssh gives no prompt and writes its
    # reason only to stderr, so discarding it turns "Host key verification failed" into an empty
    # response and sends you hunting in the wrong place. Capturing it is what lets this module report
    # the actual cause.
    $errFile = [System.IO.Path]::GetTempFileName()
    $prev = $ErrorActionPreference
    # In PS 5.1 a native command writing to STDERR raises a terminating NativeCommandError when
    # $ErrorActionPreference is 'Stop'. ssh itself writes to stderr (host-key notices, banners,
    # keepalive failures), so localise to 'Continue'; success is judged solely by the parsed status
    # below. The relay's stderr carries only its own die() messages and a failing gvm-cli's reason;
    # docker's chatter is what it discards (--progress quiet, and compose stderr sent to a file)
    # -- but ssh's is not, which is why this is still needed.
    $ErrorActionPreference = 'Continue'
    try {
        $response = $Xml | & ssh @sshArgs 2>$errFile
        # Under Set-StrictMode -Version Latest, reading $LASTEXITCODE before anything has set it
        # THROWS. That happens for real when ssh is not on PATH, so the caller would get an opaque
        # StrictMode error instead of being told ssh is missing.
        $sshExit = if (Test-Path -LiteralPath 'Variable:LASTEXITCODE') { $LASTEXITCODE } else { 'unknown' }
    } finally {
        $ErrorActionPreference = $prev
    }

    $stderr = ''
    if (Test-Path -LiteralPath $errFile) {
        $raw = Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue
        if ($null -ne $raw) { $stderr = [string]$raw }
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($stderr) {
        # Redacted before this string can reach an exception message, Write-JitLog and the event
        # log. The relay strips password elements at the source; this is the second layer, because
        # gvm-tools echoes the REQUEST on a parse error and that request carries the plaintext.
        # Attribute-tolerant and greedy, matching the relay's rule: a narrow pattern is defeated by
        # <password xml:space="preserve"> or by a raw '<' inside the value. The second rule catches an
        # orphaned closing tag, which is what a truncated error line can leave behind.
        $stderr = [regex]::Replace($stderr.Trim(), '(?is)<password[^>]*>.*</password>', '<password>[redacted]</password>')
        # Not anchored at ^: the relay prefixes its own text before the truncated tail, so an orphaned
        # close never starts the string. This matches the run of non-tag characters immediately before
        # it, which is what a cut through the opening tag leaves exposed. Idempotent on already-redacted
        # text.
        $stderr = [regex]::Replace($stderr, '(?is)[^<>]*</password>', '[redacted]</password>')
        if ($stderr.Length -gt 1024) { $stderr = $stderr.Substring(0, 1024) + ' ...[truncated]' }
    }

    $text = [string]$response
    if ([string]::IsNullOrWhiteSpace($text)) {
        $detail = if ($stderr) { "ssh exit ${sshExit}: $stderr" } else { "ssh exit $sshExit, nothing on stderr" }
        throw "No response from the GMP helper ($GmpHelper on $ScannerHost). $detail"
    }

    try { $doc = [xml]$text }
    catch {
        $excerpt = $text.Substring(0, [Math]::Min(300, $text.Length))
        throw "GMP returned unparseable XML: $excerpt"
    }

    $status = $doc.DocumentElement.GetAttribute('status')
    if ($ExpectStatus -notcontains $status) {
        throw ("GMP {0} failed: status={1} {2}" -f $doc.DocumentElement.Name, $status, $doc.DocumentElement.GetAttribute('status_text'))
    }
    return $doc
}
