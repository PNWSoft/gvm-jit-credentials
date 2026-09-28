<#
.SYNOPSIS
  Code-signs every PowerShell file in this repo, verifying each one still parses afterwards.

.DESCRIPTION
  Under an AllSigned execution policy the module will not import unless it is signed -- all of
  GvmJitCredential\*.ps1, the .psm1, the .psd1, and any bootstrap or example script you actually
  run. Sign with YOUR certificate. Do not trust a signature from someone else's repository.

  Two checks make this more than a signing loop, both learned painfully:

  BEFORE signing, it refuses any file that is not CRLF. signtool appends its signature block
  assuming CRLF line endings; on an LF-only .ps1 it silently discards the final line. The result is
  a file that reports Status: Valid and then fails to run with MissingEndCurlyBrace, because a real
  closing brace is missing from the bytes. .gitattributes should give you CRLF on checkout, but a
  file written by a script or an editor afterwards may not be.

  AFTER signing, it re-parses every file. Validating before signing proves nothing, because signing
  is the step that can corrupt the file. Parse with the PowerShell edition that will RUN the code:
  Windows PowerShell 5.1 parses differently from 7.x, so a pwsh check is not a substitute when the
  target runs 5.1. Pass -VerifyWith to control that.

.PARAMETER Thumbprint
  Certificate thumbprint in Cert:\CurrentUser\My or Cert:\LocalMachine\My. Simplest path when you
  hold the private key locally.

.PARAMETER SignCommand
  Alternative for signing services that do not expose a local private key -- Azure Trusted Signing,
  an HSM, signtool with a dlib. Receives one file path as $args[0] and must sign in place, throwing
  on failure. The certificate never has to touch this machine.

.PARAMETER VerifyWith
  Which PowerShell parses the signed output: 'powershell' (5.1), 'pwsh' (7.x), 'both' or 'current'.
  The default is 'current' -- whichever edition is running this script, which is NOT necessarily the
  one that will run the signed code. If your scheduled tasks use Windows PowerShell 5.1, pass
  'powershell' or 'both'.

.EXAMPLE
  # Local certificate
  .\Sign-Module.ps1 -Thumbprint 1A2B3C... -TimestampServer http://timestamp.digicert.com

.EXAMPLE
  # Azure Trusted Signing: no private key on this machine
  .\Sign-Module.ps1 -VerifyWith both -SignCommand {
      Invoke-TrustedSigning -Endpoint 'https://xxx.codesigning.azure.net/' `
          -CodeSigningAccountName MyAccount -CertificateProfileName MyProfile `
          -Files $args[0] -FileDigest SHA256 `
          -TimestampRfc3161 'http://timestamp.acs.microsoft.com' -TimestampDigest SHA256
  }

.EXAMPLE
  .\Sign-Module.ps1 -Thumbprint 1A2B3C... -WhatIf     # list what would be signed
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimestampServer',
    Justification = 'Used inside the $signer scriptblock created with .GetNewClosure(); the analyzer cannot see through the closure.')]
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByThumbprint')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByThumbprint')][string]$Thumbprint,
    [Parameter(Mandatory, ParameterSetName = 'BySignCommand')][scriptblock]$SignCommand,

    [string]$Path = (Split-Path $PSScriptRoot -Parent),
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [ValidateSet('powershell', 'pwsh', 'both', 'current')][string]$VerifyWith = 'current',
    # Signing test files is pointless; they are never run under AllSigned by a scheduled task.
    [string[]]$ExcludeDirectory = @('tests', '.git', '.github')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Normalise BEFORE $Path is used as a string prefix. The filter below slices FullName with
# Substring($Path.Length), which mis-slices when $Path is relative ('.') or carries a trailing
# separator: the computed first segment is then wrong, so the tests/.git exclusions quietly stop
# applying -- test files get signed -- or the slice throws outright.
$Path = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\', '/')

# --- collect
$files = @(
    Get-ChildItem -Path $Path -Recurse -Include *.ps1, *.psm1, *.psd1 -File |
        Where-Object {
            $rel = $_.FullName.Substring($Path.Length).TrimStart('\', '/')
            $first = ($rel -split '[\\/]')[0]
            $ExcludeDirectory -notcontains $first -and $_.Name -ne 'PSScriptAnalyzerSettings.psd1'
        } | Sort-Object FullName
)
if ($files.Count -eq 0) { throw "No PowerShell files found under $Path" }
Write-Host "Found $($files.Count) file(s) to sign under $Path`n"

# --- pre-flight: line endings. Refuse rather than silently produce a corrupt signed file.
$lfFiles = foreach ($f in $files) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $lf = 0; $cr = 0
    foreach ($b in $bytes) { if ($b -eq 10) { $lf++ } elseif ($b -eq 13) { $cr++ } }
    if ($lf -gt 0 -and $cr -ne $lf) { $f }
}
if ($lfFiles) {
    Write-Host 'REFUSING TO SIGN: these files are not CRLF. signtool would discard their last line,' -ForegroundColor Red
    Write-Host 'producing a signature that verifies as Valid over a file that no longer parses.' -ForegroundColor Red
    $lfFiles | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Red }
    Write-Host "`nFix with a fresh checkout (see .gitattributes), or convert in place:" -ForegroundColor Yellow
    Write-Host '  $c = Get-Content $f -Raw; [IO.File]::WriteAllText($f, ($c -replace "`r?`n", "`r`n"))' -ForegroundColor Yellow
    throw 'Line ending check failed.'
}
Write-Host "Line endings: all CRLF`n" -ForegroundColor Green

# --- resolve the signer
if ($PSCmdlet.ParameterSetName -eq 'ByThumbprint') {
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Where-Object Thumbprint -eq $Thumbprint | Select-Object -First 1
    if (-not $cert) { throw "No code-signing certificate with thumbprint $Thumbprint in CurrentUser\My or LocalMachine\My." }
    Write-Host "Signing with: $($cert.Subject)"
    Write-Host "  valid $($cert.NotBefore) -> $($cert.NotAfter)`n"
    $signer = { Set-AuthenticodeSignature -FilePath $args[0] -Certificate $cert -TimestampServer $TimestampServer -HashAlgorithm SHA256 | Out-Null }.GetNewClosure()
}
else {
    Write-Host "Signing via the supplied -SignCommand`n"
    $signer = $SignCommand
}

# --- sign
$signed = [System.Collections.Generic.List[string]]::new()
foreach ($f in $files) {
    if (-not $PSCmdlet.ShouldProcess($f.FullName, 'Code sign')) { continue }
    try {
        & $signer $f.FullName
        $signed.Add($f.FullName)
        Write-Host "  signed  $($f.Name)"
    }
    catch {
        Write-Host "  FAILED  $($f.Name): $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}
if ($signed.Count -eq 0) { Write-Host 'Nothing signed (WhatIf).'; return }

# --- post-flight: signature status
Write-Host "`nVerifying signatures..."
$bad = 0
foreach ($p in $signed) {
    $sig = Get-AuthenticodeSignature -FilePath $p
    if ($sig.Status -ne 'Valid') { $bad++; Write-Host "  $($sig.Status)  $(Split-Path $p -Leaf): $($sig.StatusMessage)" -ForegroundColor Red }
}
if ($bad -gt 0) { throw "$bad file(s) do not have a Valid signature." }
Write-Host "  all $($signed.Count) signature(s) Valid" -ForegroundColor Green

# --- post-flight: THE important one. Signing is what can corrupt the file, so parse afterwards.
$editions = switch ($VerifyWith) {
    'both'    { @('powershell', 'pwsh') }
    'current' { @($(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell' })) }
    default   { @($VerifyWith) }
}

Write-Host "`nRe-parsing signed files (this is the check that catches signing corruption)..."
$verifier = Join-Path ([IO.Path]::GetTempPath()) ("gvmjit-verify-{0}.ps1" -f [guid]::NewGuid())
@'
$bad = 0
foreach ($p in $args) {
    $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$e)
    if ($e) { $bad++; Write-Host ("  PARSE FAIL {0}:{1} {2}" -f (Split-Path $p -Leaf), $e[0].Extent.StartLineNumber, $e[0].Message) }
}
exit $bad
'@ | Set-Content -LiteralPath $verifier -Encoding ASCII

try {
    foreach ($edition in $editions) {
        $exe = Get-Command $edition -ErrorAction SilentlyContinue
        if (-not $exe) { Write-Host "  $edition not available; skipped" -ForegroundColor Yellow; continue }

        # -File, not -Command: with -Command the rest of the line is command TEXT, so '-args' is a
        # syntax error and nothing is ever parsed -- the check would report failure on every good run.
        # The verifier is a separate file precisely so the path list can be passed as arguments.
        & $exe.Source -NoProfile -ExecutionPolicy Bypass -File $verifier @signed
        if ($LASTEXITCODE -ne 0) {
            throw "$LASTEXITCODE file(s) fail to parse under $edition AFTER signing. Check line endings; signtool truncates LF-only files."
        }
        Write-Host "  $edition : all parse clean" -ForegroundColor Green
    }
}
finally {
    Remove-Item -LiteralPath $verifier -Force -ErrorAction SilentlyContinue
}

Write-Host "`nDone. $($signed.Count) file(s) signed and verified." -ForegroundColor Green
Write-Host 'If the target machine runs AllSigned, the signing certificate must also be in its' -ForegroundColor DarkGray
Write-Host 'Cert:\LocalMachine\TrustedPublisher store, and short-lived certificates rotate --' -ForegroundColor DarkGray
Write-Host 'check the thumbprint after each signing run rather than assuming it is unchanged.' -ForegroundColor DarkGray
