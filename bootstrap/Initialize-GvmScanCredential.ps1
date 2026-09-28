<#
.SYNOPSIS
  Creates the Greenbone credential object for JIT scanning and prints a ready-to-paste config file.

.DESCRIPTION
  The single biggest barrier to adopting this module is that it needs several Greenbone UUIDs, and
  finding them by hand means clicking through GSA and copying values out of URLs. This script
  discovers them and emits a config.psd1 you can save and use directly.

  It creates ONE object -- the username+password credential the module rotates. Everything else it
  only reads: scan configs, scanners, port lists and tasks are listed so their UUIDs can be
  reported.

  Run it once at setup. It is safe to re-run: pass -CredentialName matching an existing credential
  and it will report that UUID instead of creating a duplicate.

  The password set here does not matter and is deliberately random: Grant-GvmScanCredential
  overwrites it at the start of every scan. What matters is that the object exists and the module's
  GMP user can modify it.

.PARAMETER ScannerHost
  SSH login for the Greenbone host, e.g. "gvm-relay@scanner.example.local".

.PARAMETER GmpHelper
  Path to gmp.sh on that host, e.g. "/opt/greenbone/gmp.sh".

.PARAMETER ScanAccount
  The Windows/AD account the scan will authenticate as, in DOMAIN\user form. Stored as the
  credential's login; only the password is rotated per scan.

.PARAMETER CredentialName
  Display name for the Greenbone credential object. Re-running with a name that already exists reports
  that object's UUID instead of creating a duplicate, which is what makes this script idempotent.

.PARAMETER IdentityFile
  Explicit SSH private key for $ScannerHost. Omit it only if the calling account's own ~/.ssh already
  holds a key authorised for that host.

.PARAMETER OutFile
  Write the generated config here instead of only printing it.

.EXAMPLE
  .\Initialize-GvmScanCredential.ps1 -ScannerHost gvm-relay@scanner.example.local `
      -GmpHelper /opt/greenbone/gmp.sh -ScanAccount 'EXAMPLE\gvm-scan' -OutFile ..\config.psd1
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialName',
    Justification = 'CredentialName is the display name of a Greenbone object, not a secret. The rule matches on the parameter name containing "Credential".')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ScannerHost,
    [Parameter(Mandatory)][string]$GmpHelper,
    [Parameter(Mandatory)][string]$ScanAccount,
    [string]$CredentialName = 'JIT scan credential',
    [string]$IdentityFile = '',
    [string]$OutFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\GvmJitCredential\GvmJitCredential.psd1') -Force

# Invoke-GmpRequest is private, so reach into the module scope rather than duplicating it here.
$module = Get-Module GvmJitCredential
function Send-Gmp {
    param([string]$Xml, [string[]]$Expect = @('200', '201'))
    return & $module {
        param($x, $h, $g, $i, $e)
        Invoke-GmpRequest -Xml $x -ScannerHost $h -GmpHelper $g -IdentityFile $i -ExpectStatus $e
    } $Xml $ScannerHost $GmpHelper $IdentityFile $Expect
}

function Show-Section { param([string]$Title) Write-Host "`n$Title" -ForegroundColor Cyan }

Write-Host 'Checking connectivity to the Greenbone host...'
$version = Send-Gmp '<get_version/>'
$v = $version.SelectSingleNode('//version')
Write-Host ("  connected; GMP version {0}" -f $(if ($v) { $v.InnerText } else { 'unknown' })) -ForegroundColor Green

# --- credential: reuse if a name matches, otherwise create
Show-Section 'Credential'
$existing = $null
$creds = Send-Gmp '<get_credentials filter="rows=-1"/>'
foreach ($c in @($creds.SelectNodes('//credential'))) {
    $n = $c.SelectSingleNode('name')
    if ($n -and $n.InnerText -eq $CredentialName) { $existing = $c.GetAttribute('id'); break }
}

if ($existing) {
    $credentialId = $existing
    Write-Host "  reusing existing credential '$CredentialName' = $credentialId" -ForegroundColor Yellow
}
elseif ($PSCmdlet.ShouldProcess($CredentialName, 'Create Greenbone credential')) {
    # Random placeholder: Grant-GvmScanCredential replaces it before every scan.
    $placeholder = & $module { New-EphemeralPassword -Length 24 }
    # '& $module { ... }' INVOKES the block; it must be wrapped to stay callable.
    $esc = { param($t) & $module { param($x) ConvertTo-GmpText $x } $t }.GetNewClosure()
    $body = '<create_credential><name>{0}</name><type>up</type><allow_insecure>0</allow_insecure><login>{1}</login><password>{2}</password><comment>Rotated per scan by GvmJitCredential. The stored value is invalid between scans by design.</comment></create_credential>' -f
                (& $esc $CredentialName), (& $esc $ScanAccount), (& $esc $placeholder)
    $created = Send-Gmp $body @('200', '201')
    $credentialId = $created.DocumentElement.GetAttribute('id')
    Remove-Variable placeholder
    Write-Host "  created credential '$CredentialName' = $credentialId" -ForegroundColor Green
}
else {
    Write-Host '  skipped (WhatIf)'; $credentialId = '<not created>'
}

# --- read-only discovery of everything else the caller will need
function Show-IdList {
    param([string]$Label, [string]$Request, [string]$XPath)
    Show-Section $Label
    $doc = Send-Gmp $Request
    $rows = @($doc.SelectNodes($XPath))
    if ($rows.Count -eq 0) { Write-Host '  (none found)'; return }
    foreach ($r in $rows | Select-Object -First 25) {
        $n = $r.SelectSingleNode('name')
        Write-Host ("  {0}  {1}" -f $r.GetAttribute('id'), $(if ($n) { $n.InnerText } else { '' }))
    }
    if ($rows.Count -gt 25) { Write-Host ("  ... and {0} more" -f ($rows.Count - 25)) }
}

Show-IdList 'Scan configs (pick one, e.g. Full and fast)' '<get_configs filter="rows=-1"/>' '//config[not(ancestor::config)]'
Show-IdList 'Scanners (pick one, usually OpenVAS Default)' '<get_scanners filter="rows=-1"/>' '//scanner[not(ancestor::scanner)]'
Show-IdList 'Port lists' '<get_port_lists filter="rows=-1"/>' '//port_list[not(ancestor::port_list)]'
Show-IdList 'Existing tasks (for Invoke-GvmJitScan -TaskId)' '<get_tasks filter="rows=-1"/>' '//task[not(ancestor::task)]'

$config = @"
@{
    # Generated by bootstrap\Initialize-GvmScanCredential.ps1 on $(Get-Date -Format 'yyyy-MM-dd')

    Identity     = '$(($ScanAccount -split '\\')[-1])'   # sAMAccountName only, no domain prefix
    CredentialId = '$credentialId'

    ScannerHost  = '$ScannerHost'
    GmpHelper    = '$GmpHelper'
    IdentityFile = '$IdentityFile'   # explicit SSH key; strongly recommended

    # Fill from the lists printed above.
    TaskId       = ''

    ReplicationDelaySeconds = 45
    PollSeconds             = 30
    MaxScanMinutes          = 300
}
"@

Show-Section 'config.psd1'
Write-Host $config

if ($OutFile) {
    # CRLF: see .gitattributes. A .ps1/.psd1 with LF endings breaks Authenticode signing.
    [IO.File]::WriteAllText($OutFile, ($config -replace "`r?`n", "`r`n"), [Text.Encoding]::UTF8)
    Write-Host "`nWritten to $OutFile" -ForegroundColor Green
    Write-Host 'Fill in TaskId, then keep this file out of version control (it is in .gitignore).'
}
