<#
.SYNOPSIS
  Creates the AD scan account (disabled) and delegates just enough rights to the runner account.

.DESCRIPTION
  Sets up the Active Directory half of the JIT model:

    * a dedicated scan account, created DISABLED, with a password nobody records
    * delegation so the runner account can reset its password and write userAccountControl, on that
      one object only. Note that userAccountControl carries the enabled bit but also other account
      flags (DONT_REQUIRE_PREAUTH, PASSWD_NOTREQD and so on), so the runner can set those on this
      object too. That is strictly weaker than the password-reset right it already holds, but it is
      more than "enable and disable" and worth knowing.

  The delegation is the point. The runner needs to rotate one account's password on demand, which is
  a privileged-sounding capability; granting it against a single object keeps it from being a
  general-purpose one. The runner is NOT made a Domain Admin, and must not be.

  The scan account is created disabled and stays disabled between scans. It is never added to any
  privileged group here. Granting it the access it needs ON TARGETS is a separate decision you have
  to make for your environment -- see examples/Add-ScanAccountLocalAdmin.ps1 for one approach among
  several, and read the note at the top of it before using it.

.PARAMETER Identity
  sAMAccountName for the new scan account, e.g. "gvm-scan".

.PARAMETER Path
  OU distinguished name to create it in, e.g. "OU=Service Accounts,DC=example,DC=local".

.PARAMETER RunnerAccount
  The account your scheduled task runs as, which will be delegated rights over the scan account.
  For a group-managed service account include the trailing $, e.g. "EXAMPLE\gvm-runner$".

.EXAMPLE
  .\Initialize-GvmScanAccount.ps1 -Identity gvm-scan `
      -Path 'OU=Service Accounts,DC=example,DC=local' -RunnerAccount 'EXAMPLE\gvm-runner$' -WhatIf
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'New-ADUser requires -AccountPassword as a SecureString, and the value is generated here as plaintext by New-EphemeralPassword. It is discarded immediately and never recorded: the account is created disabled and the password is replaced at the first grant.')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$RunnerAccount,
    [string]$DisplayName = 'Greenbone JIT scan account',
    [string]$EventLogSource = 'GvmJitCredential'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module (Join-Path $PSScriptRoot '..\GvmJitCredential\GvmJitCredential.psd1') -Force

$pdc = (Get-ADDomainController -Discover -Service PrimaryDC).HostName[0]
Write-Host "Using domain controller: $pdc"

# --- 1) the scan account, disabled, with an unrecorded password
$existing = Get-ADUser -Filter "SamAccountName -eq '$Identity'" -Server $pdc -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  account '$Identity' already exists at $($existing.DistinguishedName)" -ForegroundColor Yellow
    $account = $existing
}
elseif ($PSCmdlet.ShouldProcess($Identity, 'Create disabled AD scan account')) {
    $module = Get-Module GvmJitCredential
    $initial = & $module { New-EphemeralPassword -Length 32 }
    # -AccountNotDelegated sets "Account is sensitive and cannot be delegated" (the NOT_DELEGATED bit in
    # userAccountControl). This account holds local administrator on every target, so its Kerberos
    # ticket must not be forwardable by a service it authenticates to -- otherwise compromising any one
    # of those services lets an attacker impersonate it onward to the rest. It costs nothing here,
    # because nothing legitimately delegates on this account's behalf.
    #
    # NOTE: do not put a comment between these backtick-continued lines. It parses, and then silently
    # ENDS the command -- every parameter after the comment is dropped, which the CI parse gate cannot
    # see. That is how this very parameter, and -Description, went missing once.
    New-ADUser -Name $Identity -SamAccountName $Identity -DisplayName $DisplayName `
        -Path $Path -Server $pdc `
        -AccountPassword (ConvertTo-SecureString $initial -AsPlainText -Force) `
        -Enabled $false `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -AccountNotDelegated $true `
        -Description 'Disabled between scans. Password rotated per scan by GvmJitCredential. Do NOT add to privileged groups.'
    Remove-Variable initial
    $account = Get-ADUser -Filter "SamAccountName -eq '$Identity'" -Server $pdc
    Write-Host "  created '$Identity' (DISABLED)" -ForegroundColor Green
    Write-Host '  -CannotChangePassword does not block rotation: that flag stops the USER changing' -ForegroundColor DarkGray
    Write-Host '  their own password; the module uses an administrative reset, which is unaffected.' -ForegroundColor DarkGray
    Write-Host '  marked sensitive and cannot be delegated, so its ticket is not forwardable by a' -ForegroundColor DarkGray
    Write-Host '  service it authenticates to.' -ForegroundColor DarkGray
}
else { return }

# --- 2) delegate enable/disable + password reset on that one object
$runner = $null
try { $runner = New-Object System.Security.Principal.NTAccount($RunnerAccount) | ForEach-Object { $_.Translate([System.Security.Principal.SecurityIdentifier]) } }
catch { throw "Could not resolve '$RunnerAccount' to a SID. For a gMSA remember the trailing '$'." }

if ($PSCmdlet.ShouldProcess($account.DistinguishedName, "Delegate password reset and enable/disable to $RunnerAccount")) {
    # The AD: drive binds to the ActiveDirectory module's own default DC, NOT to $pdc. In a
    # multi-DC domain the object we just created has usually not replicated there yet, so Get-Acl
    # fails with "Cannot find path" and the delegation is silently never applied -- every later
    # Grant then fails with access denied, far from the cause. Bind a drive to $pdc explicitly.
    $driveName = 'GvmJitPdc'
    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $driveName -Force }
    $null = New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Server $pdc -Root '' -Scope Script
    try {
        $adPath = "${driveName}:\$($account.DistinguishedName)"
        $acl = Get-Acl -Path $adPath

    # Reset Password is an extended right, identified by this well-known GUID.
    $resetPassword = [guid]'00299570-246d-11d0-a768-00aa006e0529'
    # userAccountControl carries the enabled/disabled bit; writing that property is what
    # Enable-ADAccount / Disable-ADAccount actually do.
    $userAccountControl = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
    # WriteProperty on pwdLastSet is deliberately NOT granted. It is only needed to force
    # "user must change password at next logon", which an administrative -Reset does not do:
    # the DC maintains pwdLastSet itself. The Delegation Wizard grants it as part of its
    # "reset password" task; this script aims at the minimum instead.

    $rules = @(
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $runner, 'ExtendedRight', 'Allow', $resetPassword, 'None')
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $runner, 'WriteProperty', 'Allow', $userAccountControl, 'None')
    )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
        Set-Acl -Path $adPath -AclObject $acl
        Write-Host "  delegated to $RunnerAccount on this object only" -ForegroundColor Green
    }
    finally {
        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
    }
}

# --- 3) the event log source, so the low-privilege runner can write the audit trail
if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
    if ($PSCmdlet.ShouldProcess($EventLogSource, 'Create Application event log source')) {
        # Registering a source needs admin rights, which the runner deliberately lacks. Create it
        # here, once, so the runner can write to it later without them.
        New-EventLog -LogName Application -Source $EventLogSource
        Write-Host "  created event log source '$EventLogSource'" -ForegroundColor Green
    }
}
else { Write-Host "  event log source '$EventLogSource' already present" -ForegroundColor Yellow }
Write-Host '  NOTE: the event log source is machine-local. If you ran this bootstrap somewhere' -ForegroundColor Yellow
Write-Host '  other than the RUNNER host, create it there too, or the audit trail for each run goes' -ForegroundColor Yellow
Write-Host '  to the task log only. The module warns once per run when the source is missing, so it' -ForegroundColor Yellow
Write-Host "  is visible rather than silent: New-EventLog -LogName Application -Source '$EventLogSource'" -ForegroundColor Yellow

Write-Host @"

Next:
  1. On the scanner host as root: create the Linux RELAY account the runner will SSH in as -- it is
     not this AD scan account, which never logs in there -- run host/install.sh
     (RELAY_ACCOUNT=<that account>), and fill in .gmp.env with a DEDICATED low-privilege GMP user that
     you create in Greenbone yourself. Quote the password in that file; it is sourced by /bin/sh.
  2. Give the RUNNER account an SSH key to that Linux account, and populate the RUNNER account's
     known_hosts -- not yours. With BatchMode, ssh gives no prompt and exits 255 on an unknown host
     key. For a gMSA that usually means generating the key from a one-shot scheduled task running as
     the gMSA, since you cannot log on as it.
  3. Run bootstrap\Initialize-GvmScanCredential.ps1 to create the Greenbone credential object. It
     talks to the scanner over the SSH path from step 2, so do that first.
  4. Decide how the scan account gets the access it needs ON TARGETS. Authenticated Windows scans
     need local administrator on each scanned host. See examples/Add-ScanAccountLocalAdmin.ps1 for
     one approach; it is NOT the only one, and the choice is yours.
  5. Register the scan task AND the backstop task: see examples\.
"@
