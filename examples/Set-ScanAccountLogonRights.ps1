<#
.SYNOPSIS
  Deny the scan account every logon type except network, on the machine this runs on.

.DESCRIPTION
  An authenticated Windows scan reaches a target only over SMB and DCE-RPC, which are NETWORK logons
  (type 3). Nothing about scanning needs the account to log on at the console, over RDP, as a batch job
  or as a service -- so those four can be denied outright, leaving the one type that is actually used.

  This is defence in depth, not the primary control, and it is worth being clear about why: logging on
  interactively as this account needs the same password that a network logon needs, and the network path
  stays open because the scan needs it. So this does not stop someone who has the password. What it does
  is remove three ways to misuse the account if one is ever obtained, and -- more usefully -- make any
  interactive attempt unambiguous, which is what the account's disabled-between-scans state is meant to
  expose. The thing actually preventing misuse is still that the account is disabled with a password
  nobody holds.

  SCOPE, AND WHY A GPO IS USUALLY THE RIGHT ANSWER. Logon rights are per-machine local security policy;
  there is no Active Directory attribute that sets them, so to cover every scan target you either visit
  each machine or push a GPO to the OUs containing them. A GPO is the scalable option and the one to
  prefer. Use this script when that is not available to you, for a single host, or to verify what the
  policy on one machine actually is.

  IF A GPO ALREADY MANAGES THESE RIGHTS, IT WINS. Group Policy reapplies on its own schedule and will
  overwrite whatever this sets. Check with `gpresult /scope computer /h report.html` before assuming a
  local change stuck.

  What it will NOT do: add the account to "Deny access to this computer from the network". That is the
  one right that would break authenticated scanning, and the script refuses to touch it and verifies
  afterwards that the account is not in it.

.PARAMETER Identity
  The scan account, as DOMAIN\name. Resolved to a SID, because local policy stores SIDs and a name is
  the wrong thing to write into it.

  Point this at the SCAN account, never at the RUNNER. A scheduled task running as the runner logs on as
  BATCH (type 4), so denying it SeDenyBatchLogonRight stops the scan from starting at all. The script
  cannot tell the two apart: it denies the rights to whichever account you name.

.PARAMETER DenyRight
  Which rights to add the account to. The default is the four logon types a scan does not use. Passing
  SeDenyNetworkLogonRight is refused.

.EXAMPLE
  .\Set-ScanAccountLogonRights.ps1 -Identity 'EXAMPLE\gvm-scan' -WhatIf

.EXAMPLE
  .\Set-ScanAccountLogonRights.ps1 -Identity 'EXAMPLE\gvm-scan'

.NOTES
  Run elevated. Idempotent: an account already holding a right is left alone, and existing members of
  each right are preserved -- secedit REPLACES the membership of any right named in the file it imports,
  so dropping the others would be a silent way to break a machine.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [switch]$Force,
    # Validated, not just defaulted. These names are interpolated into a regex that finds the line to
    # edit, so a stray space ('SeDenyNetworkLogonRight ') would slip past the -contains refusal below
    # while still matching -- and writing -- the one right that must never be denied. secedit applies it
    # before the verification pass notices, and nothing rolls that back.
    [ValidatePattern('^Se[A-Za-z]+(Right|Privilege)$')]
    [string[]]$DenyRight = @(
        'SeDenyInteractiveLogonRight',        # Deny log on locally
        'SeDenyRemoteInteractiveLogonRight',  # Deny log on through Remote Desktop Services
        'SeDenyBatchLogonRight',              # Deny log on as a batch job
        'SeDenyServiceLogonRight'             # Deny log on as a service
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The one right that would break scanning. Refused rather than documented, because a caller who passes
# it has misunderstood something and a warning is easy to miss.
if ($DenyRight -contains 'SeDenyNetworkLogonRight') {
    throw 'SeDenyNetworkLogonRight is the logon type authenticated scanning USES. Refusing.'
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this elevated: editing local security policy needs administrator.'
}

$sidObj = (New-Object Security.Principal.NTAccount($Identity)).Translate(
            [Security.Principal.SecurityIdentifier])
$sid = $sidObj.Value
Write-Host "$Identity resolves to $sid"

if (-not $Force) {
    # 'Everyone' (S-1-1-0), 'BUILTIN\Administrators' (S-1-5-32-544) and 'Authenticated Users' (S-1-5-11)
    # all translate perfectly well from a name. Denying them these rights would lock this machine's
    # administrators out of it.
    if ($sid -notmatch '^S-1-5-21-') {
        throw "$Identity resolves to the well-known SID $sid, not a domain account. Refusing (-Force overrides)."
    }

    # The prefix test above does NOT mean "a domain account". A LOCAL account has an S-1-5-21-<machine>
    # SID too, so 'THISHOST\Administrator' sails through it -- measured, not assumed. Denying interactive
    # and RDP logon to this machine's own Administrator is the worst outcome this script can produce, so
    # compare against the machine's own account domain.
    #
    # The machine SID is read from whichever local account comes back first, and NOT by translating the
    # name 'Administrator': that account is renamed on any CIS- or STIG-hardened host, and naming it made
    # this guard throw IdentityNotMappedException and abort the whole script -- on precisely the machines
    # most likely to run it. A guard whose failure mode is "operator reaches for -Force" is worse than no
    # guard, because -Force switches off the object-class and RID checks too. So this degrades to a
    # warning when it cannot answer, and never blocks on its own failure.
    #
    # Skipped outright on a domain controller, where there is no separate local account database: the
    # comparison would equal the DOMAIN SID and refuse every legitimate domain account.
    $localDomainSid = $null
    $isDc = $false
    # -OperationTimeoutSec so a wedged WMI repository becomes the warn-and-skip path below rather than a
    # script that hangs before doing anything. The guard degrades on error; it must degrade on silence too.
    try { $isDc = ((Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop).DomainRole -ge 4) }
    catch {
        # Not fatal: $isDc stays false, and the local-account check below either answers or warns. It is
        # reported at Verbose rather than as a warning because a member server -- the normal case -- is
        # what the default already assumes.
        Write-Verbose "could not read DomainRole, assuming this is not a domain controller: $($_.Exception.Message)"
    }
    if (-not $isDc) {
        try {
            # The LocalAccount=True filter is what keeps this off the domain-wide enumeration that makes
            # an unfiltered Win32_UserAccount query notorious for hanging on a domain member.
            $anyLocal = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' `
                            -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
            if ($anyLocal) {
                $localDomainSid = ([Security.Principal.SecurityIdentifier]$anyLocal.SID).AccountDomainSid.Value
            }
        }
        catch { Write-Warning "  could not read this machine's SID: $($_.Exception.Message)" }
    }
    if ($isDc) {
        Write-Warning '  this host is a domain controller; skipping the local-account check'
    }
    elseif (-not $localDomainSid) {
        Write-Warning '  could not determine this machine''s SID; skipping the local-account check'
    }
    elseif ($sidObj.AccountDomainSid.Value -eq $localDomainSid) {
        throw ("$Identity is a LOCAL account on this machine ($sid), not a domain account. Denying it " +
               'these rights can lock this host out of its own administration. Refusing (-Force overrides).')
    }

    # RID 500 is the built-in Administrator, local or domain. Anchored on the hyphen so it cannot match
    # -1500 or -5000.
    if ($sid -match '-500$') {
        throw "$Identity is a built-in Administrator account (RID 500). Refusing (-Force overrides)."
    }

    # Best effort, and only best effort: this script must still work on a host that cannot reach a DC at
    # this moment. It catches a domain GROUP or a managed service account, which no SID test can.
    #
    # The three outcomes are kept distinct deliberately. A serverless LDAP bind that cannot reach a DC
    # returns an EMPTY SchemaClassName rather than throwing -- measured -- so folding "unknown" in with
    # "confirmed" would print 'confirmed: a domain user object' about an object nobody looked at, and the
    # catch below would be dead code.
    $cls = ''
    try { $cls = [string]([ADSI]"LDAP://<SID=$sid>").SchemaClassName }
    catch { Write-Warning "  could not query the object class: $($_.Exception.Message)" }

    if ($cls -eq 'user') { Write-Host '  confirmed: a domain user object' }
    elseif (-not $cls) {
        Write-Warning '  could not confirm the object class (no answer from a DC); continuing on the SID alone'
    }
    else {
        throw ("$Identity is a '$cls', not a user. Denying these rights to a group or managed " +
               'service account has a blast radius nobody intends -- and a gMSA is normally the ' +
               'RUNNER, which needs batch logon. Refusing (-Force overrides).')
    }
}

function Add-PrivilegeRightMember {
    <#
      Adds $Sid to $Right in a List[string] holding a security template, returning what it did.

      Index-based, and exact on membership, for two reasons learnt the hard way. Editing a string ARRAY
      with -replace makes the first insert produce an element with an embedded newline, after which an
      anchored header pattern no longer matches it and later inserts silently do nothing. And a substring
      test for the SID reports "already present" when an existing member merely STARTS with it --
      '*S-1-...-1105' is a substring of '*S-1-...-11050' -- so nothing gets written.
    #>
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Lines,
        [Parameter(Mandatory)][string]$Right,
        [Parameter(Mandatory)][string]$Sid
    )
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match "^\s*$([regex]::Escape($Right))\s*=\s*(.*)$") {
            $members = $Matches[1].Trim()
            # Empty entries dropped before rebuilding, so a right present with no members
            # ('SeDenyBatchLogonRight = ') does not produce a leading comma that secedit may reject.
            $have = @($members -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (@($have | ForEach-Object { $_.TrimStart('*') }) -contains $Sid) { return 'present' }
            # Existing members are carried across: a template REPLACES the membership of any right it
            # names, so dropping them would silently revoke those holders.
            $Lines[$i] = "$Right = " + (@($have + "*$Sid") -join ',')
            return 'appended'
        }
    }
    $Lines.Add("$Right = *$Sid")
    return 'created'
}

function Export-UserRightsPolicy {
    param([string]$Path)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & secedit /export /areas USER_RIGHTS /cfg $Path 2>&1 }
    finally { $ErrorActionPreference = $prevEap }
    if (-not (Test-Path -LiteralPath $Path)) { throw "secedit /export produced nothing: $out" }
    # secedit writes UTF-16. Reading is fine either way; WRITING it back as anything else produces a
    # file secedit silently declines to apply, which looks like the change being ignored.
    Get-Content -LiteralPath $Path
}

$inf = Join-Path ([IO.Path]::GetTempPath()) "gvmjit-rights-$([guid]::NewGuid()).inf"
$sdb = [IO.Path]::ChangeExtension($inf, 'sdb')
$log = [IO.Path]::ChangeExtension($inf, 'log')

try {
    $exported = Export-UserRightsPolicy -Path $inf

    # A MINIMAL template is submitted, holding only the four target rights with their full current
    # membership -- not the whole export. secedit /export lists every right as the EFFECTIVE policy, so
    # re-importing it would bake rights currently granted by a GPO into local policy, where they then
    # survive that GPO's removal. Applying only what is being changed avoids that side effect entirely.
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($l in '[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]') {
        $lines.Add($l)
    }
    foreach ($right in $DenyRight) {
        $rx = "^\s*$([regex]::Escape($right))\s*="
        $cur = @($exported) | Where-Object { $_ -match $rx } | Select-Object -First 1
        if ($cur) { $lines.Add(($cur -replace '^\s+', '')) }
    }

    $changes = [System.Collections.Generic.List[string]]::new()
    foreach ($right in $DenyRight) {
        switch (Add-PrivilegeRightMember -Lines $lines -Right $right -Sid $sid) {
            'present'  { Write-Host "  already set: $right" }
            'appended' { $changes.Add("$right : added $Identity, keeping existing members") }
            'created'  { $changes.Add("$right : created with $Identity") }
        }
    }

    if ($changes.Count -eq 0) {
        Write-Host "`nNothing to do: $Identity already holds every requested deny right." -ForegroundColor Green
        return
    }

    Write-Host "`nPending:"
    $changes | ForEach-Object { Write-Host "  $_" }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply $($changes.Count) user-rights change(s)")) { return }

    Set-Content -LiteralPath $inf -Value $lines.ToArray() -Encoding Unicode
    # EAP localised to Continue: in 5.1 a native command writing to stderr raises a terminating
    # NativeCommandError under 'Stop', which would abort before the exit code and the log tail below --
    # the two things that say what went wrong.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /log $log /quiet 2>&1 }
    finally { $ErrorActionPreference = $prevEap }
    if ($LASTEXITCODE -ne 0) {
        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" } }
        throw "secedit /configure exited $LASTEXITCODE. $out"
    }

    # Verify from a FRESH export, not from the file that was submitted: the check has to read what the
    # system now believes, not what was asked for.
    $verify = Join-Path ([IO.Path]::GetTempPath()) "gvmjit-verify-$([guid]::NewGuid()).inf"
    try {
        $after = Export-UserRightsPolicy -Path $verify
        Write-Host "`nVerification:"
        $bad = 0
        foreach ($right in $DenyRight) {
            $rx = "^\s*$([regex]::Escape($right))\s*=\s*(.*)$"
            $line = $after | Where-Object { $_ -match $rx } | Select-Object -First 1
            $holds = $false
            if ($line -and $line -match $rx) {
                # Exact member comparison, for the same reason as the merge above.
                $holds = @($Matches[1] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }) -contains $sid
            }
            if ($holds) { Write-Host "  OK   $right" -ForegroundColor Green }
            else { Write-Host "  FAIL $right does not list $Identity" -ForegroundColor Red; $bad++ }
        }
        # The invariant that matters more than any of the above.
        $net = $after | Where-Object { $_ -match '^\s*SeDenyNetworkLogonRight\s*=\s*(.*)$' } | Select-Object -First 1
        $netHolds = $false
        if ($net -and $net -match '^\s*SeDenyNetworkLogonRight\s*=\s*(.*)$') {
            $netHolds = @($Matches[1] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }) -contains $sid
        }
        if ($netHolds) {
            Write-Host '  FAIL SeDenyNetworkLogonRight now lists the account -- scanning WILL break' -ForegroundColor Red
            $bad++
        }
        else { Write-Host '  OK   SeDenyNetworkLogonRight does not list the account' -ForegroundColor Green }
        if ($bad -gt 0) { throw "$bad verification failure(s)." }
    }
    finally { Remove-Item -LiteralPath $verify -Force -ErrorAction SilentlyContinue }

    Write-Host "`nDone on $env:COMPUTERNAME." -ForegroundColor Green
    Write-Host 'If a GPO manages these rights, it will overwrite this at the next refresh.' -ForegroundColor DarkGray
}
finally {
    foreach ($f in $inf, $sdb, $log) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
}
