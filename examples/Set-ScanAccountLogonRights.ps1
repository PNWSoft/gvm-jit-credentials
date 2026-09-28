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

$sid = (New-Object Security.Principal.NTAccount($Identity)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
Write-Host "$Identity resolves to $sid"

if (-not $Force) {
    # 'Everyone' (S-1-1-0), 'BUILTIN\Administrators' (S-1-5-32-544) and 'Authenticated Users' (S-1-5-11)
    # all translate perfectly well from a name. Denying them these rights would lock this machine's
    # administrators out of it. Domain SIDs only.
    if ($sid -notmatch '^S-1-5-21-') {
        throw "$Identity resolves to the well-known SID $sid, not a domain account. Refusing (-Force overrides)."
    }
    # Best effort, and only best effort: this script must still work on a host that cannot reach a DC at
    # this moment. The prefix test above already covers the dangerous well-known SIDs; this catches a
    # domain GROUP or a managed service account, which the prefix test cannot.
    try {
        $cls = ([ADSI]"LDAP://<SID=$sid>").SchemaClassName
        if ($cls -and $cls -ne 'user') {
            throw ("$Identity is a '$cls', not a user. Denying these rights to a group or managed " +
                   'service account has a blast radius nobody intends -- and a gMSA is normally the ' +
                   'RUNNER, which needs batch logon. Refusing (-Force overrides).')
        }
        Write-Host '  confirmed: a domain user object'
    }
    catch [System.Management.Automation.RuntimeException] { throw }
    catch { Write-Warning "  could not confirm the object class ($($_.Exception.Message)); continuing on the SID prefix alone" }
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
        if ($Lines[$i] -match "^\s*$Right\s*=\s*(.*)$") {
            $members = $Matches[1].Trim()
            $have = @($members -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
            if ($have -contains $Sid) { return 'present' }
            # Existing members are carried across: a template REPLACES the membership of any right it
            # names, so dropping them would silently revoke those holders.
            $Lines[$i] = "$Right = $members,*$Sid"
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
        $cur = @($exported) | Where-Object { $_ -match "^\s*$right\s*=" } | Select-Object -First 1
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
            $line = $after | Where-Object { $_ -match "^\s*$right\s*=\s*(.*)$" } | Select-Object -First 1
            $holds = $false
            if ($line -and $line -match "^\s*$right\s*=\s*(.*)$") {
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
