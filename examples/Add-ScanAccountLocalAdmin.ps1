<#
.SYNOPSIS
  SAMPLE -- ONE approach to authorising the JIT scan account on target machines. Not required, and
  not the only option. Read the note below before using it.

.DESCRIPTION
  ============================================================================================
  THIS IS A SAMPLE, NOT PART OF THE PRODUCT.

  Authenticated Windows scanning needs the scan account to have enough access on each target to
  read the registry remotely, enumerate installed hotfixes, query WMI and reach the admin shares.
  In practice that usually means local Administrator on the scanned hosts.

  How you grant that is YOUR decision, and it depends on your environment, your change process
  and your risk appetite. This script shows one way: add the account to the local Administrators
  group on every computer in an OU, via ADSI over SMB/RPC. Other approaches people legitimately
  prefer include:

    * Group Policy Preferences -> Local Users and Groups, with the Update action. Applies
      continuously and covers newly built machines automatically, which a one-off script does not.
    * A GPO-managed Restricted Groups policy, if you want the membership strictly enforced.
    * Scanning unauthenticated, accepting shallower results, and granting nothing at all.
    * Per-tier accounts, so one compromised credential does not reach every server.
    * Narrower rights than local admin, if you have worked out what your scan configuration
      actually needs and are prepared to maintain that.

  Whichever you choose, understand the trade-off this module does NOT remove: while a scan is
  running, the credential is live and holds that access on every target. JIT narrows the window;
  it does not eliminate it. Detect misuse as well -- see Test-ScanAccountLogons.ps1.

  DO NOT run this against machines you have not decided should be in scope, and do not point it at
  an OU containing domain controllers: local administrator on a DC is effectively Domain Admin.
  ============================================================================================

  Uses the WinNT ADSI provider, so it works over the same SMB/RPC channels the scan itself needs
  and does not require WinRM. Idempotent, supports -WhatIf, and writes a CSV of what it did.

.PARAMETER SearchBase
  OU distinguished name holding the target computers, e.g. "OU=Servers,DC=example,DC=local".

.PARAMETER Account
  The scan account in DOMAIN\user form, e.g. "EXAMPLE\gvm-scan".

.EXAMPLE
  .\Add-ScanAccountLocalAdmin.ps1 -SearchBase 'OU=Servers,DC=example,DC=local' `
      -Account 'EXAMPLE\gvm-scan' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SearchBase,
    [Parameter(Mandatory)][string]$Account,
    [string]$ReportPath = ".\local-admin-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

if ($Account -notmatch '^[^\\]+\\[^\\]+$') {
    throw "-Account must be in DOMAIN\user form, e.g. 'EXAMPLE\gvm-scan'. Got: $Account"
}
$domain, $user = $Account -split '\\', 2

$computers = @(Get-ADComputer -SearchBase $SearchBase -Filter "Enabled -eq 'true'" -Properties DNSHostName)
Write-Host "Found $($computers.Count) enabled computer(s) under $SearchBase"
if ($computers.Count -eq 0) { return }

# Hard refusal, deliberately with no override switch.
#
# On a domain controller, "local" Administrators is not local: a DC has no separate SAM for
# accounts, so its BUILTIN\Administrators IS the domain's group. Adding an account there grants
# administrative control over the directory and every DC -- domain-admin-equivalent. A script
# whose job is "grant local admin on the scan targets" would therefore quietly become "grant
# domain admin" the moment a DC appeared in the OU you pointed it at.
#
# There is no case where a scanning credential should hold that. And separately: a DC should be
# running as little software as possible, so an authenticated scan that needs administrative
# rights on one is the wrong shape of solution regardless of the privilege question. Scan DCs
# unauthenticated instead.
#
# An override flag would exist mainly to be found by someone in a hurry. This is a sample script:
# anyone who truly needs different behaviour can read the above and edit it.
$dcs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name)
$inScopeDcs = @($computers | Where-Object { $dcs -contains $_.Name })
if ($inScopeDcs.Count -gt 0) {
    throw ("Refusing to run: {0} domain controller(s) are in scope ({1}). Local administrator on a DC is equivalent to Domain Admin. Narrow -SearchBase." -f
        $inScopeDcs.Count, (($inScopeDcs | Select-Object -ExpandProperty Name) -join ', '))
}

$results = foreach ($c in $computers) {
    $target = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
    $row = [ordered]@{ Computer = $target; Action = ''; Detail = '' }

    try {
        $group = [ADSI]"WinNT://$target/Administrators,group"
        $members = @($group.Invoke('Members') | ForEach-Object {
            ([ADSI]$_).InvokeGet('Name')
        })

        if ($members -contains $user) {
            $row.Action = 'AlreadyMember'
        }
        elseif ($PSCmdlet.ShouldProcess($target, "Add $Account to local Administrators")) {
            $group.Add("WinNT://$domain/$user,user")
            $row.Action = 'Added'
        }
        else {
            $row.Action = 'WouldAdd'
        }
    }
    catch {
        $row.Action = 'Failed'
        $row.Detail = $_.Exception.Message
        Write-Warning "$target : $($_.Exception.Message)"
    }

    [pscustomobject]$row
}

$results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host "`nReport: $ReportPath"
$results | Group-Object Action | ForEach-Object { "  {0,-14} {1}" -f $_.Name, $_.Count }
