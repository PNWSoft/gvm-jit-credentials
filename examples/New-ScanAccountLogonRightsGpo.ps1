<#
.SYNOPSIS
  Create or update a GPO that denies the scan account every logon type except network.

.DESCRIPTION
  Logon rights are per-machine local security policy, so covering every scan target means a GPO linked
  to the OUs that hold them. `Set-ScanAccountLogonRights.ps1` does one machine; this does the estate.

  WHY THIS IS MORE THAN A FEW CMDLETS. User Rights Assignment is not registry-based policy, so
  Set-GPRegistryValue cannot touch it. The settings live in a Security template inside the GPO's SYSVOL
  folder, and three things must all be true before a client will apply them:

    1. Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf contains a [Privilege Rights] section, written
       as UTF-16LE **with a BOM**. Written as UTF-8 or ASCII it is ignored, silently.
    2. The GPO's version is incremented, in BOTH GPT.INI and the directory object's versionNumber, or
       clients decide they already have the current version and skip it.
    3. gPCMachineExtensionNames names the Security client-side extension. Without it the CSE is never
       invoked and the template is never read -- this is the step most hand-rolled attempts miss.

  The version is one integer holding two counters: user in the high 16 bits, computer in the low 16.
  Only the computer half moves here.

  SAFE BY DEFAULT. A new GPO is created UNLINKED, so nothing takes effect until you link it yourself or
  pass -LinkToOU. An existing GPO's other settings are preserved: the [Privilege Rights] section is
  merged, not replaced, and every other section of the template is left alone.

  DELIBERATELY NOT INCLUDED. The GPO in the deployment this came from also sets Remote Registry to
  Automatic and grants local administrator via Group Policy Preferences. Those enable scanning rather
  than restrict the account, they are separate decisions, and local admin has its own sample in
  Add-ScanAccountLocalAdmin.ps1. This script only takes rights away.

.PARAMETER Identity
  The scan account, DOMAIN\name. Point this at the SCAN account, never the RUNNER: a scheduled task logs
  on as batch, so denying that right would stop the scan from starting.

.PARAMETER GpoName
  GPO to create or update.

.PARAMETER LinkToOU
  Optional distinguished name of an OU to link the GPO to. Omit it and the GPO is created unlinked,
  which is the safer default: review it, then link it when you are ready.

.PARAMETER DenyRight
  Defaults to the four logon types a scan does not use. SeDenyNetworkLogonRight is refused, because that
  is the one an authenticated scan needs.

.EXAMPLE
  .\New-ScanAccountLogonRightsGpo.ps1 -Identity 'EXAMPLE\gvm-scan' -WhatIf

.EXAMPLE
  .\New-ScanAccountLogonRightsGpo.ps1 -Identity 'EXAMPLE\gvm-scan' `
      -LinkToOU 'OU=Servers,DC=example,DC=local'

.NOTES
  Needs the GroupPolicy and ActiveDirectory modules, and rights to create or edit a GPO and write to
  SYSVOL -- in practice a Domain Admin or an explicitly delegated equivalent.

  Run it from a session that can reach a DC directly. Over SSH, LDAP fails with 0x80072020 because the
  session holds no delegatable ticket; a one-shot scheduled task is the usual way around that.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [string]$GpoName = 'Scan account logon restrictions',
    [string]$LinkToOU,
    [string[]]$DenyRight = @(
        'SeDenyInteractiveLogonRight',        # Deny log on locally
        'SeDenyRemoteInteractiveLogonRight',  # Deny log on through Remote Desktop Services
        'SeDenyBatchLogonRight',              # Deny log on as a batch job
        'SeDenyServiceLogonRight'             # Deny log on as a service
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DenyRight -contains 'SeDenyNetworkLogonRight') {
    throw 'SeDenyNetworkLogonRight is the logon type authenticated scanning USES. Refusing.'
}

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# The Security CSE, paired with its snap-in GUID. Taken from a GPO known to work rather than from
# memory; a client ignores the template entirely if this is absent.
$securityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

$sid = (New-Object Security.Principal.NTAccount($Identity)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
Write-Host "$Identity resolves to $sid"

# --- the GPO
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($gpo) { Write-Host "using existing GPO '$GpoName' {$($gpo.Id)}" }
else {
    if (-not $PSCmdlet.ShouldProcess($GpoName, 'Create GPO')) { return }
    $gpo = New-GPO -Name $GpoName -Comment "Denies $Identity every logon type except network (type 3), which authenticated scanning requires."
    Write-Host "created GPO '$GpoName' {$($gpo.Id)} -- UNLINKED" -ForegroundColor Green
}

$domain = $gpo.DomainName
$bs     = [char]92
$base   = "$bs$bs$domain${bs}SYSVOL$bs$domain${bs}Policies$bs{$($gpo.Id)}"
$secDir = "$base${bs}Machine${bs}Microsoft${bs}Windows NT${bs}SecEdit"
$infPath = "$secDir${bs}GptTmpl.inf"
$iniPath = "$base${bs}GPT.INI"

# --- merge [Privilege Rights], preserving every other section and every other member of each right
$existing = if (Test-Path -LiteralPath $infPath) { Get-Content -LiteralPath $infPath } else { @() }
if ($existing.Count -eq 0) {
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
}
else { $lines = @($existing) }

if (-not ($lines -match '^\[Privilege Rights\]')) { $lines += '[Privilege Rights]' }

$changed = [System.Collections.Generic.List[string]]::new()
foreach ($right in $DenyRight) {
    $line = $lines | Where-Object { $_ -match "^\s*$right\s*=" } | Select-Object -First 1
    if (-not $line) {
        $lines = $lines -replace '^(\[Privilege Rights\])$', "`$1`r`n$right = *$sid"
        $changed.Add("$right : created with $Identity")
    }
    elseif ($line -match [regex]::Escape($sid)) { Write-Host "  already present: $right" }
    else {
        # Append. A Security template REPLACES the membership of any right it names, so the existing
        # members have to be carried across or they are silently revoked.
        $lines = $lines -replace ("^(\s*$right\s*=\s*.*)$"), "`$1,*$sid"
        $changed.Add("$right : added $Identity")
    }
}

if ($changed.Count -eq 0 -and (Test-Path -LiteralPath $infPath)) {
    Write-Host "`nNothing to change: the GPO already denies all requested rights to $Identity." -ForegroundColor Green
    if (-not $LinkToOU) { return }
}
else {
    Write-Host "`nPending:"; $changed | ForEach-Object { Write-Host "  $_" }
}

if (-not $PSCmdlet.ShouldProcess("$GpoName in $domain", "Write GptTmpl.inf, bump version, register the Security CSE")) { return }

if ($changed.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $secDir)) { New-Item -ItemType Directory -Path $secDir -Force | Out-Null }
    # UTF-16LE WITH a BOM. UnicodeEncoding($false, $true) = little-endian, emit BOM. Anything else and
    # the client reads no settings and reports no error.
    [IO.File]::WriteAllLines($infPath, $lines, (New-Object Text.UnicodeEncoding($false, $true)))
    Write-Host "  wrote $infPath"

    # --- version: one integer, user in the high 16 bits, computer in the low 16. Bump the computer half.
    $dn  = "CN={$($gpo.Id)},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"
    $obj = Get-ADObject -Identity $dn -Properties versionNumber, gPCMachineExtensionNames
    $cur      = [int]($obj.versionNumber)
    $userPart = $cur -shr 16
    # Masked back to 16 bits: at a computer version of 65535 the increment would otherwise carry into
    # the USER half, reporting a user-policy change that never happened and resetting the computer half
    # to 0 as a side effect. Wrapping within the field is correct -- the value still DIFFERS from what
    # clients cached, which is what makes them reprocess.
    $compPart = ((($cur -band 0xFFFF) + 1) -band 0xFFFF)
    $new      = ($userPart -shl 16) -bor $compPart
    Set-ADObject -Identity $dn -Replace @{ versionNumber = $new }
    Set-Content -LiteralPath $iniPath -Value @('[General]', "Version=$new") -Encoding Ascii
    Write-Host "  version $cur -> $new (computer $($cur -band 0xFFFF) -> $compPart)"

    # --- register the Security CSE if it is not already there
    $ext = [string]$obj.gPCMachineExtensionNames
    if ($ext -notmatch '827D319E-6EAC-11D2-A4EA-00C04F79F83A') {
        $ext = if ($ext) { $ext + $securityCse } else { $securityCse }
        Set-ADObject -Identity $dn -Replace @{ gPCMachineExtensionNames = $ext }
        Write-Host '  registered the Security client-side extension'
    }
    else { Write-Host '  Security CSE already registered' }
}

# --- optional link
if ($LinkToOU) {
    $already = Get-GPInheritance -Target $LinkToOU |
        Select-Object -ExpandProperty GpoLinks |
        Where-Object { $_.DisplayName -eq $GpoName }
    if ($already) { Write-Host "  already linked to $LinkToOU" }
    elseif ($PSCmdlet.ShouldProcess($LinkToOU, "Link GPO '$GpoName'")) {
        New-GPLink -Guid $gpo.Id -Target $LinkToOU -LinkEnabled Yes | Out-Null
        Write-Host "  linked to $LinkToOU" -ForegroundColor Green
    }
}

# --- verify from the report the domain will actually serve, not from what was written
Write-Host "`nVerification (from Get-GPOReport):"
$report = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
$assigned = @()
foreach ($n in $report.GPO.Computer.ExtensionData.Extension.UserRightsAssignment) {
    if ($n) { $assigned += $n }
}
$bad = 0
foreach ($right in $DenyRight) {
    $entry = $assigned | Where-Object { $_.Name -eq $right }
    $holds = $entry -and (@($entry.Member) | Where-Object { $_.SID.'#text' -eq $sid -or $_.Name.'#text' -like "*$($Identity.Split('\')[-1])*" })
    if ($holds) { Write-Host "  OK   $right" -ForegroundColor Green }
    else { Write-Host "  MISSING $right" -ForegroundColor Red; $bad++ }
}
$net = $assigned | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }
if ($net -and (@($net.Member) | Where-Object { $_.SID.'#text' -eq $sid })) {
    Write-Host '  FAIL SeDenyNetworkLogonRight lists the account -- scanning WILL break' -ForegroundColor Red
    $bad++
}
else { Write-Host '  OK   SeDenyNetworkLogonRight does not list the account' -ForegroundColor Green }
if ($bad -gt 0) { throw "$bad verification problem(s)." }

Write-Host "`nDone." -ForegroundColor Green
if (-not $LinkToOU) {
    Write-Host 'The GPO is not linked. Link it to the OUs holding your scan targets when you are ready:' -ForegroundColor DarkGray
    Write-Host "  New-GPLink -Name '$GpoName' -Target 'OU=Servers,DC=example,DC=local'" -ForegroundColor DarkGray
}
Write-Host 'Then on a target: gpupdate /force, and check with gpresult /scope computer /h report.html' -ForegroundColor DarkGray
