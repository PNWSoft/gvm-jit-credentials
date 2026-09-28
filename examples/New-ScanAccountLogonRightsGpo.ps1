<#
.SYNOPSIS
  Create or update a GPO that denies the scan account every logon type except network.

.DESCRIPTION
  Logon rights are per-machine local security policy, so covering every scan target means a GPO linked to
  the OUs that hold them. `Set-ScanAccountLogonRights.ps1` does one machine; this does the estate, and is
  the way most deployments will want to apply it.

  WHY THIS IS MORE THAN A FEW CMDLETS. User Rights Assignment is not registry policy, so
  Set-GPRegistryValue cannot reach it and the GroupPolicy module has no cmdlet that authors it. The
  settings live in a security template inside the GPO's SYSVOL folder, and THREE things must all hold
  before a client applies them. Each fails silently on its own:

    1. Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf carries a [Privilege Rights] section, written as
       UTF-16LE with a BOM -- the format secedit itself produces.
    2. The version is incremented in BOTH GPT.INI and the directory object's versionNumber. Clients
       compare against what they last applied and skip a GPO whose version has not moved.
    3. gPCMachineExtensionNames names the Security client-side extension, AND the groups in that
       attribute are sorted ascending by CSE GUID. MS-GPOL 2.2.4: "Group Policy processing terminates at
       the first <CSE GUIDn> out of sequence." Appending without sorting therefore silently disables
       every extension from that point on -- including this one.

  The version is one integer holding two counters: user in the high 16 bits, computer in the low 16. Only
  the computer half moves here, masked so a carry cannot reach the user half.

  SAFE BY DEFAULT. A new GPO is created UNLINKED and is linked only after verification passes, so a GPO
  that failed to author correctly is never left applying to anything. An existing GPO keeps its other
  settings: [Privilege Rights] is merged member-wise, and other sections are rewritten verbatim.

  DELIBERATELY NOT INCLUDED. A full scan-target GPO usually also sets Remote Registry to Automatic and
  grants local administrator through Group Policy Preferences. Those enable scanning rather than restrict
  the account, GPP items are not practical to author this way, and local admin has its own sample in
  Add-ScanAccountLocalAdmin.ps1. This script only takes rights away.

.PARAMETER Identity
  The scan account, DOMAIN\name. Must resolve to a domain USER: groups, computers, well-known SIDs and
  group-managed service accounts are refused, because denying these rights to any of them has a blast
  radius nobody intends. -Force overrides.

  Never point this at the RUNNER account. A scheduled task logs on as batch, so denying that right stops
  every scan. The class check refuses a gMSA outright, which is what the runner normally is.

.PARAMETER GpoName
  GPO to create or update.

.PARAMETER LinkToOU
  Distinguished name of an OU to link to, AFTER verification passes. Omit it and the GPO is left
  unlinked for you to review and link yourself.

.PARAMETER DenyRight
  Defaults to the four logon types a scan does not use. SeDenyNetworkLogonRight is refused.

.PARAMETER Force
  Allow an -Identity that is not a domain user.

.EXAMPLE
  .\New-ScanAccountLogonRightsGpo.ps1 -Identity 'EXAMPLE\gvm-scan' -WhatIf

.EXAMPLE
  .\New-ScanAccountLogonRightsGpo.ps1 -Identity 'EXAMPLE\gvm-scan' `
      -LinkToOU 'OU=Servers,DC=example,DC=local'

.NOTES
  Needs the GroupPolicy and ActiveDirectory modules and rights to create or edit a GPO and write to
  SYSVOL -- in practice a Domain Admin. Every directory and SYSVOL operation is pinned to the PDC
  emulator, so a GPO created on one DC is not then read from another that has not replicated it yet.

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
    ),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DenyRight -contains 'SeDenyNetworkLogonRight') {
    throw 'SeDenyNetworkLogonRight is the logon type authenticated scanning USES. Refusing.'
}

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

# The Security CSE, paired with its snap-in GUID, taken from a GPO known to work.
$securityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$securityCseGuid = '827D319E-6EAC-11D2-A4EA-00C04F79F83A'

# ---------------------------------------------------------------- helpers

function Add-PrivilegeRightMember {
    <#
      Adds $Sid to $Right in a security template held as a List[string], and returns what it did.

      Index-based on purpose. Doing this with -replace over a string ARRAY looks equivalent and is not:
      the first insert produces an element containing an embedded newline, which then no longer matches
      an anchored header pattern, so the second and later inserts silently do nothing while still
      reporting success.

      Member comparison is exact, not substring. '*S-1-...-1105' is a substring of '*S-1-...-11050', so a
      substring test reports "already present" for a different account and writes nothing.
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
            # Every existing member is carried across: a template REPLACES the membership of any right
            # it names, so dropping them here would silently revoke those holders.
            $Lines[$i] = "$Right = $members,*$Sid"
            return 'appended'
        }
    }
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*\[Privilege Rights\]\s*$') {   # tolerant of trailing whitespace
            $Lines.Insert($i + 1, "$Right = *$Sid")
            return 'created'
        }
    }
    $Lines.Add('[Privilege Rights]')
    $Lines.Add("$Right = *$Sid")
    return 'created'
}

function Add-SortedCseGroup {
    <#
      Adds a CSE group to a gPCMachineExtensionNames value and returns it sorted by CSE GUID.

      Sorting is a protocol requirement, not tidiness (MS-GPOL 2.2.4). Uppercased before comparison so
      ordinal and culture-aware ordering agree over the hex-and-dash character set of a GUID.
    #>
    param([string]$Existing, [Parameter(Mandatory)][string]$Group, [Parameter(Mandatory)][string]$Guid)

    $groups = @([regex]::Matches([string]$Existing, '\[[^\]]*\]') | ForEach-Object { $_.Value })
    if ($groups | Where-Object { $_ -like "*$Guid*" }) { return @{ Value = [string]$Existing; Added = $false } }
    $groups += $Group
    $sorted = $groups | Sort-Object -Property @{
        Expression = { ([regex]::Match($_, '\{[^}]*\}')).Value.ToUpperInvariant() }
    }
    return @{ Value = ($sorted -join ''); Added = $true }
}

# ---------------------------------------------------------------- principal

$sid = (New-Object Security.Principal.NTAccount($Identity)).Translate(
            [Security.Principal.SecurityIdentifier]).Value
Write-Host "$Identity resolves to $sid"

$pdc = (Get-ADDomain).PDCEmulator
$domainDn = (Get-ADDomain).DistinguishedName

if (-not $Force) {
    # A well-known SID (Everyone S-1-1-0, Administrators S-1-5-32-544, Authenticated Users S-1-5-11)
    # translates perfectly well from a name, and denying it these rights would be catastrophic across
    # every machine the GPO reaches. Domain SIDs only, and then only user objects.
    if ($sid -notmatch '^S-1-5-21-') {
        throw "$Identity resolves to the well-known SID $sid, not a domain account. Refusing (-Force overrides)."
    }
    $obj = Get-ADObject -Filter "objectSid -eq '$sid'" -Server $pdc -Properties objectClass -ErrorAction Stop
    if (-not $obj) { throw "Could not find a directory object for $sid." }
    if ($obj.ObjectClass -ne 'user') {
        throw ("$Identity is a '$($obj.ObjectClass)', not a user. Denying these rights to a group, " +
               'computer or managed service account has a blast radius nobody intends -- and a gMSA is ' +
               'normally the RUNNER, which needs batch logon. Refusing (-Force overrides).')
    }
    Write-Host "  confirmed: a domain user object on $pdc"
}

# ---------------------------------------------------------------- the GPO

$gpo = Get-GPO -Name $GpoName -Server $pdc -ErrorAction SilentlyContinue
if ($gpo) { Write-Host "using existing GPO '$GpoName' {$($gpo.Id)}" }
else {
    if (-not $PSCmdlet.ShouldProcess($GpoName, 'Create GPO (unlinked)')) { return }
    $gpo = New-GPO -Name $GpoName -Server $pdc -Comment "Denies $Identity every logon type except network (type 3), which authenticated scanning requires."
    Write-Host "created GPO '$GpoName' {$($gpo.Id)} -- UNLINKED" -ForegroundColor Green
}

$bs      = [char]92
$base    = "$bs$bs$pdc${bs}SYSVOL$bs$($gpo.DomainName)${bs}Policies$bs{$($gpo.Id)}"
$secDir  = "$base${bs}Machine${bs}Microsoft${bs}Windows NT${bs}SecEdit"
$infPath = "$secDir${bs}GptTmpl.inf"
$iniPath = "$base${bs}GPT.INI"
$gpoDn   = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDn"

# ---------------------------------------------------------------- merge the template

$lines = [System.Collections.Generic.List[string]]::new()
if (Test-Path -LiteralPath $infPath) {
    # @() so a one-line or empty file does not throw on .Count under StrictMode.
    foreach ($l in @(Get-Content -LiteralPath $infPath)) { $lines.Add([string]$l) }
}
if ($lines.Count -eq 0) {
    foreach ($l in '[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]') {
        $lines.Add($l)
    }
}

$changed = [System.Collections.Generic.List[string]]::new()
foreach ($right in $DenyRight) {
    switch (Add-PrivilegeRightMember -Lines $lines -Right $right -Sid $sid) {
        'present'  { Write-Host "  already present: $right" }
        'appended' { $changed.Add("$right : added $Identity, keeping existing members") }
        'created'  { $changed.Add("$right : created with $Identity") }
    }
}

if ($changed.Count -gt 0) { Write-Host "`nPending:"; $changed | ForEach-Object { Write-Host "  $_" } }
else { Write-Host "`nTemplate already denies every requested right to $Identity." }

if (-not $PSCmdlet.ShouldProcess("$GpoName on $pdc", 'Write template, bump version, register the Security CSE, verify')) { return }

if ($changed.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $secDir)) { New-Item -ItemType Directory -Path $secDir -Force | Out-Null }
    # UTF-16LE WITH a BOM: UnicodeEncoding($false, $true) = little-endian, emit BOM.
    [IO.File]::WriteAllLines($infPath, $lines.ToArray(), (New-Object Text.UnicodeEncoding($false, $true)))
    Write-Host "  wrote $infPath ($($lines.Count) lines)"
}

# --- version and CSE are checked and repaired UNCONDITIONALLY, not only when the template changed.
#     A previous run that died between writing the template and registering the CSE leaves a GPO that
#     can never apply; if these lived behind the "something changed" test, a rerun would print
#     "nothing to do" and leave it broken forever.
$obj = Get-ADObject -Identity $gpoDn -Server $pdc -Properties versionNumber, gPCMachineExtensionNames

$cse = Add-SortedCseGroup -Existing $obj.gPCMachineExtensionNames -Group $securityCse -Guid $securityCseGuid
if ($cse.Added) {
    Set-ADObject -Identity $gpoDn -Server $pdc -Replace @{ gPCMachineExtensionNames = $cse.Value }
    Write-Host "  registered the Security CSE, groups sorted: $($cse.Value)"
}
else { Write-Host '  Security CSE already registered' }

$curVer   = [int]$obj.versionNumber
$iniVer   = if (Test-Path -LiteralPath $iniPath) {
                $m = [regex]::Match((Get-Content -LiteralPath $iniPath -Raw), 'Version\s*=\s*(\d+)')
                if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }
            } else { -1 }

if ($changed.Count -gt 0 -or $iniVer -ne $curVer) {
    $userPart = $curVer -shr 16
    # Masked to 16 bits: without this, a computer version of 65535 carries into the USER half, claiming
    # a user-policy change that never happened. Wrapping to 0 is fine -- clients reprocess on a version
    # that DIFFERS from the one they last applied, not one that is larger.
    $compPart = ((($curVer -band 0xFFFF) + 1) -band 0xFFFF)
    $newVer   = ($userPart -shl 16) -bor $compPart
    Set-ADObject -Identity $gpoDn -Server $pdc -Replace @{ versionNumber = $newVer }
    Set-Content -LiteralPath $iniPath -Value @('[General]', "Version=$newVer") -Encoding Ascii
    Write-Host "  version $curVer -> $newVer (computer $($curVer -band 0xFFFF) -> $compPart); GPT.INI and AD agree"
}
else { Write-Host "  version $curVer already consistent between GPT.INI and the directory" }

# ---------------------------------------------------------------- verify, THEN link

Write-Host "`nVerification (from Get-GPOReport, which is what the domain will serve):"
$report = [xml](Get-GPOReport -Guid $gpo.Id -Server $pdc -ReportType Xml)
$assigned = @()
foreach ($e in $report.GPO.Computer.ExtensionData) {
    foreach ($u in @($e.Extension.UserRightsAssignment)) { if ($u) { $assigned += $u } }
}
$bad = 0
foreach ($right in $DenyRight) {
    $entry = $assigned | Where-Object { $_.Name -eq $right }
    $holds = $entry -and (@($entry.Member) | Where-Object { $_.SID.'#text' -eq $sid })
    if ($holds) { Write-Host "  OK   $right" -ForegroundColor Green }
    else { Write-Host "  MISSING $right" -ForegroundColor Red; $bad++ }
}
$net = $assigned | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }
if ($net -and (@($net.Member) | Where-Object { $_.SID.'#text' -eq $sid })) {
    Write-Host '  FAIL SeDenyNetworkLogonRight lists the account -- scanning WILL break' -ForegroundColor Red
    $bad++
}
else { Write-Host '  OK   SeDenyNetworkLogonRight does not list the account' -ForegroundColor Green }
if ($bad -gt 0) { throw "$bad verification problem(s). The GPO has NOT been linked." }

if ($LinkToOU) {
    $already = Get-GPInheritance -Target $LinkToOU -Server $pdc |
        Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    if ($already) { Write-Host "`nalready linked to $LinkToOU" }
    elseif ($PSCmdlet.ShouldProcess($LinkToOU, "Link GPO '$GpoName'")) {
        New-GPLink -Guid $gpo.Id -Target $LinkToOU -Server $pdc -LinkEnabled Yes | Out-Null
        Write-Host "`nlinked to $LinkToOU" -ForegroundColor Green
    }
}

Write-Host "`nDone." -ForegroundColor Green
if (-not $LinkToOU) {
    Write-Host 'Not linked. Link it to the OUs holding your scan targets when you are ready:' -ForegroundColor DarkGray
    Write-Host "  New-GPLink -Name '$GpoName' -Target 'OU=Servers,DC=example,DC=local'" -ForegroundColor DarkGray
}
Write-Host 'Then on a target: gpupdate /force, and confirm with gpresult /scope computer /h report.html' -ForegroundColor DarkGray
