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

  TWO THINGS ABOUT USER RIGHTS THAT SURPRISE PEOPLE, both demonstrated live while building this script.

    They do not MERGE across GPOs. Every other Group Policy setting you are used to either merges or is
    simply won by the highest-precedence GPO for that one setting. A user right is won as a WHOLE LIST:
    the winning GPO's membership for, say, SeDenyBatchLogonRight replaces every other GPO's membership
    for it. Linking a second GPO that sets these four rights took an already-restricted scan account
    from 4 deny rights to 0. If a GPO here already sets any of these rights, add the account to THAT
    GPO instead of creating a second one. This script checks for that before it links, and says so.

    They TATTOO. Unlinking or deleting the GPO does not give the rights back. The setting is written into
    each machine's local security database and stays there until some GPO overwrites it, so a removed
    GPO leaves its last state in place indefinitely. To undo a deny right, empty the membership in the
    GPO that set it and let that apply -- do not just delete the GPO.

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
    # Validated, not just defaulted. These names are interpolated into a regex that finds the line to
    # edit, so a stray space ('SeDenyNetworkLogonRight ') would slip past the -contains refusal below
    # while still matching -- and writing -- the one right that must never be denied.
    [ValidatePattern('^Se[A-Za-z]+(Right|Privilege)$')]
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
        if ($Lines[$i] -match "^\s*$([regex]::Escape($Right))\s*=\s*(.*)$") {
            $members = $Matches[1].Trim()
            # Empty entries dropped before rebuilding. A right present with NO members --
            # 'SeDenyBatchLogonRight = ' -- is exactly what the docs tell an operator to write to undo a
            # deny right, and joining onto it blindly produces a leading comma, which GPMC renders fine
            # while the client-side extension may reject the whole line.
            $have = @($members -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (@($have | ForEach-Object { $_.TrimStart('*') }) -contains $Sid) { return 'present' }
            # Every existing member is carried across: a template REPLACES the membership of any right
            # it names, so dropping them here would silently revoke those holders.
            $Lines[$i] = "$Right = " + (@($have + "*$Sid") -join ',')
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

function Get-ReportUserRight {
    <#
      Reads every User Rights Assignment out of a Get-GPOReport XML document, as objects carrying the
      right's name and the SIDs it lists.

      XPath with local-name(), not PowerShell's XML adapter, for two reasons that cost a broken release
      between them. The report's elements are namespace-PREFIXED, so GetElementsByTagName with a bare
      local name matches nothing at all. And under Set-StrictMode the adapter THROWS
      PropertyNotFoundException for a child element that is absent -- so $e.Extension.UserRightsAssignment
      terminates the script on any extension that is not Security, and on a Security extension that sets
      no user rights. Every real domain has such a GPO: measured against a live domain, the Default
      Domain Policy throws on all three of its computer extensions, and a Registry-only GPO throws too.
      That took out the whole -LinkToOU path. XPath returns an empty node set instead, which is the
      correct answer to "what user rights does this GPO set" when the answer is none.
    #>
    param([Parameter(Mandatory)][xml]$Report)

    foreach ($u in $Report.SelectNodes("//*[local-name()='UserRightsAssignment']")) {
        $nameNode = $u.SelectSingleNode("*[local-name()='Name']")
        if (-not $nameNode) { continue }
        [pscustomobject]@{
            Name = $nameNode.InnerText
            Sids = @($u.SelectNodes("*[local-name()='Member']/*[local-name()='SID']") |
                     ForEach-Object { $_.InnerText })
        }
    }
}

# ---------------------------------------------------------------- principal

$domain = Get-ADDomain
$pdc = $domain.PDCEmulator
$domainDn = $domain.DistinguishedName

# One query to a DC, which returns both the SID and the object class. This is the direct way to answer
# "who is this and what are they" when the script is already talking to Active Directory -- and it avoids
# NTAccount.Translate(), whose name-to-SID cache can return the SID of a DELETED account after a name has
# been recreated. A stale SID in a deny right denies nothing to nobody while looking correct in a report.
# [char]92 rather than a literal backslash: this has to survive being edited by tooling that treats a
# backslash as an escape, and a lone '\' is also an invalid regex, so Split on a char beats -split here.
$parts = $Identity.Split([char]92)
$samName = $parts[-1]

# The prefix is CHECKED, not merely stripped. This script resolves and writes within ONE domain -- the
# one it is running in -- so accepting 'OTHER\gvm-scan' and then querying this domain would find a
# same-named account here, write ITS SID into the GPO, and report success: the intended account is left
# untouched while an unrelated principal is denied four logon types. Refuse instead of guessing, and
# refuse a UPN too, since user@domain is not the form this resolves.
if ($parts.Count -gt 2) { throw "-Identity '$Identity' has more than one '\'. Use DOMAIN\name." }
if ($parts.Count -eq 2) {
    $given = $parts[0]
    if ($given -ne $domain.NetBIOSName -and $given -ne $domain.DNSRoot) {
        throw ("-Identity names domain '$given', but this script writes to '$($domain.NetBIOSName)' " +
               "($($domain.DNSRoot)). Run it against that domain instead -- it resolves the account and " +
               'authors the GPO in the domain it is running in, and will not reach across a trust.')
    }
}
if ($samName -like '*@*') { throw "-Identity '$Identity' looks like a UPN. Use DOMAIN\name." }

# Single-quoted -Filter: the AD filter parser expands $samName itself. Interpolating it into a
# double-quoted string breaks on an apostrophe, which is legal in a sAMAccountName (o'scan).
$adObj = Get-ADObject -Filter 'sAMAccountName -eq $samName' -Server $pdc `
            -Properties objectSid, objectClass -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $adObj) {
    throw ("No object with sAMAccountName '$samName' on $pdc. Pass -Identity as " +
           'DOMAIN' + [char]92 + 'name for an account in this domain.')
}
$sid = $adObj.objectSid.Value
Write-Host "$Identity resolves to $sid (class '$($adObj.objectClass)', from $pdc)"

if (-not $Force) {
    # A well-known SID (Everyone S-1-1-0, Administrators S-1-5-32-544, Authenticated Users S-1-5-11)
    # translates perfectly well from a name, and denying it these rights would be catastrophic across
    # every machine the GPO reaches. Domain SIDs only, and then only user objects.
    if ($adObj.objectClass -ne 'user') {
        throw ("$Identity is a '$($adObj.objectClass)', not a user. Denying these rights to a group, " +
               'computer or managed service account has a blast radius nobody intends -- and a gMSA is ' +
               'normally the RUNNER, which needs batch logon. Refusing (-Force overrides).')
    }
    Write-Host '  confirmed: a domain user object'
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

# $cse.Added is part of the test: a run that repairs a missing CSE registration has changed how the GPO
# is PROCESSED even when the template was already correct, and clients reprocess on a version that
# differs from the one they last applied. Without it, a rerun after a run that died between writing the
# template and registering the CSE reports everything already in place and bumps nothing, leaving clients
# skipping the GPO until the Security extension's own periodic reapply.
if ($changed.Count -gt 0 -or $cse.Added -or $iniVer -ne $curVer) {
    $userPart = $curVer -shr 16
    # Masked to 16 bits: without this, a computer version of 65535 carries into the USER half, claiming
    # a user-policy change that never happened. Wrapping to 0 is fine -- clients reprocess on a version
    # that DIFFERS from the one they last applied, not one that is larger.
    $compPart = ((($curVer -band 0xFFFF) + 1) -band 0xFFFF)
    $newVer   = ($userPart -shl 16) -bor $compPart
    Set-ADObject -Identity $gpoDn -Server $pdc -Replace @{ versionNumber = $newVer }

    # Only the Version key is rewritten. Replacing the file wholesale would drop displayName=, which
    # New-GPO writes -- harmless to clients, since MS-GPOL requires only Version, but there is no reason
    # to discard a key this script does not own.
    if (Test-Path -LiteralPath $iniPath) {
        $ini = Get-Content -LiteralPath $iniPath -Raw
        $ini = if ($ini -match '(?im)^\s*Version\s*=') { $ini -replace '(?im)^\s*Version\s*=.*$', "Version=$newVer" }
               else { $ini.TrimEnd() + "`r`nVersion=$newVer" }
        Set-Content -LiteralPath $iniPath -Value $ini.TrimEnd() -Encoding Ascii
    }
    else { Set-Content -LiteralPath $iniPath -Value @('[General]', "Version=$newVer") -Encoding Ascii }
    Write-Host "  version $curVer -> $newVer (computer $($curVer -band 0xFFFF) -> $compPart); GPT.INI and AD agree"
}
else { Write-Host "  version $curVer already consistent between GPT.INI and the directory" }

# ---------------------------------------------------------------- verify, THEN link

Write-Host "`nVerification (from Get-GPOReport, which is what the domain will serve):"
$report = [xml](Get-GPOReport -Guid $gpo.Id -Server $pdc -ReportType Xml)
$assigned = @(Get-ReportUserRight -Report $report)
$bad = 0
foreach ($right in $DenyRight) {
    $entry = $assigned | Where-Object { $_.Name -eq $right }
    $holds = $entry -and ($entry.Sids -contains $sid)
    if ($holds) { Write-Host "  OK   $right" -ForegroundColor Green }
    else { Write-Host "  MISSING $right" -ForegroundColor Red; $bad++ }
}
$net = $assigned | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }
if ($net -and ($net.Sids -contains $sid)) {
    Write-Host '  FAIL SeDenyNetworkLogonRight lists the account -- scanning WILL break' -ForegroundColor Red
    $bad++
}
else { Write-Host '  OK   SeDenyNetworkLogonRight does not list the account' -ForegroundColor Green }
if ($bad -gt 0) { throw "$bad verification problem(s). The GPO has NOT been linked." }

if ($LinkToOU) {
    $inh = Get-GPInheritance -Target $LinkToOU -Server $pdc

    # --- PRECEDENCE, which for these settings decides whether this GPO does anything at all.
    #     User Rights Assignment does NOT merge across GPOs. The winning GPO's member list for a right
    #     REPLACES every other GPO's list for that right -- it is not unioned with them. So if another
    #     GPO already sets one of these four rights here, exactly one of two things happens, and both are
    #     worth knowing BEFORE the link goes in:
    #       - that GPO has higher precedence -> this GPO authors perfectly and applies nothing;
    #       - this GPO has higher precedence -> whoever that GPO was denying STOPS being denied.
    #     Demonstrated live while building this: linking a second GPO that set these rights took the
    #     existing scan account from 4 deny rights to 0.
    $conflicts = @()
    foreach ($link in @($inh.InheritedGpoLinks)) {
        if ($link.DisplayName -eq $GpoName) { continue }
        try { $x = [xml](Get-GPOReport -Guid $link.GpoId -Server $pdc -ReportType Xml) }
        catch { Write-Warning "  could not read '$($link.DisplayName)' to check for conflicts: $($_.Exception.Message)"; continue }
        $hit = @(Get-ReportUserRight -Report $x | Where-Object { $DenyRight -contains $_.Name } |
                 ForEach-Object { $_.Name })
        if ($hit) { $conflicts += [pscustomobject]@{ Name = $link.DisplayName; Order = $link.Order; Rights = ($hit | Sort-Object -Unique) } }
    }
    if ($conflicts) {
        Write-Host "`nAnother GPO at $LinkToOU already sets these rights:" -ForegroundColor Yellow
        foreach ($c in $conflicts) { Write-Host ("  precedence {0}: '{1}' sets {2}" -f $c.Order, $c.Name, ($c.Rights -join ', ')) -ForegroundColor Yellow }
        Write-Host '  User Rights Assignment does not merge: the highest-precedence GPO wins outright.' -ForegroundColor Yellow
        Write-Host '  Add this account to that GPO instead, or accept that one of the two lists will be' -ForegroundColor Yellow
        Write-Host '  discarded entirely. Verify the result on a target with: gpresult /scope computer /h report.html' -ForegroundColor Yellow
    }

    $already = @($inh.GpoLinks) | Where-Object { $_.DisplayName -eq $GpoName }
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
