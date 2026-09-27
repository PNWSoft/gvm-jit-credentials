<#
.SYNOPSIS
  Weekly authenticated scan of every enabled computer in an AD OU, using a just-in-time credential.

.DESCRIPTION
  A worked example of the -ScanAction path: the credential lifecycle is handled by
  Invoke-GvmJitScan, while this script supplies the scan orchestration, because the host set changes
  between runs and so a fixed Greenbone task cannot represent it.

  Each run builds a FRESH target and task from current OU membership. That is not a stylistic choice:
  GVM refuses to edit a target that is in use, and refuses to retarget a task that has already run,
  so a long-lived task cannot follow a changing inventory.

  KNOWN CONSEQUENCE: one target and one task accumulate per run, and Greenbone never prunes them.
  After a year of weekly scans that is 52 dead tasks, each holding a report that any "latest report
  per task" query will happily treat as current. Prune them, or filter by report age downstream.

.PARAMETER SearchBase
  OU distinguished name whose ENABLED computers become the target,
  e.g. "OU=Servers,DC=EXAMPLE,DC=local".

.PARAMETER TargetSubnet
  Optional IP prefix used to choose each host's scan address when it resolves to several. Empty
  takes the first IPv4. Without it, a host with a public and a private address may be scanned on the
  wrong interface.

.PARAMETER StateFile
  Remembers the host set and task UUID from the previous run. When the host set is unchanged the
  existing task is started again, so scan history accumulates under one task instead of leaving a
  dead task and target behind every run. Delete the file to force a fresh task.

.PARAMETER AlertId
  Optional Greenbone alert UUID to attach to the per-run task. It MUST be passed here: because each
  run creates a new task, an alert attached to a previous task does not carry over. Omitting it is a
  silent failure -- scans run, findings land, and no alert is ever sent.

.EXAMPLE
  .\weekly-ou-scan.ps1 -Identity gvm-scan -ScannerHost scanner@scanner.example.local `
      -GmpHelper /opt/greenbone/gmp.sh -CredentialId ... -ConfigId ... -ScannerId ... `
      -PortListId ... -SearchBase 'OU=Servers,DC=EXAMPLE,DC=local' -TargetSubnet '10.0.0.' -WhatIf
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'ConfigId, ScannerId, TargetNamePrefix, TaskNamePrefix, PollSeconds and MaxScanMinutes are all used inside the -ScanAction script block. PSScriptAnalyzer does not look into script blocks passed as arguments.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId',
    Justification = 'CredentialId is a Greenbone object UUID, not a secret; the rule matches on the parameter name containing "Credential".')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Identity,
    [Parameter(Mandatory)][string]$ScannerHost,
    [Parameter(Mandatory)][string]$GmpHelper,
    [Parameter(Mandatory)][string]$CredentialId,
    [Parameter(Mandatory)][string]$ConfigId,
    [Parameter(Mandatory)][string]$ScannerId,
    [Parameter(Mandatory)][string]$PortListId,
    [Parameter(Mandatory)][string]$SearchBase,
    [string]$TargetSubnet = '',
    [string]$AlertId = '',
    [string]$IdentityFile = '',
    # Records the host set and task UUID from the last run, so an unchanged host set can reuse
    # its task instead of orphaning one per run. Delete it to force a fresh task.
    [string]$StateFile = 'C:\ProgramData\GvmJit\weekly-ou-scan.state.psd1',
    [string]$TargetNamePrefix = 'JIT auto target',
    [string]$TaskNamePrefix = 'JIT weekly scan',
    [int]$ReplicationDelaySeconds = 45,
    [int]$PollSeconds = 30,
    [int]$MaxScanMinutes = 300,
    [string]$ModulePath = (Join-Path $PSScriptRoot '..\GvmJitCredential\GvmJitCredential.psd1'),
    [string]$LogSource = 'GvmJitCredential'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory
Import-Module $ModulePath -Force

$gmp = @{ ScannerHost = $ScannerHost; GmpHelper = $GmpHelper; IdentityFile = $IdentityFile }

# --- Resolve the target host list BEFORE granting the credential. Anything that can fail without
#     needing the credential should fail while the account is still disabled.
Write-Host "Resolving scan targets from $SearchBase"
$computers = @(Get-ADComputer -SearchBase $SearchBase -Filter "Enabled -eq 'true'" -Properties DNSHostName)

$ipList = foreach ($c in $computers) {
    $fqdn = if ($c.DNSHostName) { $c.DNSHostName } else { "$($c.Name).$env:USERDNSDOMAIN" }
    $v4 = @()
    $dnsError = $null
    try {
        $v4 = @([System.Net.Dns]::GetHostAddresses($fqdn) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.IPAddressToString })
    }
    catch {
        # Distinguish "DNS does not know this host" from "resolved, but nothing in the wanted
        # subnet". Swallowing the reason makes a decommissioned machine look identical to a
        # misconfigured -TargetSubnet, and both just quietly shrink the scan.
        $dnsError = $_.Exception.Message
    }
    $pick = if ($TargetSubnet) { $v4 | Where-Object { $_.StartsWith($TargetSubnet) } | Select-Object -First 1 }
            else { $v4 | Select-Object -First 1 }
    if ($pick) { $pick }
    elseif ($dnsError) { Write-Warning "DNS lookup failed for $fqdn - skipped: $dnsError" }
    elseif ($v4.Count -eq 0) { Write-Warning "$fqdn resolved to no IPv4 address - skipped" }
    else { Write-Warning "$fqdn has no IPv4 in subnet '$TargetSubnet' (found: $($v4 -join ', ')) - skipped" }
}
$ipList = @($ipList | Sort-Object -Unique)

if ($ipList.Count -eq 0) {
    throw "Target sync produced 0 hosts under $SearchBase (subnet '$TargetSubnet'). Refusing to run a scan of nothing."
}
Write-Host "  $($ipList.Count) host(s): $($ipList -join ', ')"

if (-not $PSCmdlet.ShouldProcess("$($ipList.Count) host(s) via '$Identity'", 'Grant credential, scan, revoke')) {
    return
}

# --- Reuse an existing task when the host set has not changed.
#
# VERIFIED on a live instance: modify_task can change a task's target only while the task is New.
# Once it has run, GMP answers 400 "Status must be New to edit Target". So a task is locked to its
# host set after its first run, and a NEW task is needed only when that set actually changes.
#
# Creating one unconditionally, as the obvious implementation does, leaves a dead task and target
# behind every single run -- 52 a year, each holding a report that any "latest report per task"
# query will treat as current. Reusing the task when the hosts are identical keeps the scan history
# together under one task, which is both tidier and what downstream queries expect.
$fingerprint = ($ipList -join ',')
$state = $null
if ($StateFile -and (Test-Path -LiteralPath $StateFile)) {
    try { $state = Import-PowerShellDataFile -LiteralPath $StateFile }
    catch { Write-Warning "Could not read $StateFile ($($_.Exception.Message)); treating this as a first run." }
}

$reuseTaskId = ''
if ($state) {
    # Import-PowerShellDataFile returns a hashtable; ContainsKey keeps this safe under StrictMode
    # and tolerant of a state file written by an older version.
    $prevHosts = if ($state.ContainsKey('Hosts'))  { [string]$state['Hosts'] }  else { '' }
    $prevTask  = if ($state.ContainsKey('TaskId')) { [string]$state['TaskId'] } else { '' }
    if ($prevHosts -eq $fingerprint -and $prevTask) {
        # Confirm it still exists: someone may have deleted it in GSA, and starting a missing task
        # would fail after the credential is already live.
        try {
            $chk = Invoke-GvmGmpRequest @gmp -Xml ('<get_tasks task_id="{0}"/>' -f $prevTask)
            if ($chk.SelectSingleNode('//task/name')) {
                $reuseTaskId = $prevTask
                Write-Host "  host set unchanged; reusing task $reuseTaskId"
            }
            else { Write-Host '  recorded task no longer exists; creating a new one' }
        }
        catch { Write-Host "  could not verify the recorded task ($($_.Exception.Message)); creating a new one" }
    }
    elseif ($prevHosts -ne $fingerprint) {
        Write-Host '  host set CHANGED since the last run; a new target and task are required'
        Write-Host "    was: $prevHosts"
        Write-Host "    now: $fingerprint"
    }
}

$stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$script:taskId = ''
$script:targetId = ''

$result = Invoke-GvmJitScan -Identity $Identity -CredentialId $CredentialId `
    -ScannerHost $ScannerHost -GmpHelper $GmpHelper -IdentityFile $IdentityFile `
    -ReplicationDelaySeconds $ReplicationDelaySeconds -LogSource $LogSource `
    -ScanAction {
        param($grant)

        if ($reuseTaskId) {
            $script:taskId = $reuseTaskId
        }
        else {
            # create_target answers 201.
            $targetXml = '<create_target><name>{0}</name><hosts>{1}</hosts><port_list id="{2}"/><smb_credential id="{3}"/></create_target>' -f
                (ConvertTo-GvmGmpText ("$TargetNamePrefix $stamp")), ($ipList -join ','), $PortListId, $CredentialId
            $doc = Invoke-GvmGmpRequest @gmp -Xml $targetXml -ExpectStatus 200, 201
            $script:targetId = $doc.DocumentElement.GetAttribute('id')
            if (-not $script:targetId) { throw 'create_target returned no id' }

            $alertXml = if ($AlertId) { '<alert id="{0}"/>' -f $AlertId } else { '' }
            $taskXml = '<create_task><name>{0}</name><config id="{1}"/><target id="{2}"/><scanner id="{3}"/>{4}</create_task>' -f
                (ConvertTo-GvmGmpText ("$TaskNamePrefix $stamp")), $ConfigId, $script:targetId, $ScannerId, $alertXml
            $doc = Invoke-GvmGmpRequest @gmp -Xml $taskXml -ExpectStatus 200, 201
            $script:taskId = $doc.DocumentElement.GetAttribute('id')
            if (-not $script:taskId) { throw 'create_task returned no id' }
            Write-Host "  created target $($script:targetId) and task $($script:taskId)"
        }

        # start_task answers 202.
        $null = Invoke-GvmGmpRequest @gmp -Xml ('<start_task task_id="{0}"/>' -f $script:taskId) -ExpectStatus 200, 202
        Write-Host '  scan started; polling'

        # Poll on the REPORT the start produced, not merely on task status: a fresh task has no
        # previous report, so requiring last_report to exist AND status to be terminal avoids
        # mistaking a stale state for this run's completion.
        $deadline = (Get-Date).AddMinutes($MaxScanMinutes)
        $terminal = @('Done', 'Stopped', 'Interrupted')
        do {
            Start-Sleep -Seconds $PollSeconds
            if ((Get-Date) -gt $deadline) {
                throw "Scan exceeded MaxScanMinutes ($MaxScanMinutes); revoking rather than waiting longer."
            }
            $doc = Invoke-GvmGmpRequest @gmp -Xml ('<get_tasks task_id="{0}"/>' -f $script:taskId)
            $node = $doc.SelectSingleNode('//task/status')
            $status = if ($node) { $node.InnerText } else { 'Unknown' }
        } until ($terminal -contains $status)

        Write-Host "  scan reached terminal state: $status"
    }

$reportNode = $null
try {
    $doc = Invoke-GvmGmpRequest @gmp -Xml ('<get_tasks task_id="{0}"/>' -f $script:taskId)
    $reportNode = $doc.SelectSingleNode('//task/last_report/report')
}
catch { Write-Warning "Could not read the report id back: $($_.Exception.Message)" }

"Task     : $($script:taskId)"
"Target   : $($script:targetId)"
"Report   : $(if ($reportNode) { $reportNode.GetAttribute('id') } else { 'unknown' })"
"Duration : $($result.Duration)"
"Revoked  : disabled=$($result.Revoke.Disabled) passwordReset=$($result.Revoke.PasswordReset) greenboneBlanked=$($result.Revoke.GreenboneBlanked)"

# Record the host set and task for the next run. Written only after the scan reached a terminal
# state: recording a task that failed to start would make the next run reuse something unusable.
if ($StateFile -and $script:taskId) {
    try {
        $dir = Split-Path -Parent $StateFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
        $content = @"
@{
    # Written by weekly-ou-scan.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Hosts  = '$fingerprint'
    TaskId = '$($script:taskId)'
}
"@
        [IO.File]::WriteAllText($StateFile, ($content -replace "`r?`n", "`r`n"), [Text.Encoding]::ASCII)
    }
    catch { Write-Warning "Could not write $StateFile ($($_.Exception.Message)); the next run will create a new task." }
}
if ($result.Revoke.Warnings.Count -gt 0) { $result.Revoke.Warnings | ForEach-Object { Write-Warning $_ } }

# Exit codes the scheduled task can act on.
if ($result.Revoke.Errors.Count -gt 0) {
    $result.Revoke.Errors | ForEach-Object { Write-Error $_ }
    exit 2      # the credential did not fully revoke: investigate immediately
}
exit 0
