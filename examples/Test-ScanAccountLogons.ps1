<#
.SYNOPSIS
  Monitoring check for misuse of the JIT scan account.

.DESCRIPTION
  JIT narrows the window in which the credential is usable. This detects use of it that does not
  fit the expected pattern, which is the other half of the story: narrowing a window is only
  valuable if you would notice someone climbing through it.

  The scan account should only ever perform Network logons (type 3), and only while a scan is
  running. Anything else is worth an alert:

    * a successful logon (4624) whose type is not in -AllowedTypes. An interactive (2),
      RemoteInteractive (10) or Service (5) logon by this account means it is being used as a
      general-purpose credential, which is not what it is for.
    * with -ScanWindowCheck, a type 3 logon OUTSIDE the scan window. This is the one that catches
      an attacker using the credential for lateral SMB movement, which otherwise looks exactly
      like legitimate scan traffic.
    * with -IncludeFailed, failed logons (4625), which may indicate the stale password being
      replayed after revocation -- expected occasionally, interesting in volume.

  Emits Nagios/PRTG-style output and exit code: 0 = OK, 2 = CRITICAL, 3 = UNKNOWN.

  Reads the Security log, so it must run where the events actually land. IMPORTANT: a type 3
  logon to a member server is written to THAT SERVER's Security log, not to a DC. Running this on a
  domain controller therefore shows only logons to the DC itself and will NOT see the lateral SMB
  movement this is meant to catch. Either point -ComputerName at the scanned hosts, or run it
  against a collector that Windows Event Forwarding / your SIEM populates. On a DC, Kerberos
  service tickets (4769) are the closer equivalent signal.

.PARAMETER ComputerName
  Where to read the Security log from. Defaults to the local machine.

.PARAMETER Identity
  sAMAccountName of the scan account.

.PARAMETER Hours
  How far back to look. Match this to your check interval, with a little overlap.

.PARAMETER AllowedTypes
  Logon types considered normal. Default 3 (Network), which is what an authenticated scan uses.

.PARAMETER ScanWindowStart / ScanWindowEnd
  Local times bounding the expected scan window, e.g. '01:00' and '06:00'. Only meaningful with
  -ScanWindowCheck. A window crossing midnight is handled.

.EXAMPLE
  .\Test-ScanAccountLogons.ps1 -Identity gvm-scan -Hours 24 -ScanWindowCheck `
      -ScanWindowStart '01:00' -ScanWindowEnd '06:00'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Identity,
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$Hours = 24,
    [int[]]$AllowedTypes = @(3),
    [switch]$ScanWindowCheck,
    [string]$ScanWindowStart = '01:00',
    [string]$ScanWindowEnd = '06:00',
    [switch]$IncludeFailed,
    [int]$FailedThreshold = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-InScanWindow {
    param([datetime]$When, [string]$Start, [string]$End)
    $s = [datetime]::ParseExact($Start, 'HH:mm', $null).TimeOfDay
    $e = [datetime]::ParseExact($End, 'HH:mm', $null).TimeOfDay
    $t = $When.TimeOfDay
    if ($s -le $e) { return ($t -ge $s -and $t -le $e) }
    # window crosses midnight
    return ($t -ge $s -or $t -le $e)
}

$after     = (Get-Date).AddHours(-$Hours)
$problems  = [System.Collections.Generic.List[string]]::new()
$failCount = 0
$okCount   = 0

foreach ($computer in $ComputerName) {
    try {
        $ids = if ($IncludeFailed) { 4624, 4625 } else { 4624 }
        $filter = @{ LogName = 'Security'; Id = $ids; StartTime = $after }
        $events = @(Get-WinEvent -FilterHashtable $filter -ComputerName $computer -ErrorAction Stop |
                    Where-Object { $_.Properties.Count -gt 5 })
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { continue }
        Write-Output "UNKNOWN - cannot read Security log on ${computer}: $($_.Exception.Message)"
        exit 3
    }

    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $target = $data['TargetUserName']
        if ($target -ne $Identity) { continue }

        if ($e.Id -eq 4625) {
            $failCount++
            continue
        }

        $okCount++
        $type = 0
        [void][int]::TryParse($data['LogonType'], [ref]$type)
        $source = $data['IpAddress']
        $stamp  = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')

        if ($AllowedTypes -notcontains $type) {
            $problems.Add("unexpected logon type $type on $computer from $source at $stamp")
            continue
        }

        if ($ScanWindowCheck -and -not (Test-InScanWindow -When $e.TimeCreated -Start $ScanWindowStart -End $ScanWindowEnd)) {
            $problems.Add("type $type logon OUTSIDE scan window on $computer from $source at $stamp")
        }
    }
}

if ($IncludeFailed -and $failCount -gt $FailedThreshold) {
    $problems.Add("$failCount failed logons (4625) exceed threshold $FailedThreshold")
}

if ($problems.Count -gt 0) {
    Write-Output ("CRITICAL - {0} anomalous logon(s) for '{1}' in the last {2}h | anomalies={0};;;; logons={3};;;; failed={4};;;;" -f
        $problems.Count, $Identity, $Hours, $okCount, $failCount)
    $problems | Select-Object -First 20 | ForEach-Object { Write-Output "  $_" }
    exit 2
}

Write-Output ("OK - '{0}': {1} logon(s) in the last {2}h, all type(s) {3}{4} | anomalies=0;;;; logons={1};;;; failed={5};;;;" -f
    $Identity, $okCount, $Hours, ($AllowedTypes -join ','),
    $(if ($ScanWindowCheck) { " within $ScanWindowStart-$ScanWindowEnd" } else { '' }), $failCount)
exit 0
