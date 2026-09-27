# gvm-jit-credentials

[![CI](https://github.com/PNWSoft/gvm-jit-credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/PNWSoft/gvm-jit-credentials/actions/workflows/ci.yml)

Just-in-time credentials for authenticated Greenbone / OpenVAS scans.

The scan account is **disabled**, with a password nobody holds, except during a scan. For the scan
window it is enabled and its password rotated to a fresh random value; afterwards both are undone.
The goal is narrow and worth stating plainly: to make that account **useless outside the scan
window**, so that stealing the credential gains an attacker nothing until the next scan — and so that
any attempt to use it in the meantime is unambiguous.

```powershell
$grant = Grant-GvmScanCredential -Identity gvm-scan -CredentialId $cfg.CredentialId `
           -ScannerHost scanner@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh
try     { Start-Sleep $grant.ReplicationDelaySeconds; <run your scan> }
finally { Revoke-GvmScanCredential -Grant $grant }
```

---

## Why

Authenticated Windows scanning needs the scanner to hold a credential with local administrator on
every target. The standard setup stores that credential in the scanner's database permanently. So
between scans — which is most of the time — there is a domain account with local admin across your
estate, whose password sits in a database on an appliance, and which nothing is watching because it
is *supposed* to be there.

The obvious Windows answer is a group-managed service account: let AD own the password so no human
or database holds a standing secret. That does not work here — Greenbone needs a plaintext password
it can store and replay over SMB, which is exactly what a gMSA will not give you. This module is the
nearest equivalent for a credential that must be handed to a third-party scanner: the same goal of
"no standing usable secret", reached by disabling the account and rotating the password around each
scan instead of by letting AD manage it.

It reduces *when* the account can be used. It does not reduce what the account can do while a scan is
running.

## Threat model

**What this fixes**

- **The account is disabled between scans, and its password is one nobody holds.** Two independent
  layers, either of which alone would be enough. An attacker who extracts the credential from the
  scanner's database, from a backup, or from the wire gets something that authenticates nowhere until
  the next scan window opens. (Getting this wrong is easy: reusing the value written to AD during
  revoke would leave the scanner holding the account's *current* password, collapsing the two layers
  into one. `tests/Regression.Tests.ps1` pins it.)
- **Detection becomes trivial, which is the underrated half.** A disabled account has no legitimate
  reason to be used at all, so *any* authentication attempt outside the scan window is anomalous by
  construction — there is no baseline to learn and no threshold to tune. Compare that with a
  permanently-enabled scan account, where distinguishing malicious use from normal use is genuinely
  hard. This repository does not supply monitoring; it makes the monitoring easy to write.
  `examples/Test-ScanAccountLogons.ps1` is a starting point, not a product.
- A tampered scheduled task fails closed rather than escalating, when combined with
  `-ExecutionPolicy AllSigned` in the task action. Note this protects *scripts*, not `config.psd1`:
  that is data, not signed, so its directory must be admin-only. Parameters that reach a command
  line (`ScannerHost`, `GmpHelper`) and every Greenbone UUID are pattern-validated for this reason.

**What this does NOT fix — read this part**

- **During a scan the credential is live**, and it holds local administrator on every target. This
  narrows the window from *always* to *the scan window*; it does not eliminate it, and it does
  nothing to reduce the account's privileges while that window is open. If your scan takes four
  hours, that is a four-hour window in which the credential is exactly as dangerous as a permanent
  one. Inside the window, volume-based detection is also useless — one day of scanning seven hosts
  produced 5608 type 3 logons, because every check opens its own SMB session.
- **A kill -9 or a reboot mid-scan leaves the credential live.** The revoke runs in a `finally`
  block, which cannot survive the process dying outright. This is not hypothetical; it is the
  normal outcome of a reboot during a long scan. **Deploy `examples/backstop-task.ps1`** — an
  independent scheduled task that revokes unconditionally after your longest plausible scan.
- **The password exists in process memory** for the duration of the grant. .NET strings are
  immutable and are not zeroed; `Remove-Variable` drops the reference, it does not scrub the bytes.
  Anyone who can read that process's memory is already in a position to do worse.
- **Never enable PowerShell transcription OR Module Logging for the runner account.** Both capture
  the plaintext password from outside the module, so nothing the module does can prevent it.
  Transcription is the obvious one; **Module Logging is the dangerous one**, because it is far more
  widely deployed via GPO and less obviously a problem. With it on, event 4103 records
  `ParameterBinding(ConvertTo-SecureString): value="<password>"` into
  `Microsoft-Windows-PowerShell/Operational`, whose default channel ACL grants **Interactive Users**
  read — so any interactive non-admin on the runner can read the live scan password during the
  window. Script Block Logging (4104) does not leak values here, because nothing builds dynamic
  script blocks. If your estate mandates Module Logging, exempt this task or accept that the window
  is only as private as that event log.
- **Anyone who is already admin on the runner host** can do all of this themselves. This defends
  the credential at rest, not the machine that legitimately holds it.
- **Your target list is only as trustworthy as your AD hygiene.** `examples/weekly-ou-scan.ps1`
  resolves every *enabled* computer object in an OU through DNS at run time. A decommissioned machine
  whose object was never deleted and whose A record has since been scavenged is a name that any
  authenticated domain user can claim, because AD-integrated DNS lets authenticated users create
  records for names that do not currently exist. Claim the name, and the credentialed scan
  authenticates to a host of the attacker's choosing during the window — NetNTLMv2 capture, and relay
  to any in-scope server not enforcing SMB signing. Mitigations: delete stale computer objects,
  enforce SMB signing, and consider filtering targets on `lastLogonTimestamp`, since a stale object is
  exactly the one with no live DNS record. The same applies more sharply to
  `examples/Add-ScanAccountLocalAdmin.ps1`, which a Domain Admin runs.
- **Revoke writes to the PDC emulator, so a lagging DC can still accept the old password** for one
  replication interval — seconds within a site, potentially hours across a slow link. It only extends
  an exposure an attacker already has (they must have captured the plaintext during the window), but
  the window does not close everywhere at once.

## How it works

1. **Grant** — enable the AD account, reset its password to a fresh random value on the PDC
   emulator, push that same value into the Greenbone credential object. AD first, Greenbone second:
   the reverse order would leave Greenbone holding a password AD does not have, producing
   authentication failures across every target, which looks exactly like an attack in progress.
2. **Wait** — for the reset to replicate to the DCs your targets will authenticate against. Too
   short and the scan silently falls back to unauthenticated results, which reads as a clean scan
   rather than a failed one.
3. **Scan** — start a Greenbone task and poll it, or run your own orchestration.
4. **Revoke** — always, in a `finally` block: disable the account, reset the password to a value
   nobody records, overwrite the stored Greenbone value.

### The scanner side

Neither password ever reaches a command line, which takes more care than it sounds:

- The Windows side pipes the GMP request over **SSH stdin**, so it is never in argv or shell history
  on the calling host.
- `host/gmp.sh` is a world-readable **stub** that does nothing but `exec sudo -n gmp-relay.sh`.
- `host/gmp-relay.sh` is root-owned `0700` and does the Docker work. `install.sh` writes a sudoers
  rule letting the scan account run **that one command** and nothing else, so the SSH account never
  needs docker-group membership — which on any Docker host is root-equivalent.
- The relay writes the request and a `gvm-tools.conf` into a `mktemp` directory under **`/dev/shm`**
  (tmpfs, so neither touches disk), `0444` root-owned inside a `0700` root-owned directory, and
  bind-mounts them read-only. `gvm-cli` receives file paths, never values.

Two details there are load-bearing and easy to "simplify" wrongly. **`gvm-cli` cannot read the
request from stdin** — omitting the positional file gives
`TypeError: object of type 'NoneType' has no len()` — so the request must be a file. And **do not
chown those files to the container's uid**: a bind mount does not translate uids, so that hands both
passwords to whatever *host* account holds that number, which on a normal machine is a real login.

### Task reuse

`examples/weekly-ou-scan.ps1` builds its target from live OU membership, so it cannot use a fixed
Greenbone task: GVM refuses to edit a target that is in use, and refuses to retarget a task that has
already run (`status="400" "Status must be New to edit Target"`). Creating a fresh target and task
every run is the usual workaround — and it leaves a dead pair behind each time, 52 a year, each
holding a report that any "latest report per task" query will treat as current.

So the driver creates a new task **only when the host set actually changes**. It records a fingerprint
of the resolved host list plus the task UUID, and on the next run starts that same task if the
fingerprint matches, so reports accumulate as history under one task. A changed host list produces a
new target and task, and says so.

The recorded task is verified before reuse — scan config, scanner, target host list and SMB credential
must all match this run — because the state file is unsigned data that names something this tool is
about to start *with the credential live*. Existence alone is not enough.

## Domain controllers

This tool's scan account is not intended for domain controllers, and `examples/weekly-ou-scan.ps1`
assumes they are out of scope.

The reason is mechanical rather than a matter of taste. A DC has no separate local account database,
so its `BUILTIN\Administrators` is the domain's group: adding an account to "local Administrators" on
a DC grants administrative control over the directory and every DC, not just that machine. Whatever
you think of scanning DCs authenticated, a credential that a scanner stores and replays over SMB is a
poor candidate for that level of access, and narrowing the *window* does not change what the access
is. `examples/Add-ScanAccountLocalAdmin.ps1` refuses to run if a domain controller appears in the OU
you point it at, for that reason.

A common approach — the one this was extracted from — is to keep DCs free of third-party software and
scan them **unauthenticated**, as a separate task with its own target. Where that holds, Microsoft
Update plus an unauthenticated scan gives many people decent coverage, because a good deal of what
authenticated scanning adds is third-party patch and configuration detail that is not present to find.

How well that generalises depends on your estate. DCs that do run third-party software — backup
agents, monitoring, AV management, PKI or HSM tooling — have more that an unauthenticated scan will not
see, and the gap may matter to you. There are reasonable answers other than authenticating this
account into a DC: a separate process for tier-0 with its own credential handling and controls,
agent-based assessment, or accepting a known gap deliberately. Which of those fits is your call; the
point here is only that this tool does not try to be that answer, and its example scripts assume you
have made the decision elsewhere.

## Scope

v1 covers exactly one configuration, because it is the only one that has been tested:

- **Scan targets:** Windows hosts in an Active Directory domain
- **Scan account:** an AD user account
- **Runner:** Windows, PowerShell 5.1 or later, with RSAT
- **Scanner:** Greenbone Community Edition in Docker on Linux, reachable over SSH

The seam for other setups is `host/gmp-relay.sh` and the four AD wrappers in
`GvmJitCredential/Private/` — nothing else knows how credentials are stored or how the scanner is
reached. Contributions welcome; please don't claim support for a configuration you haven't run.

## Install

```powershell
# 1. AD side: disabled scan account + delegation for the runner (run as a Domain Admin)
.\bootstrap\Initialize-GvmScanAccount.ps1 -Identity gvm-scan `
    -Path 'OU=Service Accounts,DC=example,DC=local' -RunnerAccount 'EXAMPLE\gvm-runner$' -WhatIf

# 2. Scanner host, AS ROOT: install stub + relay + the scoped sudoers rule
#    ./host/install.sh    then edit /opt/greenbone/.gmp.env  (chmod 600)
#    Then pin the runner's SSH key in ~gvm-scan/.ssh/authorized_keys:
#      command="/opt/greenbone/gmp.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 ...

# 3. Greenbone side: create the credential object and discover the UUIDs you need
.\bootstrap\Initialize-GvmScanCredential.ps1 -ScannerHost scanner@scanner.example.local `
    -GmpHelper /opt/greenbone/gmp.sh -ScanAccount 'EXAMPLE\gvm-scan' -OutFile .\config.psd1

# 4. Decide how the account gets access on targets — your call.
#    examples\Add-ScanAccountLocalAdmin.ps1 shows one approach among several.

# 5. Register the scan task AND the backstop task — see examples\
```

Two things the scripts cannot do for you:

- **Lock down the config and state directory.** `C:\ProgramData` grants `BUILTIN\Users`
  container-inherited create-file rights, so a subfolder created without resetting the ACL lets any
  local user pre-create `config.psd1` or the state file — and the state file names the task that
  gets started with the credential live. Break inheritance: SYSTEM and Administrators Full, the
  runner Modify, nothing for Users.
- **Create the event log source on the RUNNER host.** `Initialize-GvmScanAccount.ps1` registers it
  where *it* runs, which may not be the runner. If it is missing, the audit trail goes to the task
  log only — you get one warning saying so, rather than silence.

Every script supports `-WhatIf`. Use it first.

## Gotchas that will cost you an afternoon

**The SSH key belongs to the runner account, not to you.** `ssh` resolves keys from the *calling*
account's profile, so the same code works under the scheduled task and fails when you run it by
hand. Pass `-IdentityFile` to make the dependency explicit. Do **not** grant yourself access to the
runner's `.ssh` directory to copy the key — adding an ACE makes OpenSSH reject the key as having
permissive permissions, breaking the working task.

**`known_hosts` belongs to the runner account too.** With `BatchMode=yes`, an unknown host key makes
`ssh` fail *silently* with exit 255. Verify the fingerprint out of band before trusting it.

**An `authorized_keys` forced command overrides the command the client asks for.** Pinning the key
is worth doing — a stolen key then yields GMP relay access rather than a shell — but it also means
`ssh host /some/other/path` silently runs the pinned command instead, *and appears to succeed*. Move
the helper without updating the key and you will spend an afternoon testing the wrong binary. `sudo`'s
log on the scanner is the ground truth for which one actually ran.

**`-CannotChangePassword` does not block rotation.** That flag stops the *user* changing their own
password; the module uses an administrative reset, which is unaffected.

**Under `AllSigned`, this module will not load unless you sign it.** All of `GvmJitCredential/*.ps1`,
the `.psm1`, the `.psd1`, and any bootstrap or example script you run. Sign with *your* certificate,
not one from this repo. `examples/Sign-Module.ps1` does the loop, refuses to sign a non-CRLF file,
and re-parses everything afterwards — validating *before* signing proves nothing, because signing is
the step that can corrupt the file.

**Sign `.ps1` files with CRLF line endings.** `signtool` appends its signature block assuming CRLF;
on an LF-only file it silently eats the final line, producing a file that reports `Status: Valid`
and then fails to parse with `MissingEndCurlyBrace`. `.gitattributes` enforces CRLF on checkout for
exactly this reason.

## Testing

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Invoke-Pester -Path ./tests
```

The suite needs **no Active Directory and no scanner**. Every external dependency goes through a
private seam that the tests mock, which is why it runs in CI. If you add a code path that talks to
AD or GMP directly instead of through those seams, it becomes untestable — please don't.

## Status

Extracted from a working deployment, then run against it. Every script here has been executed against
a live Greenbone 22.7 instance and a multi-DC Active Directory domain: the full grant/scan/revoke
lifecycle, task reuse and its refusal path, the AD delegation, the scanner relay under load, and the
backstop's failure path. The 60-case test suite needs neither.

That is not a claim of correctness — it is a statement that nothing here is untried, which for this
kind of tool is the minimum bar. v1 supports one configuration for the same reason.

## License

MIT. See `LICENSE`.
