# gvm-jit-credentials

[![CI](https://github.com/PNWSoft/gvm-jit-credentials/actions/workflows/ci.yml/badge.svg)](https://github.com/PNWSoft/gvm-jit-credentials/actions/workflows/ci.yml)

Just-in-time credentials for authenticated Greenbone / OpenVAS scans.

Authenticated vulnerability scanning normally needs a standing Active Directory account, with local
administrator rights on every target, holding the same password all year. This is a PowerShell module
and a working reference deployment that removes the standing part, by driving credential rotation from
the scan schedule rather than from a password policy.

The scan account is **disabled**, with a password nobody holds, except during a scan. For the scan
window it is enabled and its password rotated to a fresh random value; afterwards both are undone.
The goal is narrow: to make that account **useless outside the scan window**, so that a stolen
credential authenticates nowhere — then or later, because the next window uses a fresh value, not
this one — and so that any attempt to use it is unambiguous.

It is a sample to read and adapt, taken from a deployment that runs weekly — not a product. It does
not reduce what the account can do *while* a scan is running; see [Threat model](#threat-model) and
[Scope](#scope) for what it does and does not buy.

```powershell
$grant = Grant-GvmScanCredential -Identity gvm-scan -CredentialId $cfg.CredentialId `
           -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh
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

A group-managed service account is the other way to approach this, and a reasonable one. What follows is
not an argument that gMSAs are wrong — it is an argument that one buys little *here*.

To use a gMSA, the runner has to read `msDS-ManagedPassword` and hand the value to Greenbone. A
principal authorised to retrieve it can do that, but arranging and holding that authorisation is its own
piece of work, and at the end of it Greenbone is still storing the password. The properties you arrive
at are close to what this produces, with one difference that decides it for this use case: AD rotates a
gMSA password on its own interval (30 days by default), not on demand — so there is no way to make the
copy in the scanner database stale at the end of each scan. Being able to do exactly that is the
mechanism this relies on.

So the SCAN account used here is an ordinary one, deliberately shaped like a service identity: created
disabled, unable to change its own password, marked *sensitive and cannot be delegated*, and with a
password no human ever holds. What a gMSA would manage on a schedule of its own is done explicitly
instead, on the schedule the scan actually runs on.

Being clear about that last flag rather than overselling it: it stops any Kerberos ticket for the account
being forwarded by a service it authenticates to. The scan's own logon does not involve one — the
credential this creates is Greenbone's `up` type, which it labels SMB (NTLM) — so the flag is invisible
to the scan itself. It is set because it is free, because an account with local admin everywhere should
not be delegatable, and because it is correct for any other use of the account. The NTLM analogue,
relay during the scan window, is a separate problem it does not address.

On top of that, the account is denied every logon type a scan does not use. An authenticated scan reaches
a target only over SMB and DCE-RPC, which are **network** logons (type 3), so the other four can be
denied outright:

| user right | scan account |
| --- | --- |
| Deny log on locally | denied |
| Deny log on through Remote Desktop Services | denied |
| Deny log on as a batch job | denied |
| Deny log on as a service | denied |
| Deny access to this computer from the network | **not set** — this is the one a scan needs |

Logon rights are per-machine local security policy; no Active Directory attribute sets them. So the
scalable way to apply this is a GPO linked to the OUs holding your targets, which is how it is done in
the deployment this came from. `examples/Set-ScanAccountLogonRights.ps1` does the same thing on a single
machine for a small estate, for a host a GPO does not reach, or just to report what one machine's policy
actually says — and if a GPO does manage these rights, it reapplies on its own schedule and overwrites
any local change.

Two properties of user rights caught us out, both confirmed against a live domain, and both matter before
you create a GPO for this:

- **They do not merge across GPOs.** A user right is won as a whole membership list, not setting by
  setting: the highest-precedence GPO's list for `SeDenyBatchLogonRight` *replaces* every other GPO's
  list for it. Linking a second GPO that set these four rights took an already-restricted scan account
  from 4 deny rights to 0. If a GPO in scope already sets any of them, add the account to **that** GPO
  rather than creating a second one. `New-ScanAccountLogonRightsGpo.ps1` checks the target OU for this
  and warns before it links, but it cannot decide for you.
- **They tattoo.** Unlinking or deleting the GPO does not hand the rights back; the values are written
  into each machine's local security database and stay until something overwrites them. To undo a deny
  right, empty its membership in the GPO that set it and let that apply — deleting the GPO freezes the
  last state instead of reverting it.

Worth being honest about what this buys: an interactive logon as this account needs the same password a
network logon needs, and the network path stays open because the scan needs it. So it does not stop
someone holding the password — it removes other ways to use one if obtained, and makes an interactive
attempt unambiguous. What prevents misuse is still the account being disabled with a password nobody
holds.

Be careful with the `LogonWorkstations` attribute ("Log On To…") instead. It looks like the scriptable
equivalent, but the DC evaluates it against the client workstation name supplied during authentication,
and a Linux SMB client sends whatever it likes there — so restricting it can lock the scanner out, with
a failure that reads like a bad credential. Pinning it to the scanner's name is appealing hardening, but
test it against your own client before relying on it.

The RUNNER account, by contrast, is a gMSA in this deployment and in the examples — that is precisely
where one fits, because its password is never handed to anything. The distinction is not gMSA versus
ordinary account; it is whether the password has to leave AD.

It reduces *when* the account can be used. It does not reduce what the account can do while a scan is
running.

## Threat model

**What this fixes**

- **The account is disabled between scans, and its password is one nobody holds.** Two independent
  layers, either of which alone would be enough. An attacker who extracts the credential from the
  scanner's database, from a backup, or from the wire gets something that authenticates nowhere, and
  waiting for the next window does not help them: that window rotates the password again, so the value
  they hold is never valid again. (Getting this wrong is easy: reusing the value written to AD during
  revoke would leave the scanner holding the account's *current* password, collapsing the two layers
  into one. `tests/Regression.Tests.ps1` pins it.)
- **The signal for detection becomes unambiguous.** A disabled account
  has no legitimate reason to be used, so an authentication attempt outside the scan window is
  anomalous *by construction* rather than by comparison against a learned baseline — contrast a
  permanently-enabled scan account, where separating malicious use from normal use is genuinely hard.
  Collecting that signal still takes work: type 3 logons land on each member server's Security log
  rather than on a DC, so you need event forwarding or per-host queries. Attempts against the
  *disabled* account do surface centrally on a DC, as 4776 with `0xC0000072` or Kerberos 4768 with
  `KDC_ERR_CLIENT_REVOKED`, which is the cheapest place to watch. This repository does not supply
  monitoring; `examples/Test-ScanAccountLogons.ps1` is a starting point, not a product.
- Defence in depth rather than a primary control: with `-ExecutionPolicy AllSigned` in the task
  action, a tampered *script* fails to run instead of running as the runner. It does not help against
  a tampered *task* — an attacker who can edit the action simply removes the flag — and both need
  write access that the deployment notes already say must be admin-only. One caveat worth checking on
  your own host: if execution policy is set by **Group Policy**, the `MachinePolicy`/`UserPolicy` scope
  overrides the command-line flag and the flag does nothing. `Get-ExecutionPolicy -List` shows which
  scope is in force; if it is a policy scope, `AllSigned` has to be set there instead. Separately, and independent
  of signing: `config.psd1` and the state file are unsigned data, so parameters that reach a command
  line (`ScannerHost`, `GmpHelper`) and every Greenbone UUID are pattern-validated, and a reused task
  is verified against the current run before it is started.

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
- **Error text from the scanner is redacted, not trusted.** `gvm-tools` validates a GMP request before
  sending it and echoes the whole request on a parse error — which for a credential push contains the
  plaintext. The relay strips `<password>` elements from anything it forwards, `Invoke-GmpRequest`
  strips them again on arrival, and the relay never forwards the shell's own error when `.gmp.env`
  fails to parse. If you extend the GMP surface, keep both layers: the module's own requests are
  escaped and short, but a hand-built request through `Invoke-GvmGmpRequest` need not be either.
- **Anyone who is already admin on the runner host** can do all of this themselves. This defends
  the credential at rest, not the machine that legitimately holds it.
- **Nor does it defend the scanner host.** This moves the standing secret out of the appliance
  database; it does not move the appliance out of your trust boundary. A one-time theft of the stored
  value — a stolen backup, a database dump — gains nothing, because the next window uses a fresh
  random value. But *persistent* root on the scanner gets the live credential every window: from
  gvmd's database, or from the relay's tmpfs directory while a request is in flight. Against a
  compromised scanner this narrows the blast radius of a snapshot, not of ongoing access.
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
2. **Wait** — for the change to replicate to the DCs your targets will authenticate against. The
   attribute that matters is the *enabled* flag more than the password: a DC that fails a password
   check normally forwards it to the PDC emulator, so a not-yet-replicated password is usually
   rescued, whereas a DC that still believes the account is disabled rejects outright. Too short a
   wait and the scan falls back to unauthenticated results, which reads as a clean scan rather than a
   failed one.
3. **Scan** — `Invoke-GvmJitScan` composes all of this: grant, wait, start a Greenbone task by UUID,
   poll to a terminal state, then revoke in a `finally` block. If you build your own targets each run,
   pass `-ScanAction { ... }` instead of `-TaskId`, and your script block runs inside the same
   guarantees with `Invoke-GvmGmpRequest` available for its own GMP calls. Use the `Grant`/`Revoke`
   primitives directly only when you already have orchestration that owns the lifecycle.
   `-MaxScanMinutes` and `-PollSeconds` bound the **`-TaskId`** poll loop, so a hung scan cannot hold
   the credential open. They do **not** apply to `-ScanAction`: that block is simply invoked, so it
   must enforce its own deadline — `examples/weekly-ou-scan.ps1` shows one. A timed-out `-TaskId` scan
   is also sent `stop_task` before the credential is revoked, so it does not keep running against
   targets with a credential that no longer works.
4. **Revoke** — always, in a `finally` block: disable the account, reset the password to a value
   nobody records, overwrite the stored Greenbone value.

### The scanner side

Neither password ever reaches a command line, which takes more care than it sounds:

- The Windows side pipes the GMP request over **SSH stdin**, so it is never in argv or shell history
  on the calling host.
- `host/gmp.sh` is a world-readable **stub** that does nothing but `exec sudo -n gmp-relay.sh`.
- `host/gmp-relay.sh` is root-owned `0700` and does the Docker work. `install.sh` writes a sudoers
  rule letting the **relay account** — the Linux account the runner SSHes in as, not the AD scan
  account — run *that one command* and nothing else, so it never needs docker-group membership, which
  on any Docker host is root-equivalent.
- The relay writes the request and a `gvm-tools.conf` into a `mktemp` directory under **`/dev/shm`**
  — tmpfs, so neither is written to the filesystem, although tmpfs pages *can* be swapped, making this
  "off disk" only to the extent that swap is disabled or encrypted. Both are `0444` root-owned inside
  a `0700` root-owned directory and bind-mounted read-only; `gvm-cli` receives file paths, never
  values.

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
scan them **unauthenticated**, as a separate task with its own target. Where that holds, a managed
patch process plus an unauthenticated scan gives many people coverage they are comfortable with. It is
a trade rather than a free win: authenticated scanning is also how a scanner confirms OS patch state
and local configuration, so you are choosing to verify those through your patch reporting and
configuration baseline instead of through the scan.

How well that generalises depends on your estate. DCs that do run third-party software — backup
agents, monitoring, AV management, PKI or HSM tooling — have more that an unauthenticated scan will not
see, and the gap may matter to you. There are reasonable answers other than authenticating this
account into a DC: a separate process for tier-0 with its own credential handling and controls,
agent-based assessment, or accepting a known gap deliberately. Which of those fits is your call; the
point here is only that this tool does not try to be that answer, and its example scripts assume you
have made the decision elsewhere.

## Scope

Version 0.1.0 covers exactly one configuration, because it is the only one that has been tested:

- **Scan targets:** Windows hosts in an Active Directory domain
- **Scan account:** an AD user account
- **Runner:** Windows, PowerShell 5.1 or later, with RSAT
- **Scanner:** Greenbone Community Edition in Docker on Linux, reachable over SSH

Porting to another setup touches more than one seam:
`GvmJitCredential/Private/Invoke-GmpRequest.ps1` owns how the scanner is reached, `host/gmp-relay.sh`
owns the Docker end of that transport, the `Set-Jit*` and `Resolve-Jit*` wrappers in `Private/` own
every Active Directory call, and the `<modify_credential>` bodies in `Grant-` and
`Revoke-GvmScanCredential.ps1` own how the credential is stored. Contributions welcome; please don't
claim support for a configuration you haven't run.

## Install

```powershell
# 1. AD side: disabled scan account + delegation for the runner (run as a Domain Admin)
.\bootstrap\Initialize-GvmScanAccount.ps1 -Identity gvm-scan `
    -Path 'OU=Service Accounts,DC=example,DC=local' -RunnerAccount 'EXAMPLE\gvm-runner$' -WhatIf

# 2. Scanner host, AS ROOT. Create the Linux account the runner will SSH in as, install the
#    stub + relay + scoped sudoers rule, then fill in the GMP credentials:
#      useradd -r -m -s /bin/sh gvm-relay
#    A REAL shell is required: sshd runs both the requested command and an authorized_keys
#    forced command through the account's login shell, and /usr/sbin/nologin ignores -c and
#    exits 1 with "This account is currently not available." The forced command plus no-pty
#    below is what denies an interactive session, not the shell.
#      RELAY_ACCOUNT=gvm-relay ./host/install.sh
#      edit /opt/greenbone/.gmp.env  (chmod 600, root-owned) — a DEDICATED low-privilege GMP user,
#      which you create in Greenbone yourself; the bootstrap makes a credential, not a user.
#      Quote the password in that file: it is SOURCED by /bin/sh as root, not parsed as config.
#    Then pin the runner's key in ~gvm-relay/.ssh/authorized_keys so a stolen key cannot get a shell:
#      command="/opt/greenbone/gmp.sh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 ...
#
#    Step 3 below has to reach the relay as well, and you cannot use the runner's key for it -- that
#    key lives inside the gMSA's profile and granting yourself access to it breaks the runner's own
#    ssh (see "Gotchas"). Do NOT add a second key to ~gvm-relay/.ssh/authorized_keys either: that
#    account's whole security property is that it holds exactly ONE key pinned to ONE command, and a
#    second, longer-lived key trades a permanent runtime weakness for a one-off setup convenience.
#    Instead give YOURSELF the same scoped sudo rule for the duration of setup, and remove it after:
#      printf '%s\n' 'you ALL=(root) NOPASSWD: /opt/greenbone/gmp-relay.sh ""' \
#        > /etc/sudoers.d/99-you-setup-temp && visudo -c
#    ...then pass -ScannerHost you@scanner in step 3, and when setup is done:
#      rm /etc/sudoers.d/99-you-setup-temp && visudo -c
#    Removing it is the last step of installation, not an optional tidy-up.

# 3. Greenbone side: create the credential object and discover the UUIDs you need.
#    This makes GMP calls only — no Active Directory, nothing Windows-specific — so it needs the
#    temporary access from step 2 and nothing more. Run it once.
.\bootstrap\Initialize-GvmScanCredential.ps1 -ScannerHost you@scanner.example.local `
    -GmpHelper /opt/greenbone/gmp.sh -ScanAccount 'EXAMPLE\gvm-scan' -OutFile .\config.psd1

# 4. Decide how the account gets access on targets — your call.
#    examples\Add-ScanAccountLocalAdmin.ps1 shows one approach among several.
#    Then deny it every logon type a scan does not use. examples\New-ScanAccountLogonRightsGpo.ps1
#    builds the GPO for that (created unlinked; link it when you are ready), and
#    examples\Set-ScanAccountLogonRights.ps1 does one machine at a time. Do NOT point either at
#    the runner: a scheduled task logs on as batch, so denying that right stops the scan starting.

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

The bootstrap scripts, `weekly-ou-scan.ps1`, `Set-ScanAccountLogonRights.ps1` and
`New-ScanAccountLogonRightsGpo.ps1` support `-WhatIf`. Use it first. The scheduled-task entry points (`scan-task.ps1`, `backstop-task.ps1`) do not, because they
delegate to functions that implement it; `Test-ScanAccountLogons.ps1` does not, because it only reads.

## Gotchas that will cost you an afternoon

**The SSH key belongs to the runner account, not to you.** `ssh` resolves keys from the *calling*
account's profile, so the same code works under the scheduled task and fails when you run it by
hand. Pass `-IdentityFile` to make the dependency explicit. Do **not** grant yourself access to the
runner's `.ssh` directory to copy the key — adding an ACE makes OpenSSH reject the key as having
permissive permissions, breaking the working task.

**`known_hosts` belongs to the runner account too.** With `BatchMode=yes`, an unknown host key makes
`ssh` exit 255 with no prompt and nothing useful on the console — this module captures stderr and
reports `ssh exit 255: Host key verification failed`, but anything calling raw `ssh` will not. Verify
the fingerprint out of band before trusting it.

**An `authorized_keys` forced command overrides the command the client asks for.** Pinning the key
is worth doing — a stolen key then yields GMP relay access rather than a shell — but it also means
`ssh host /some/other/path` silently runs the pinned command instead, *and appears to succeed*. Move
the helper without updating the key and you will spend an afternoon testing the wrong binary. `sudo`'s
log on the scanner is the ground truth for which one actually ran.

**`-CannotChangePassword` does not block rotation.** That flag stops the *user* changing their own
password; the module uses an administrative reset, which is unaffected.

**Under `AllSigned`, this module will not load unless you sign it.** Everything under `GvmJitCredential/`
(both `Public/` and `Private/`, plus the `.psm1` and `.psd1`), and any bootstrap or example script you
run. Sign with *your* certificate,
not one from this repo. `examples/Sign-Module.ps1` does the loop, refuses to sign a non-CRLF file,
and re-parses everything afterwards — validating *before* signing proves nothing, because signing is
the step that can corrupt the file.

**Sign `.ps1` files with CRLF line endings.** `signtool` appends its signature block assuming CRLF;
on an LF-only file it silently eats the final line, producing a file that reports `Status: Valid`
and then fails to parse with `MissingEndCurlyBrace`. `.gitattributes` enforces CRLF on checkout for
exactly this reason.

## Testing

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Invoke-Pester -Path ./tests
```

The suite needs **no Active Directory and no scanner**. Every external dependency goes through a
private seam that the tests mock, which is why it runs in CI. It does need **Windows**: the exit-code
contract tests spawn `powershell.exe` to run the entry-point scripts as child processes, so those cases
fail under `pwsh` on Linux or macOS. CI runs on `windows-latest` for that reason. If you add a code path that talks to
AD or GMP directly instead of through those seams, it becomes untestable — please don't.

## Status

Extracted from a working deployment, then run against it. As of 0.1.0 every script here had been
executed against a live Greenbone 22.7 instance and a multi-DC Active Directory domain: the full
grant/scan/revoke lifecycle, task reuse and its refusal path, the AD delegation, the scanner relay
under load, and the backstop's failure path including a deliberately failing revoke. The 87-case test
suite needs neither.

The three scheduled-task entry points were re-verified as a signed deployment, run by the runner gMSA
under `-ExecutionPolicy AllSigned`. What was observed live, as distinct from what is covered by tests:

- **`backstop-task.ps1` — every documented code observed**: a clean revoke (0), a revoke whose
  scanner-side overwrite failed while the AD side succeeded (3), a malformed `CredentialId` and a
  config naming no scanner at all (3 each, with the AD revoke still performed — the case that matters,
  since refusing to start would leave the account enabled), and a revoke against a nonexistent
  account (1).
- **`scan-task.ps1` — the success path observed** (0), both fast and with an authenticated scan.
  Its 1, 2 and 3 are exercised in the test suite against a stub module, not live.
- **`weekly-ou-scan.ps1` — the success path observed** (0), building a target and task and then
  reusing both on a second run. Its non-zero codes share `scan-task.ps1`'s logic and are inferred
  from it; they have no test of their own.

Authentication was confirmed from the scan report itself — `login/SMB/success: TRUE` — rather than from
the scan merely finishing.

What the suite does **not** cover: there are no tests for the shell in `host/`, and the entry points'
`exit 2` for a failed grant rollback is asserted at the module level rather than through a child
process. The rest of the exit-code contract runs as a real child process against a stub module.

`New-ScanAccountLogonRightsGpo.ps1` authors a GPO's security template directly, because no cmdlet can:
User Rights Assignment is not registry policy. That means three things it has to get right, each of which
fails **silently** on its own — a UTF-16LE template with a BOM, a version bumped in both GPT.INI and the
directory object, and the Security client-side extension registered in `gPCMachineExtensionNames` with the
groups **sorted by CSE GUID** (MS-GPOL 2.2.4: processing stops at the first one out of order, so appending
without sorting disables every extension from that point on). Run it with `-WhatIf` first.

That is not a claim of correctness — it is a statement that nothing here is untried, which for this
kind of tool is the minimum bar. It supports one configuration for the same reason.

## Questions people actually ask

**Does this work with OpenVAS, or only Greenbone Community Edition?**
Either. The module talks GMP, the Greenbone Management Protocol, so it does not care which
distribution serves it. The reference relay on the scanner runs `gvm-cli` inside the Community
Edition's Docker Compose project; `COMPOSE_DIR` and the service name are both overridable, and the
relay is a short shell script to rewrite if your scanner is not Dockerised.

**Does the scan account need Domain Admin?**
No, and it should not have it. It needs local administrator on the *targets* — that is what an
authenticated scan requires to read the registry and installed-software inventory — and nothing in
Active Directory beyond existing. Domain controllers are deliberately excluded from scope, because
local administrator on a DC *is* domain administrator; see [Domain controllers](#domain-controllers).

**Why not just use a gMSA for the scan account?**
Because a gMSA's whole value is that its password never leaves Active Directory, and an authenticated
SMB scan needs the password handed to the scanner. A gMSA fits the *runner* — the account that
executes the scheduled task — and that is what the examples use. See the discussion under
[Why](#why).

**What happens if the scan crashes, or the machine reboots mid-window?**
That is what the backstop task is for: it re-runs the revoke independently, so a killed process or a
reboot does not leave the account enabled. Both entry points are in `examples/`, and the exit codes
are documented so a scheduler can tell a clean revoke from a partial one.

**Does it need WinRM or PowerShell remoting?**
No. The runner reaches the scanner over SSH to a single pinned command, and the AD work happens
locally. The local-administrator example applies group membership by Group Policy rather than by
remoting into each host.

**Windows PowerShell 5.1, or PowerShell 7?**
The manifest declares 5.1, which is what the deployment it came from runs, and the tests are executed
on it. Nothing in the module is 5.1-only, but 5.1 is the version the behaviour has been verified
against — including several places where 5.1 and 7 genuinely differ.

**Does it handle more than one domain?**
Not by itself. The domain controller is discovered as the PDC emulator of the domain the runner is a
member of, so a multi-domain forest needs one scheduled task per domain rather than one task that
crosses trusts. The GPO sample refuses a `-Identity` that names a different domain instead of
silently restricting a same-named account in the wrong one.

**Is the password ever written to disk or visible in a process list?**
Not by design, and the threat model states the residual honestly: it is passed to `gvm-cli` through
files on `tmpfs` rather than on the command line, and scanner error text is redacted before it reaches
a log. What the scanner does with the credential once it holds it is outside this tool's control.

## License

MIT. See `LICENSE`.
