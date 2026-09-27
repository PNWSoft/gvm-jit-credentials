# gvm-jit-credentials

Just-in-time credentials for authenticated Greenbone / OpenVAS scans.

The scan account is enabled and its password rotated **only for the duration of a scan**, then
disabled and invalidated. Between scans there is no usable credential to steal — not in the
scanner's database, and not in Active Directory.

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
estate, whose password sits in a database on an internet-facing appliance, and which nothing is
watching because it is *supposed* to be there.

This module makes that credential valid only while a scan is running.

## Threat model

**What this fixes**

- No standing usable password in the scanner database. Extracting it between scans yields a value
  that authenticates nowhere.
- No standing enabled account. Between scans the AD account is disabled, so the credential fails
  even if the password were somehow correct. Two independent layers.
- A tampered scheduled task fails closed rather than escalating, when combined with
  `-ExecutionPolicy AllSigned` in the task action.

**What this does NOT fix — read this part**

- **During a scan the credential is live**, and it holds local administrator on every target. JIT
  narrows the window from *always* to *the scan window*. It does not eliminate it. If your scan
  takes four hours, that is a four-hour window. Detect misuse as well as narrowing it — see
  `examples/Test-ScanAccountLogons.ps1`.
- **A kill -9 or a reboot mid-scan leaves the credential live.** The revoke runs in a `finally`
  block, which cannot survive the process dying outright. This is not hypothetical; it is the
  normal outcome of a reboot during a long scan. **Deploy `examples/backstop-task.ps1`** — an
  independent scheduled task that revokes unconditionally after your longest plausible scan.
- **The password exists in process memory** for the duration of the grant. .NET strings are
  immutable and are not zeroed; `Remove-Variable` drops the reference, it does not scrub the bytes.
  Anyone who can read that process's memory is already in a position to do worse.
- **Never enable PowerShell transcription for the runner account.** Transcription captures the
  plaintext password. The module never writes it to disk or to a log, but transcription operates
  above the module.
- **Anyone who is already admin on the runner host** can do all of this themselves. This defends
  the credential at rest, not the machine that legitimately holds it.

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

The GMP request travels over **SSH stdin**, never on a command line, so the password never appears
in `ps` output or shell history at either end. That is what `host/gmp.sh` is for.

## Scope

v1 covers exactly one configuration, because it is the only one that has been tested:

- **Scan targets:** Windows hosts in an Active Directory domain
- **Scan account:** an AD user account
- **Runner:** Windows, PowerShell 5.1 or later, with RSAT
- **Scanner:** Greenbone Community Edition in Docker on Linux, reachable over SSH

The seam for other setups is `host/gmp.sh` and the four AD wrappers in `GvmJitCredential/Private/`.
Nothing else knows how credentials are stored. Contributions welcome; please don't claim support
for a configuration you haven't run.

## Install

```powershell
# 1. AD side: disabled scan account + delegation for the runner (run as a Domain Admin)
.\bootstrap\Initialize-GvmScanAccount.ps1 -Identity gvm-scan `
    -Path 'OU=Service Accounts,DC=example,DC=local' -RunnerAccount 'EXAMPLE\gvm-runner$' -WhatIf

# 2. Scanner host: install the GMP helper (run on the Docker host)
#    ./host/install.sh    then edit /opt/greenbone/.gmp.env  (chmod 600)

# 3. Greenbone side: create the credential object and discover the UUIDs you need
.\bootstrap\Initialize-GvmScanCredential.ps1 -ScannerHost scanner@scanner.example.local `
    -GmpHelper /opt/greenbone/gmp.sh -ScanAccount 'EXAMPLE\gvm-scan' -OutFile .\config.psd1

# 4. Decide how the account gets access on targets -- your call.
#    examples\Add-ScanAccountLocalAdmin.ps1 shows one approach among several.

# 5. Register the scan task AND the backstop task -- see examples\
```

Every script supports `-WhatIf`. Use it first.

## Gotchas that will cost you an afternoon

**The SSH key belongs to the runner account, not to you.** `ssh` resolves keys from the *calling*
account's profile, so the same code works under the scheduled task and fails when you run it by
hand. Pass `-IdentityFile` to make the dependency explicit. Do **not** grant yourself access to the
runner's `.ssh` directory to copy the key — adding an ACE makes OpenSSH reject the key as having
permissive permissions, breaking the working task.

**`known_hosts` belongs to the runner account too.** With `BatchMode=yes`, an unknown host key makes
`ssh` fail *silently* with exit 255. Verify the fingerprint out of band before trusting it.

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

## License

MIT. See `LICENSE`.
