@{
    # Copy to config.psd1 (gitignored) and fill in. Generate most of this with
    # bootstrap\Initialize-GvmScanCredential.ps1, which prints it ready to paste.

    Identity     = 'gvm-scan'                     # sAMAccountName only, no domain prefix
    CredentialId = '00000000-0000-0000-0000-000000000000'

    ScannerHost  = 'scanner@scanner.example.local'
    GmpHelper    = '/opt/greenbone/gmp.sh'

    # Name the SSH key explicitly. Without it, ssh uses the CALLING account's profile, so the same
    # code works under the scheduled task and fails when you run it by hand.
    IdentityFile = 'C:\ProgramData\GvmJit\gmp_id_ed25519'

    TaskId       = '00000000-0000-0000-0000-000000000000'

    # Load-bearing: the reset is written to the PDC emulator and must reach the DCs your targets
    # authenticate against before the scan starts. Too short and the scan silently returns
    # unauthenticated results, which looks like a clean scan rather than a failed one.
    ReplicationDelaySeconds = 45

    PollSeconds             = 30
    MaxScanMinutes          = 300
}
