function New-EphemeralPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Generates a value in memory and changes no system state despite the New- verb.')]
    <#
    .SYNOPSIS
      Generates a random password for a single scan window.

    .DESCRIPTION
      Guarantees one character from each class so the value satisfies a typical AD complexity
      policy, then shuffles so those characters are not always in fixed positions. Ambiguous
      glyphs (I, O, l, 0, 1) are excluded: the value is never meant to be read by a human, but
      it may end up in a support transcript being compared by eye.

      This returns a [string], not a SecureString, because Set-ADAccountPassword and the GMP
      payload both need the plaintext anyway. See the README, under "Threat model -- What this does NOT fix": .NET strings are
      immutable and are not zeroed, so the value exists in process memory until collected.
      Do NOT enable PowerShell transcription for the account that runs this.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([ValidateRange(14, 127)][int]$Length = 24)

    $classes = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',   # no I, O
        'abcdefghijkmnpqrstuvwxyz',   # no l
        '23456789',                   # no 0, 1
        '!@#$%^&*()-_=+'
    )
    $all = -join $classes

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $chars = [System.Collections.Generic.List[char]]::new()
        foreach ($class in $classes) {
            $chars.Add($class[(Get-SecureRandomInt -Max $class.Length -Rng $rng)])
        }
        while ($chars.Count -lt $Length) {
            $chars.Add($all[(Get-SecureRandomInt -Max $all.Length -Rng $rng)])
        }
        # Fisher-Yates, so the four guaranteed characters are not always the first four.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-SecureRandomInt -Max ($i + 1) -Rng $rng
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        return (-join $chars)
    }
    finally { $rng.Dispose() }
}
