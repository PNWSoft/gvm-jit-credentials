function Get-SecureRandomInt {
    <#
    .SYNOPSIS
      Uniform random integer in 0..($Max-1) from a CSPRNG.

    .DESCRIPTION
      Uses rejection sampling rather than `byte % $Max`. A plain modulo favours low indices
      whenever 256 is not a multiple of $Max, which is immaterial for a throwaway password but
      indefensible in a repository people adopt for security reasons.

      RandomNumberGenerator.GetInt32() would do this for us, but it arrived in .NET Core 3.0 and
      this module targets Windows PowerShell 5.1 on .NET Framework, where it does not exist.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][ValidateRange(2, 256)][int]$Max,
        [Parameter(Mandatory)][System.Security.Cryptography.RandomNumberGenerator]$Rng
    )
    $limit  = 256 - (256 % $Max)   # discard the biased tail
    $buffer = [byte[]]::new(1)
    do { $Rng.GetBytes($buffer) } while ($buffer[0] -ge $limit)
    return [int]($buffer[0] % $Max)
}
