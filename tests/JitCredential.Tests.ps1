#requires -Modules Pester

<#
  Unit tests for GvmJitCredential.

  These run with NO Active Directory and NO scanner. That is the point: every external
  dependency is reached through a private seam (Set-JitAccountEnabled, Set-JitAccountPassword,
  Resolve-JitDomainController, Invoke-GmpRequest) which is mocked here. Mocking the AD cmdlets
  directly is not possible on a machine without RSAT -- including GitHub Actions runners --
  because Pester cannot mock a command that does not exist.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psm1'
    Import-Module $ModulePath -Force
}

Describe 'New-EphemeralPassword' {
    It 'returns the requested length' {
        InModuleScope GvmJitCredential {
            (New-EphemeralPassword -Length 24).Length | Should -Be 24
            (New-EphemeralPassword -Length 32).Length | Should -Be 32
        }
    }

    It 'includes every character class so AD complexity policy is satisfied' {
        InModuleScope GvmJitCredential {
            foreach ($i in 1..100) {
                $p = New-EphemeralPassword -Length 14
                $p | Should -MatchExactly '[A-Z]'
                $p | Should -MatchExactly '[a-z]'
                $p | Should -Match '[0-9]'
                $p | Should -Match '[!@#$%^&*()\-_=+]'
            }
        }
    }

    It 'excludes glyphs that are ambiguous when read by eye' {
        InModuleScope GvmJitCredential {
            foreach ($i in 1..100) {
                New-EphemeralPassword -Length 24 | Should -Not -MatchExactly '[IOl01]'
            }
        }
    }

    It 'does not repeat itself' {
        InModuleScope GvmJitCredential {
            $all = 1..200 | ForEach-Object { New-EphemeralPassword -Length 24 }
            ($all | Sort-Object -Unique).Count | Should -Be 200
        }
    }

    It 'shuffles, so the guaranteed characters are not in fixed positions' {
        InModuleScope GvmJitCredential {
            # Unshuffled, position 0 would be upper-case every single time.
            $upperFirst = @(1..300 | ForEach-Object { New-EphemeralPassword -Length 24 } |
                             Where-Object { $_[0] -cmatch '[A-Z]' }).Count
            $upperFirst | Should -BeLessThan 260
        }
    }
}

Describe 'ConvertTo-GmpText' {
    It 'escapes characters that would break the GMP request body' {
        InModuleScope GvmJitCredential {
            ConvertTo-GmpText 'a&b'  | Should -Be 'a&amp;b'
            ConvertTo-GmpText 'a<b'  | Should -Be 'a&lt;b'
            ConvertTo-GmpText 'a>b'  | Should -Be 'a&gt;b'
            ConvertTo-GmpText ''     | Should -Be ''
        }
    }
}

Describe 'Get-SecureRandomInt' {
    It 'stays within bounds' {
        InModuleScope GvmJitCredential {
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $vals = 1..500 | ForEach-Object { Get-SecureRandomInt -Max 10 -Rng $rng }
                ($vals | Measure-Object -Minimum).Minimum | Should -BeGreaterOrEqual 0
                ($vals | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 9
            } finally { $rng.Dispose() }
        }
    }

    It 'covers the whole range' {
        InModuleScope GvmJitCredential {
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                $seen = 1..600 | ForEach-Object { Get-SecureRandomInt -Max 10 -Rng $rng } | Sort-Object -Unique
                $seen.Count | Should -Be 10
            } finally { $rng.Dispose() }
        }
    }
}

Describe 'Grant-GvmScanCredential' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword {}
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { [xml]'<modify_credential_response status="200"/>' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}

        $common = @{
            Identity     = 'scan-acct'
            CredentialId = '11111111-2222-3333-4444-555555555555'
            ScannerHost  = 'scanner@scanner.example.local'
            GmpHelper    = '/opt/gvm/gmp.sh'
        }
    }

    It 'enables the account, rotates the password and pushes it to Greenbone' {
        $null = Grant-GvmScanCredential @common
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 1 -Exactly `
            -ParameterFilter { $Enabled -eq $true }
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountPassword -Times 1 -Exactly
        Should -Invoke -ModuleName GvmJitCredential Invoke-GmpRequest -Times 1 -Exactly
    }

    It 'sets the password in AD BEFORE pushing to Greenbone' {
        # Order matters: the reverse would leave Greenbone holding a password AD does not have,
        # producing authentication failures on every target, which looks like an attack.
        $order = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { $order.Add('ad') }
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
            $order.Add('gmp'); [xml]'<r status="200"/>'
        }
        $null = Grant-GvmScanCredential @common
        $order -join ',' | Should -Be 'ad,gmp'
    }

    It 'returns a grant record that carries no password' {
        $g = Grant-GvmScanCredential @common
        $g.Identity     | Should -Be 'scan-acct'
        $g.Server       | Should -Be 'dc1.example.local'
        $g.PSObject.Properties.Name | Should -Not -Contain 'Password'
        ($g | Out-String) | Should -Not -Match 'password'
    }

    It 'propagates a Greenbone rejection instead of starting a scan with a mismatched credential' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'GMP modify_credential failed: status=400' }
        { Grant-GvmScanCredential @common } | Should -Throw '*status=400*'
    }

    It 'honours -WhatIf and changes nothing' {
        $null = Grant-GvmScanCredential @common -WhatIf
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 0
        Should -Invoke -ModuleName GvmJitCredential Invoke-GmpRequest -Times 0
    }
}

Describe 'Revoke-GvmScanCredential' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword {}
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { [xml]'<modify_credential_response status="200"/>' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}
    }

    It 'disables the account and invalidates the password' {
        $r = Revoke-GvmScanCredential -Identity 'scan-acct'
        $r.Disabled      | Should -BeTrue
        $r.PasswordReset | Should -BeTrue
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 1 -Exactly `
            -ParameterFilter { $Enabled -eq $false }
    }

    It 'still invalidates the password when the disable fails' {
        # The two layers are independent on purpose: one failing must not skip the other.
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled { throw 'access denied' }
        $r = Revoke-GvmScanCredential -Identity 'scan-acct'
        $r.Disabled      | Should -BeFalse
        $r.PasswordReset | Should -BeTrue
        $r.Errors.Count  | Should -BeGreaterThan 0
    }

    It 'does not throw by default, so it is safe inside a finally block' {
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled { throw 'boom' }
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { throw 'boom' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' } | Should -Not -Throw
    }

    It 'throws with -Strict, but only after attempting every step' {
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled { throw 'boom' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' -Strict } | Should -Throw '*Revoke incomplete*'
        # the password reset was still attempted despite the earlier failure
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountPassword -Times 1 -Exactly
    }

    It 'accepts a grant record with extra properties' {
        $grant = [pscustomobject]@{
            Identity = 'scan-acct'; CredentialId = 'cred-1'
            ScannerHost = 'scanner@host'; GmpHelper = '/opt/gvm/gmp.sh'
            Server = 'dc1.example.local'; LogSource = 'GvmJitCredential'
            GrantedAt = (Get-Date); ReplicationDelaySeconds = 45
        }
        $r = Revoke-GvmScanCredential -Grant $grant
        $r.Disabled | Should -BeTrue
    }

    It 'rejects a grant record with no Identity rather than silently doing nothing' {
        { Revoke-GvmScanCredential -Grant ([pscustomobject]@{ CredentialId = 'x' }) } |
            Should -Throw '*no Identity*'
    }

    It 'is idempotent -- a second revoke is not an error' {
        $null = Revoke-GvmScanCredential -Identity 'scan-acct'
        { Revoke-GvmScanCredential -Identity 'scan-acct' } | Should -Not -Throw
    }

    It 'treats a failed Greenbone blanking as a warning, not a failure' {
        # The AD reset has already invalidated the stored value, so this is belt-and-braces.
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'unreachable' }
        $r = Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId 'c' `
                -ScannerHost 'scanner@host' -GmpHelper '/opt/gvm/gmp.sh'
        $r.PasswordReset    | Should -BeTrue
        $r.GreenboneBlanked | Should -BeFalse
    }
}
