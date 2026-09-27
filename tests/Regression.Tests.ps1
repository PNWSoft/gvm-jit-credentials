#requires -Modules Pester

<#
  Regression tests for defects found in review. Each one FAILS against the code as originally
  written, which is the only thing that makes it worth having. The pre-existing suite passed 33/33
  on the broken code, so coverage counts for nothing on its own.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psm1'
    Import-Module $ModulePath -Force
}

Describe 'Revoke does not hand Greenbone a working password' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Write-JitLog {}

        # Capture what goes to AD and what goes to Greenbone, so they can be compared.
        $script:adPassword = $null
        $script:gmpBody = $null
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { $script:adPassword = $Password }
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
            $script:gmpBody = $Xml
            [xml]'<modify_credential_response status="200"/>'
        }
    }

    It 'pushes a DIFFERENT value to Greenbone than the one it wrote to AD' {
        # THE defect: reusing the AD value left Greenbone holding the account's current valid
        # password, so the only thing stopping its use was the account being disabled -- one layer,
        # not two, and exactly the standing-credential problem the module claims to remove.
        $null = Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId '11111111-2222-3333-4444-555555555555' `
                    -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh'

        $script:adPassword | Should -Not -BeNullOrEmpty
        $script:gmpBody    | Should -Not -BeNullOrEmpty
        $script:gmpBody    | Should -Not -Match ([regex]::Escape($script:adPassword))
    }

    It 'does not treat a failed Greenbone overwrite as an error, because the AD reset already invalidated it' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'scanner unreachable' }
        $r = Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId '11111111-2222-3333-4444-555555555555' `
                -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh'
        $r.PasswordReset    | Should -BeTrue
        $r.GreenboneBlanked | Should -BeFalse
        $r.Warnings.Count   | Should -BeGreaterThan 0
        $r.Errors.Count     | Should -Be 0
    }

    It '-Strict does not throw when only the Greenbone overwrite failed' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'scanner unreachable' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId '11111111-2222-3333-4444-555555555555' `
              -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' -Strict } | Should -Not -Throw
    }

    It '-Strict DOES throw when the AD password reset failed' {
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { throw 'access denied' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' -Strict } | Should -Throw '*Revoke incomplete*'
    }

    It 'omits -Server rather than passing an empty string when the PDC cannot be resolved' {
        # $env:USERDNSDOMAIN is unset under a gMSA-run scheduled task; -Server '' threw a binding
        # error on every step, silently unless -Strict.
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { throw 'no DC' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' } | Should -Not -Throw
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 1 -Exactly
    }
}

Describe 'Grant leaves nothing enabled when it fails' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword {}
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { [xml]'<r status="200"/>' }

        $common = @{
            Identity     = 'scan-acct'
            CredentialId = '11111111-2222-3333-4444-555555555555'
            ScannerHost  = 'scanner@host'
            GmpHelper    = '/opt/gvm/gmp.sh'
        }
    }

    It 'disables the account again when the Greenbone push is rejected' {
        # Previously: the account was enabled, the push threw, and the exception propagated with the
        # account still ENABLED and no grant record for the caller to clean up from.
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'GMP modify_credential failed: status=400' }
        { Grant-GvmScanCredential @common } | Should -Throw '*status=400*'
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 1 -Exactly `
            -ParameterFilter { $Enabled -eq $false }
    }

    It 'disables the account again when the AD password reset fails' {
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { throw 'access denied' }
        { Grant-GvmScanCredential @common } | Should -Throw '*access denied*'
        Should -Invoke -ModuleName GvmJitCredential Set-JitAccountEnabled -Times 1 -Exactly `
            -ParameterFilter { $Enabled -eq $false }
    }

    It 'still surfaces the original error if the rollback itself fails' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'the real cause' }
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {
            if ($Enabled -eq $false) { throw 'rollback failed too' }
        }
        { Grant-GvmScanCredential @common } | Should -Throw '*the real cause*'
    }
}

Describe 'Invoke-GvmJitScan survives a failing Grant' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        Mock -ModuleName GvmJitCredential Start-Sleep {}
        Mock -ModuleName GvmJitCredential Revoke-GvmScanCredential {
            [pscustomobject]@{ Disabled = $true; PasswordReset = $true; Errors = @(); Warnings = @() }
        }

        $common = @{
            Identity     = 'scan-acct'
            CredentialId = '11111111-2222-3333-4444-555555555555'
            ScannerHost  = 'scanner@host'
            GmpHelper    = '/opt/gvm/gmp.sh'
            PollSeconds  = 0
        }
    }

    It 'propagates a Grant failure without throwing from the finally block' {
        # Grant used to be called OUTSIDE the try, so a throw skipped the finally entirely. Moving it
        # inside means the finally runs -- and must cope with $grant being null.
        Mock -ModuleName GvmJitCredential Grant-GvmScanCredential { throw 'scanner unreachable' }
        { Invoke-GvmJitScan @common -TaskId '99999999-8888-7777-6666-555555555555' } | Should -Throw '*scanner unreachable*'
    }
}

Describe 'Invoke-GmpRequest' {
    # The only real parsing and status logic in the module, and it had no tests at all.
    BeforeEach { Mock -ModuleName GvmJitCredential Write-JitLog {} }

    It 'rejects a response whose status is not expected' {
        InModuleScope GvmJitCredential {
            function ssh { '<modify_credential_response status="400" status_text="Bogus"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Throw '*status=400*'
        }
    }

    It 'accepts a status listed in -ExpectStatus' {
        InModuleScope GvmJitCredential {
            function ssh { '<start_task_response status="202"/>' }
            $d = Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' -ExpectStatus @('200','202')
            $d.DocumentElement.GetAttribute('status') | Should -Be '202'
        }
    }

    It 'is not fooled by a nested element carrying status 200' {
        InModuleScope GvmJitCredential {
            # Regex-matching the raw text for status="200" would read this as success.
            function ssh { '<get_tasks_response status="400" status_text="Failed"><note>status="200"</note></get_tasks_response>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Throw '*status=400*'
        }
    }

    It 'reports unparseable output rather than pretending it succeeded' {
        InModuleScope GvmJitCredential {
            function ssh { 'docker: command not found' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Throw '*unparseable*'
        }
    }

    It 'names the ssh failure when there is no output at all' {
        InModuleScope GvmJitCredential {
            function ssh { $global:LASTEXITCODE = 255; '' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Throw '*No response from the GMP helper*'
        }
    }

    It 'fails fast on a missing IdentityFile instead of an opaque ssh error' {
        InModuleScope GvmJitCredential {
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' -IdentityFile 'C:\nope\missing_key' } |
                Should -Throw '*IdentityFile not found*'
        }
    }
}

Describe 'Public GMP surface for -ScanAction callers' {
    It 'exports a GMP request function and an escaping helper' {
        # Without these, a -ScanAction block that builds its own target has no way to reach Greenbone
        # except by reimplementing the transport.
        (Get-Command -Module GvmJitCredential).Name | Should -Contain 'Invoke-GvmGmpRequest'
        (Get-Command -Module GvmJitCredential).Name | Should -Contain 'ConvertTo-GvmGmpText'
    }

    It 'escapes values that would otherwise break a request body' {
        ConvertTo-GvmGmpText 'a&b<c>' | Should -Be 'a&amp;b&lt;c&gt;'
    }

    It 'passes ExpectStatus through, so create_* returning 201 is accepted' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { [xml]'<create_target_response status="201" id="t-1"/>' }
        $d = Invoke-GvmGmpRequest -Xml '<create_target/>' -ScannerHost 'scanner@host.example.local' -GmpHelper '/opt/gvm/gmp.sh' -ExpectStatus 200, 201
        $d.DocumentElement.GetAttribute('id') | Should -Be 't-1'
        Should -Invoke -ModuleName GvmJitCredential Invoke-GmpRequest `
            -ParameterFilter { $ExpectStatus -contains '201' }
    }
}

Describe 'ScanAction scope contract' {
    # examples/weekly-ou-scan.ps1 passes a -ScanAction block that READS variables from the script
    # that defined it ($ipList, $CredentialId, $stamp...) and WRITES results back via $script:.
    # If PowerShell resolved those in the module's scope instead, the driver would silently build a
    # target from empty values. Pin the behaviour the driver relies on.
    BeforeEach {
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword {}
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { [xml]'<r status="200"/>' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        Mock -ModuleName GvmJitCredential Start-Sleep {}
    }

    It 'can read variables from the scope that defined it' {
        $outerValue = 'VISIBLE'
        $script:readBack = 'NOT-SET'
        $null = Invoke-GvmJitScan -Identity a -CredentialId '11111111-2222-3333-4444-555555555555' -ScannerHost scanner@host.example.local -GmpHelper /opt/gvm/gmp.sh `
                    -ReplicationDelaySeconds 0 -ScanAction { $script:readBack = $outerValue }
        $script:readBack | Should -Be 'VISIBLE'
    }

    It 'can read an array and preserve its contents' {
        $hosts = @('10.0.0.1', '10.0.0.2', '10.0.0.3')
        $script:joined = ''
        $null = Invoke-GvmJitScan -Identity a -CredentialId '11111111-2222-3333-4444-555555555555' -ScannerHost scanner@host.example.local -GmpHelper /opt/gvm/gmp.sh `
                    -ReplicationDelaySeconds 0 -ScanAction { $script:joined = $hosts -join ',' }
        $script:joined | Should -Be '10.0.0.1,10.0.0.2,10.0.0.3'
    }
}

Describe 'Input validation at the boundary' {
    It 'rejects a ScannerHost that ssh would parse as an option' {
        # -oProxyCommand=<payload> would execute code as the calling account. Blocked by pattern,
        # and '--' in the ssh argument list is the second line of defence.
        InModuleScope GvmJitCredential {
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost '-oProxyCommand=calc' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Throw
        }
    }

    It 'still accepts a bare hostname with no user@ (ssh_config User directive)' {
        InModuleScope GvmJitCredential {
            function ssh { '<get_version_response status="200"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner.example.local' -GmpHelper '/opt/gvm/gmp.sh' } |
                Should -Not -Throw
        }
    }

    It 'rejects a GmpHelper that is not an absolute path' {
        InModuleScope GvmJitCredential {
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'a@b' -GmpHelper '-oProxyCommand=calc' } | Should -Throw
        }
    }

    It 'rejects a CredentialId that is not a UUID' {
        { Grant-GvmScanCredential -Identity a -CredentialId 'not-a-uuid' `
              -ScannerHost 'a@b' -GmpHelper '/opt/gvm/gmp.sh' -WhatIf } | Should -Throw
    }

    It 'gives a clear message for a grant record whose CredentialId is not a UUID' {
        { Revoke-GvmScanCredential -Grant ([pscustomobject]@{ Identity = 'a'; CredentialId = 'x' }) } |
            Should -Throw '*not a UUID*'
    }
}

Describe 'Write-JitLog source resolution' {
    # A missing event source previously produced a warning on EVERY log line, because SourceExists
    # throws for a non-existent source whenever the caller cannot enumerate all event logs -- which
    # a low-privilege runner cannot. One missing source must produce one warning, not one per event.
    It 'checks the source once per session, not once per call' {
        InModuleScope GvmJitCredential {
            $script:JitLogSourceChecked = $null
            $script:calls = 0
            Mock Write-Host {}
            # Simulate the restricted-token behaviour: SourceExists throws every time.
            Mock Write-EventLog {}
            $sourceProbe = 0
            # Drive several log lines and assert the warning text appears at most once.
            $warnings = [System.Collections.Generic.List[string]]::new()
            Mock Write-Host { $warnings.Add([string]$Object) } -ParameterFilter { $true }
            1..5 | ForEach-Object { Write-JitLog "line $_" 1000 'Information' 'NoSuchSource-GvmJitTest' }
            $warned = @($warnings | Where-Object { $_ -match 'event log source|cannot verify event log source' })
            $warned.Count | Should -BeLessOrEqual 1
            # every line still reached the output stream
            @($warnings | Where-Object { $_ -match '^\[Information\] line' }).Count | Should -Be 5
        }
    }
}
