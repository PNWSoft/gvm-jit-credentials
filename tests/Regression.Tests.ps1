#requires -Modules Pester

<#
  Regression tests for defects found in review. Each one FAILS against the code as originally
  written, which is the only thing that makes it worth having. The pre-existing suite passed 33/33
  on the broken code, so coverage counts for nothing on its own.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psd1'
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
                    -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh'

        $script:adPassword | Should -Not -BeNullOrEmpty
        $script:gmpBody    | Should -Not -BeNullOrEmpty

        # Compare the ESCAPED form, because that is what the body would contain. Comparing the raw AD
        # value let this test pass against the very defect it pins: the generated alphabet includes
        # '&', so whenever the password contained one, ConvertTo-GmpText turned it into '&amp;' in the
        # body and the raw-value regex no longer matched -- roughly 40% of runs went green on a
        # regression. Asserted on both forms so neither escaping nor its absence can hide a reuse.
        $escaped = InModuleScope GvmJitCredential -Parameters @{ p = $script:adPassword } { ConvertTo-GmpText $p }
        $script:gmpBody | Should -Not -Match ([regex]::Escape($escaped))
        $script:gmpBody | Should -Not -Match ([regex]::Escape($script:adPassword))
    }

    It 'does not treat a failed Greenbone overwrite as an error, because the AD reset already invalidated it' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'scanner unreachable' }
        $r = Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId '11111111-2222-3333-4444-555555555555' `
                -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh'
        $r.PasswordReset    | Should -BeTrue
        $r.GreenboneBlanked | Should -BeFalse
        $r.Warnings.Count   | Should -BeGreaterThan 0
        $r.Errors.Count     | Should -Be 0
    }

    It '-Strict does not throw when only the Greenbone overwrite failed' {
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'scanner unreachable' }
        { Revoke-GvmScanCredential -Identity 'scan-acct' -CredentialId '11111111-2222-3333-4444-555555555555' `
              -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' -Strict } | Should -Not -Throw
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
            ScannerHost  = 'gvm-relay@scanner.example.local'
            GmpHelper    = '/opt/greenbone/gmp.sh'
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
            ScannerHost  = 'gvm-relay@scanner.example.local'
            GmpHelper    = '/opt/greenbone/gmp.sh'
            PollSeconds  = 0
        }
    }

    It 'propagates a Grant failure without throwing from the finally block' {
        # Grant runs INSIDE the try so the finally always gets a chance to revoke; the finally must
        # therefore cope with $grant being null, which is the state when Grant itself threw.
        Mock -ModuleName GvmJitCredential Grant-GvmScanCredential { throw 'scanner unreachable' }
        { Invoke-GvmJitScan @common -TaskId '99999999-8888-7777-6666-555555555555' } | Should -Throw '*scanner unreachable*'
    }

    It 'carries the revoke result out on the exception when the SCAN fails' {
        # The gap the child-process exit-code tests cannot reach, because their stub never throws.
        # When the scan throws, the finally revokes and then the exception propagates -- and the result
        # object, including Revoke.Errors, went with it. So "timed out" and "timed out AND the account
        # is still enabled" both arrived at the scheduler as 1, documented as "not a security one".
        Mock -ModuleName GvmJitCredential Grant-GvmScanCredential {
            [pscustomobject]@{ Identity = 'scan-acct'; CredentialId = '11111111-2222-3333-4444-555555555555'
                               ScannerHost = 'gvm-relay@scanner.example.local'; GmpHelper = '/opt/greenbone/gmp.sh' }
        }
        Mock -ModuleName GvmJitCredential Revoke-GvmScanCredential {
            [pscustomobject]@{ Disabled = $false; PasswordReset = $false
                               Errors = [string[]]@('DISABLE FAILED'); Warnings = [string[]]@() }
        }
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'poll failed mid-scan' }

        $caught = $null
        try { Invoke-GvmJitScan @common -TaskId '99999999-8888-7777-6666-555555555555' }
        catch { $caught = $_ }

        $caught | Should -Not -BeNullOrEmpty
        $revoke = $caught.Exception.Data['GvmJitRevoke']
        $revoke | Should -Not -BeNullOrEmpty -Because 'the entry points need it to tell exit 2 from exit 1'
        $revoke.Errors.Count | Should -Be 1
        $revoke.Errors[0] | Should -Be 'DISABLE FAILED'
    }

    It 'stops the Greenbone task when MaxScanMinutes expires, instead of abandoning it running' {
        # Revoking while the task keeps running makes every remaining target see the scanner
        # authenticate as a now-disabled account, generating the module's own alerting signal in bulk
        # from the scanner's address -- and leaves the task Running, so the next start_task is refused.
        Mock -ModuleName GvmJitCredential Grant-GvmScanCredential {
            [pscustomobject]@{ Identity = 'scan-acct'; CredentialId = '11111111-2222-3333-4444-555555555555'
                               ScannerHost = 'gvm-relay@scanner.example.local'; GmpHelper = '/opt/greenbone/gmp.sh' }
        }
        $script:sent = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
            $script:sent.Add($Xml)
            if ($Xml -match 'get_tasks') { [xml]'<get_tasks_response status="200"><task><status>Running</status></task></get_tasks_response>' }
            else { [xml]'<r status="200"/>' }
        }

        # MaxScanMinutes 0: the deadline is already past when the first poll checks it.
        { Invoke-GvmJitScan @common -TaskId '99999999-8888-7777-6666-555555555555' -MaxScanMinutes 0 } |
            Should -Throw '*exceeded MaxScanMinutes*'

        ($script:sent | Where-Object { $_ -match '<stop_task task_id="99999999-8888-7777-6666-555555555555"/>' }).Count |
            Should -Be 1 -Because 'the timed-out task must be stopped, not left running'
    }
}

Describe 'Invoke-GmpRequest' {
    # The only real parsing and status logic in the module, and it had no tests at all.
    BeforeEach { Mock -ModuleName GvmJitCredential Write-JitLog {} }

    It 'rejects a response whose status is not expected' {
        InModuleScope GvmJitCredential {
            function ssh { '<modify_credential_response status="400" status_text="Bogus"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Throw '*status=400*'
        }
    }

    It 'accepts a status listed in -ExpectStatus' {
        InModuleScope GvmJitCredential {
            function ssh { '<start_task_response status="202"/>' }
            $d = Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' -ExpectStatus @('200','202')
            $d.DocumentElement.GetAttribute('status') | Should -Be '202'
        }
    }

    It 'is not fooled by a nested element carrying status 200' {
        InModuleScope GvmJitCredential {
            # Regex-matching the raw text for status="200" would read this as success.
            function ssh { '<get_tasks_response status="400" status_text="Failed"><note>status="200"</note></get_tasks_response>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Throw '*status=400*'
        }
    }

    It 'reports unparseable output rather than pretending it succeeded' {
        InModuleScope GvmJitCredential {
            function ssh { 'docker: command not found' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Throw '*unparseable*'
        }
    }

    It 'names the ssh failure when there is no output at all' {
        InModuleScope GvmJitCredential {
            function ssh { $global:LASTEXITCODE = 255; '' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Throw '*No response from the GMP helper*'
        }
    }

    It 'fails fast on a missing IdentityFile instead of an opaque ssh error' {
        InModuleScope GvmJitCredential {
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' -IdentityFile 'C:\nope\missing_key' } |
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
        $d = Invoke-GvmGmpRequest -Xml '<create_target/>' -ScannerHost 'gvm-relay@scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' -ExpectStatus 200, 201
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
        $null = Invoke-GvmJitScan -Identity a -CredentialId '11111111-2222-3333-4444-555555555555' -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh `
                    -ReplicationDelaySeconds 0 -ScanAction { $script:readBack = $outerValue }
        $script:readBack | Should -Be 'VISIBLE'
    }

    It 'can read an array and preserve its contents' {
        $hosts = @('10.0.0.1', '10.0.0.2', '10.0.0.3')
        $script:joined = ''
        $null = Invoke-GvmJitScan -Identity a -CredentialId '11111111-2222-3333-4444-555555555555' -ScannerHost gvm-relay@scanner.example.local -GmpHelper /opt/greenbone/gmp.sh `
                    -ReplicationDelaySeconds 0 -ScanAction { $script:joined = $hosts -join ',' }
        $script:joined | Should -Be '10.0.0.1,10.0.0.2,10.0.0.3'
    }
}

Describe 'Input validation at the boundary' {
    It 'rejects a ScannerHost that ssh would parse as an option' {
        # Asserts the PARAMETER BINDING failed, not merely that something threw. A bare -Throw passes
        # even with the ValidatePattern removed, because the call then reaches real ssh, fails to
        # resolve the hostname '-oProxyCommand=calc' and throws "No response from the GMP helper" --
        # green test, absent defence. Stub ssh too, so no fallback can supply the exception.
        InModuleScope GvmJitCredential {
            function ssh { '<r status="200"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost '-oProxyCommand=calc' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }
    }

    It 'still accepts a bare hostname with no user@ (ssh_config User directive)' {
        InModuleScope GvmJitCredential {
            function ssh { '<get_version_response status="200"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'scanner.example.local' -GmpHelper '/opt/greenbone/gmp.sh' } |
                Should -Not -Throw
        }
    }

    It 'rejects a GmpHelper that is not an absolute path' {
        InModuleScope GvmJitCredential {
            function ssh { '<r status="200"/>' }
            { Invoke-GmpRequest -Xml '<x/>' -ScannerHost 'a@b' -GmpHelper '-oProxyCommand=calc' } |
                Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
        }
    }

    It 'rejects a CredentialId that is not a UUID' {
        # Resolve-JitDomainController runs before ShouldProcess, so on a machine without RSAT this
        # test passed from THAT exception even with the pattern removed. Mock it away and assert the
        # binding exception specifically.
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        { Grant-GvmScanCredential -Identity a -CredentialId 'not-a-uuid' `
              -ScannerHost 'a@b' -GmpHelper '/opt/greenbone/gmp.sh' -WhatIf } |
            Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException])
    }

    It 'still revokes AD when the grant record has a malformed CredentialId, rather than refusing to start' {
        # The AD revoke is the security boundary; the Greenbone overwrite is hygiene. A bad CredentialId
        # must therefore degrade step 3, never prevent step 1 -- so no ValidatePattern on that parameter
        # and no throw here, because both reject before the account is disabled. Realistic input:
        # config.psd1 filled in from a -WhatIf bootstrap run holds CredentialId = '<not created>'.
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        $script:disabled = $false
        $script:reset    = $false
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled  { $script:disabled = -not $Enabled }
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword { $script:reset = $true }
        Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'must not be called with a bad id' }

        # Called directly, NOT inside a { } passed to Should -Not -Throw: assignment inside that
        # scriptblock is local to it, so $r would be $null and every assertion below would silently
        # examine nothing ($null.Count is 0, not an error). A throw here fails the test anyway, so the
        # guarantee is the same and the result is usable.
        $r = Revoke-GvmScanCredential -Grant ([pscustomobject]@{
                    Identity = 'a'; CredentialId = '<not created>'
                    ScannerHost = 'gvm-relay@scanner.example.local'; GmpHelper = '/opt/greenbone/gmp.sh' })

        $script:disabled | Should -BeTrue -Because 'disabling the account is the whole job'
        $script:reset    | Should -BeTrue -Because 'the password must be invalidated regardless'
        $r.GreenboneBlanked | Should -BeFalse
        $r.Errors.Count   | Should -Be 0 -Because 'a bad id is a hygiene problem, not a failed revoke'
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -BeLike '*not a UUID*' -Because 'the reason must still be reported'
    }

    It 'warns rather than silently skipping when the Greenbone settings are incomplete' {
        # The failure mode introduced by making those keys optional: step 3 simply fell through, so
        # GreenboneBlanked stayed false with nothing in Warnings and the task reported a clean run.
        Mock -ModuleName GvmJitCredential Resolve-JitDomainController { 'dc1.example.local' }
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        Mock -ModuleName GvmJitCredential Set-JitAccountEnabled {}
        Mock -ModuleName GvmJitCredential Set-JitAccountPassword {}

        $r = Revoke-GvmScanCredential -Identity 'a' -CredentialId '11111111-2222-3333-4444-555555555555'
        $r.GreenboneBlanked | Should -BeFalse
        $r.Warnings.Count | Should -Be 1 -Because 'a skipped overwrite must be visible in the exit code'
        $r.Warnings[0] | Should -BeLike '*ScannerHost*'
    }
}

Describe 'Write-JitLog source resolution' {
    # A missing event source previously produced a warning on EVERY log line, because SourceExists
    # throws for a non-existent source whenever the caller cannot enumerate all event logs -- which
    # a low-privilege runner cannot. One missing source must produce one warning, not one per event.
    It 'checks the source once per session, not once per call' {
        # Deliberately does NOT pre-initialise the module's state variables. An earlier version of
        # this test set $script:JitLogSourceChecked itself, which masked a real defect: under
        # StrictMode, READING an unset $script: variable throws, so production failed with
        # "The variable ... has not been set" while the test passed. Import fresh instead.
        Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psd1') -Force
        InModuleScope GvmJitCredential {
            $warnings = [System.Collections.Generic.List[string]]::new()
            Mock Write-Host { $warnings.Add([string]$Object) }
            Mock Write-EventLog {}
            1..5 | ForEach-Object { Write-JitLog "line $_" 1000 'Information' 'NoSuchSource-GvmJitTest' }
            $warned = @($warnings | Where-Object { $_ -match 'event log source' })
            $warned.Count | Should -BeLessOrEqual 1
            @($warnings | Where-Object { $_ -match '^\[Information\] line' }).Count | Should -Be 5
        }
    }

    It 'does not throw on the very first call with module state unset' {
        # The regression itself: a fresh module + first Write-JitLog must not raise a StrictMode
        # "variable has not been set" error.
        Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psd1') -Force
        InModuleScope GvmJitCredential {
            Mock Write-Host {}
            Mock Write-EventLog {}
            { Write-JitLog 'first call' 1000 'Information' 'NoSuchSource-GvmJitTest2' } | Should -Not -Throw
        }
    }
}

Describe 'Scheduled-task exit-code contract' {
    # These run the entry-point scripts as CHILD PROCESSES against a stub module, because the thing
    # under test IS the exit code, and a dot-sourced 'exit' would kill the test host instead. The
    # scripts take -ModulePath precisely so the module can be substituted here.
    #
    # The regression: a bad CredentialId left greenboneBlanked=$false, put a message in Warnings,
    # and the backstop still exited 0 -- while its own help promised non-zero when the revoke did not
    # fully succeed. Found by running it against a live scanner, not by any test that existed then.

    BeforeAll {
        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("gvmjit-exit-{0}" -f [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
        $script:examples = Join-Path (Split-Path $PSScriptRoot -Parent) 'examples'

        $script:cfg = Join-Path $script:tmp 'config.psd1'
        @'
@{
    Identity     = 'stub-scan'
    CredentialId = '11111111-2222-3333-4444-555555555555'
    ScannerHost  = 'relay@scanner.invalid'
    GmpHelper    = '/opt/greenbone/gmp.sh'
    TaskId       = '66666666-7777-8888-9999-aaaaaaaaaaaa'
}
'@ | Set-Content -LiteralPath $script:cfg -Encoding Ascii

        # Builds a stub module whose Revoke/Scan return whatever the case under test needs.
        function script:New-StubModule {
            param([string]$Name, [string[]]$Warnings = @(), [string[]]$Errors = @(), [string]$Status = 'Done')
            $path = Join-Path $script:tmp "$Name.psm1"
            $w = if ($Warnings) { "@('" + ($Warnings -join "','") + "')" } else { '@()' }
            $e = if ($Errors)   { "@('" + ($Errors   -join "','") + "')" } else { '@()' }
            @"
function New-StubRevoke {
    [pscustomobject]@{
        Identity = 'stub-scan'; Server = 'dc.invalid'
        Disabled = `$true; PasswordReset = `$true
        GreenboneBlanked = ($(if ($Warnings) { '$false' } else { '$true' }))
        Warnings = [string[]]$w
        Errors   = [string[]]$e
        RevokedAt = Get-Date
    }
}
function Revoke-GvmScanCredential {
    param(`$Identity, `$CredentialId, `$ScannerHost, `$GmpHelper, `$IdentityFile, `$LogSource,
          [switch]`$Strict, `$Grant)
    `$r = New-StubRevoke
    if (`$Strict -and `$r.Errors.Count -gt 0) { throw ('Revoke incomplete: ' + (`$r.Errors -join ' | ')) }
    `$r
}
function Invoke-GvmJitScan {
    param(`$Identity, `$CredentialId, `$TaskId, `$ScannerHost, `$GmpHelper, `$IdentityFile,
          `$ReplicationDelaySeconds, `$PollSeconds, `$MaxScanMinutes, `$LogSource, `$ScanAction)
    [pscustomobject]@{
        Status = '$Status'; ReportId = 'rpt-1'; Duration = [timespan]::FromSeconds(3)
        Revoke = New-StubRevoke
    }
}
Export-ModuleMember -Function Revoke-GvmScanCredential, Invoke-GvmJitScan
"@ | Set-Content -LiteralPath $path -Encoding Ascii
            $path
        }

        function script:Invoke-EntryScript {
            param([string]$Script, [string]$ModulePath)
            # Bypass: the working-tree copies are unsigned source. The signed artifact is verified
            # separately by examples\Sign-Module.ps1 re-parsing every file after signing.
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
                (Join-Path $script:examples $Script) -ConfigPath $script:cfg -ModulePath $ModulePath *> $null
            $LASTEXITCODE
        }
    }

    AfterAll { Remove-Item $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'backstop exits 0 when the revoke fully succeeded' {
        $m = script:New-StubModule -Name 'clean'
        script:Invoke-EntryScript -Script 'backstop-task.ps1' -ModulePath $m | Should -Be 0
    }

    It 'backstop exits 3 when the AD revoke worked but the scanner copy was not overwritten' {
        $m = script:New-StubModule -Name 'warned' -Warnings @('Greenbone credential blanking failed: status=404')
        script:Invoke-EntryScript -Script 'backstop-task.ps1' -ModulePath $m | Should -Be 3
    }

    It 'backstop exits non-zero when the AD revoke itself failed' {
        $m = script:New-StubModule -Name 'errored' -Errors @('DISABLE FAILED')
        script:Invoke-EntryScript -Script 'backstop-task.ps1' -ModulePath $m | Should -Not -Be 0
    }

    It 'scan-task exits 0 on a clean scan and revoke' {
        $m = script:New-StubModule -Name 'scanclean'
        script:Invoke-EntryScript -Script 'scan-task.ps1' -ModulePath $m | Should -Be 0
    }

    It 'scan-task exits 3 when only the scanner copy was left stale' {
        $m = script:New-StubModule -Name 'scanwarned' -Warnings @('Greenbone credential blanking failed: status=404')
        script:Invoke-EntryScript -Script 'scan-task.ps1' -ModulePath $m | Should -Be 3
    }

    It 'scan-task exits 1 when the scan did not reach Done, even though the revoke was clean' {
        $m = script:New-StubModule -Name 'scanstopped' -Status 'Stopped'
        script:Invoke-EntryScript -Script 'scan-task.ps1' -ModulePath $m | Should -Be 1
    }

    It 'scan-task exits 2 when the revoke reported errors, which outranks the scan result' {
        $m = script:New-StubModule -Name 'scanerrored' -Errors @('PASSWORD INVALIDATION FAILED') -Status 'Stopped'
        script:Invoke-EntryScript -Script 'scan-task.ps1' -ModulePath $m | Should -Be 2
    }
}

Describe 'Write-Error cannot be used as a report-then-exit in a Stop-preference script' {
    # The bug class, not one instance of it. All three entry points set $ErrorActionPreference =
    # 'Stop', under which Write-Error is TERMINATING -- so "report the errors, then exit 2" never
    # reached its exit, and the most serious outcome each script has arrived as a plain 1. It was
    # present in scan-task.ps1 and weekly-ou-scan.ps1 simultaneously, which is why this is asserted
    # over every entry point by AST rather than fixed twice and trusted.

    BeforeDiscovery {
        $script:entryPoints = Get-ChildItem (Join-Path (Split-Path $PSScriptRoot -Parent) 'examples') -Filter *.ps1 |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
    }

    It 'every Write-Error in <Name> passes -ErrorAction explicitly, if the script sets Stop' -ForEach $script:entryPoints {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)

        $setsStop = $ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $n.Left.Extent.Text -eq '$ErrorActionPreference' -and $n.Right.Extent.Text -match "'Stop'"
            }, $true).Count -gt 0

        if (-not $setsStop) { Set-ItResult -Skipped -Because 'this script does not set $ErrorActionPreference to Stop'; return }

        $writeErrors = $ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and
                $n.GetCommandName() -eq 'Write-Error'
            }, $true)

        foreach ($we in $writeErrors) {
            $txt = $we.Extent.Text
            # Must be a NON-terminating action specifically. Matching '-ErrorAction' alone accepted
            # '-ErrorAction Stop', which is the bug rather than the fix -- the assertion would have
            # passed on code that still skipped the exit following it.
            $txt | Should -Match '-ErrorAction\s+(Continue|SilentlyContinue|Ignore)' -Because `
                "Write-Error terminates under `$ErrorActionPreference='Stop', skipping the exit that follows it: $txt"
        }
    }
}

Describe 'Task registration examples survive powershell.exe -Command' {
    # MEASURED on Windows PowerShell 5.1: -Command does not propagate a called script's exit code.
    #   "& 'x.ps1' *> 'log'"        exit 3 -> 1
    #   "& { & 'x.ps1' } *> 'log'"  exit 3 -> 0, and a MISSING script -> 0 as well
    # The documented codes are worthless if the copy-pasteable registration example throws them away,
    # and the missing-script case makes a silently broken backstop look green forever.

    It 'the <Name> registration example re-exits $LASTEXITCODE and catches a script that never ran' -ForEach @(
        @{ Name = 'scan-task.ps1' }, @{ Name = 'backstop-task.ps1' }
    ) {
        $text = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) "examples\$Name") -Raw
        $help = $text.Substring(0, $text.IndexOf('#>'))

        # Assert on the ARGUMENT STRING, not on the help text as a whole. `Should -Match 'catch'`
        # matched the surrounding prose ("only the catch fixes the second"), so it passed even with the
        # catch deleted from the example -- a test that could not fail for the reason it existed.
        $action = [regex]::Match($help, '(?s)\$action\s*=\s*New-ScheduledTaskAction.*?\)\r?\n')
        $action.Success | Should -BeTrue -Because 'the help must contain a copy-pasteable $action example'
        # The backtick is expected: the example is PowerShell that BUILDS the argument string, so it
        # escapes the $ as `$ to keep it literal. Matching a bare '$' failed on correct examples.
        $action.Value | Should -Match 'exit `?\$LASTEXITCODE' -Because 'otherwise every documented exit code collapses to 0 or 1'
        $action.Value | Should -Match 'catch\s*\{' -Because 'a missing or AllSigned-refused script otherwise reports success'
    }
}

Describe 'Relayed stderr cannot carry a password into the exception message' {
    # gvm-tools validates a request BEFORE sending it and prints "Invalid XML '<the whole request>'" on
    # failure -- and for a credential push that request holds the plaintext. The relay forwards that
    # stderr so a GMP auth failure is diagnosable, and this module puts it in an exception message that
    # Write-JitLog writes to the Windows event log. Both layers must redact, or that path leaks.
    BeforeAll {
        Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psd1') -Force
    }

    # Shapes chosen by REACHABILITY, not by regex taxonomy. What this module emits is only ever a plain
    # element: New-EphemeralPassword's alphabet has no '<' or '>' (it does have '&'), and both call sites
    # pass the value through ConvertTo-GmpText. So:
    #   plain element      -- the real case, observed leaking from the live relay before the guard existed
    #   orphaned close     -- what the relay's own `tail -c 1024` leaves when it cuts off the opening
    #                         tag, since tail keeps the END of the stream
    #   unterminated tag   -- the opposite cut, or simply malformed XML from such a caller
    # The redaction is deliberately broader than these (attribute-tolerant, case-insensitive, greedy)
    # because widening costs nothing at runtime. That extra tolerance is intentionally NOT pinned: it
    # could only matter for XML no part of this project generates, and a '<' or '>' inside a value needs
    # no special rule at all, since '.' matches both under (?s).
    It 'redacts <Shape> arriving on stderr' -ForEach @(
        @{ Shape = 'a plain element';          Body = '<password>CANARY-A</password>' }
        @{ Shape = 'an orphaned close after truncation'; Body = 'CANARY-H</password>' }
        @{ Shape = 'an opening tag with no close'; Body = '<password>CANARY-I' }
    ) {
        # Passed through the environment on purpose. InModuleScope runs in the MODULE's session state, so
        # $script: does not cross from this file, and InModuleScope -Parameters reads to PSScriptAnalyzer
        # as an unused parameter because the value is only consumed inside a Mock body.
        $env:GVMJIT_TEST_STDERR_BODY = $Body
        InModuleScope GvmJitCredential {
            Mock Write-JitLog {}
            Mock Test-Path { $true }
            Mock Remove-Item {}
            # stderr echoing the request with no stdout: the gvm-tools parse-error shape.
            Mock Get-Content { "gmp-relay.sh: gvm-cli exit 1: Invalid XML '<modify_credential>$($env:GVMJIT_TEST_STDERR_BODY)'. Error was Premature end of data" }
            $err = $null
            try {
                Invoke-GmpRequest -Xml '<get_version/>' -ScannerHost 'relay@scanner.invalid' `
                    -GmpHelper '/opt/greenbone/gmp.sh'
            }
            catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            # 'CANARY' with no suffix: a partial redaction leaving any fragment must fail too.
            $err.Exception.Message | Should -Not -Match 'CANARY' -Because 'no part of a password may reach the exception message, which is logged'
            $err.Exception.Message | Should -Match 'redacted'
        }
        Remove-Item Env:\GVMJIT_TEST_STDERR_BODY -ErrorAction SilentlyContinue
    }

    It 'is idempotent: redacting already-redacted text changes nothing and re-exposes nothing' {
        InModuleScope GvmJitCredential {
            Mock Write-JitLog {}
            Mock Test-Path { $true }
            Mock Remove-Item {}
            # Feed back the exact shape a previous pass produces.
            Mock Get-Content { "gmp-relay.sh: gvm-cli exit 1: Invalid XML '<modify_credential><password>[redacted]</password>'. Error was Premature end of data" }
            $err = $null
            try {
                Invoke-GmpRequest -Xml '<get_version/>' -ScannerHost 'relay@scanner.invalid' `
                    -GmpHelper '/opt/greenbone/gmp.sh'
            }
            catch { $err = $_ }
            $err.Exception.Message | Should -Match '<password>\[redacted\]</password>'
            $err.Exception.Message | Should -Match 'Premature end of data' -Because 'the parser reason must survive a well-formed redaction'
        }
    }
}

Describe 'A failed Grant rollback reaches the scheduler, not just the event log' {
    # Worst state there is: the account was enabled, Grant's own rollback failed (event 1903), and the
    # GMP push may in fact have been applied, so Greenbone can hold the live password. It used to
    # arrive as a plain exit 1, which the entry points document as "usually the scan".
    BeforeAll {
        Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psd1') -Force
    }

    It 'marks the error so an entry point can tell this apart from an ordinary failure' {
        InModuleScope GvmJitCredential {
            Mock Write-JitLog {}
            Mock Resolve-JitDomainController { 'dc1.example.local' }
            Mock Set-JitAccountEnabled {}
            Mock New-EphemeralPassword { 'pw-not-secret-in-test' }
            Mock Set-JitAccountPassword {}
            # The push fails, so Grant rolls back; the rollback then fails too.
            Mock Invoke-GmpRequest { throw 'scanner rejected the push' }
            Mock Revoke-GvmScanCredential { throw 'AD unreachable during rollback' }

            $err = $null
            try {
                Grant-GvmScanCredential -Identity 'scan-acct' `
                    -CredentialId '11111111-2222-3333-4444-555555555555' `
                    -ScannerHost 'relay@scanner.invalid' -GmpHelper '/opt/greenbone/gmp.sh' `
                    -ReplicationDelaySeconds 0 -Confirm:$false
            }
            catch { $err = $_ }

            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Match 'scanner rejected the push' -Because 'the ORIGINAL cause must survive'
            $err.Exception.Data['GvmJitRollbackFailed'] | Should -BeTrue
        }
    }

    It 'does not mark the error when the rollback succeeded' {
        InModuleScope GvmJitCredential {
            Mock Write-JitLog {}
            Mock Resolve-JitDomainController { 'dc1.example.local' }
            Mock Set-JitAccountEnabled {}
            Mock New-EphemeralPassword { 'pw-not-secret-in-test' }
            Mock Set-JitAccountPassword {}
            Mock Invoke-GmpRequest { throw 'scanner rejected the push' }
            Mock Revoke-GvmScanCredential { [pscustomobject]@{ Errors = @(); Warnings = @() } }

            $err = $null
            try {
                Grant-GvmScanCredential -Identity 'scan-acct' `
                    -CredentialId '11111111-2222-3333-4444-555555555555' `
                    -ScannerHost 'relay@scanner.invalid' -GmpHelper '/opt/greenbone/gmp.sh' `
                    -ReplicationDelaySeconds 0 -Confirm:$false
            }
            catch { $err = $_ }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Data['GvmJitRollbackFailed'] | Should -BeNullOrEmpty
        }
    }
}
