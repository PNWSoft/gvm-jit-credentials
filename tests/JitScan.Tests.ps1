#requires -Modules Pester

<#
  Tests for Invoke-GvmJitScan.

  The property under test is not "does it run a scan" but "is the credential ALWAYS revoked".
  Every failure mode below -- scan throws, poll times out, Greenbone unreachable -- must still end
  with the account disabled and the password invalidated. These are the tests that would catch a
  refactor quietly moving the revoke out of the finally block.
#>

BeforeAll {
    $ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'GvmJitCredential\GvmJitCredential.psm1'
    Import-Module $ModulePath -Force
}

Describe 'Invoke-GvmJitScan' {
    BeforeEach {
        Mock -ModuleName GvmJitCredential Write-JitLog {}
        Mock -ModuleName GvmJitCredential Start-Sleep {}
        Mock -ModuleName GvmJitCredential Grant-GvmScanCredential {
            [pscustomobject]@{
                Identity = 'scan-acct'; CredentialId = 'cred-1'
                ScannerHost = 'scanner@host'; GmpHelper = '/opt/gvm/gmp.sh'
                IdentityFile = ''; Server = 'dc1.example.local'
                LogSource = 'GvmJitCredential'; GrantedAt = (Get-Date)
                ReplicationDelaySeconds = 0
            }
        }
        Mock -ModuleName GvmJitCredential Revoke-GvmScanCredential {
            [pscustomobject]@{ Disabled = $true; PasswordReset = $true; Errors = @() }
        }

        $common = @{
            Identity     = 'scan-acct'
            CredentialId = 'cred-1'
            ScannerHost  = 'scanner@host'
            GmpHelper    = '/opt/gvm/gmp.sh'
            PollSeconds  = 0
        }
    }

    Context 'happy path, existing task' {
        BeforeEach {
            Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
                if ($Xml -match 'start_task') { return [xml]'<start_task_response status="202"/>' }
                return [xml]'<get_tasks_response status="200"><task><status>Done</status><last_report><report id="rep-9"/></last_report></task></get_tasks_response>'
            }
        }

        It 'grants, scans and revokes exactly once each' {
            $r = Invoke-GvmJitScan @common -TaskId 'task-1'
            Should -Invoke -ModuleName GvmJitCredential Grant-GvmScanCredential -Times 1 -Exactly
            Should -Invoke -ModuleName GvmJitCredential Revoke-GvmScanCredential -Times 1 -Exactly
            $r.Status | Should -Be 'Done'
        }

        It 'reports the terminal status and the report id' {
            $r = Invoke-GvmJitScan @common -TaskId 'task-1'
            $r.Status   | Should -Be 'Done'
            $r.ReportId | Should -Be 'rep-9'
            $r.TaskId   | Should -Be 'task-1'
            $r.Duration | Should -Not -BeNullOrEmpty
        }

        It 'accepts 202 Accepted from start_task' {
            # start_task answers 202, not 200. Treating only 200 as success would fail every scan.
            { Invoke-GvmJitScan @common -TaskId 'task-1' } | Should -Not -Throw
        }

        It 'treats Stopped and Interrupted as terminal, not as reasons to poll forever' {
            foreach ($state in 'Stopped', 'Interrupted') {
                Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
                    if ($Xml -match 'start_task') { return [xml]'<r status="202"/>' }
                    return [xml]"<get_tasks_response status=`"200`"><task><status>$state</status></task></get_tasks_response>"
                }
                $r = Invoke-GvmJitScan @common -TaskId 'task-1'
                $r.Status | Should -Be $state
            }
        }
    }

    Context 'the credential is revoked whatever goes wrong' {
        It 'revokes when starting the task fails' {
            Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'GMP start_task failed: status=404' }
            { Invoke-GvmJitScan @common -TaskId 'task-1' } | Should -Throw
            Should -Invoke -ModuleName GvmJitCredential Revoke-GvmScanCredential -Times 1 -Exactly
        }

        It 'revokes when the scan exceeds MaxScanMinutes' {
            Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
                if ($Xml -match 'start_task') { return [xml]'<r status="202"/>' }
                return [xml]'<get_tasks_response status="200"><task><status>Running</status></task></get_tasks_response>'
            }
            { Invoke-GvmJitScan @common -TaskId 'task-1' -MaxScanMinutes 0 } |
                Should -Throw '*exceeded MaxScanMinutes*'
            Should -Invoke -ModuleName GvmJitCredential Revoke-GvmScanCredential -Times 1 -Exactly
        }

        It 'revokes when a caller-supplied ScanAction throws' {
            { Invoke-GvmJitScan @common -ScanAction { throw 'my orchestration broke' } } |
                Should -Throw '*my orchestration broke*'
            Should -Invoke -ModuleName GvmJitCredential Revoke-GvmScanCredential -Times 1 -Exactly
        }

        It 'propagates the original error rather than masking it with the revoke outcome' {
            # A revoke that swallowed or replaced the real failure would leave you debugging
            # the cleanup instead of the scan.
            Mock -ModuleName GvmJitCredential Invoke-GmpRequest { throw 'the actual root cause' }
            { Invoke-GvmJitScan @common -TaskId 'task-1' } | Should -Throw '*the actual root cause*'
        }

        It 'still revokes when the revoke itself reports partial failure' {
            Mock -ModuleName GvmJitCredential Revoke-GvmScanCredential {
                [pscustomobject]@{ Disabled = $false; PasswordReset = $true; Errors = @('disable failed') }
            }
            Mock -ModuleName GvmJitCredential Invoke-GmpRequest {
                if ($Xml -match 'start_task') { return [xml]'<r status="202"/>' }
                return [xml]'<get_tasks_response status="200"><task><status>Done</status></task></get_tasks_response>'
            }
            $r = Invoke-GvmJitScan @common -TaskId 'task-1'
            $r.Revoke.Disabled      | Should -BeFalse
            $r.Revoke.Errors.Count  | Should -BeGreaterThan 0
        }
    }

    Context 'ScanAction contract' {
        It 'hands the grant record to the script block' {
            $script:captured = $null
            $null = Invoke-GvmJitScan @common -ScanAction { param($g) $script:captured = $g }
            $script:captured.Identity | Should -Be 'scan-acct'
            $script:captured.Server   | Should -Be 'dc1.example.local'
        }

        It 'waits for replication before handing over, when a delay is configured' {
            $null = Invoke-GvmJitScan @common -ScanAction {} -ReplicationDelaySeconds 45
            Should -Invoke -ModuleName GvmJitCredential Start-Sleep -Times 1 -Exactly `
                -ParameterFilter { $Seconds -eq 45 }
        }

        It 'honours -WhatIf and neither grants nor revokes' {
            $null = Invoke-GvmJitScan @common -TaskId 'task-1' -WhatIf
            Should -Invoke -ModuleName GvmJitCredential Grant-GvmScanCredential -Times 0
            Should -Invoke -ModuleName GvmJitCredential Revoke-GvmScanCredential -Times 0
        }
    }
}
