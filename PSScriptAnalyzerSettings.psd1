@{
    # Rules excluded repo-wide, with reasons. Everything else is enforced in CI as an error.
    ExcludeRules = @(
        # The bootstrap and example scripts are interactive setup tools run by an operator at a
        # console. Their output IS the product -- coloured, ordered, human-read progress. Write-Output
        # would pollute the pipeline of anything that dot-sources them, and Write-Information is
        # invisible by default, which defeats the purpose. The module itself does not use Write-Host:
        # it logs to the Windows event log, and Test-ScanAccountLogons uses Write-Output because its
        # stdout is consumed by a monitoring system.
        'PSAvoidUsingWriteHost',

        # Fires on Pester $common splat hashtables, which are assigned in a Before* block and
        # consumed as @common inside It blocks. The analyzer cannot see through the splat.
        'PSUseDeclaredVarsMoreThanAssignments'
    )
}
