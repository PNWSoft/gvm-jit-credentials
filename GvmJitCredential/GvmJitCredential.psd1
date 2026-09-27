@{
    RootModule        = 'GvmJitCredential.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '97b94687-4074-4a85-a78d-5a00c421167a'
    Author            = 'Mike Hayner'
    CompanyName       = 'Pacific Northwest Software'
    Copyright         = '(c) 2026 Mike Hayner, Pacific Northwest Software. MIT Licensed.'
    Description       = 'Just-in-time credentials for authenticated Greenbone / OpenVAS scans. The scan account is enabled and its password rotated only for the duration of a scan, then disabled and invalidated, so no standing local-admin credential sits in the scanner database or in AD.'

    PowerShellVersion = '5.1'

    # ActiveDirectory is deliberately NOT in RequiredModules. Listing it would make the module
    # impossible to import -- and therefore to unit test -- on any machine without RSAT, including
    # CI runners. It is loaded on demand by Assert-JitAdModule, which gives an actionable error.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Grant-GvmScanCredential'
        'Revoke-GvmScanCredential'
        'Invoke-GvmJitScan'
        # Needed by -ScanAction callers who build their own targets and tasks each run.
        'Invoke-GvmGmpRequest'
        'ConvertTo-GvmGmpText'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Greenbone','OpenVAS','GVM','VulnerabilityScanning','ActiveDirectory','Credentials','JIT','Security')
            LicenseUri   = 'https://github.com/PNWSoft/gvm-jit-credentials/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/PNWSoft/gvm-jit-credentials'
            ReleaseNotes = 'Initial release: Grant/Revoke primitives, Invoke-GvmJitScan wrapper, host-side GMP helper.'
        }
    }
}
