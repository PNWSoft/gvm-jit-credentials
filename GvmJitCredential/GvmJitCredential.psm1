#requires -Version 5.1
Set-StrictMode -Version Latest

foreach ($folder in 'Private','Public') {
    $dir = Join-Path $PSScriptRoot $folder
    if (Test-Path -LiteralPath $dir) {
        foreach ($file in Get-ChildItem -LiteralPath $dir -Filter *.ps1 | Sort-Object Name) {
            . $file.FullName
        }
    }
}

Export-ModuleMember -Function (
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter *.ps1 |
        ForEach-Object { $_.BaseName }
)
