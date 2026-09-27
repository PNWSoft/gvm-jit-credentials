#requires -Version 5.1
Set-StrictMode -Version Latest

foreach ($folder in 'Private', 'Public') {
    $dir = Join-Path $PSScriptRoot $folder
    if (Test-Path -LiteralPath $dir) {
        foreach ($file in Get-ChildItem -LiteralPath $dir -Filter *.ps1 | Sort-Object Name) {
            . $file.FullName
        }
    }
}

# Exported names come from PARSING each public file, not from its filename. Deriving them from the
# filename assumes exactly one function per file and silently drops any others -- a trap that cost a
# debugging round when a second helper was added to an existing file.
$publicDir = Join-Path $PSScriptRoot 'Public'
$exported = foreach ($file in Get-ChildItem -LiteralPath $publicDir -Filter *.ps1) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
    foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        $fn.Name
    }
}
Export-ModuleMember -Function ($exported | Sort-Object -Unique)
