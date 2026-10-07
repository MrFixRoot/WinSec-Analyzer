[CmdletBinding()]
param()

$MainScript = Join-Path $PSScriptRoot 'src\winsec-analyzer.ps1'

if (-not (Test-Path $MainScript)) {
    Write-Error "WinSec Analyzer main script not found: $MainScript"
    exit 1
}

& $MainScript