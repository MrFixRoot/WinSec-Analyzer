#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ========================================================
# PATHS
# ========================================================

$ProjectRoot = $PSScriptRoot
$MainScript  = Join-Path $ProjectRoot 'main.ps1'

# ========================================================
# VALIDATION
# ========================================================

if (-not (Test-Path -LiteralPath $MainScript -PathType Leaf)) {
    Write-Error "Main script not found: $MainScript"
    exit 1
}

# ========================================================
# EXECUTION
# ========================================================

try {
    & $MainScript
}
catch {
    Write-Error "WinSec Analyzer execution failed: $($_.Exception.Message)"
    exit 1
}