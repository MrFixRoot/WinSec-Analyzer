
# ============================================================
# WinSec-Analyzer
# Main Entry Point
# Version: 0.8
# ============================================================

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ============================================================
# PROJECT PATHS
# ============================================================

$ProjectRoot = $PSScriptRoot

$LoaderPath = Join-Path $ProjectRoot 'src\Core\Import-Functions.ps1'
$AnalyzerPath = Join-Path $ProjectRoot 'src\winsec-analyzer.ps1'

# ============================================================
# VALIDATE REQUIRED FILES
# ============================================================

if (-not (Test-Path -LiteralPath $LoaderPath -PathType Leaf)) {
    throw "Required file not found: $LoaderPath"
}

if (-not (Test-Path -LiteralPath $AnalyzerPath -PathType Leaf)) {
    throw "Required file not found: $AnalyzerPath"
}

# ============================================================
# IMPORT FUNCTIONS
# ============================================================

. $LoaderPath

# ============================================================
# START WINSEC-ANALYZER
# ============================================================

& $AnalyzerPath