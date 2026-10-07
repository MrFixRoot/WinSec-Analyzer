<#
.SYNOPSIS
    Windows Security Analyzer.

.DESCRIPTION
    WinSec-Analizer is a PowerShell-based security auditing tool
    designed to collect and analyze security-related configuration
    information from Windows systems.

.NOTES
    Project: WinSec-Analizer
    made by: Norman Daniel L.
    https://www.linkedin.com/in/normandaniell/
#>

$ErrorActionPreference = 'Stop'

# Project paths
$FunctionsPath = Join-Path $PSScriptRoot 'Functions'

# Load functions
Get-ChildItem -Path $FunctionsPath -Filter '*.ps1' | ForEach-Object {
    . $_.FullName
}

Write-Host ""
Write-Host "WinSec-Analizer"
Write-Host "Windows Security Assessment Tool"
Write-Host "--------------------------------"
Write-Host ""

Get-SystemInfo