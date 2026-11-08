# Punto de entrada. Ejemplos: .\run.ps1 ; .\run.ps1 -s ; .\run.ps1 -s system
[CmdletBinding()]
param(
    [Alias('s')][switch]$Scan,
    [Alias('a')][string]$Analyze,
    [Alias('n')][switch]$Nist,
    [Alias('w')][switch]$WinSecBaseline,
    [Alias('r')][switch]$Correlate,
    [ValidateRange(1,5)][int]$Correlation,
    [Parameter(Position=0)][string]$Domain = 'all',
    [string]$Collector,
    [string]$Snapshot,
    [string]$OutputRoot,
    [switch]$Deep,
    [switch]$List,
    [switch]$Report,
    [switch]$NoBanner,
    [Alias('h')][switch]$Help
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WinSecAnalyzer.psm1') -Force -DisableNameChecking
$p = @{ Scan=$Scan; Domain=$Domain; Nist=$Nist; WinSecBaseline=$WinSecBaseline; Correlate=$Correlate; Deep=$Deep; List=$List; Report=$Report; NoBanner=$NoBanner; Help=$Help }
if ($Analyze) { $p.Analyze = $Analyze }
if ($PSBoundParameters.ContainsKey('Correlation')) { $p.Correlation=$Correlation }
if ($Collector) { $p.Collector = $Collector }
if ($Snapshot) { $p.Snapshot = $Snapshot }
if ($OutputRoot) { $p.OutputRoot = $OutputRoot }
winsec @p
