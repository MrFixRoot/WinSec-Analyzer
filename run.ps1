# Punto de entrada. Ejemplos: .\run.ps1 ; .\run.ps1 -s ; .\run.ps1 -s system
[CmdletBinding()]
param(
    [Alias('s')][switch]$Scan,
    [Alias('a')][ValidateSet('cis','nist')][string[]]$Analyze,
    [Alias('c')][ValidateRange(1,5)][int]$Correlation,
    [Parameter(Position=0)][string]$Domain = 'all',
    [string]$Collector,
    [string]$Snapshot,
    [string]$OutputRoot,
    [switch]$Deep,
    [switch]$List,
    [switch]$Report,
    [switch]$NoBanner
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WinSecAnalyzer.psm1') -Force
$p = @{ Scan=$Scan; Domain=$Domain; Deep=$Deep; List=$List; Report=$Report; NoBanner=$NoBanner }
if ($Analyze) { $p.Analyze = $Analyze }
if ($PSBoundParameters.ContainsKey('Correlation')) { $p.Correlation=$Correlation }
if ($Collector) { $p.Collector = $Collector }
if ($Snapshot) { $p.Snapshot = $Snapshot }
if ($OutputRoot) { $p.OutputRoot = $OutputRoot }
winsec @p
