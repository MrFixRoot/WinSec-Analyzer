#requires -Version 5.1
[CmdletBinding()]
param([string]$Version = '0.9.0')

$ErrorActionPreference = 'Stop'
$uiModule = Join-Path $PSScriptRoot 'Modules\UI\WinSec.UI.psm1'
$reports = Join-Path $PSScriptRoot 'Reports'

Import-Module -Name $uiModule -Force
Start-WinSecUI -Version $Version -ReportDirectory $reports
