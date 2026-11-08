# WinSec-Analyzer | Windows 11 desktop only | PowerShell 5.1+
Set-StrictMode -Version 2.0
$script:WinSecRoot = $PSScriptRoot
. (Join-Path $PSScriptRoot 'src/core/Common.ps1')
. (Join-Path $PSScriptRoot 'src/core/Storage.ps1')
. (Join-Path $PSScriptRoot 'src/core/Devices.ps1')
. (Join-Path $PSScriptRoot 'src/core/Session.ps1')
. (Join-Path $PSScriptRoot 'src/core/Collection.ps1')
. (Join-Path $PSScriptRoot 'src/core/Analysis.ps1')
. (Join-Path $PSScriptRoot 'src/ui/Completion.ps1')
. (Join-Path $PSScriptRoot 'src/ui/Input.ps1')
. (Join-Path $PSScriptRoot 'src/ui/Help.ps1')
. (Join-Path $PSScriptRoot 'src/ui/Console.ps1')

Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src/collectors') -Filter '*.ps1' -Recurse -File |
    Sort-Object FullName | ForEach-Object { . $_.FullName }

. (Join-Path $PSScriptRoot 'src/core/Commands.ps1')
Export-ModuleMember -Function winsec,win-defender,win-firewall,win-bitlocker,win-update,win-network,win-identity,win-logging,win-services
