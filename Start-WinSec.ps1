
# ============================================================
# WinSec Analyzer
# Component : Application Entry Point
# Version   : 0.9.0
# Author    : mrRoot
#
# Description:
# Official application launcher.
# Initializes the PowerShell environment and starts
# the WinSec Analyzer terminal interface.
# ============================================================

[CmdletBinding()]
param(
    [string]$Version = '0.9.0',
    [switch]$ElevationAttempted
)


# ------------------------------------------------------------
# Validate PowerShell version
# ------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'WinSec Analyzer requires PowerShell 5.1 or later.'
}


# ------------------------------------------------------------
# Validate operating system
# ------------------------------------------------------------

if (
    [Environment]::OSVersion.Platform -ne
    [PlatformID]::Win32NT
) {
    throw 'WinSec Analyzer requires Windows.'
}


# ------------------------------------------------------------
# Resolve project directories
# ------------------------------------------------------------

$ProjectRoot = $PSScriptRoot

$CLIPath = Join-Path `
    -Path $ProjectRoot `
    -ChildPath 'src\CLI\Invoke-WinSecCLI.ps1'

$StartupPath = Join-Path $ProjectRoot 'src\Core\StartupElevation.ps1'

$ConfigPath = Join-Path `
    -Path $ProjectRoot `
    -ChildPath 'config'

$ReportsPath = Join-Path `
    -Path $ProjectRoot `
    -ChildPath 'reports'

$LogsPath = Join-Path `
    -Path $ProjectRoot `
    -ChildPath 'logs'


# ------------------------------------------------------------
# Validate project structure
# ------------------------------------------------------------

if (-not (Test-Path -LiteralPath $CLIPath -PathType Leaf)) {
    throw "CLI controller not found: $CLIPath"
}

if (-not (Test-Path -LiteralPath $StartupPath -PathType Leaf)) {
    throw 'Startup elevation component not found.'
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Container)) {
    throw "Configuration directory not found: $ConfigPath"
}

if (-not (Test-Path -LiteralPath $ReportsPath -PathType Container)) {
    throw "Reports directory not found: $ReportsPath"
}

if (-not (Test-Path -LiteralPath $LogsPath -PathType Container)) {
    throw "Logs directory not found: $LogsPath"
}


# ------------------------------------------------------------
# Request administrator privileges before loading the CLI
# ------------------------------------------------------------

. $StartupPath
$StartupResult = Invoke-WinSecStartupElevation -LauncherPath $PSCommandPath `
    -Version $Version -ElevationAttempted:$ElevationAttempted

if ($StartupResult.Status -cne 'READY') {
    if ($StartupResult.Status -cin @('CANCELLED', 'FAILED')) {
        Write-Host $StartupResult.Message -ForegroundColor Yellow
    }
    # A successful relaunch starts only the elevated instance. Cancellation or
    # failure never opens the CLI, registers a device, or starts a scan.
    return
}


# ------------------------------------------------------------
# Initialize terminal environment
# ------------------------------------------------------------

try {
    $OriginalTitle = $Host.UI.RawUI.WindowTitle

    $Host.UI.RawUI.WindowTitle = "WinSec Analyzer v$Version"
}
catch {
    $OriginalTitle = $null
}


# ------------------------------------------------------------
# Start application
# ------------------------------------------------------------

try {

    # Load CLI controller without automatic execution
    . $CLIPath

    # Verify application entry function
    if (-not (Get-Command 'Invoke-WinSecCLI' `
        -CommandType Function -ErrorAction SilentlyContinue)) {

        throw 'Invoke-WinSecCLI function was not loaded.'
    }

    # Launch terminal UI
    Invoke-WinSecCLI -Version $Version

}
catch {

    Write-Host ''
    Write-Host 'WINSEC ANALYZER - APPLICATION ERROR' `
        -ForegroundColor Red

    Write-Host $_.Exception.Message `
        -ForegroundColor Yellow

    Write-Host ''

}
finally {

    # Restore original terminal title
    if ($null -ne $OriginalTitle) {
        try {
            $Host.UI.RawUI.WindowTitle = $OriginalTitle
        }
        catch {
            # Terminal does not support changing the title
        }
    }
}
