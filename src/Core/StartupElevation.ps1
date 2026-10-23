# WinSec Analyzer startup privilege boundary. Importing this file does nothing.
# Elevation starts the interactive launcher only; it never authorizes a scan.

function Test-WinSecAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    finally {
        if ($null -ne $identity) { $identity.Dispose() }
    }
}

function Invoke-WinSecStartupElevation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LauncherPath,
        [Parameter(Mandatory)][string]$Version,
        [switch]$ElevationAttempted
    )

    try {
        $decision = @(Test-WinSecAdministrator)
        if ($decision.Count -ne 1 -or $decision[0] -isnot [bool]) {
            throw 'Invalid administrator token result.'
        }
        if ($decision[0]) {
            return [pscustomobject]@{ Status = 'READY'; Message = '' }
        }
        if ($ElevationAttempted) {
            return [pscustomobject]@{
                Status = 'FAILED'
                Message = 'Administrator privileges were not granted. Startup stopped.'
            }
        }

        if (-not [IO.Path]::IsPathRooted($LauncherPath)) { throw 'Absolute launcher path required.' }
        $launcher = [IO.Path]::GetFullPath($LauncherPath)
        if ([IO.Path]::GetFileName($launcher) -cne 'Start-WinSec.ps1' -or
            -not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
            throw 'Launcher unavailable.'
        }
        $executableName = if ($PSVersionTable.PSEdition -ceq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
        $executable = Join-Path $PSHOME $executableName
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'PowerShell runtime unavailable.' }

        # UTF-16LE transport and literal strings preserve paths/arguments without
        # shell interpolation, including apostrophes, spaces and metacharacters.
        $command = "& '{0}' -Version '{1}' -ElevationAttempted" -f
            [Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($launcher),
            [Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Version)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $null = Start-Process -FilePath $executable -Verb RunAs `
            -ArgumentList ('-NoLogo -NoProfile -EncodedCommand ' + $encoded) `
            -WorkingDirectory ([IO.Path]::GetDirectoryName($launcher)) -WindowStyle Normal -ErrorAction Stop

        return [pscustomobject]@{ Status = 'RELAUNCHED'; Message = '' }
    }
    catch {
        $exception = $_.Exception
        for ($depth = 0; $depth -lt 8 -and $null -ne $exception; $depth++) {
            if ($exception -is [ComponentModel.Win32Exception] -and $exception.NativeErrorCode -eq 1223) {
                return [pscustomobject]@{
                    Status = 'CANCELLED'
                    Message = 'Administrator request cancelled. WinSec Analyzer was not started.'
                }
            }
            $exception = $exception.InnerException
        }
        return [pscustomobject]@{
            Status = 'FAILED'
            Message = 'Unable to start WinSec Analyzer as administrator. Startup stopped.'
        }
    }
}
