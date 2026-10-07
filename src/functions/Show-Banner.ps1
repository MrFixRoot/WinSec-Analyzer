function Show-Banner {
    [CmdletBinding()]
    param(
        [string]$Version = '0.8'
    )

    Write-Host ""
    Write-Host "██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗" -ForegroundColor Cyan
    Write-Host "██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝" -ForegroundColor Cyan
    Write-Host "██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║     " -ForegroundColor Cyan
    Write-Host "██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║     " -ForegroundColor Cyan
    Write-Host "╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗" -ForegroundColor Cyan
    Write-Host " ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "            WinSec-Analyzer v$Version" -ForegroundColor White
    Write-Host "                 mrRoot" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "PowerShell-based Windows security auditing toolkit" -ForegroundColor DarkGray
    Write-Host "      linkedin.com/in/normandaniell" -ForegroundColor DarkCyan
    Write-Host ""
}