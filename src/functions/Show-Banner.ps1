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
    Write-Host "            WinSec-Analyzer v$Version" -ForegroundColor White
    Write-Host "                 mrRoot" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "PowerShell-based Windows security auditing toolkit" -ForegroundColor DarkGray
    Write-Host "      https://github.com/MrFixRoot/WinSec-Analyzer" -ForegroundColor DarkCyan
    Write-Host "             https://www.linkedin.com/in/normanlp/" -ForegroundColor DarkCyan
    Write-Host ""
}