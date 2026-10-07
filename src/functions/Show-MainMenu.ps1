function Show-MainMenu {
    [CmdletBinding()]
    param()

    Clear-Host

    Write-Host "========================================"
    Write-Host "          WinSec Analyzer"
    Write-Host "========================================"
    Write-Host " Windows Security Assessment Tool"
    Write-Host ""

    Write-Host "SYSTEM"
    Write-Host "[1] System Information"
    Write-Host ""

    Write-Host "SECURITY CONTROLS"
    Write-Host "[2] Windows Firewall"
    Write-Host "[3] Open Ports"
    Write-Host ""

    Write-Host "ASSESSMENT"
    Write-Host "[4] Full Security Assessment"
    Write-Host ""

    Write-Host "[0] Exit"
    Write-Host ""
}