function Show-MainMenu {
    [CmdletBinding()]
    param(
        [string]$Version = '0.8'
    )

    Clear-Host

    Show-Banner -Version $Version

    Show-SectionHeader -Title "MAIN MENU"

    Write-Host " [1] " -ForegroundColor Cyan -NoNewline
    Write-Host "System Information"

    Write-Host " [2] " -ForegroundColor Cyan -NoNewline
    Write-Host "Windows Firewall"

    Write-Host " [3] " -ForegroundColor Cyan -NoNewline
    Write-Host "Open Ports"

    Write-Host " [4] " -ForegroundColor Cyan -NoNewline
    Write-Host "Windows Defender"

    Write-Host ""
    Write-Host " [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit"

    Write-Host ""
}