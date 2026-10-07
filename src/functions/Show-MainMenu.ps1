function Show-MainMenu {
    [CmdletBinding()]
    param(
        [string]$Version = '0.8'
    )

    Clear-Host

    Show-Banner -Version $Version

    $MenuWidth = 58

    function Write-CenteredTitle {
        param(
            [Parameter(Mandatory)]
            [string]$Title
        )

        $Padding = [math]::Max(
            0,
            [math]::Floor(($MenuWidth - $Title.Length) / 2)
        )

        Write-Host (" " * $Padding) -NoNewline
        Write-Host $Title -ForegroundColor Yellow
    }

    # ========================================================
    # SYSTEM
    # ========================================================

    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray
    Write-CenteredTitle -Title "SYSTEM"
    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray

    Write-Host " [1] " -ForegroundColor Cyan -NoNewline
    Write-Host "System Information"

    Write-Host ""

    # ========================================================
    # NETWORK SECURITY
    # ========================================================

    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray
    Write-CenteredTitle -Title "NETWORK SECURITY"
    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray

    Write-Host " [2] " -ForegroundColor Cyan -NoNewline
    Write-Host "Windows Firewall"

    Write-Host " [3] " -ForegroundColor Cyan -NoNewline
    Write-Host "Open Ports"

    Write-Host ""

    # ========================================================
    # ENDPOINT SECURITY
    # ========================================================

    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray
    Write-CenteredTitle -Title "ENDPOINT SECURITY"
    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray

    Write-Host " [4] " -ForegroundColor Cyan -NoNewline
    Write-Host "Windows Defender"

    Write-Host " [5] " -ForegroundColor Cyan -NoNewline
    Write-Host "BitLocker"

    Write-Host ""

    # ========================================================
    # EXIT
    # ========================================================

    Write-Host ("═" * $MenuWidth) -ForegroundColor DarkGray

    Write-Host " [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit"

    Write-Host ""
}