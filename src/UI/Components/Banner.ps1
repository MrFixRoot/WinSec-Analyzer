
function Show-Banner {
    [CmdletBinding()]
    param(
        [string]$Version = '0.9.0',
        [string]$Nickname = 'mrRoot',
        [string]$Description = 'PowerShell-based Windows security auditing toolkit',
        [string]$GitHub = 'https://github.com/MrFixRoot/WinSec-Analyzer',
        [string]$LinkedIn = 'https://www.linkedin.com/in/normanlp/'
    )

    # Obtener ancho actual de la terminal
    try {
        $width = [int]$Host.UI.RawUI.WindowSize.Width
    }
    catch {
        $width = 80
    }

    if ($width -lt 1) {
        $width = 80
    }

    # Escribir texto centrado y adaptado a la terminal
    function Write-BannerLine {
        param(
            [string]$Text,
            [ConsoleColor]$Color = 'White'
        )

        $availableWidth = [Math]::Max(1, $width - 1)

        if ($Text.Length -gt $availableWidth) {
            $Text = $Text.Substring(0, $availableWidth)
        }

        $padding = [Math]::Max(
            0,
            [Math]::Floor(($availableWidth - $Text.Length) / 2)
        )

        Write-Host ((' ' * $padding) + $Text) -ForegroundColor $Color
    }

    # Banner ASCII original
    $logo = @(
        '██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗'
        '██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝'
        '██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║     '
        '██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║     '
        '╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗'
        ' ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝'
    )

    Write-Host ''

    if ($width -ge 55) {
        foreach ($line in $logo) {
            Write-BannerLine -Text $line -Color Cyan
        }
    }
    else {
        # Versión compacta para terminales pequeñas
        Write-BannerLine -Text 'WINSEC ANALYZER' -Color Cyan
    }

    Write-Host ''

    Write-BannerLine -Text "WinSec-Analyzer v$Version" -Color White
    Write-BannerLine -Text $Nickname -Color DarkGray

    Write-Host ''

    Write-BannerLine -Text $Description -Color DarkGray
    Write-BannerLine -Text $GitHub -Color DarkCyan
    Write-BannerLine -Text $LinkedIn -Color DarkCyan

    Write-Host ''
}
