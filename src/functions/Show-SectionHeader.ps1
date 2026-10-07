function Show-SectionHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
}