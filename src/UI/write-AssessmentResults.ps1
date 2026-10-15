

function Show-AssessmentResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Results,

        [Parameter(Mandatory)]
        [string[]]$TableColumns
    )

    # ========================================================
    # SECTION HEADER
    # ========================================================

    Write-Host ""
    Show-SectionHeader -Title $Title

    # ========================================================
    # VALIDATE RESULTS
    # ========================================================

    if ($Results.Count -eq 0) {
        Write-Host ""
        Write-Host " No assessment results available." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    # ========================================================
    # RESULTS TABLE
    # ========================================================

    Write-Host ""

    $Results |
        Format-Table -Property $TableColumns -AutoSize |
        Out-Host

    # ========================================================
    # SUMMARY
    # ========================================================

    Write-Host ("═" * 58) -ForegroundColor DarkGray
    Write-Host " Total results: $($Results.Count)" -ForegroundColor Cyan
    Write-Host ("═" * 58) -ForegroundColor DarkGray
    Write-Host ""
}
