function Show-AssessmentResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter(Mandatory)]
        [string[]]$TableColumns
    )

    # ========================================================
    # TABLE
    # ========================================================

    Write-Host ""
    Write-Host "========================================"
    Write-Host "       $Title"
    Write-Host "========================================"
    Write-Host ""

    $Results |
        Format-Table -Property $TableColumns -AutoSize

    # ========================================================
    # FINDINGS
    # ========================================================

    $Findings = @(
        $Results |
            Where-Object {
                $_.Status -eq 'FAIL' -or
                $_.Status -eq 'WARNING' -or
                $_.Status -eq 'ERROR'
            }
    )

    Write-Host ""
    Write-Host "Security Findings"
    Write-Host "-----------------"

    if ($Findings.Count -eq 0) {

        Write-Host ""
        Write-Host "No security findings detected."
    }
    else {

        foreach ($Finding in $Findings) {

            Write-Host ""
            Write-Host "[$($Finding.Status)] $($Finding.Control)"
            Write-Host "Severity: $($Finding.Severity)"

            # Known Service
            if (
                $Finding.PSObject.Properties.Name -contains 'KnownService'
            ) {

                if (
                    $Finding.KnownService -and
                    $Finding.KnownService -ne 'Unknown' -and
                    $Finding.KnownService -ne '-'
                ) {

                    Write-Host "Service:"
                    Write-Host "  $($Finding.KnownService)"
                }
            }

            # Process
            if (
                $Finding.PSObject.Properties.Name -contains 'ProcessName'
            ) {

                if (
                    $Finding.ProcessName -and
                    $Finding.ProcessName -ne 'Unknown' -and
                    $Finding.ProcessName -ne '-'
                ) {

                    Write-Host "Process:"

                    if (
                        $Finding.PSObject.Properties.Name -contains 'ProcessId'
                    ) {

                        Write-Host "  $($Finding.ProcessName) (PID $($Finding.ProcessId))"
                    }
                    else {

                        Write-Host "  $($Finding.ProcessName)"
                    }
                }
            }

            # Exposure
            if (
                $Finding.PSObject.Properties.Name -contains 'Exposure'
            ) {

                if ($Finding.Exposure) {

                    Write-Host "Exposure:"
                    Write-Host "  $($Finding.Exposure)"
                }
            }

            # Evidence
            if (
                $Finding.PSObject.Properties.Name -contains 'Evidence'
            ) {

                Write-Host "Evidence:"
                Write-Host "  $($Finding.Evidence)"
            }

            # Recommendation
            if (
                $Finding.PSObject.Properties.Name -contains 'Recommendation'
            ) {

                Write-Host "Recommendation:"
                Write-Host "  $($Finding.Recommendation)"
            }
        }
    }

    # ========================================================
    # SUMMARY
    # ========================================================

    $PassCount = @(
        $Results |
            Where-Object {
                $_.Status -eq 'PASS'
            }
    ).Count

    $WarningCount = @(
        $Results |
            Where-Object {
                $_.Status -eq 'WARNING'
            }
    ).Count

    $FailCount = @(
        $Results |
            Where-Object {
                $_.Status -eq 'FAIL'
            }
    ).Count

    $ErrorCount = @(
        $Results |
            Where-Object {
                $_.Status -eq 'ERROR'
            }
    ).Count

    $InfoCount = @(
        $Results |
            Where-Object {
                $_.Status -eq 'INFO'
            }
    ).Count

    # ========================================================
    # SCORE
    # ========================================================

    $ScoredResults = @(
        $Results |
            Where-Object {
                $_.MaxScore -gt 0
            }
    )

    $ObtainedPoints = (
        $ScoredResults |
            Measure-Object -Property Score -Sum
    ).Sum

    $MaximumPoints = (
        $ScoredResults |
            Measure-Object -Property MaxScore -Sum
    ).Sum

    if ($null -eq $ObtainedPoints) {
        $ObtainedPoints = 0
    }

    if ($null -eq $MaximumPoints) {
        $MaximumPoints = 0
    }

    if ($MaximumPoints -gt 0) {

        $SecurityScore = [math]::Round(
            ($ObtainedPoints / $MaximumPoints) * 100
        )

        if ($SecurityScore -ge 90) {

            $RiskLevel = 'LOW'
        }
        elseif ($SecurityScore -ge 75) {

            $RiskLevel = 'MODERATE'
        }
        elseif ($SecurityScore -ge 50) {

            $RiskLevel = 'HIGH'
        }
        else {

            $RiskLevel = 'CRITICAL'
        }
    }
    else {
        
        $securityScore = $null = $null

        if ($ErrorCount -gt 0) {
            $RiskLevel = 'NOT ASSESSED'
        }
        else {
            $RiskLevel = 'INFORMATIONAL'
        }

    }

    # ========================================================
    # DISPLAY SUMMARY
    # ========================================================

    Write-Host ""
    Write-Host "========================================"
    Write-Host "             Summary"
    Write-Host "========================================"
    Write-Host ""

    Write-Host "PASS    : $PassCount"
    Write-Host "WARNING : $WarningCount"
    Write-Host "FAIL    : $FailCount"
    Write-Host "ERROR   : $ErrorCount"
    Write-Host "INFO    : $InfoCount"

    Write-Host ""

    if ($null -ne $SecurityScore) {

        Write-Host "Security Score : $SecurityScore/100"
        Write-Host "Risk Level     : $RiskLevel"
    }
    else {

        Write-Host "Security Score : N/A"
        Write-Host "Assessment     : $RiskLevel"
    }
}