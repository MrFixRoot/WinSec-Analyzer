# Compare production permissions; never change the catalog to satisfy a test.
function Test-WinSecValidatedCatalogFixture {
    param($Catalog)
    $enabled=@($Catalog.checks|Where-Object {$_.execution.enabled -eq $true})
    $pending=@($Catalog.checks|Where-Object {$_.execution.enabled -ne $true})
    return ($Catalog.checks.Count -eq 14 -and $enabled.Count -eq 11 -and
        (($enabled.checkId|Sort-Object) -join '|') -ceq 'WSA-IAM-001|WSA-IAM-002|WSA-IAM-003|WSA-NET-001|WSA-NET-002|WSA-NET-003|WSA-NET-004|WSA-NET-005|WSA-SYS-001|WSA-SYS-002|WSA-SYS-003' -and
        @($enabled|Where-Object {$_.implementationStatus -cne 'VALIDATED'}).Count -eq 0 -and
        (($pending.checkId|Sort-Object) -join '|') -ceq 'WSA-HRD-001|WSA-LOG-001|WSA-LOG-002' -and
        @($pending|Where-Object {$_.checkId -cin @('WSA-LOG-001','WSA-LOG-002') -and $_.implementationStatus -cne 'PENDING_VALIDATION'}).Count -eq 0 -and
        @($pending|Where-Object {$_.checkId -ceq 'WSA-HRD-001' -and $_.implementationStatus -cne 'PLANNED'}).Count -eq 0 -and
        @($Catalog.checks|Where-Object {$_.assessment.scoringEligible -cne $false}).Count -eq 0 -and
        $Catalog.executionPolicy.readOnly -ceq $true -and $Catalog.executionPolicy.automaticRemediation -ceq $false -and
        $Catalog.executionPolicy.allowUnvalidatedChecks -ceq $false -and $Catalog.executionPolicy.requireEnabledCheck -ceq $true -and
        $Catalog.executionPolicy.requireImplementationValidation -ceq $true)
}
