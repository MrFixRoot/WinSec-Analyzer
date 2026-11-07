function Get-WinSecSections {
    @(
        [pscustomobject]@{ Number=1; Domain='SystemSecurity'; Name='System Security'; Command='system' }
        [pscustomobject]@{ Number=2; Domain='NetworkSecurity'; Name='Network Security'; Command='network' }
        [pscustomobject]@{ Number=3; Domain='IdentityAccess'; Name='Identity & Access'; Command='identity' }
        [pscustomobject]@{ Number=4; Domain='ServicesHardening'; Name='Services & Hardening'; Command='services' }
        [pscustomobject]@{ Number=5; Domain='LoggingAuditing'; Name='Logging & Auditing'; Command='logging' }
        [pscustomobject]@{ Number=6; Domain='PatchManagement'; Name='Patch Management'; Command='patch' }
    )
}

function Show-WinSecHelp {
    param([string]$Domain='all')
    $resolved=Resolve-WinSecDomain $Domain
    $file=if ($resolved -eq 'all') {'README.md'} else {$resolved+'.md'}
    $path=Join-Path (Join-Path $script:WinSecRoot 'help') $file
    Write-Host ''
    Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop | ForEach-Object {
        if ($_ -match '^#{1,6}\s+') { Write-Host ('  '+($_ -replace '^#{1,6}\s+','')) -ForegroundColor Cyan }
        else { Write-Host ('  '+$_) }
    }
}

function Get-WinSecHint {
    param($Session,[string]$Domain='all',[string]$Collector)
    $section=@(Get-WinSecSections | Where-Object { $_.Domain -eq $Domain })
    $scan=if ($section.Count -gt 0) {'winsec -s '+$section[0].Command} else {'winsec -s'}
    $target=if ($Collector) {$Collector} elseif ($section.Count -gt 0) {$section[0].Command} else {'all'}
    $hints=@(
        [pscustomobject]@{ Lines=@($(if ($section.Count -gt 0) {'Scan this section:'} else {'Scan all sections on this device:'}),$scan) }
        [pscustomobject]@{ Lines=@('Type help for commands and navigation.','Esc = back / cancel   |   Q = quit') }
        [pscustomobject]@{ Lines=@('Analyze saved evidence with NIST CSF:',('winsec -a {0} -n' -f $target)) }
        [pscustomobject]@{ Lines=@('Analyze saved evidence with CIS Benchmarks:',('winsec -a {0} -c' -f $target)) }
        [pscustomobject]@{ Lines=@('Scan all sections on this device:','winsec -s') }
    )
    $hint=$hints[$Session.HintIndex % $hints.Count]
    $Session.HintIndex++
    return $hint.Lines
}

function Get-WinSecCollectorState {
    param($Session,[string]$Collector)
    $entry=@()
    if ($null -ne $Session.Context) { $entry=@($Session.Context.Manifest.collectors | Where-Object { $_.id -eq $Collector }) }
    if ($entry.Count -eq 0) { return [pscustomobject]@{ Text='Not yet'; Color='DarkGray' } }
    switch ($entry[0].status) {
        'COMPLETED' { return [pscustomobject]@{ Text='Scanned'; Color='Green' } }
        'PARTIAL' { return [pscustomobject]@{ Text='Scanned (partial)'; Color='Yellow' } }
        'NOT_APPLICABLE' { return [pscustomobject]@{ Text='Not applicable'; Color='DarkYellow' } }
        default { return [pscustomobject]@{ Text='Scan error'; Color='Red' } }
    }
}
