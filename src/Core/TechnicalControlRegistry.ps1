# Reviewed adapters, not execution permissions. Adding an adapter never enables a check.
function Get-WinSecTechnicalControls {
    @(
        [pscustomobject]@{CheckId='WSA-SYS-001';SectionKey='SystemSecurity';Name='Windows Defender'}
        [pscustomobject]@{CheckId='WSA-SYS-002';SectionKey='SystemSecurity';Name='BitLocker'}
        [pscustomobject]@{CheckId='WSA-SYS-003';SectionKey='SystemSecurity';Name='Windows Update'}
        [pscustomobject]@{CheckId='WSA-NET-001';SectionKey='NetworkSecurity';Name='Windows Firewall'}
        [pscustomobject]@{CheckId='WSA-NET-002';SectionKey='NetworkSecurity';Name='SMBv1'}
    )
}
function Get-WinSecTechnicalControl {
    param([string]$CheckId)
    $found=@(Get-WinSecTechnicalControls|Where-Object CheckId -CEQ $CheckId)
    if($found.Count -ne 1){throw 'Technical adapter is not reviewed.'}
    return $found[0]
}
function Get-WinSecTechnicalScopeChecks {
    param([string]$ScopeType,[string]$ScopeKey)
    Assert-WinSecResultScope $ScopeType $ScopeKey
    # An unimplemented control can have an empty findings view. This is only a
    # coverage expectation; actual report/source adapters remain strictly closed.
    if($ScopeType -ceq 'CONTROL'){return $ScopeKey}
    if($ScopeType -cne 'SECTION'){throw 'An explicit review scope is required.'}
    return @(Get-WinSecTechnicalControls|Where-Object SectionKey -CEQ $ScopeKey|ForEach-Object CheckId)
}
