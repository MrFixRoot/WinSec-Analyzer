[CmdletBinding()]param()
$ErrorActionPreference='Stop';$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Core/IdentityNativeReadOnly.ps1')
. (Join-Path $root 'tests/Fixtures/IdentityAccessNativeValidationSupport.ps1')
$passed=0
function Assert-IdentityRequest {param([bool]$Value);if(-not $Value){throw 'Identity request assertion failed.'}}
# Compiles declarations only. No entry point or native function is invoked.
Add-Type -TypeDefinition (Get-WinSecIdentityNativeSource) -ErrorAction Stop
$passed++
$target=[pscustomobject]@{DeviceId=('local:hw1-'+('b'*64));Hostname='SYNTHETIC'}
$snapshot=Open-WinSecIdentityAccessValidationSnapshot $root
try {
    $all=@()
    foreach($id in @('WSA-IAM-001','WSA-IAM-002','WSA-IAM-003')){
        $plan=Get-WinSecAssessmentProfilePlan $root @($id) WSA-W11-23H2-PRO-DEF-BASE
        $r=New-WinSecIdentityAccessValidationRequest $target $id ('a'*32) '7.0.0' $true $false '2026-10-28' $plan $snapshot
        $hash=Get-WinSecIdentityAccessValidationHash (ConvertTo-Json $r -Compress -Depth 6);$all+=$hash
        Assert-IdentityRequest ($r.ScopeKey -ceq $id -and $r.Checks.Count -eq 1 -and $r.ReadOnly -and -not $r.PersistReports -and $r.DependencyCount -eq $snapshot.Files.Count)
        $copy=Copy-WinSecResultData $r;$copy.Runtime='5.1.0';Assert-IdentityRequest ((Get-WinSecIdentityAccessValidationHash (ConvertTo-Json $copy -Compress -Depth 6)) -cne $hash)
        $options=@(Get-WinSecAssessmentProfileOptions $root @($id));$matches=@($options|Where-Object Profile -CEQ $r.Profile)
        Assert-IdentityRequest ($matches.Count -eq 1 -and $matches[0].Policies[0].CatalogSha256 -ceq $r.ProfileSha256)
        $passed++
    }
    Assert-IdentityRequest (@($all|Select-Object -Unique).Count -eq 3);$passed++
    $paths=@($snapshot.Files|ForEach-Object Path)
    Assert-IdentityRequest ('src/Core/IdentityNativeReadOnly.ps1' -cin $paths -and 'src/Checks/Accounts/IdentityAccessCollector.ps1' -cin $paths);$passed++
    Assert-WinSecIdentityAccessValidationSnapshot $root $snapshot;$passed++
}finally{foreach($stream in $snapshot.Streams){$stream.Dispose()}}
Write-Host ('Identity native request: '+$passed+' passed; 0 failed. No native API called.')
