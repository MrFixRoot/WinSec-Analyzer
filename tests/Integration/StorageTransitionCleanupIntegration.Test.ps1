[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'));$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$sandbox=Join-Path $base ('wcl-'+[guid]::NewGuid().ToString('N').Substring(0,12));$null=New-Item -ItemType Directory -Path $sandbox
$oldName=$env:COMPUTERNAME;$env:COMPUTERNAME='SYNTHETIC-CLEANUP';$passed=0;$failed=0
function Assert-WinSecCleanupFixture {param([bool]$Value);if(-not $Value){throw 'Cleanup assertion failed.'}}
function Reject-WinSecCleanupFixture {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecCleanupFixture $caught}
function Test-WinSecCleanupFixture {param($Label,[scriptblock]$Action);try{& $Action;$script:passed++;Write-Host ('[PASS] '+$Label)}catch{$script:failed++;Write-Host ('[FAIL] '+$Label+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
try {
    foreach($dir in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $dir) -Destination (Join-Path $sandbox $dir) -Recurse}
    . (Join-Path $sandbox 'src/Core/ScanCoordinator.ps1')
    . (Join-Path $sandbox 'src/Checks/Accounts/IdentityAccessCollector.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/IdentityAccessMemory.ps1')
    function Get-CimInstance {throw 'Native queries forbidden.'}
    function Get-WinSecCleanupHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-WinSecCleanupHardware -Scope Script
    Set-Alias Invoke-WinSecIdentityAccessQuery Invoke-WinSecIdentityFixtureQuery -Scope Script
    Initialize-WinSecIdentityFixture;$null=Register-WinSecLocalDevice $sandbox;$target=New-WinSecLocalTarget
    $c=New-WinSecScanCoordinator $sandbox;$c.Registry=[pscustomobject]@{schemaVersion='1.0.0';targets=@($target)}
    $s=New-WinSecIdentityFixtureSession
    $null=Save-WinSecPublicHistory $sandbox $s;$receipt=Save-WinSecTechnicalReports $c $s $target
    if($receipt.Status -cne 'SAVED'){throw 'Synthetic legacy setup failed.'}
    $foreign=Join-Path $sandbox 'reports/foreign.md';[IO.File]::WriteAllText($foreign,'SYNTHETIC FOREIGN DATA')
    $keep=Join-Path $sandbox 'reports/.gitkeep';[IO.File]::WriteAllText($keep,'')
    $inventoryBefore=Get-WinSecDeviceInventoryFingerprint $sandbox
    $plan=Get-WinSecLegacyCleanupPlan $sandbox
    Test-WinSecCleanupFixture 'Inventory classifies exactly four legacy artifacts and protects foreign files and placeholders' {
        Assert-WinSecCleanupFixture ($plan.Files.Count -eq 4 -and @($plan.Excluded|Where-Object Path -CEQ $foreign).Count -eq 1 -and @($plan.Excluded|Where-Object Reason -CEQ PLACEHOLDER).Count -eq 1)
        Assert-WinSecCleanupFixture ((Get-WinSecDeviceInventoryFingerprint $sandbox) -ceq $inventoryBefore)
    }
    Test-WinSecCleanupFixture 'Denial or a missing confirmation cannot remove artifacts' {
        $answer=Remove-WinSecLegacyResults $sandbox $plan -ConfirmAction {$false};Assert-WinSecCleanupFixture ($null -eq $answer)
        foreach($file in $plan.Files){Assert-WinSecCleanupFixture ([IO.File]::Exists($file.Path))}
        Reject-WinSecCleanupFixture {Remove-WinSecLegacyResults $sandbox $plan -ConfirmAction {'yes'}}
    }
    Test-WinSecCleanupFixture 'A stale or changed plan is rejected before any deletion' {
        $file=$plan.Files[0].Path;$bytes=[IO.File]::ReadAllBytes($file)
        try {[IO.File]::AppendAllText($file,'SYNTHETIC CORRUPTION');Reject-WinSecCleanupFixture {Remove-WinSecLegacyResults $sandbox $plan -ConfirmAction {$true}}}
        finally{[IO.File]::WriteAllBytes($file,$bytes)}
        foreach($entry in $plan.Files){Assert-WinSecCleanupFixture ([IO.File]::Exists($entry.Path))}
    }
    Test-WinSecCleanupFixture 'Confirmed cleanup removes only its exact verified files, preserving managed devices and foreign data' {
        $result=Remove-WinSecLegacyResults $sandbox $plan -ConfirmAction {param($r);Assert-WinSecCleanupFixture ($r.PlanSha256 -ceq $plan.PlanSha256 -and $r.Files.Count -eq 4);$true}
        Assert-WinSecCleanupFixture ($result.Status -ceq 'REMOVED' -and $result.RemovedCount -eq 4)
        foreach($file in $plan.Files){Assert-WinSecCleanupFixture (-not [IO.File]::Exists($file.Path))}
        Assert-WinSecCleanupFixture ([IO.File]::Exists($foreign) -and [IO.File]::Exists($keep) -and (Get-WinSecDeviceInventoryFingerprint $sandbox) -ceq $inventoryBefore)
    }
}finally{
    $env:COMPUTERNAME=$oldName;$full=[IO.Path]::GetFullPath($sandbox)
    if(-not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cnotmatch '\Awcl-[a-f0-9]{12}\z'){throw 'Unsafe cleanup fixture target.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Host ("Transition cleanup: $passed passed; $failed failed.");if($failed){exit 1}
