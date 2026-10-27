# Display-only means of independently validated public manifests. Synthetic data only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ScanCoordinator.ps1','src/UI/Screens/Results.ps1',
    'src/UI/Screens/MainMenu.ps1','tests/Fixtures/WeightedConfiguration.ps1')){. (Join-Path $root $file)}
function Get-CimInstance {throw 'Unexpected native query.'}
function Get-MpComputerStatus {throw 'Unexpected native query.'}
function Get-MpPreference {throw 'Unexpected native query.'}
$template=(Invoke-WinSecWeightedConfigurationFixture (New-WinSecWeightedConfigurationFixture)).Summary
$state=[pscustomobject]@{SelectedDeviceId=('local:hw1-'+('b'*64))}
function New-WinSecLatestViews {
    $views=@()
    for($i=0;$i -lt 3;$i++) {
        $id='WSA-SYS-00'+($i+1);$scan='synthetic-control-'+$i
        $a=Copy-WinSecResultData $template
        $a.DeviceId=$state.SelectedDeviceId;$a.ScanId=$scan;$a.ScopeKey=$id
        $c=$a.Controls[0];$c.CheckId=$id
        for($j=0;$j -lt 3;$j++) {
            $c.Criteria[$j].Weight=1
            $c.Criteria[$j].Status=if($j -eq 0){'PASS'}else{'FAIL'}
        }
        if($i -eq 2){$c.Criteria[1].Weight=4;$c.Criteria[2].Weight=5}
        $totals=Get-WinSecConfigurationControlTotals $c $a.MethodologyVersion
        foreach($p in $totals.PSObject.Properties){$c.($p.Name)=$p.Value}
        $views += [pscustomobject]@{CheckId=$id;DeviceId=$a.DeviceId;ScanId=$scan;ScopeType='CONTROL';ScopeKey=$id;
            ControlResults=@();ConfigurationAssessment=$a}
    }
    return $views
}
$script:passed=0;$script:failed=0
function Assert-WinSecLatest {param([bool]$Value);if(-not $Value){throw 'Latest System Security summary assertion failed.'}}
function Test-WinSecLatest {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
Test-WinSecLatest 'No scans do not invent a summary or perform collection' {
    Assert-WinSecLatest ($null -eq (Get-WinSecLatestSystemSecuritySummary $state))
}
Test-WinSecLatest 'Three independent controls use original fractions rather than rounded row scores' {
    $views=@(New-WinSecLatestViews);$before=ConvertTo-Json $views -Depth 32 -Compress
    $s=Get-WinSecLatestSystemSecuritySummary $state $views
    Assert-WinSecLatest ($s.Value -eq 25.56 -and $s.Status -ceq 'COMPLETE' -and $s.Source -ceq 'LATEST_CONTROLS' -and
        $s.ScanCount -eq 3 -and $s.Sources.Count -eq 3 -and (ConvertTo-Json $views -Depth 32 -Compress) -ceq $before)
    $row=@(Get-WinSecMainMenuSections -DeviceId $state.SelectedDeviceId -SystemControlViews $views)[0]
    Assert-WinSecLatest ($row.Score -ceq '25.56/100' -and $row.Status -ceq 'LATEST_CONTROLS')
}
Test-WinSecLatest 'Two completed controls cannot publish a partial section note' {
    $s=Get-WinSecLatestSystemSecuritySummary $state @(New-WinSecLatestViews|Select-Object -First 2)
    Assert-WinSecLatest ($null -eq $s.Value -and $s.Status -ceq 'NOT_SCORED')
}
Test-WinSecLatest 'A technical unknown blocks the note and is never a security failure' {
    $views=@(New-WinSecLatestViews);$c=$views[2].ConfigurationAssessment.Controls[0];$c.Criteria[0].Status='UNKNOWN'
    $totals=Get-WinSecConfigurationControlTotals $c '1.2.0'
    foreach($p in $totals.PSObject.Properties){$c.($p.Name)=$p.Value}
    $s=Get-WinSecLatestSystemSecuritySummary $state $views
    Assert-WinSecLatest ($null -eq $s.Value -and $s.Reason -ceq 'INCOMPLETE_CONTROLS')
}
foreach($difference in @('PolicySha256','CatalogVersion','Profile','Edition','OSRelease')) {
    Test-WinSecLatest ('Incompatible contexts do not produce a mean: '+$difference) {
        $views=@(New-WinSecLatestViews);$a=$views[2].ConfigurationAssessment
        if($difference -ceq 'PolicySha256'){$a.PolicySha256='F'*64}
        elseif($difference -ceq 'CatalogVersion'){$a.CatalogVersion='different-registry'}
        else{foreach($c in $a.Controls[0].Criteria){$c.$difference='different-context'}}
        $s=Get-WinSecLatestSystemSecuritySummary $state $views
        Assert-WinSecLatest ($null -eq $s.Value -and $s.Reason -ceq 'INCOMPATIBLE_CONTEXTS')
    }
}
foreach($fault in @('Device','Scope','Score','Duplicate','ScanArray','ConflictingScan')) {
    Test-WinSecLatest ('Invalid public source is rejected before any summary: '+$fault) {
        $views=@(New-WinSecLatestViews)
        switch($fault) {
            Device {$views[0].DeviceId='local:other'}
            Scope {$views[0].ScopeKey='WSA-SYS-002'}
            Score {$views[0].ConfigurationAssessment.Controls[0].Value=100}
            Duplicate {$views[2]=$views[0]}
            ScanArray {$views[0].ScanId=@('synthetic-control-0')}
            ConflictingScan {foreach($view in $views){$view.ScanId='same-scan';$view.ConfigurationAssessment.ScanId='same-scan'}}
        }
        $caught=$false;$published=@()
        try{$published=@(Get-WinSecLatestSystemSecuritySummary $state $views)}catch{$caught=$true}
        Assert-WinSecLatest ($caught -and $published.Count -eq 0)
    }
}
[Console]::WriteLine(('Latest System Security summary: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Latest System Security summary failed.'}
