# Catalogos y variantes puras. Ningun proveedor Windows, escritura o ejecucion.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/ScanCoordinator.ps1')
. (Join-Path $root 'src/Services/WindowsUpdateProfileRegistry.ps1')
function Get-CimInstance {throw 'Unexpected native query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Get-BitLockerVolume {throw 'Unexpected BitLocker query.'}
$snapshot=Get-WinSecWindowsUpdateVariantCatalog $root
$matrix=(Get-WinSecDefenderProfileMatrix $root).Matrix
$script:passed=0;$script:failed=0
function Assert-WinSecUpdateVariant {param([bool]$Value);if(-not $Value){throw 'Windows Update variant assertion failed.'}}
function Assert-WinSecUpdateVariantRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecUpdateVariant $caught}
function Test-WinSecUpdateVariant {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
function New-WinSecVariantPolicy {
    param([string]$Release,[int]$Sku)
    $r=@($matrix.Releases|Where-Object Name -CEQ $Release)[0]
    [pscustomobject]@{CheckId='WSA-SYS-003';OSFamily='Windows';OSRelease=('Windows 11 10.0.'+$r.Build);Edition=('SKU:'+$Sku)}
}
Test-WinSecUpdateVariant 'Installed JSON has a closed schema, reviewed official sources and no execution or scoring settings' {
    Assert-WinSecUpdateVariant ($snapshot.Sha256 -cmatch '\A[A-F0-9]{64}\z' -and $snapshot.Catalog.Purpose -ceq 'PROFILE_PRESENTATION_ONLY' -and
        $snapshot.Catalog.Sources.Count -eq 5 -and (ConvertTo-Json $snapshot.Catalog -Depth 8 -Compress) -notmatch 'ExecutionEnabled|ScoringEnabled|ApprovalReference')
}
foreach($edition in $matrix.Editions) {
    Test-WinSecUpdateVariant ('Every installed context resolves exactly one family without changing its selection: '+$edition.Key) {
        foreach($release in $edition.Releases) {
            $policy=New-WinSecVariantPolicy $release $edition.Sku
            $before=ConvertTo-Json $policy -Compress
            $variant=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix $policy
            Assert-WinSecUpdateVariant ($variant.Id -cmatch '\AWSA-WUP-[A-Z_]+-(LEGACY|SPLIT)\z' -and
                $before -ceq (ConvertTo-Json $policy -Compress) -and $variant.Label -notmatch '[\p{C}]')
        }
    }
}
foreach($sku in @(98,99,100,101)) {
    Test-WinSecUpdateVariant ('Home is consumer configuration rather than an assumed managed policy verdict: '+$sku) {
        $v=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '25H2' $sku)
        Assert-WinSecUpdateVariant ($v.PolicySurface -ceq 'CONSUMER' -and $v.DeadlineModel -ceq 'Consumer policy source required' -and $v.SupportModel -ceq 'HOME_PRO')
    }
}
Test-WinSecUpdateVariant 'Pro Education uses the Pro support family while Education uses Enterprise support' {
    $pro=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '24H2' 164)
    $edu=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '24H2' 121)
    Assert-WinSecUpdateVariant ($pro.SupportModel -ceq 'HOME_PRO' -and $edu.SupportModel -ceq 'ENTERPRISE_EDUCATION' -and
        $pro.PolicySurface -ceq $edu.PolicySurface)
}
Test-WinSecUpdateVariant 'Enterprise and IoT LTSC have distinct support contexts and only the installed 24H2 selection' {
    $ent=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '24H2' 125)
    $iot=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '24H2' 191)
    Assert-WinSecUpdateVariant ($ent.Channel -ceq 'LTSC' -and $iot.Channel -ceq 'LTSC' -and $ent.SupportModel -cne $iot.SupportModel)
    Assert-WinSecUpdateVariantRejected {Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '25H2' 125)}
}
Test-WinSecUpdateVariant '21H2 distinguishes legacy deadlines from the split model in 22H2 and later' {
    $legacy=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '21H2' 48)
    $split=Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix (New-WinSecVariantPolicy '22H2' 48)
    Assert-WinSecUpdateVariant ($legacy.Id.EndsWith('-LEGACY') -and $split.Id.EndsWith('-SPLIT') -and $legacy.DeadlineModel -cne $split.DeadlineModel)
}
foreach($mutate in @(
    {$args[0].SchemaVersion=@('1.0.0')},{$args[0].Purpose='SCORING_POLICY'},{$args[0].Sources[0]='https://example.invalid'},
    {$args[0].EditionGroups[0].Skus=@(48)},{$args[0].EditionGroups[0].Channel=@('GAC')},
    {$args[0].EditionGroups[1].Key='HOME'},{$args[0].ReleaseGroups[0].Releases=@('21H2','22H2')},
    {$args[0].EditionGroups[0].Label="bad`nlabel"},{$args[0]|Add-Member Enabled $true}
)) {
    Test-WinSecUpdateVariant 'Unreviewed mappings, schema, fields and unsafe labels reject' {
        $copy=Copy-WinSecResultData $snapshot.Catalog;$null=& $mutate $copy
        Assert-WinSecUpdateVariantRejected {Assert-WinSecWindowsUpdateVariantCatalog $copy}
    }
}
foreach($mutate in @({$args[0].CheckId='WSA-SYS-001'},{$args[0].Edition='SKU:9999'},{$args[0].OSRelease='Windows 11 10.0.99999'})) {
    Test-WinSecUpdateVariant 'Foreign controls, editions and builds cannot select an arbitrary variant' {
        $policy=New-WinSecVariantPolicy '24H2' 48;$null=& $mutate $policy
        Assert-WinSecUpdateVariantRejected {Get-WinSecWindowsUpdateProfileVariant $snapshot.Catalog $matrix $policy}
    }
}
Write-Host ('Windows Update variants: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update variant tests failed.'}
