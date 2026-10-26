# Catalog and resolver tests only. No Windows collection or persistent artifacts.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
foreach($file in @('src/Core/ResultModel.ps1','src/Core/DeviceInventory.ps1','src/Services/FrameworkService.ps1',
    'src/Core/FrameworkMappingEngine.ps1')) {. (Join-Path $root $file)}
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Get-MpComputerStatus {throw 'Unexpected Defender query.'}
function Get-MpPreference {throw 'Unexpected Defender query.'}
function Invoke-CimMethod {throw 'Unexpected BitLocker query.'}
$script:passed=0;$script:failed=0
$catalogs=@{}
foreach($id in @('cis-controls','nist-csf','mitre-attack')) {
    $catalogs[$id]=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath (Join-Path $root ('config/frameworks/'+$id+'.json')) -Raw -Encoding UTF8)
}
function Assert-WinSecUpdateFramework {param([bool]$Value);if(-not $Value){throw 'Windows Update framework assertion failed.'}}
function Assert-WinSecUpdateFrameworkRejected {param([scriptblock]$Action);$caught=$false;try{$null=& $Action}catch{$caught=$true};Assert-WinSecUpdateFramework $caught}
function Test-WinSecUpdateFramework {
    param([string]$Name,[scriptblock]$Action)
    try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$Name)}
    catch{$script:failed++;Write-Host ('[FAIL] '+$Name+' : '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}
}
foreach($framework in @('cis-controls','nist-csf','mitre-attack')) {
    Test-WinSecUpdateFramework ('Strict JSON and framework schema remain valid: '+$framework) {
        $fw=Copy-WinSecResultData $catalogs[$framework]
        Assert-WinSecUpdateFramework (Test-WinSecFrameworkDocument $fw $framework)
        $mappings=@($fw.mappings|Where-Object checkId -CEQ 'WSA-SYS-003')
        Assert-WinSecUpdateFramework ($mappings.Count -eq 1 -and $mappings[0].references.Count -eq 3 -and
            $fw.schemaVersion -ceq '1.0.0' -and $fw.enabled -is [bool] -and $fw.enabled)
    }
    foreach($criterion in @('WSA-WUP-BASE-001','WSA-WUP-BASE-002','WSA-WUP-BASE-003')) {
        Test-WinSecUpdateFramework ('Approved criterion resolves one specific contextual recommendation: '+$framework+' / '+$criterion) {
            $fw=Copy-WinSecResultData $catalogs[$framework]
            $before=ConvertTo-Json $fw -Depth 20 -Compress
            $refs=@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-003 -CriterionId $criterion -Platform Windows -Frameworks @($fw))
            $expected=switch($framework){cis-controls {if($criterion -ceq 'WSA-WUP-BASE-003'){'2.2'}else{'7.3'}};nist-csf {'PR.PS-02'};mitre-attack {'M1051'}}
            Assert-WinSecUpdateFramework ($refs.Count -eq 1 -and $refs[0].ReferenceId -ceq $expected -and
                $refs[0].FrameworkId -ceq $framework -and $refs[0].CheckId -ceq 'WSA-SYS-003' -and
                $refs[0].Description.Length -gt 20 -and $refs[0].Recommendation.Length -gt 20 -and
                $refs[0].Url -cmatch '\Ahttps://' -and $before -ceq (ConvertTo-Json $fw -Depth 20 -Compress))
            switch($framework) {
                cis-controls {Assert-WinSecUpdateFramework ($refs[0].ReferenceType -ceq 'Safeguard' -and @($fw.safeguards|Where-Object id -CEQ $expected).Count -eq 1)}
                nist-csf {Assert-WinSecUpdateFramework ($refs[0].ReferenceType -ceq 'Subcategory' -and $refs[0].FunctionId -ceq 'PR' -and
                    $refs[0].CategoryId -ceq 'PR.PS' -and @($fw.subcategories|Where-Object id -CEQ $expected).Count -eq 1)}
                mitre-attack {Assert-WinSecUpdateFramework ($refs[0].ReferenceType -ceq 'Mitigation' -and -not $refs[0].TechniqueId -and
                    @($fw.mitigations|Where-Object id -CEQ M1051).Count -eq 1)}
            }
        }
    }
    foreach($id in @('','WSA-DEF-BASE-001','WSA-WUP-BASE-004','RestartInformation')) {
        Test-WinSecUpdateFramework ('Diagnostic or foreign criterion receives no mapping: '+$framework+' / '+$id) {
            Assert-WinSecUpdateFramework (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-003 -CriterionId $id -Platform Windows -Frameworks @($catalogs[$framework])).Count -eq 0)
        }
    }
    foreach($fault in @('Missing','Null','Empty','Scalar','Foreign','Duplicate')) {
        Test-WinSecUpdateFramework ('Catalog and resolver cannot widen an Update mapping: '+$framework+' / '+$fault) {
            $fw=Copy-WinSecResultData $catalogs[$framework]
            foreach($ref in @($fw.mappings|Where-Object checkId -CEQ 'WSA-SYS-003')[0].references) {
                switch($fault) {
                    Missing {$ref.PSObject.Properties.Remove('criterionIds')};Null {$ref.criterionIds=$null};Empty {$ref.criterionIds=@()}
                    Scalar {$ref.criterionIds='WSA-WUP-BASE-001'};Foreign {$ref.criterionIds=@('WSA-WUP-BASE-001','FOREIGN')}
                    Duplicate {$ref.criterionIds=@('WSA-WUP-BASE-001','WSA-WUP-BASE-001')}
                }
            }
            Assert-WinSecUpdateFrameworkRejected {Test-WinSecFrameworkDocument $fw $framework}
            Assert-WinSecUpdateFramework (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-003 -CriterionId WSA-WUP-BASE-001 -Platform Windows -Frameworks @($fw)).Count -eq 0)
        }
    }
    Test-WinSecUpdateFramework ('Existing Defender and BitLocker references remain available: '+$framework) {
        foreach($pair in @(@('WSA-SYS-001','WSA-DEF-BASE-001'),@('WSA-SYS-002','WSA-BLK-BASE-001'))) {
            Assert-WinSecUpdateFramework (@(Get-WinSecFrameworkMappings -CheckId $pair[0] -CriterionId $pair[1] -Platform Windows -Frameworks @($catalogs[$framework])).Count -gt 0)
        }
    }
}
foreach($fault in @('Undeclared','TechniqueSpoof','WrongType','WrongMitigation','Disabled','WrongPlatform')) {
    Test-WinSecUpdateFramework ('M1051 cannot be published as an attack technique or undeclared mitigation: '+$fault) {
        $fw=Copy-WinSecResultData $catalogs['mitre-attack']
        $platform='Windows'
        switch($fault) {
            Undeclared {$fw.mitigations=@($fw.mitigations|Where-Object id -CNE M1051)}
            TechniqueSpoof {foreach($ref in @($fw.mappings|Where-Object checkId -CEQ 'WSA-SYS-003')[0].references){$ref|Add-Member techniqueId T1068}}
            WrongType {foreach($ref in @($fw.mappings|Where-Object checkId -CEQ 'WSA-SYS-003')[0].references){$ref.type='Technique'}}
            WrongMitigation {foreach($ref in @($fw.mappings|Where-Object checkId -CEQ 'WSA-SYS-003')[0].references){$ref.mitigationId='M1041'}}
            Disabled {$fw.mappingRules.includeMitigations=$false};WrongPlatform {$platform='Linux'}
        }
        Assert-WinSecUpdateFramework (@(Get-WinSecFrameworkMappings -CheckId WSA-SYS-003 -CriterionId WSA-WUP-BASE-001 -Platform $platform -Frameworks @($fw)).Count -eq 0)
    }
}
Test-WinSecUpdateFramework 'The framework selector still offers only the approved three catalogs' {
    Assert-WinSecUpdateFramework (((Get-WinSecFrameworkDefinitions).Id -join ',') -ceq 'cis-controls,nist-csf,mitre-attack')
}
Write-Host ('Windows Update frameworks: {0} passed, {1} failed.' -f $script:passed,$script:failed)
if($script:failed){throw 'Windows Update framework tests failed.'}
