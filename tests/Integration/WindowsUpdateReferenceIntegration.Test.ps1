# Real bounded file reader against disposable public-reference fixtures only.
# No native queries, execution permission overrides or persistent application data.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Services/WindowsUpdateReferenceService.ps1')
function Get-CimInstance {throw 'Unexpected Windows query.'}
function Import-WinSecDeviceInventory {throw 'Unexpected device inventory read.'}
function Save-WinSecPublicHistory {throw 'Unexpected history write.'}
function Save-WinSecEvidence {throw 'Unexpected evidence write.'}
$script:passed=0;$script:failed=0
$catalogPath=Join-Path $root 'config/criteria/windows-update-servicing.json'
$json=[IO.File]::ReadAllText($catalogPath)
$expectedHash=(Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash
$checksHash=(Get-FileHash -LiteralPath (Join-Path $root 'config/checks.json') -Algorithm SHA256).Hash
$scoringHash=(Get-FileHash -LiteralPath (Join-Path $root 'config/scoring.json') -Algorithm SHA256).Hash
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot=Join-Path $tempParent ('WinSec-WU-reference-'+[guid]::NewGuid().ToString('N'))
$configPath=Join-Path $tempRoot 'config';$criteriaPath=Join-Path $configPath 'criteria'
$fixturePath=Join-Path $criteriaPath 'windows-update-servicing.json'
$null=[IO.Directory]::CreateDirectory($criteriaPath)
$utf8=New-Object Text.UTF8Encoding($false,$true)
function Assert-WinSecWUReferenceIntegration {param([bool]$Value);if(-not $Value){throw 'Windows Update reference integration assertion failed.'}}
function Assert-WinSecWUReferenceLoadRejected {
    param([string]$Root=$tempRoot)
    $message=$null;try{$null=Get-WinSecWindowsUpdateReferenceCatalog $Root}catch{$message=$_.Exception.Message}
    Assert-WinSecWUReferenceIntegration ($message -ceq 'Windows Update reference catalog could not be validated.')
}
function Test-WinSecWUReferenceIntegration {
    param([string]$Name,[scriptblock]$Action)
    try {
        [IO.File]::WriteAllText($fixturePath,$json,$utf8)
        $null=& $Action;$script:passed++;[Console]::WriteLine('[PASS] '+$Name)
    } catch {
        $script:failed++;[Console]::WriteLine('[FAIL] '+$Name+' : '+$_.Exception.Message);[Console]::WriteLine($_.ScriptStackTrace)
    }
}
try {
    Test-WinSecWUReferenceIntegration 'Importing the modules defines functions without opening inventory, files or Windows providers' {
        function Get-Item {throw 'Unexpected import stat.'};function Get-Content {throw 'Unexpected import read.'}
        . (Join-Path $root 'src/Services/WindowsUpdateReferenceService.ps1')
    }
    Test-WinSecWUReferenceIntegration 'The installed catalog hash describes the exact bytes read; no application data is needed' {
        $snapshot=Get-WinSecWindowsUpdateReferenceCatalog $root
        Assert-WinSecWUReferenceIntegration ($snapshot.Sha256 -ceq $expectedHash -and
            $snapshot.Catalog.CatalogVersion -ceq '2026.10.24.1')
    }
    foreach($fault in @('Repeated','CaseRepeated','Comment','TrailingComma','Reserved','WrongSchema')) {
        Test-WinSecWUReferenceIntegration ('Strict JSON and schema validation reject: '+$fault) {
            $bad=switch($fault) {
                Repeated {$json.Replace('"SchemaVersion": "1.0.0"','"SchemaVersion": "1.0.0", "SchemaVersion": "1.0.0"')}
                CaseRepeated {$json.Replace('"SchemaVersion": "1.0.0"','"SchemaVersion": "1.0.0", "schemaversion": "1.0.0"')}
                Comment {$json.Replace('"SchemaVersion":','/* PRIVATE-WU */ "SchemaVersion":')}
                TrailingComma {$json.TrimEnd().Substring(0,$json.TrimEnd().Length-1)+',}'}
                Reserved {$json.Replace('"SchemaVersion":','"psbase": "PRIVATE-WU", "SchemaVersion":')}
                WrongSchema {$json.Replace('"SchemaVersion": "1.0.0"','"SchemaVersion": "9.0.0"')}
            }
            [IO.File]::WriteAllText($fixturePath,$bad,$utf8)
            Assert-WinSecWUReferenceLoadRejected
        }
    }
    Test-WinSecWUReferenceIntegration 'Invalid UTF-8 is not silently replaced with another document' {
        [IO.File]::WriteAllBytes($fixturePath,[byte[]]@(123,34,193,129,34,58,49,125))
        Assert-WinSecWUReferenceLoadRejected
    }
    Test-WinSecWUReferenceIntegration 'Oversized and empty documents are rejected before parsing' {
        [IO.File]::WriteAllBytes($fixturePath,(New-Object byte[] 1048577));Assert-WinSecWUReferenceLoadRejected
        [IO.File]::WriteAllBytes($fixturePath,[byte[]]@());Assert-WinSecWUReferenceLoadRejected
    }
    Test-WinSecWUReferenceIntegration 'Missing reference files do not trigger creation or default scoring data' {
        [IO.File]::Delete($fixturePath);Assert-WinSecWUReferenceLoadRejected
        Assert-WinSecWUReferenceIntegration (-not [IO.File]::Exists($fixturePath))
    }
    Test-WinSecWUReferenceIntegration 'A directory cannot substitute for the fixed reference file' {
        [IO.File]::Delete($fixturePath);$null=[IO.Directory]::CreateDirectory($fixturePath)
        try {Assert-WinSecWUReferenceLoadRejected} finally {[IO.Directory]::Delete($fixturePath)}
    }
    foreach($linked in @('File','Criteria','Root','Ancestor')) {
        Test-WinSecWUReferenceIntegration ('A reparse point is rejected without following it: '+$linked) {
            $linkedPath=switch($linked){File {$fixturePath};Criteria {$criteriaPath};Root {$tempRoot};Ancestor {$tempParent.TrimEnd('\','/')}}
            function Get-Item {
                [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
                $item=Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
                if([string]::Equals($LiteralPath,$linkedPath,[StringComparison]::OrdinalIgnoreCase)) {
                    return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;PSIsContainer=$item.PSIsContainer}
                }
                return $item
            }
            Assert-WinSecWUReferenceLoadRejected
        }
    }
    Test-WinSecWUReferenceIntegration 'An existing writer lock prevents a partially read snapshot' {
        $writer=[IO.File]::Open($fixturePath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {Assert-WinSecWUReferenceLoadRejected} finally {$writer.Dispose()}
        $snapshot=Get-WinSecWindowsUpdateReferenceCatalog $tempRoot
        Assert-WinSecWUReferenceIntegration ($snapshot.Catalog.CatalogVersion -ceq '2026.10.24.1')
    }
    Test-WinSecWUReferenceIntegration 'Successful and rejected reads both release their file handles' {
        $null=Get-WinSecWindowsUpdateReferenceCatalog $tempRoot
        $writer=[IO.File]::Open($fixturePath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None);$writer.Dispose()
        [IO.File]::WriteAllText($fixturePath,'{"PRIVATE-WU":true}',$utf8);Assert-WinSecWUReferenceLoadRejected
        $writer=[IO.File]::Open($fixturePath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None);$writer.Dispose()
    }
    Test-WinSecWUReferenceIntegration 'A new reference snapshot cannot mutate an earlier loaded catalog' {
        $first=Get-WinSecWindowsUpdateReferenceCatalog $tempRoot
        [IO.File]::WriteAllText($fixturePath,$json.Replace('2026.10.24.1','2026.10.24.2'),$utf8)
        $second=Get-WinSecWindowsUpdateReferenceCatalog $tempRoot
        Assert-WinSecWUReferenceIntegration ($first.Catalog.CatalogVersion -ceq '2026.10.24.1' -and
            $second.Catalog.CatalogVersion -ceq '2026.10.24.2' -and $first.Sha256 -cne $second.Sha256)
    }
    Test-WinSecWUReferenceIntegration 'Reference loading and comparison leave installed permissions, scoring and catalog bytes intact' {
        $snapshot=Get-WinSecWindowsUpdateReferenceCatalog $root
        Assert-WinSecWUReferenceIntegration ($snapshot.Sha256 -ceq $expectedHash -and
            (Get-FileHash -LiteralPath (Join-Path $root 'config/checks.json') -Algorithm SHA256).Hash -ceq $checksHash -and
            (Get-FileHash -LiteralPath (Join-Path $root 'config/scoring.json') -Algorithm SHA256).Hash -ceq $scoringHash)
        $checks=ConvertFrom-WinSecStoredJson ([IO.File]::ReadAllText((Join-Path $root 'config/checks.json')))
        $update=@($checks.checks|Where-Object checkId -CEQ 'WSA-SYS-003')
        Assert-WinSecWUReferenceIntegration ($update.Count -eq 1 -and -not $update[0].execution.enabled)
    }
} finally {
    # Only the fixture's known files and now-empty directories; no recursive deletion.
    if(-not ([IO.Path]::GetFullPath($tempRoot)).StartsWith($tempParent,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($tempRoot) -cnotmatch '\AWinSec-WU-reference-[a-f0-9]{32}\z') {
        throw 'Invalid reference fixture cleanup path.'
    }
    if([IO.File]::Exists($fixturePath)){[IO.File]::Delete($fixturePath)}
    foreach($directory in @($criteriaPath,$configPath,$tempRoot)) {
        if([IO.Directory]::Exists($directory)){[IO.Directory]::Delete($directory)}
    }
}
[Console]::WriteLine(('Windows Update reference integration: {0} passed, {1} failed.' -f $script:passed,$script:failed))
if($script:failed){throw 'Windows Update reference integration failed.'}
