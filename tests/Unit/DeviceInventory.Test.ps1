# Inventory decoding contracts, entirely in memory. No collection or writes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/Core/TargetRegistry.ps1')
. (Join-Path $root 'src/Core/DeviceInventory.ps1')
$script:passed = 0
$script:failed = 0

function Assert-WinSecInventoryUnit {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Inventory assertion failed.' }
}
function Test-WinSecInventoryUnitCase {
    param([string]$Name, [scriptblock]$Action)
    try { $null = & $Action; $script:passed++; Write-Host "[PASS] $Name" }
    catch { $script:failed++; Write-Host "[FAIL] $Name : $($_.Exception.Message)" }
}
function Assert-WinSecInventoryJsonRejected {
    param([AllowNull()][AllowEmptyString()][object]$InputJson)
    $caught = $null
    try { $null = ConvertFrom-WinSecDeviceInventoryJson -Json $InputJson } catch { $caught = $_ }
    Assert-WinSecInventoryUnit ($null -ne $caught)
    Assert-WinSecInventoryUnit ($caught.Exception.Message -notmatch 'PRIVATE-INVENTORY-FIXTURE')
}
function New-WinSecInventoryUnitDocument {
    return [pscustomobject]@{
        schemaVersion = '1.0.0'
        targets = @([pscustomobject]@{
            DeviceId = 'local:UNIT-DEVICE'; Hostname = 'UNIT-DEVICE'; Mode = 'LOCAL'; Enabled = $false
            Description = 'Synthetic metadata'; RegisteredAtUtc = '2026-10-20T12:34:56.1234567Z'
        })
    }
}

Test-WinSecInventoryUnitCase 'Empty first-run inventory is valid' {
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json '{"schemaVersion":"1.0.0","targets":[]}'
    Assert-WinSecInventoryUnit ($result.targets -is [array] -and $result.targets.Count -eq 0)
}
Test-WinSecInventoryUnitCase 'Canonical metadata and disabled registration are preserved' {
    $document = New-WinSecInventoryUnitDocument
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json ($document | ConvertTo-Json -Depth 5)
    Assert-WinSecInventoryUnit ($result.targets.Count -eq 1 -and $result.targets[0].Enabled -ceq $false)
    Assert-WinSecInventoryUnit ($result.targets[0].Description -ceq 'Synthetic metadata')
    Assert-WinSecInventoryUnit ($result.targets[0].RegisteredAtUtc.ToString().Length -gt 0)
}
Test-WinSecInventoryUnitCase 'UTC timestamps also validate when the JSON runtime preserves strings' {
    # Exercise the 5.1 representation even on runtimes that decode ISO dates.
    function ConvertFrom-Json {
        [CmdletBinding()]
        param([string]$InputObject)
        $value = Microsoft.PowerShell.Utility\ConvertFrom-Json @PSBoundParameters
        foreach ($record in @($value.targets)) {
            if ($null -ne $record -and $record.RegisteredAtUtc -is [DateTime]) {
                $record.RegisteredAtUtc = $record.RegisteredAtUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            }
        }
        return $value
    }
    $inputJson = (New-WinSecInventoryUnitDocument) | ConvertTo-Json -Depth 5
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json $inputJson
    Assert-WinSecInventoryUnit ($result.targets[0].RegisteredAtUtc -is [string] -and
        $result.targets[0].RegisteredAtUtc -ceq '2026-10-20T12:34:56.1234567Z')
}
Test-WinSecInventoryUnitCase 'Historical local devices remain distinct' {
    $document = New-WinSecInventoryUnitDocument
    $document.targets += [pscustomobject]@{
        DeviceId = 'local:OLDER-DEVICE'; Hostname = 'OLDER-DEVICE'; Mode = 'LOCAL'; Enabled = $true
    }
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json ($document | ConvertTo-Json -Depth 5)
    Assert-WinSecInventoryUnit ($result.targets.Count -eq 2 -and $result.targets[1].Enabled -ceq $true)
}
Test-WinSecInventoryUnitCase 'Optional metadata can be absent' {
    $document = New-WinSecInventoryUnitDocument
    $document.targets[0].PSObject.Properties.Remove('Description')
    $document.targets[0].PSObject.Properties.Remove('RegisteredAtUtc')
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json ($document | ConvertTo-Json -Depth 5)
    Assert-WinSecInventoryUnit ($result.targets.Count -eq 1)
}
Test-WinSecInventoryUnitCase 'A UTF-8 BOM and surrounding JSON whitespace are accepted' {
    $inputJson = [string][char]0xFEFF + " `r`n" + ((New-WinSecInventoryUnitDocument) | ConvertTo-Json -Depth 5)
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json $inputJson
    Assert-WinSecInventoryUnit ($result.targets.Count -eq 1)
}
Test-WinSecInventoryUnitCase 'Quoted property-like text in descriptions is not a duplicate key' {
    $document = New-WinSecInventoryUnitDocument
    $document.targets[0].Description = 'Text: "DeviceId": "A", "DeviceId": "B"; { } [ ] // /* */'
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json ($document | ConvertTo-Json -Depth 5)
    Assert-WinSecInventoryUnit ($result.targets[0].Description -ceq $document.targets[0].Description)
}
Test-WinSecInventoryUnitCase 'Escaped canonical field names are decoded normally' {
    $inputJson = ((New-WinSecInventoryUnitDocument) | ConvertTo-Json -Depth 5).Replace('"DeviceId"', '"\u0044eviceId"')
    $result = ConvertFrom-WinSecDeviceInventoryJson -Json $inputJson
    Assert-WinSecInventoryUnit ($result.targets[0].DeviceId -ceq 'local:UNIT-DEVICE')
}

foreach ($inputJson in @($null, '', '   ', 123, @('a'), 'null', '[]', '"PRIVATE-INVENTORY-FIXTURE"',
    '{"schemaVersion":"PRIVATE-INVENTORY-FIXTURE",',
    '{"schemaVersion":"1.0.0","targets":[],}',
    '{"schemaVersion":"1.0.0",/*PRIVATE-INVENTORY-FIXTURE*/"targets":[]}',
    "{`"schemaVersion`":`"1.0.0`",//PRIVATE-INVENTORY-FIXTURE`n`"targets`":[]}")) {
    Test-WinSecInventoryUnitCase 'Malformed non-object or non-standard JSON is rejected privately' {
        Assert-WinSecInventoryJsonRejected -InputJson $inputJson
    }
}
foreach ($field in @('Score', 'Evidence', 'RawEvidence', 'ScanId', 'Metadata')) {
    Test-WinSecInventoryUnitCase "Unexpected root field is rejected: $field" {
        $document = New-WinSecInventoryUnitDocument
        $document | Add-Member -NotePropertyName $field -NotePropertyValue 'PRIVATE-INVENTORY-FIXTURE'
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
    Test-WinSecInventoryUnitCase "Unexpected device field is rejected: $field" {
        $document = New-WinSecInventoryUnitDocument
        $document.targets[0] | Add-Member -NotePropertyName $field -NotePropertyValue @{Value='PRIVATE-INVENTORY-FIXTURE'}
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
}
foreach ($field in @('DeviceId', 'Hostname', 'Mode', 'Enabled')) {
    Test-WinSecInventoryUnitCase "A canonical required field cannot be omitted: $field" {
        $document = New-WinSecInventoryUnitDocument
        $document.targets[0].PSObject.Properties.Remove($field)
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
    Test-WinSecInventoryUnitCase "A required field cannot be an array: $field" {
        $document = New-WinSecInventoryUnitDocument
        $document.targets[0].$field = @('PRIVATE-INVENTORY-FIXTURE')
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
}
foreach ($invalidValue in @($null, 'true', 1)) {
    Test-WinSecInventoryUnitCase 'Enabled must be an explicit JSON Boolean' {
        $document = New-WinSecInventoryUnitDocument
        $document.targets[0].Enabled = $invalidValue
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
}
foreach ($invalidValue in @($null, 42, 'PRIVATE-INVENTORY-FIXTURE', '2026-02-30T00:00:00Z', '2026-10-20T10:00:00+02:00')) {
    Test-WinSecInventoryUnitCase 'Registration timestamp must identify a valid UTC time' {
        $document = New-WinSecInventoryUnitDocument
        $document.targets[0].RegisteredAtUtc = $invalidValue
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
}
foreach ($mutation in @(
    { param($d) $d.schemaVersion = 1 },
    { param($d) $d.schemaVersion = '999.0.0' },
    { param($d) $d.PSObject.Properties.Remove('schemaVersion') },
    { param($d) $d.PSObject.Properties.Remove('targets') },
    { param($d) $d.targets = $null },
    { param($d) $d.targets = [pscustomobject]@{} },
    { param($d) $d.targets = @($null) },
    { param($d) $d.targets = @('PRIVATE-INVENTORY-FIXTURE') },
    { param($d) $d.targets[0].Description = $null },
    { param($d) $d.targets[0].Description = "PRIVATE-INVENTORY-FIXTURE`n" },
    { param($d) $d.targets[0].Description = 'x' * 513 },
    { param($d) $d.targets[0].Hostname = '../PRIVATE-INVENTORY-FIXTURE' },
    { param($d) $d.targets[0].Mode = 'local' },
    { param($d) $d.targets[0].Mode = 'REMOTE' },
    { param($d) $d.targets += $d.targets[0].PSObject.Copy() }
)) {
    Test-WinSecInventoryUnitCase 'Invalid schema identity or metadata is rejected privately' {
        $document = New-WinSecInventoryUnitDocument
        & $mutation $document
        Assert-WinSecInventoryJsonRejected -InputJson ($document | ConvertTo-Json -Depth 5)
    }
}
foreach ($inputJson in @(
    '{''schemaVersion'':''1.0.0'',''targets'':[]}',
    '{schemaVersion:"1.0.0",targets:[]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL",Enabled:false,Enabled:true}]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL","Enabled":true,"Description":"\''"}]}',
    ([string][char]0x00A0 + '{"schemaVersion":"1.0.0","targets":[]}'),
    ('{"schemaVersion":"1.0.0",' + [char]0x00A0 + '"targets":[]}')
)) {
    Test-WinSecInventoryUnitCase 'Parser extensions cannot bypass strict JSON property inspection' {
        Assert-WinSecInventoryJsonRejected -InputJson $inputJson
    }
}
foreach ($inputJson in @(
    '{"schemaVersion":"1.0.0","schemaVersion":"1.0.0","targets":[]}',
    '{"schemaVersion":"1.0.0","targets":[],"targets":[]}',
    '{"schemaVersion":"1.0.0","targets":[],"Targets":[]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL","Enabled":false,"Enabled":true}]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL","Enabled":true,"\u0045nabled":true}]}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL","Enabled":true},]}'
)) {
    Test-WinSecInventoryUnitCase 'Repeated keys or trailing array commas cannot change interpretation' {
        Assert-WinSecInventoryJsonRejected -InputJson $inputJson
    }
}
Test-WinSecInventoryUnitCase 'Noncanonical root field casing is rejected' {
    Assert-WinSecInventoryJsonRejected -InputJson '{"SchemaVersion":"1.0.0","targets":[]}'
}
Test-WinSecInventoryUnitCase 'Noncanonical device field casing is rejected' {
    $inputJson = ((New-WinSecInventoryUnitDocument) | ConvertTo-Json -Depth 5).Replace('"Hostname"', '"hostname"')
    Assert-WinSecInventoryJsonRejected -InputJson $inputJson
}
Test-WinSecInventoryUnitCase 'UTF-8 document limit is enforced even before parsing' {
    Assert-WinSecInventoryJsonRejected -InputJson ('x' * 1048577)
}
Test-WinSecInventoryUnitCase 'UTF-8 limit counts bytes rather than characters' {
    $document = New-WinSecInventoryUnitDocument
    $document.targets[0].Description = [string][char]0x00E9 * 525000
    $inputJson = $document | ConvertTo-Json -Depth 5 -Compress
    Assert-WinSecInventoryUnit ($inputJson.Length -lt 1048576 -and [Text.Encoding]::UTF8.GetByteCount($inputJson) -gt 1048576)
    Assert-WinSecInventoryJsonRejected -InputJson $inputJson
}
foreach ($inputJson in @(
    '{"schemaVersion":"1.0.0","targets":[],"PSObject":{"Properties":{"Name":["schemaVersion","targets"]}}}',
    '{"schemaVersion":"1.0.0","targets":[],"psbase":{"Keys":["schemaVersion","targets"]}}',
    '{"schemaVersion":"1.0.0","targets":[{"DeviceId":"local:A","Hostname":"A","Mode":"LOCAL","Enabled":true,"PSObject":{"Properties":{"Name":["DeviceId","Hostname","Mode","Enabled"]}}}]}'
)) {
    Test-WinSecInventoryUnitCase 'Reserved-looking fields cannot hide unexpected metadata' {
        Assert-WinSecInventoryJsonRejected -InputJson $inputJson
    }
}

Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if ($script:failed -gt 0) { throw "$script:failed inventory unit test(s) failed." }
