# Historial público inmutable. No serializar Coordinator.Sessions ni evidencia.
function Get-WinSecPublicHistoryJson {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    function ConvertTo-WinSecHistoryOrderedValue {
        param([AllowNull()][object]$Node)
        if($Node -is [pscustomobject]){
            $ordered=[ordered]@{}
            foreach($p in @($Node.PSObject.Properties|Sort-Object Name -CaseSensitive)){$ordered[$p.Name]=ConvertTo-WinSecHistoryOrderedValue $p.Value}
            return [pscustomobject]$ordered
        }
        if($Node -is [array]){return ,@(foreach($item in $Node){ConvertTo-WinSecHistoryOrderedValue $item})}
        return $Node
    }
    ConvertTo-Json -InputObject (ConvertTo-WinSecHistoryOrderedValue $Value) -Depth 64 -Compress
}

function Get-WinSecPublicHistoryDigest {
    param([Parameter(Mandatory)][object]$Record)
    $copy=Copy-WinSecResultData -Value $Record
    $copy.PSObject.Properties.Remove('ContentSha256')
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((Get-WinSecPublicHistoryJson $copy)))).Replace('-','')}
    finally{$sha.Dispose()}
}

function ConvertFrom-WinSecPublicHistoryRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Record)
    $r=Copy-WinSecResultData -Value $Record
    $fields=@('SchemaVersion','DeviceId','ScanId','ScopeType','ScopeKey','CatalogVersion','ExpectedCheckIds','PublicResult','ContentSha256')
    if($r -isnot [pscustomobject] -or @($r.PSObject.Properties).Count -ne $fields.Count -or
        @($r.PSObject.Properties|Where-Object{$_.Name -cnotin $fields}).Count -or $r.SchemaVersion -isnot [string] -or $r.SchemaVersion -cne '1.0.0' -or
        -not (Test-WinSecTargetIdentifier $r.DeviceId) -or -not (Test-WinSecTargetIdentifier $r.ScanId) -or
        $r.CatalogVersion -isnot [string] -or $r.CatalogVersion.Length -gt 128 -or $r.CatalogVersion -match '[\p{C}]' -or
        $r.ExpectedCheckIds -isnot [array] -or $r.PublicResult -isnot [pscustomobject]){throw 'Invalid public history schema.'}
    $p=$r.PublicResult
    foreach ($finding in @($p.Findings)) {
        if ($null -ne (Get-WinSecResultField $finding 'Guidance')) {
            $finding.Guidance = ConvertTo-WinSecPublicFindingGuidance -Finding $finding -Guidance $finding.Guidance
        }
    }
    foreach($id in $r.ExpectedCheckIds){if(-not (Test-WinSecTargetIdentifier $id)){throw 'Invalid historical check identifier.'}}
    foreach($field in @('StartedAtUTC','CompletedAtUTC')){
        $value=Get-WinSecResultField $p $field
        if($value -is [DateTime] -and $value.Kind -eq [DateTimeKind]::Utc){$value=$value.ToString('o')}
        if($value -isnot [string]){throw 'Invalid public history timestamp.'}
        $date=ConvertTo-WinSecResultUtc -Value $value -FieldName $field
        $p.$field=$date.UtcDateTime.ToString('o')
    }
    if($r.ContentSha256 -isnot [string] -or $r.ContentSha256 -cne (Get-WinSecPublicHistoryDigest $r) -or
        $p.DeviceId -cne $r.DeviceId -or $p.ScanId -cne $r.ScanId -or $p.ScopeType -cne $r.ScopeType -or $p.ScopeKey -cne $r.ScopeKey -or
        $p.CollectionMode -cne 'LOCAL' -or $p.ExecutionStatus -cnotin @('COMPLETED','COMPLETED_WITH_ERRORS')){throw 'Inconsistent public history identity or integrity.'}
    if($p.ControlResults -isnot [array] -or $p.Findings -isnot [array] -or $p.ReviewItems -isnot [array]){throw 'Invalid public history collections.'}
    # Reconstruir sólo desde campos públicos y comparar la proyección completa.
    # Una bandera PublicProjection no autoriza campos adicionales o puntuaciones.
    try {
        $session=New-WinSecResultSession -DeviceId $r.DeviceId -ScanId $r.ScanId -CollectionMode LOCAL `
            -StartedAtUTC $p.StartedAtUTC -CompletedAtUTC $p.CompletedAtUTC -ExecutionStatus $p.ExecutionStatus `
            -ScopeType $r.ScopeType -ScopeKey $r.ScopeKey -ExpectedCheckIds $r.ExpectedCheckIds `
            -ControlResults $p.ControlResults -Findings $p.Findings -ReviewItems $p.ReviewItems -CatalogVersion $r.CatalogVersion
    } catch { throw 'Public history failed ResultModel validation.' }
    $canonical=ConvertTo-WinSecPublicScanResult -Session $session
    if((Get-WinSecPublicHistoryJson $p) -cne (Get-WinSecPublicHistoryJson $canonical)){throw 'History contains nonpublic or inconsistent result data.'}
    $registry=Get-WinSecCheckRegistry -ProjectRoot ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')))
    foreach($control in $canonical.ControlResults){
        $check=Get-WinSecRegisteredCheck -Registry $registry -CheckId $control.CheckId
        if($null -eq $check -or $check.SectionKey -cne $control.SectionKey){throw 'Unknown historical control or section.'}
    }
    return [pscustomobject]@{Record=$r;Session=$session;PublicResult=$canonical}
}

function New-WinSecPublicHistoryRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Session)
    $sessionCopy=Copy-WinSecResultData -Value $Session
    $public=ConvertTo-WinSecPublicScanResult -Session $sessionCopy
    $record=[pscustomobject]@{SchemaVersion='1.0.0';DeviceId=$sessionCopy.DeviceId;ScanId=$sessionCopy.ScanId;
        ScopeType=$sessionCopy.ScopeType;ScopeKey=$sessionCopy.ScopeKey;CatalogVersion=$sessionCopy.CatalogVersion;
        ExpectedCheckIds=@($sessionCopy.ExpectedCheckIds);PublicResult=$public;ContentSha256=''}
    $record.ContentSha256=Get-WinSecPublicHistoryDigest $record
    return (ConvertFrom-WinSecPublicHistoryRecord $record).Record
}

function Get-WinSecPublicHistoryPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$DeviceId,[string]$ScanId='')
    $installation=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    if(-not [string]::Equals([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/'),$installation.TrimEnd('\','/'),[StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-WinSecTargetIdentifier $DeviceId) -or ($ScanId -and -not (Test-WinSecTargetIdentifier $ScanId))){throw 'Invalid history storage identity or installation.'}
    $path=Join-Path $installation ('data/scans/'+(Get-WinSecEvidenceHash $DeviceId))
    if($ScanId){$path=Join-Path $path ((Get-WinSecEvidenceHash $ScanId)+'.json')}
    Assert-WinSecDeviceRemovalPath -ProjectRoot $installation -Path $path
    return $path
}

function Write-WinSecPublicHistoryArtifact {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Record)
    $validated=(ConvertFrom-WinSecPublicHistoryRecord $Record).Record
    $path=Get-WinSecPublicHistoryPath $ProjectRoot $validated.DeviceId $validated.ScanId
    $json=Get-WinSecPublicHistoryJson $validated
    $bytes=[Text.Encoding]::UTF8.GetBytes($json)
    if($bytes.Length -gt 1048576){throw 'Public session exceeds 1 MiB.'}
    $directory=[IO.Path]::GetDirectoryName($path)
    $null=[IO.Directory]::CreateDirectory($directory)
    $null=Get-WinSecPublicHistoryPath $ProjectRoot $validated.DeviceId $validated.ScanId
    $temporary=Join-Path $directory ('.'+[guid]::NewGuid().ToString('N')+'.tmp')
    $owned=$false;$moved=$false
    try{
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$owned=$true
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $temporary
        $verify=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $temporary -Raw -Encoding UTF8 -ErrorAction Stop)
        if((Get-WinSecPublicHistoryJson (ConvertFrom-WinSecPublicHistoryRecord $verify).Record) -cne $json){throw 'History temporary verification failed.'}
        $null=Get-WinSecPublicHistoryPath $ProjectRoot $validated.DeviceId $validated.ScanId
        [IO.File]::Move($temporary,$path);$moved=$true
        $null=Get-WinSecPublicHistoryPath $ProjectRoot $validated.DeviceId $validated.ScanId
        $saved=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop)
        if((Get-WinSecPublicHistoryJson (ConvertFrom-WinSecPublicHistoryRecord $saved).Record) -cne $json){throw 'History publication verification failed.'}
    }finally{
        if($owned -and -not $moved){
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $temporary
            if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
        }
    }
}

function Save-WinSecPublicHistory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][object]$Session)
    $record=New-WinSecPublicHistoryRecord $Session
    $store=Open-WinSecDeviceInventoryStore $ProjectRoot
    try{
        $inventory=Import-WinSecDeviceInventory $ProjectRoot
        $device=@($inventory.targets|Where-Object{$_.DeviceId -ceq $record.DeviceId -and $_.Mode -ceq 'LOCAL' -and $_.Enabled -ceq $true})
        if($device.Count -ne 1){throw 'Persistent device is unavailable for this scan.'}
        $existingBytes=0
        $existing=@(Read-WinSecPublicHistoryArtifacts -ProjectRoot $ProjectRoot -Devices @($inventory.targets) -TotalBytes ([ref]$existingBytes))
        $newBytes=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $record))
        if($existing.Count -ge 10000 -or ($existingBytes+$newBytes) -gt 33554432 -or
            @($existing|Where-Object{$_.DeviceId -ceq $record.DeviceId -and $_.ScanId -ceq $record.ScanId}).Count){throw 'History capacity or immutable session conflict.'}
        $null=Write-WinSecPublicHistoryArtifact -ProjectRoot $ProjectRoot -Record $record
    }finally{$store.Lock.Dispose()}
}

function Read-WinSecPublicHistoryArtifacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Devices,[ref]$TotalBytes)
    $records=New-Object 'System.Collections.Generic.List[object]';$observedBytes=0
    foreach($device in $Devices){
        $directory=Get-WinSecPublicHistoryPath $ProjectRoot $device.DeviceId
        if(-not (Test-Path -LiteralPath $directory -ErrorAction Stop)){continue}
        if(-not (Get-Item -LiteralPath $directory -Force -ErrorAction Stop).PSIsContainer){throw 'Invalid history directory.'}
        foreach($file in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)){
            Assert-WinSecDeviceRemovalPath -ProjectRoot $ProjectRoot -Path $file.FullName
            $observedBytes+=$file.Length
            if($file.PSIsContainer -or $file.Extension -cne '.json' -or $file.Length -gt 1048576 -or $observedBytes -gt 33554432 -or $records.Count -ge 10000){throw 'Invalid or excessive public history storage.'}
            $before=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            $record=ConvertFrom-WinSecStoredJson (Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop)
            $validated=ConvertFrom-WinSecPublicHistoryRecord $record
            if($validated.Record.DeviceId -cne $device.DeviceId -or
                -not [string]::Equals($file.FullName,(Get-WinSecPublicHistoryPath $ProjectRoot $device.DeviceId $validated.Record.ScanId),[StringComparison]::OrdinalIgnoreCase) -or
                (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -cne $before){throw 'Public history ownership or file changed.'}
            $records.Add($validated.Record)
        }
    }
    if($null -ne $TotalBytes){$TotalBytes.Value=$observedBytes}
    return $records.ToArray()
}

function Restore-WinSecPublicHistory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Context)
    Assert-WinSecScanCoordinator $Context.ScanCoordinator
    if($Context.ScanCoordinator.Sessions.Count -or $Context.PublicScans.Count -or $Context.ActiveScanByDevice.Count -or $Context.ActiveScanByScope.Count){throw 'Restore requires empty session caches.'}
    $sessions=@{};$publics=@{};$devices=@{};$scopes=@{}
    $lease=Open-WinSecDeviceInventoryStore $Context.ProjectRoot
    try{
        $records=@(Read-WinSecPublicHistoryArtifacts -ProjectRoot $Context.ProjectRoot -Devices @($Context.Devices))
        $validated=@(foreach($record in $records){ConvertFrom-WinSecPublicHistoryRecord $record})
        foreach($item in @($validated|Sort-Object {$_.PublicResult.CompletedAtUTC},{$_.Record.ScanId})){
            $r=$item.Record
            if(@($Context.Devices|Where-Object{$_.DeviceId -ceq $r.DeviceId}).Count -ne 1){throw 'Historical device not present in inventory.'}
            $key=Get-WinSecScanSessionKey $r.DeviceId $r.ScanId
            if($sessions.ContainsKey($key)){throw 'Duplicate stored public session.'}
            $sessions[$key]=[pscustomobject]@{DeviceId=$r.DeviceId;ScanId=$r.ScanId;Session=$item.Session;
                EvidenceStorage=[pscustomobject]@{DeviceId=$r.DeviceId;ScanId=$r.ScanId;Status='NOT_RECORDED';StoredCount=0;FailedCount=0;SkippedCount=0};
                RegisteredAtUTC=$item.PublicResult.CompletedAtUTC;HistoryOrigin='PUBLIC_STORE'}
            $publicKey='{0}:{1}{2}:{3}' -f $r.DeviceId.Length,$r.DeviceId,$r.ScanId.Length,$r.ScanId
            $publics[$publicKey]=Copy-WinSecResultData $item.PublicResult
            if($r.ScopeType -ceq 'DEVICE'){$devices[$r.DeviceId]=$r.ScanId}
            # Contrato de índices de longitudes; sin dependencia de funciones de la CLI.
            $scopeIndex='{0}:{1}{2}:{3}{4}:{5}' -f $r.DeviceId.Length,$r.DeviceId,$r.ScopeType.Length,$r.ScopeType,$r.ScopeKey.Length,$r.ScopeKey
            $scopes[$scopeIndex]=$r.ScanId
        }
        $Context.ScanCoordinator.Sessions=$sessions;$Context.PublicScans=$publics
        $Context.ActiveScanByDevice=$devices;$Context.ActiveScanByScope=$scopes
        $Context | Add-Member -NotePropertyName HistoryReady -NotePropertyValue $true -Force
    }finally{$lease.Lock.Dispose()}
}
