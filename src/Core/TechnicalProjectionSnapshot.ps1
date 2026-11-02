# Transitional transport of the existing reviewed technical projection; no provider calls.
function Get-WinSecProjectionCatalog {
    param([string]$CheckId)
    $null=Get-WinSecTechnicalControl $CheckId
    $rule=[pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=@()}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.1.0';CatalogId=('WinSec.Reviewed.'+$CheckId);CatalogVersion='1.0.0';CheckId=$CheckId
        Sources=@([pscustomobject]@{Id='ReviewedProjection';Provider='DERIVED';ReferenceUrl='https://github.com/MrFixRoot/WinSec-Analyzer'})
        Inventories=@(
            [pscustomobject]@{Id='Header';SourceId='ReviewedProjection';Required=$true;Singleton=$true;Applicability=$rule}
            [pscustomobject]@{Id='Rows';SourceId='ReviewedProjection';Required=$true;Singleton=$false;Applicability=$rule})
        Fields=@(
            [pscustomobject]@{Id='Header.Record';InventoryId='Header';Type='ReviewedHeader';Unit='none';Required=$true;Exposure='IDENTIFIABLE';Applicability=$rule}
            [pscustomobject]@{Id='Rows.Record';InventoryId='Rows';Type='ReviewedRow';Unit='none';Required=$true;Exposure='CONFIGURATION';Applicability=$rule})}
}

function ConvertFrom-WinSecProjectionSnapshot {
    param([object]$Snapshot)
    $header=@($Snapshot.Batches|Where-Object InventoryId -CEQ Header)
    if($header.Count -ne 1 -or $header[0].Records.Count -ne 1){throw 'Missing reviewed header.'}
    $r=Copy-WinSecResultData $header[0].Records[0].Readings[0].Value
    $rows=@(foreach($b in @($Snapshot.Batches|Where-Object InventoryId -CEQ Rows)){foreach($record in $b.Records){$record.Readings[0].Value}})
    $r|Add-Member -NotePropertyName Rows -NotePropertyValue $rows
    $r=ConvertTo-WinSecTechnicalReport $r
    foreach($field in @('DeviceId','ScanId','CheckId','SectionKey','ScopeType','ScopeKey')){if($r.$field -cne $Snapshot.Identity.$field){throw 'Mixed reviewed projection identity.'}}
    foreach($field in @('StartedAtUTC','CompletedAtUTC','CollectedAtUTC','GeneratedAtUTC')){if($r.$field -cne $Snapshot.$field){throw 'Mixed reviewed projection timestamps.'}}
    if($r.Profile -cne $Snapshot.SelectedProfile){throw 'Mixed selected profile.'}
    return $r
}

function Get-WinSecProjectionCompletion {
    param([object]$Report)
    $row=@($Report.Rows|Where-Object SettingId -CEQ CollectionComplete)
    return ($row.Count -eq 1 -and $row[0].State -ceq 'OBSERVED' -and $row[0].Value -ceq $true -and $Report.CollectorStatus -ceq 'INFORMATIONAL')
}

function New-WinSecProjectionSnapshot {
    param([object]$Report)
    $r=ConvertTo-WinSecTechnicalReport $Report
    $catalog=Get-WinSecProjectionCatalog $r.CheckId;$digest=Get-WinSecSnapshotCatalogHash $catalog
    $identity=[pscustomobject]@{DeviceId=$r.DeviceId;ScanId=$r.ScanId;SnapshotId=[guid]::NewGuid().ToString('N');CheckId=$r.CheckId;SectionKey=$r.SectionKey;ScopeType=$r.ScopeType;ScopeKey=$r.ScopeKey}
    $header=Copy-WinSecResultData $r;$header.PSObject.Properties.Remove('Rows')
    $batches=New-Object 'Collections.Generic.List[object]'
    foreach($area in @('Header','Rows')){
        $values=if($area -ceq 'Header'){@($header)}else{@($r.Rows)};$sequence=1;$records=@();$n=0
        foreach($value in $values){
            $record=[pscustomobject]@{Id=('Record'+$n);Readings=@([pscustomobject]@{FieldId=($area+'.Record');State='OBSERVED';Reason='NONE';Value=$value})};$n++
            $candidate=[pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;SnapshotId=$identity.SnapshotId;CheckId=$identity.CheckId;InventoryId=$area;Sequence=$sequence;Records=@($records)+@($record)}
            if($records.Count -and ($candidate.Records.Count -gt 128 -or [Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $candidate -Depth 24 -Compress)) -gt 1048576)){
                $candidate.Records=$records;$batches.Add($candidate);$sequence++;$records=@()
            }
            $records+=,$record
        }
        if($records.Count){$batches.Add([pscustomobject]@{DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;SnapshotId=$identity.SnapshotId;CheckId=$identity.CheckId;InventoryId=$area;Sequence=$sequence;Records=$records})}
    }
    $platform=[pscustomobject]@{Version=$null;OSRelease=$null;Edition=$null;BuildNumber=$null;UBR=$null;OperatingSystemSKU=$null;ProductType=$null}
    foreach($name in @('BuildNumber','OperatingSystemSKU','ProductType')){
        $row=@($r.Rows|Where-Object SettingId -CEQ ('Platform.'+$name))
        if($row.Count -eq 1 -and $row[0].State -ceq 'OBSERVED' -and (Test-WinSecSnapshotUInt $row[0].Value)){$platform.$name=$row[0].Value}
    }
    $row=@($r.Rows|Where-Object SettingId -CEQ Platform.Version)
    if($row.Count -eq 1 -and $row[0].State -ceq 'OBSERVED'){$platform.Version=$row[0].Value}
    $complete=Get-WinSecProjectionCompletion $r
    $covered=($null -ne $platform.BuildNumber -and $null -ne $platform.OperatingSystemSKU -and $platform.ProductType -eq 1 -and @($r.Rows|Where-Object State -CIN @('UNKNOWN','ERROR','NOT_COLLECTED')).Count -eq 0)
    $s=[pscustomobject]@{ArtifactType='WinSec.TechnicalSnapshot';SchemaVersion='2.1.0';Identity=$identity;CatalogId=$catalog.CatalogId;CatalogVersion=$catalog.CatalogVersion;CatalogSha256=$digest;CollectorVersion='0.9.0'
        StartedAtUTC=$r.StartedAtUTC;CollectedAtUTC=$r.CollectedAtUTC;CompletedAtUTC=$r.CompletedAtUTC;GeneratedAtUTC=$r.GeneratedAtUTC;Platform=$platform;SelectedProfile=$r.Profile
        Collection=[pscustomobject]@{Status=$(if($complete){'COMPLETE'}else{'PARTIAL'});Coverage=$(if($complete -and $covered){'COMPLETE'}else{'LIMITED'});RetainedRecords=($r.Rows.Count+1);Observed=($r.Rows.Count+1);Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
        Inventories=@([pscustomobject]@{Id='Header';State='OBSERVED';Complete=$true;ReportedRecords=1;RetainedRecords=1;Reason='NONE'},
            [pscustomobject]@{Id='Rows';State='OBSERVED';Complete=$complete;ReportedRecords=$r.Rows.Count;RetainedRecords=$r.Rows.Count;Reason=$(if($complete){'NONE'}else{'PROVIDER_UNAVAILABLE'})})
        Batches=$batches.ToArray()}
    Assert-WinSecTechnicalSnapshot $s $catalog $digest $identity
    [pscustomobject]@{Snapshot=$s;Catalog=$catalog;CatalogSha256=$digest;Identity=$identity}
}
