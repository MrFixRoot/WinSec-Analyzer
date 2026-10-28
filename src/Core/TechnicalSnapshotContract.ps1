# Isolated technical contract v2. No collector calls, registration, file writes or production imports.
function Get-WinSecSnapshotSpecification {
    [CmdletBinding()]param()
    [pscustomobject]@{
        SchemaVersion='2.0.0'; CatalogSchemaVersion='1.0.0'; ProductionEnabled=$false
        MaxDocumentBytes=16777216; MaxBatchBytes=1048576; BatchRecords=128
        MaxTextChars=4096; MaxJsonDepth=16; MaxPathChars=240
        ValidationTimeoutMilliseconds=10000
        States=@('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_CONFIGURED','NOT_APPLICABLE')
        Types=@('Boolean','UInt32','Int64','String','StringArray')
        Units=@('none','count','seconds','bytes','characters','bits','percent')
        Reasons=@('NONE','PROVIDER_UNAVAILABLE','INVALID_VALUE','NOT_REQUESTED','ABSENT','PLATFORM_EXCLUDED','RESOURCE_LIMIT')
    }
}

function Get-WinSecSnapshotControl {
    [CmdletBinding()]param([string]$CheckId)
    # Storage identities only. This map grants no execution permission.
    $rows=@('WSA-SYS-001|SystemSecurity|Defender','WSA-SYS-002|SystemSecurity|BitLocker','WSA-SYS-003|SystemSecurity|WindowsUpdate',
        'WSA-NET-001|NetworkSecurity|Firewall','WSA-NET-002|NetworkSecurity|SMBv1','WSA-NET-003|NetworkSecurity|RemoteDesktop',
        'WSA-NET-004|NetworkSecurity|OpenPorts','WSA-NET-005|NetworkSecurity|NetworkConfiguration',
        'WSA-IAM-001|IdentityAccess|LocalAdministrators','WSA-IAM-002|IdentityAccess|GuestAccount','WSA-IAM-003|IdentityAccess|PasswordPolicy',
        'WSA-LOG-001|LoggingAuditing|PowerShellLogging','WSA-LOG-002|LoggingAuditing|AuditPolicy','WSA-HRD-001|ServicesHardening|WindowsServices')
    foreach($row in $rows){$p=$row.Split('|');if($p[0] -ceq $CheckId){return [pscustomobject]@{CheckId=$p[0];SectionKey=$p[1];ControlName=$p[2]}}}
    throw 'Unknown snapshot control.'
}

function Assert-WinSecSnapshotFields {
    param([object]$Value,[string[]]$Fields)
    if($null -eq $Value -or $Value.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Snapshot requires plain objects.'}
    $names=@($Value.PSObject.Properties)
    if($names.Count -ne $Fields.Count){throw 'Unexpected snapshot properties.'}
    foreach($p in $names){if($p.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or $p.Name -cnotin $Fields){throw 'Unreviewed snapshot property.'}}
}

function Test-WinSecSnapshotToken {
    param([object]$Value)
    return ($Value -is [string] -and $Value -cmatch '\A[A-Za-z][A-Za-z0-9_.-]{0,95}\z')
}

function Test-WinSecSnapshotUInt {
    param([object]$Value,[long]$Maximum=4294967295)
    return ($null -ne $Value -and $Value.GetType() -in @([byte],[int16],[uint16],[int],[uint32],[long],[uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le $Maximum)
}

function ConvertTo-WinSecSnapshotUtc {
    param([object]$Value)
    $parsed=[datetime]::MinValue
    if($Value -isnot [string] -or -not [datetime]::TryParseExact($Value,'yyyy-MM-ddTHH:mm:ss.fffffffZ',
        [Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal),[ref]$parsed)){
        throw 'Snapshot requires canonical UTC text.'
    }
    return $parsed
}

function Assert-WinSecSnapshotIdentity {
    [CmdletBinding()]param([object]$Identity)
    Assert-WinSecSnapshotFields $Identity @('DeviceId','ScanId','SnapshotId','CheckId','SectionKey','ScopeType','ScopeKey')
    if($Identity.DeviceId -isnot [string] -or $Identity.DeviceId -cnotmatch '\Alocal:hw1-[a-f0-9]{64}\z' -or
        $Identity.ScanId -isnot [string] -or $Identity.ScanId -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z' -or
        $Identity.SnapshotId -isnot [string] -or $Identity.SnapshotId -cnotmatch '\A[a-f0-9]{32}\z') {throw 'Invalid snapshot identity.'}
    if($Identity.CheckId -isnot [string]){throw 'Invalid control identity.'}
    $control=Get-WinSecSnapshotControl $Identity.CheckId
    if($Identity.SectionKey -isnot [string] -or $Identity.SectionKey -cne $control.SectionKey -or
        $Identity.ScopeType -isnot [string] -or $Identity.ScopeKey -isnot [string]){throw 'Invalid snapshot section or scope.'}
    switch -CaseSensitive ($Identity.ScopeType){
        CONTROL {if($Identity.ScopeKey -cne $Identity.CheckId){throw 'Foreign control scope.'}}
        SECTION {if($Identity.ScopeKey -cne $Identity.SectionKey){throw 'Foreign section scope.'}}
        DEVICE {if($Identity.ScopeKey -cne 'ALL'){throw 'Invalid device scope.'}}
        default {throw 'Unknown snapshot scope.'}
    }
}

function Assert-WinSecSnapshotApplicability {
    param([object]$Rule)
    Assert-WinSecSnapshotFields $Rule @('MinBuild','MaxBuild','Skus')
    if(-not (Test-WinSecSnapshotUInt $Rule.MinBuild) -or $Rule.MinBuild -lt 22000 -or
        ($null -ne $Rule.MaxBuild -and (-not (Test-WinSecSnapshotUInt $Rule.MaxBuild) -or $Rule.MaxBuild -lt $Rule.MinBuild)) -or
        $Rule.Skus -isnot [array] -or $Rule.Skus.Count -gt 128){throw 'Invalid applicability definition.'}
    $seen=@{};foreach($sku in $Rule.Skus){if(-not (Test-WinSecSnapshotUInt $sku) -or $seen.ContainsKey([string]$sku)){throw 'Invalid applicability SKU.'};$seen[[string]$sku]=$true}
}

function Test-WinSecSnapshotApplicable {
    param([object]$Rule,[object]$Platform)
    if($null -eq $Platform.BuildNumber -or $Platform.ProductType -ne 1){return $null}
    if($Platform.BuildNumber -lt $Rule.MinBuild -or ($null -ne $Rule.MaxBuild -and $Platform.BuildNumber -gt $Rule.MaxBuild)){return $false}
    if($Rule.Skus.Count){if($null -eq $Platform.OperatingSystemSKU){return $null};if($Platform.OperatingSystemSKU -notin $Rule.Skus){return $false}}
    return $true
}

function Assert-WinSecSnapshotCatalog {
    [CmdletBinding()]param([object]$Catalog)
    Assert-WinSecSnapshotFields $Catalog @('ArtifactType','SchemaVersion','CatalogId','CatalogVersion','CheckId','Sources','Inventories','Fields')
    foreach($name in @('ArtifactType','SchemaVersion','CheckId')){if($Catalog.$name -isnot [string]){throw 'Invalid catalog scalar.'}}
    $null=Get-WinSecSnapshotControl $Catalog.CheckId
    if($Catalog.ArtifactType -cne 'WinSec.TechnicalFieldCatalog' -or $Catalog.SchemaVersion -cnotin @('1.0.0','1.1.0') -or
        -not (Test-WinSecSnapshotToken $Catalog.CatalogId) -or $Catalog.CatalogVersion -isnot [string] -or
        $Catalog.CatalogVersion -cnotmatch '\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\z'){throw 'Invalid field catalog identity.'}
    $sources=@{};$inventories=@{};$fields=@{};$spec=Get-WinSecSnapshotSpecification
    if($Catalog.SchemaVersion -ceq '1.1.0'){
        $expected=Get-WinSecProjectionCatalog $Catalog.CheckId
        if((ConvertTo-Json -InputObject $Catalog -Depth 16 -Compress) -cne (ConvertTo-Json -InputObject $expected -Depth 16 -Compress)){throw 'Unreviewed transitional catalog.'}
        $spec.Types+=@('ReviewedHeader','ReviewedRow')
    }
    foreach($name in @('Sources','Inventories','Fields')){
        $limit=if($name -ceq 'Fields'){1024}else{64}
        if($Catalog.$name -isnot [array] -or $Catalog.$name.Count -lt 1 -or $Catalog.$name.Count -gt $limit){throw 'Invalid catalog metadata budget.'}
    }
    foreach($source in $Catalog.Sources){
        Assert-WinSecSnapshotFields $source @('Id','Provider','ReferenceUrl')
        $uri=$null
        if(-not (Test-WinSecSnapshotToken $source.Id) -or $sources.ContainsKey($source.Id) -or
            $source.Provider -isnot [string] -or $source.Provider -cnotin @('CIM','REGISTRY','NETAPI','CMDLET','DERIVED') -or $source.ReferenceUrl -isnot [string] -or
            $source.ReferenceUrl.Length -gt 2048 -or $source.ReferenceUrl -match '[\s\p{C}]' -or
            -not [uri]::TryCreate($source.ReferenceUrl,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.UserInfo){throw 'Invalid reviewed source.'}
        $sources[$source.Id]=$true
    }
    foreach($inventory in $Catalog.Inventories){
        Assert-WinSecSnapshotFields $inventory @('Id','SourceId','Required','Singleton','Applicability')
        if(-not (Test-WinSecSnapshotToken $inventory.Id) -or $inventories.ContainsKey($inventory.Id) -or
            $inventory.SourceId -isnot [string] -or -not $sources.ContainsKey($inventory.SourceId) -or
            $inventory.Required -isnot [bool] -or $inventory.Singleton -isnot [bool]){throw 'Invalid inventory definition.'}
        Assert-WinSecSnapshotApplicability $inventory.Applicability;$inventories[$inventory.Id]=$true
    }
    foreach($field in $Catalog.Fields){
        Assert-WinSecSnapshotFields $field @('Id','InventoryId','Type','Unit','Required','Exposure','Applicability')
        if(-not (Test-WinSecSnapshotToken $field.Id) -or $fields.ContainsKey($field.Id) -or
            $field.InventoryId -isnot [string] -or -not $inventories.ContainsKey($field.InventoryId) -or
            $field.Type -isnot [string] -or $field.Type -cnotin $spec.Types -or $field.Unit -isnot [string] -or $field.Unit -cnotin $spec.Units -or $field.Required -isnot [bool] -or
            $field.Exposure -isnot [string] -or $field.Exposure -cnotin @('CONFIGURATION','IDENTIFIABLE') -or
            $field.Id -imatch '(?:^|\.)(?:Password|PasswordHash|PrivateKey|RecoveryKey|RecoveryPassword|KeyProtector|AccessToken|RefreshToken|Credential|Credentials|Secret|Score|OverallScore|SecurityScore)(?:\.|$)'){
            throw 'Unreviewed or prohibited technical field.'
        }
        if($field.Unit -cne 'none' -and $field.Type -cnotin @('UInt32','Int64')){throw 'Unit requires a numeric field.'}
        Assert-WinSecSnapshotApplicability $field.Applicability;$fields[$field.Id]=$true
    }
    foreach($id in $inventories.Keys){if(@($Catalog.Fields|Where-Object InventoryId -CEQ $id).Count -eq 0){throw 'Inventory without field definitions.'}}
}

function Assert-WinSecSnapshotValue {
    param([object]$Value,[object]$Definition)
    $spec=Get-WinSecSnapshotSpecification
    switch -CaseSensitive ($Definition.Type){
        Boolean {if($Value -isnot [bool]){throw 'Invalid Boolean reading.'}}
        UInt32 {if(-not (Test-WinSecSnapshotUInt $Value)){throw 'Invalid UInt32 reading.'}}
        Int64 {if($null -eq $Value -or $Value.GetType() -notin @([byte],[int16],[uint16],[int],[uint32],[long])){throw 'Invalid Int64 reading.'}}
        String {if($Value -isnot [string] -or $Value.Length -gt $spec.MaxTextChars -or $Value -match '[\p{C}\p{Zl}\p{Zp}]'){throw 'Invalid text reading.'}}
        StringArray {
            if($Value -isnot [array]){throw 'Invalid list reading.'}
            foreach($item in $Value){if($item -isnot [string] -or $item.Length -gt $spec.MaxTextChars -or $item -match '[\p{C}\p{Zl}\p{Zp}]'){throw 'Invalid list item.'}}
        }
        ReviewedHeader {Assert-WinSecSnapshotFields $Value @('SchemaVersion','CatalogVersion','DeviceId','ScanId','SectionKey','CheckId','ScopeType','ScopeKey','DeviceName','Hostname','Profile','ObservedOSRelease','ObservedEdition','StartedAtUTC','CompletedAtUTC','CollectedAtUTC','GeneratedAtUTC','CollectorStatus')}
        ReviewedRow {Assert-WinSecSnapshotFields $Value @('SettingId','Value','State','Reason')}
        default {throw 'Unknown value type.'}
    }
    if($Definition.Unit -cne 'none' -and $Value -lt 0){throw 'Negative quantity is not a measured value.'}
    if($Definition.Unit -ceq 'percent' -and ($Value -is [bool] -or $Value -isnot [ValueType] -or $Value -lt 0 -or $Value -gt 100)){throw 'Invalid native percentage.'}
}

function Assert-WinSecTechnicalSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Snapshot,[Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$CatalogSha256,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotCatalog $Catalog;Assert-WinSecSnapshotIdentity $ExpectedIdentity
    Assert-WinSecSnapshotFields $Snapshot @('ArtifactType','SchemaVersion','Identity','CatalogId','CatalogVersion','CatalogSha256',
        'CollectorVersion','StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC','Platform','SelectedProfile','Collection','Inventories','Batches')
    Assert-WinSecSnapshotIdentity $Snapshot.Identity
    foreach($name in @('ArtifactType','SchemaVersion','CatalogId','CatalogVersion')){if($Snapshot.$name -isnot [string]){throw 'Invalid snapshot scalar.'}}
    if((Get-WinSecSnapshotCatalogHash $Catalog) -cne $CatalogSha256){throw 'Catalog fingerprint mismatch.'}
    foreach($p in $ExpectedIdentity.PSObject.Properties){if($Snapshot.Identity.($p.Name) -cne $p.Value){throw 'Foreign snapshot identity.'}}
    $schema=if($Catalog.SchemaVersion -ceq '1.1.0'){'2.1.0'}else{'2.0.0'}
    if($Snapshot.ArtifactType -cne 'WinSec.TechnicalSnapshot' -or $Snapshot.SchemaVersion -cne $schema -or
        $Snapshot.Identity.CheckId -cne $Catalog.CheckId -or $Snapshot.CatalogId -cne $Catalog.CatalogId -or
        $Snapshot.CatalogVersion -cne $Catalog.CatalogVersion -or $CatalogSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $Snapshot.CatalogSha256 -isnot [string] -or $Snapshot.CatalogSha256 -cne $CatalogSha256 -or
        $Snapshot.CollectorVersion -isnot [string] -or $Snapshot.CollectorVersion -cnotmatch '\A[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\z' -or
        -not (Test-WinSecSnapshotToken $Snapshot.SelectedProfile)){throw 'Snapshot version or provenance mismatch.'}
    $start=ConvertTo-WinSecSnapshotUtc $Snapshot.StartedAtUTC;$collected=ConvertTo-WinSecSnapshotUtc $Snapshot.CollectedAtUTC
    $end=ConvertTo-WinSecSnapshotUtc $Snapshot.CompletedAtUTC;$generated=ConvertTo-WinSecSnapshotUtc $Snapshot.GeneratedAtUTC
    if($start -gt $collected -or $collected -gt $end -or $end -gt $generated){throw 'Invalid snapshot timeline.'}
    Assert-WinSecSnapshotFields $Snapshot.Platform @('Version','OSRelease','Edition','BuildNumber','UBR','OperatingSystemSKU','ProductType')
    foreach($name in @('BuildNumber','UBR','OperatingSystemSKU','ProductType')){if($null -ne $Snapshot.Platform.$name -and -not (Test-WinSecSnapshotUInt $Snapshot.Platform.$name)){throw 'Invalid observed platform number.'}}
    if(($null -ne $Snapshot.Platform.BuildNumber -and $Snapshot.Platform.BuildNumber -lt 22000) -or
        ($null -ne $Snapshot.Platform.ProductType -and $Snapshot.Platform.ProductType -ne 1)){throw 'Snapshot is not a Windows 11 client.'}
    foreach($name in @('Version','OSRelease','Edition')){if($null -ne $Snapshot.Platform.$name -and ($Snapshot.Platform.$name -isnot [string] -or -not (Test-WinSecSnapshotToken ('V'+$Snapshot.Platform.$name)))){throw 'Invalid observed platform text.'}}
    if($null -ne $Snapshot.Platform.Version -and ($null -eq $Snapshot.Platform.BuildNumber -or $Snapshot.Platform.Version -cne ('10.0.'+$Snapshot.Platform.BuildNumber))){throw 'Observed version/build mismatch.'}
    Assert-WinSecSnapshotFields $Snapshot.Collection @('Status','Coverage','RetainedRecords','Observed','Unknown','Errors','NotCollected','NotConfigured','NotApplicable')
    foreach($name in @('Status','Coverage')){if($Snapshot.Collection.$name -isnot [string]){throw 'Invalid collection state.'}}
    if($Snapshot.Inventories -isnot [array] -or $Snapshot.Inventories.Count -ne $Catalog.Inventories.Count -or $Snapshot.Batches -isnot [array]){throw 'Invalid snapshot inventories.'}
    $counts=@{RetainedRecords=0;Observed=0;Unknown=0;Errors=0;NotCollected=0;NotConfigured=0;NotApplicable=0}
    $stateCount=@{OBSERVED='Observed';UNKNOWN='Unknown';ERROR='Errors';NOT_COLLECTED='NotCollected';NOT_CONFIGURED='NotConfigured';NOT_APPLICABLE='NotApplicable'}
    $spec=Get-WinSecSnapshotSpecification;$seenInventories=@{};$sequence=@{};$records=@{};$inventoryCounts=@{}
    $complete=($null -ne $Snapshot.Platform.BuildNumber -and $null -ne $Snapshot.Platform.OperatingSystemSKU -and $Snapshot.Platform.ProductType -eq 1)
    $coverage=$complete
    foreach($inventory in $Snapshot.Inventories){
        Assert-WinSecSnapshotFields $inventory @('Id','State','Complete','ReportedRecords','RetainedRecords','Reason')
        foreach($name in @('Id','State','Reason')){if($inventory.$name -isnot [string]){throw 'Invalid inventory scalar.'}}
        $definition=@($Catalog.Inventories|Where-Object Id -CEQ $inventory.Id)
        if($definition.Count -ne 1 -or $seenInventories.ContainsKey($inventory.Id) -or $inventory.State -cnotin @('OBSERVED','UNKNOWN','ERROR','NOT_COLLECTED','NOT_APPLICABLE') -or
            $inventory.Complete -isnot [bool] -or -not (Test-WinSecSnapshotUInt $inventory.RetainedRecords) -or
            ($null -ne $inventory.ReportedRecords -and (-not (Test-WinSecSnapshotUInt $inventory.ReportedRecords) -or $inventory.ReportedRecords -lt $inventory.RetainedRecords))){throw 'Invalid inventory summary.'}
        $seenInventories[$inventory.Id]=$inventory;$sequence[$inventory.Id]=0;$records[$inventory.Id]=@{};$inventoryCounts[$inventory.Id]=0
        if($inventory.State -ceq 'NOT_APPLICABLE'){
            if((Test-WinSecSnapshotApplicable $definition[0].Applicability $Snapshot.Platform) -cne $false -or
                -not $inventory.Complete -or $inventory.RetainedRecords -ne 0 -or $null -ne $inventory.ReportedRecords -or $inventory.Reason -cne 'PLATFORM_EXCLUDED'){throw 'Unverified inventory exclusion.'}
        }elseif($inventory.Complete){
            if($inventory.State -cne 'OBSERVED' -or $inventory.Reason -cne 'NONE' -or
                ($null -ne $inventory.ReportedRecords -and $inventory.ReportedRecords -ne $inventory.RetainedRecords) -or
                ($definition[0].Singleton -and $inventory.RetainedRecords -ne 1)){throw 'False inventory completion.'}
        }else{
            $complete=$false;$coverage=$false
            if($inventory.Reason -cnotin @('PROVIDER_UNAVAILABLE','INVALID_VALUE','NOT_REQUESTED','RESOURCE_LIMIT') -or
                ($inventory.State -cne 'OBSERVED' -and $inventory.RetainedRecords -ne 0)){throw 'Invalid incomplete inventory.'}
        }
        if($definition[0].Singleton -and $inventory.RetainedRecords -gt 1){throw 'Singleton inventory overflow.'}
    }
    foreach($batch in $Snapshot.Batches){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        Assert-WinSecSnapshotFields $batch @('DeviceId','ScanId','SnapshotId','CheckId','InventoryId','Sequence','Records')
        foreach($name in @('DeviceId','ScanId','SnapshotId','CheckId')){if($batch.$name -isnot [string] -or $batch.$name -cne $Snapshot.Identity.$name){throw 'Foreign batch identity.'}}
        if($batch.InventoryId -isnot [string] -or -not $seenInventories.ContainsKey($batch.InventoryId) -or -not (Test-WinSecSnapshotUInt $batch.Sequence) -or
            $batch.Sequence -ne ($sequence[$batch.InventoryId]+1) -or $batch.Records -isnot [array] -or $batch.Records.Count -lt 1 -or $batch.Records.Count -gt $spec.BatchRecords){throw 'Invalid batch ordering or budget.'}
        if($seenInventories[$batch.InventoryId].State -cne 'OBSERVED'){throw 'Unavailable inventory supplies records.'}
        $sequence[$batch.InventoryId]++
        $definitions=@($Catalog.Fields|Where-Object InventoryId -CEQ $batch.InventoryId)
        foreach($record in $batch.Records){
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            Assert-WinSecSnapshotFields $record @('Id','Readings')
            if(-not (Test-WinSecSnapshotToken $record.Id) -or $records[$batch.InventoryId].ContainsKey($record.Id) -or
                $record.Readings -isnot [array] -or $record.Readings.Count -ne $definitions.Count){throw 'Duplicate record or missing readings.'}
            $records[$batch.InventoryId][$record.Id]=$true;$inventoryCounts[$batch.InventoryId]++;$counts.RetainedRecords++
            $seenFields=@{}
            foreach($reading in $record.Readings){
                Assert-WinSecSnapshotFields $reading @('FieldId','State','Reason','Value')
                foreach($name in @('FieldId','State','Reason')){if($reading.$name -isnot [string]){throw 'Invalid reading scalar.'}}
                $field=@($definitions|Where-Object Id -CEQ $reading.FieldId)
                if($field.Count -ne 1 -or $seenFields.ContainsKey($reading.FieldId) -or $reading.State -cnotin $spec.States){throw 'Unknown, repeated or invalid reading.'}
                $seenFields[$reading.FieldId]=$true;$counts[$stateCount[$reading.State]]++
                if($reading.State -ceq 'OBSERVED'){
                    if($null -eq $reading.Value -or $reading.Reason -cne 'NONE'){throw 'Missing observed value.'};Assert-WinSecSnapshotValue $reading.Value $field[0]
                }else{
                    if($null -ne $reading.Value){throw 'Unresolved reading supplies a value.'}
                    $reasons=switch -CaseSensitive ($reading.State){UNKNOWN {@('PROVIDER_UNAVAILABLE','INVALID_VALUE')};ERROR {@('PROVIDER_UNAVAILABLE','INVALID_VALUE')};NOT_COLLECTED {@('NOT_REQUESTED','RESOURCE_LIMIT')};NOT_CONFIGURED {@('ABSENT')};NOT_APPLICABLE {@('PLATFORM_EXCLUDED')}}
                    if($reading.Reason -cnotin $reasons){throw 'Invalid absence reason.'}
                    if($reading.State -ceq 'NOT_APPLICABLE' -and (Test-WinSecSnapshotApplicable $field[0].Applicability $Snapshot.Platform) -cne $false){throw 'Unverified field exclusion.'}
                    if($reading.State -cin @('UNKNOWN','ERROR','NOT_COLLECTED')){if($field[0].Required){$complete=$false};$coverage=$false}
                }
            }
        }
        if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $batch -Depth 16 -Compress)) -gt $spec.MaxBatchBytes){throw 'Snapshot batch byte budget exceeded.'}
    }
    foreach($id in $seenInventories.Keys){if($seenInventories[$id].RetainedRecords -ne $inventoryCounts[$id]){throw 'Inventory record count mismatch.'}}
    foreach($name in $counts.Keys){if(-not (Test-WinSecSnapshotUInt $Snapshot.Collection.$name) -or $Snapshot.Collection.$name -ne $counts[$name]){throw 'Snapshot coverage counts disagree.'}}
    if($Snapshot.SchemaVersion -ceq '2.1.0'){
        $projection=ConvertFrom-WinSecProjectionSnapshot $Snapshot
        $complete=Get-WinSecProjectionCompletion $projection
        $rowSummary=@($Snapshot.Inventories|Where-Object Id -CEQ Rows)[0]
        if($rowSummary.Complete -cne $complete){throw 'Projection collection summary contradicts its source.'}
        $coverage=($null -ne $Snapshot.Platform.BuildNumber -and $null -ne $Snapshot.Platform.OperatingSystemSKU -and $Snapshot.Platform.ProductType -eq 1 -and
            @($projection.Rows|Where-Object State -CIN @('UNKNOWN','ERROR','NOT_COLLECTED')).Count -eq 0)
        foreach($name in @('BuildNumber','OperatingSystemSKU','ProductType','Version')){
            $native=@($projection.Rows|Where-Object SettingId -CEQ ('Platform.'+$name))
            $observed=if($native.Count -eq 1 -and $native[0].State -ceq 'OBSERVED'){$native[0].Value}else{$null}
            if($Snapshot.Platform.$name -cne $observed){throw 'Transitional platform differs from recorded observation.'}
        }
        if($null -ne $Snapshot.Platform.OSRelease -or $null -ne $Snapshot.Platform.Edition -or $null -ne $Snapshot.Platform.UBR){throw 'Unrecorded platform metadata.'}
    }
    $coverage=($coverage -and $complete)
    if($Snapshot.Collection.Status -cne $(if($complete){'COMPLETE'}else{'PARTIAL'}) -or
        $Snapshot.Collection.Coverage -cne $(if($coverage){'COMPLETE'}else{'LIMITED'})){throw 'False collection or coverage status.'}
    if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $Snapshot -Depth 16 -Compress)) -gt $spec.MaxDocumentBytes){throw 'Snapshot document budget exceeded.'}
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
}

function ConvertFrom-WinSecTechnicalSnapshotJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Json,[Parameter(Mandatory)][object]$Catalog,
        [Parameter(Mandatory)][string]$CatalogSha256,[Parameter(Mandatory)][object]$ExpectedIdentity,
        [scriptblock]$CancellationAction)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    Assert-WinSecSnapshotJsonBudget $Json $clock $CancellationAction
    # Reuse the existing strict lexical/duplicate-key parser in this local scope.
    # Preserve strings on PS 7.5+ as on 5.1; do not let ISO text become DateTime values.
    . (Join-Path $PSScriptRoot 'DeviceInventory.ps1')
    $jsonReader=Get-Command Microsoft.PowerShell.Utility\ConvertFrom-Json -CommandType Cmdlet
    if($jsonReader.Parameters.ContainsKey('DateKind')){
        function ConvertFrom-WinSecSnapshotJsonString {param($InputObject);& $jsonReader -InputObject $InputObject -DateKind String -ErrorAction Stop}
        Set-Alias ConvertFrom-Json ConvertFrom-WinSecSnapshotJsonString -Scope Local
    }
    try {$data=ConvertFrom-WinSecBoundedStoredJson -Json $Json -MaxBytes 16777216}catch{throw 'Invalid technical snapshot JSON.'}
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    Assert-WinSecTechnicalSnapshot $data $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
    Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
    return $data
}

function Get-WinSecSnapshotCatalogHash {
    [CmdletBinding()]param([Parameter(Mandatory)][object]$Catalog)
    Assert-WinSecSnapshotCatalog $Catalog
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Catalog -Depth 16 -Compress))))).Replace('-','')}
    finally {$sha.Dispose()}
}

function Assert-WinSecSnapshotJsonBudget {
    param([string]$Json,[Diagnostics.Stopwatch]$Clock=([Diagnostics.Stopwatch]::StartNew()),[scriptblock]$CancellationAction)
    $spec=Get-WinSecSnapshotSpecification
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    if($utf8.GetByteCount($Json) -gt $spec.MaxDocumentBytes){throw 'Snapshot JSON byte budget exceeded.'}
    $depth=0;$quoted=$false;$escaped=$false
    for($index=0;$index -lt $Json.Length;$index++){
        if(($index % 4096) -eq 0){Assert-WinSecSnapshotValidationBudget $Clock $CancellationAction}
        $ch=$Json[$index]
        if($quoted){if($escaped){$escaped=$false}elseif($ch -ceq '\'){$escaped=$true}elseif($ch -ceq '"'){$quoted=$false};continue}
        if($ch -ceq '"'){$quoted=$true;continue}
        if($ch -in @('{','[')){$depth++;if($depth -gt $spec.MaxJsonDepth){throw 'Snapshot JSON nesting budget exceeded.'}}
        elseif($ch -in @('}',']')){$depth--;if($depth -lt 0){throw 'Invalid snapshot JSON nesting.'}}
    }
    if($quoted -or $depth -ne 0){throw 'Incomplete snapshot JSON.'}
}

function Assert-WinSecSnapshotValidationBudget {
    param([Diagnostics.Stopwatch]$Clock,[scriptblock]$CancellationAction)
    if($Clock.ElapsedMilliseconds -ge (Get-WinSecSnapshotSpecification).ValidationTimeoutMilliseconds){throw 'Snapshot validation time budget exceeded.'}
    if($CancellationAction){$cancel=& $CancellationAction;if($cancel -isnot [bool]){throw 'Invalid snapshot cancellation response.'};if($cancel){throw [OperationCanceledException]::new('Snapshot validation cancelled.')}}
}
