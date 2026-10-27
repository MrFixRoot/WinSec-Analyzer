# Reviewed local endpoint projection. Importing this file performs no queries.
function Get-WinSecOpenPortsProperties {
    param([ValidateSet('TCP','UDP')][string]$Protocol)
    @('LocalAddress','LocalPort','OwningProcess','CreationTime')
    if($Protocol -ceq 'TCP'){@('State','AppliedSetting','OffloadState')}
}
function Get-WinSecOpenPortsIssueCodes {
    @('PLATFORM_UNAVAILABLE','TCP_UNAVAILABLE','UDP_UNAVAILABLE')
}
function Get-WinSecOpenPortsTechnicalDefinitions {
    $spec=@('CollectionSuccessful|Collection|bool|','CollectionComplete|Collection|bool|',
        'CoverageComplete|Collection coverage|bool|','UnknownFieldCount|Collection coverage|number|',
        'CollectionIssueCount|Collection|number|','CollectionIssueCodes|Collection|portsIssues|',
        'Platform.BuildNumber|Windows context|number|','Platform.OperatingSystemSKU|Windows context|number|',
        'Platform.ProductType|Windows context|number|')
    foreach($protocol in @('TCP','UDP')){
        $spec+=('Availability.'+$protocol+'|Provider availability|mode|')
        foreach($name in @('Total','IPv4','IPv6','Loopback','NonLoopback','Wildcard','UnknownFields')){
            $spec+=('Counts.'+$protocol+'.'+$name+'|'+$protocol+' endpoint counts|number|Availability.'+$protocol)
        }
    }
    foreach($s in $spec){$p=$s.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source='Local NetTCPIP inventory';StatePath=$p[3]}}
}
function ConvertTo-WinSecOpenPortsNumber {
    param([AllowNull()][object]$Value,[long]$Maximum=4294967295)
    if($null -ne $Value -and $Value.GetType() -in @([byte],[uint16],[int16],[int],[uint32],[long],[uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le $Maximum){return [long]$Value}
    return $null
}
function ConvertTo-WinSecOpenPortsEndpoint {
    param([Parameter(Mandatory)][object]$Record,[ValidateSet('TCP','UDP')][string]$Protocol,[int]$Index)
    $address=$null;$raw=$Record.PSObject.Properties['LocalAddress'].Value
    if($Index -lt 1 -or $Index -gt 512 -or $raw -isnot [string] -or $raw.Length -gt 80 -or
        $raw -notmatch '\A[0-9A-Fa-f:.%]+\z' -or -not [Net.IPAddress]::TryParse($raw,[ref]$address)){throw 'Invalid local endpoint address.'}
    $port=ConvertTo-WinSecOpenPortsNumber $Record.PSObject.Properties['LocalPort'].Value 65535
    if($null -eq $port -or $port -lt 1){throw 'Invalid local endpoint port.'}
    if($Protocol -ceq 'TCP' -and (ConvertTo-WinSecOpenPortsNumber $Record.PSObject.Properties['State'].Value 255) -ne 2){throw 'Non-listening TCP record rejected.'}
    $scope=if([Net.IPAddress]::IsLoopback($address)){'LOOPBACK'}elseif($address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any)){'ANY'}else{'SPECIFIC'}
    $family=if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){'IPv4'}elseif($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){'IPv6'}else{throw 'Invalid endpoint family.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$addressId='sha256:'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($address.ToString()))).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}
    $created=$null;$value=$Record.PSObject.Properties['CreationTime'].Value
    if($value -is [datetime] -and $value.Year -ge 1970){$created=$value.ToUniversalTime().ToString('o')}
    $endpoint=[ordered]@{Id=($Protocol+'-'+('{0:D6}' -f $Index));Protocol=$Protocol;Family=$family;BindingScope=$scope;
        AddressId=$addressId;Port=$port;OwningProcess=(ConvertTo-WinSecOpenPortsNumber $Record.PSObject.Properties['OwningProcess'].Value);CreationTimeUTC=$created}
    if($Protocol -ceq 'TCP'){
        $endpoint.State='LISTEN'
        $endpoint.AppliedSetting=ConvertTo-WinSecOpenPortsNumber $Record.PSObject.Properties['AppliedSetting'].Value 255
        $endpoint.OffloadState=ConvertTo-WinSecOpenPortsNumber $Record.PSObject.Properties['OffloadState'].Value 255
    }
    [pscustomobject]$endpoint
}
function ConvertTo-WinSecOpenPortsBatch {
    param([string]$Json)
    if($Json.Length -gt 65536){throw 'Endpoint batch too large.'}
    $batch=ConvertFrom-WinSecStoredJson $Json
    Assert-WinSecConfigurationFields $batch @('SchemaVersion','Protocol','Items')
    if($batch.SchemaVersion -cne '1.0.0' -or $batch.Protocol -cnotin @('TCP','UDP')){throw 'Invalid endpoint batch identity.'}
    $items=$batch.Items
    if($items -isnot [array] -or $items.Count -lt 1 -or $items.Count -gt 64){throw 'Invalid endpoint batch.'}
    $seen=@{}
    foreach($item in $items){
        $fields=@('Id','Protocol','Family','BindingScope','AddressId','Port','OwningProcess','CreationTimeUTC')
        if($item.Protocol -ceq 'TCP'){$fields+=@('State','AppliedSetting','OffloadState')}
        Assert-WinSecConfigurationFields $item $fields
        if($item.Protocol -cne $batch.Protocol -or $item.Id -isnot [string] -or
            $item.Id -cnotmatch ('\A'+$item.Protocol+'-000(?:[0-4][0-9]{2}|50[0-9]|51[0-2])\z') -or $item.Id.EndsWith('-000000') -or
            $seen.ContainsKey($item.Id) -or $item.Family -cnotin @('IPv4','IPv6') -or $item.BindingScope -cnotin @('ANY','LOOPBACK','SPECIFIC') -or
            $item.AddressId -isnot [string] -or $item.AddressId -cnotmatch '\Asha256:[a-f0-9]{64}\z' -or
            $null -eq (ConvertTo-WinSecOpenPortsNumber $item.Port 65535) -or $item.Port -lt 1){throw 'Invalid endpoint record.'}
        if($null -ne $item.OwningProcess -and $null -eq (ConvertTo-WinSecOpenPortsNumber $item.OwningProcess)){throw 'Invalid endpoint PID.'}
        if($item.CreationTimeUTC -is [datetime]){$item.CreationTimeUTC=$item.CreationTimeUTC.ToUniversalTime().ToString('o')}
        if($null -ne $item.CreationTimeUTC){$null=ConvertTo-WinSecResultUtc $item.CreationTimeUTC 'CreationTimeUTC'}
        if($item.Protocol -ceq 'TCP'){
            if($item.State -cne 'LISTEN'){throw 'Non-listening stored endpoint.'}
            foreach($field in @('AppliedSetting','OffloadState')){if($null -ne $item.$field -and $null -eq (ConvertTo-WinSecOpenPortsNumber $item.$field 255)){throw 'Invalid endpoint metadata.'}}
        }
        $seen[$item.Id]=$true
    }
    return ,$items
}
function Get-WinSecOpenPortsCounts {
    param([AllowEmptyCollection()][object[]]$Items=@())
    $unknown=0
    foreach($item in $Items){foreach($field in @('OwningProcess','CreationTimeUTC')+$(if($item.Protocol -ceq 'TCP'){@('AppliedSetting','OffloadState')}else{@()})){
        if($null -eq $item.$field){$unknown++}
    }}
    [pscustomobject]@{Total=$Items.Count;IPv4=@($Items|Where-Object Family -CEQ IPv4).Count;IPv6=@($Items|Where-Object Family -CEQ IPv6).Count;
        Loopback=@($Items|Where-Object BindingScope -CEQ LOOPBACK).Count;NonLoopback=@($Items|Where-Object BindingScope -CNE LOOPBACK).Count;
        Wildcard=@($Items|Where-Object BindingScope -CEQ ANY).Count;UnknownFields=$unknown}
}
function Assert-WinSecOpenPortsReport {
    param([object]$Report)
    $rows=@{};foreach($row in $Report.Rows){$rows[$row.SettingId]=$row}
    $unknown=0;$complete=$true;$providers=0;$expectedIssues=@()
    foreach($protocol in @('TCP','UDP')){
        $items=@();$ids=@{};$batchNumber=0
        foreach($row in @($Report.Rows|Where-Object {$_.SettingId -clike ('Inventory.'+$protocol+'.*')})){
            $batchNumber++
            if($row.SettingId -cne ('Inventory.'+$protocol+'.'+('{0:D4}' -f $batchNumber)) -or $row.State -cne 'OBSERVED'){throw 'Incomplete endpoint batches.'}
            foreach($item in (ConvertTo-WinSecOpenPortsBatch $row.Value)){
                if($item.Protocol -cne $protocol -or $ids.ContainsKey($item.Id) -or $item.Id -cne ($protocol+'-'+('{0:D6}' -f ($items.Count+1)))){throw 'Foreign, missing or duplicate endpoint.'}
                $ids[$item.Id]=$true;$items+=,$item
            }
        }
        if($items.Count -gt 512){throw 'Endpoint inventory too large.'}
        $availability=$rows['Availability.'+$protocol]
        if($availability.State -ceq 'OBSERVED' -and $availability.Value -ceq 'OBSERVED'){
            $providers++
            $counts=Get-WinSecOpenPortsCounts $items;$unknown+=$counts.UnknownFields
            foreach($field in $counts.PSObject.Properties){$row=$rows['Counts.'+$protocol+'.'+$field.Name];if($row.State -cne 'OBSERVED' -or $row.Value -ne $field.Value){throw 'Endpoint count mismatch.'}}
        }else{
            $complete=$false
            $expectedIssues+=($protocol+'_UNAVAILABLE')
            if($availability.State -cne 'UNKNOWN' -or $null -ne $availability.Value){throw 'Invalid endpoint provider state.'}
            if($items.Count -or @($Report.Rows|Where-Object {$_.SettingId -clike ('Counts.'+$protocol+'.*') -and $_.State -ceq 'OBSERVED'}).Count){throw 'Unavailable provider cannot supply endpoints or counts.'}
        }
    }
    if(@($Report.Rows|Where-Object {$_.SettingId -clike 'Platform.*' -and $_.State -cne 'OBSERVED'}).Count){$complete=$false;$expectedIssues+='PLATFORM_UNAVAILABLE'}
    elseif($rows['Platform.BuildNumber'].Value -lt 22000 -or $rows['Platform.ProductType'].Value -ne 1 -or
        $null -eq (ConvertTo-WinSecOpenPortsNumber $rows['Platform.OperatingSystemSKU'].Value)){throw 'Invalid observed Windows endpoint context.'}
    $codes=if($rows.CollectionIssueCodes.Value -ceq 'NONE'){@()}else{@($rows.CollectionIssueCodes.Value.Split(','))}
    if($rows.CollectionIssueCount.State -cne 'OBSERVED' -or $rows.CollectionIssueCount.Value -ne $expectedIssues.Count -or
        (($codes|Sort-Object) -join '|') -cne (($expectedIssues|Sort-Object) -join '|')){throw 'Endpoint diagnostics contradict coverage.'}
    if($rows.CollectionSuccessful.Value -ne ($providers -gt 0) -or $rows.CollectionComplete.Value -ne $complete -or $rows.UnknownFieldCount.Value -ne $unknown -or
        $rows.CoverageComplete.Value -ne ($complete -and $unknown -eq 0)){throw 'Invalid endpoint completion or coverage claim.'}
}
