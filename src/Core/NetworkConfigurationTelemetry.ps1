# Reviewed network configuration projection. Importing this file never queries Windows.
function Get-WinSecNetworkConfigurationProviders {
    param([ValidateSet('1.0.0','1.1.0')][string]$CatalogVersion='1.1.0')
    $spec=@(
        'Adapter|MSFT_NetAdapter|InterfaceIndex|InterfaceIndex:u,InterfaceType:u,State:u,InterfaceOperationalStatus:u,InterfaceAdminStatus:u,MediaConnectState:u,MediaDuplexState:u,MtuSize:u,VlanID:u,TransmitLinkSpeed:l,ReceiveLinkSpeed:l,Virtual:b,Hidden:b,HardwareInterface:b,ConnectorPresent:b,FullDuplex:b,PromiscuousMode:b,AutoSense:b'
        'IPInterface|MSFT_NetIPInterface|InterfaceIndex,AddressFamily|InterfaceIndex:u,AddressFamily:f,Forwarding:e,Advertising:e,NlMtu:u,InterfaceMetric:u,NeighborUnreachabilityDetection:e,BaseReachableTime:u,RetransmitTime:u,DadTransmits:u,RouterDiscovery:e,ManagedAddressConfiguration:e,OtherStatefulConfiguration:e,WeakHostSend:e,WeakHostReceive:e,IgnoreDefaultRoutes:e,CurrentHopLimit:u,Dhcp:e,AutomaticMetric:e,ConnectionState:e'
        'IPAddress|MSFT_NetIPAddress|InterfaceIndex,AddressFamily,IPAddress,PrefixLength|InterfaceIndex:u,AddressFamily:f,IPAddress:ip,PrefixLength:p,PrefixOrigin:e,SuffixOrigin:e,AddressState:e,SkipAsSource:b,Type:e'
        'Route|MSFT_NetRoute|InterfaceIndex,AddressFamily,DestinationPrefix,NextHop|InterfaceIndex:u,AddressFamily:f,DestinationPrefix:prefix,NextHop:ip,RouteMetric:u,Protocol:e,Publish:e,Store:e,IsStatic:b'
        'DNSServer|MSFT_DNSClientServerAddress|InterfaceIndex,AddressFamily|InterfaceIndex:u,AddressFamily:f,ServerAddresses:ips'
        'DNSClient|MSFT_DNSClient|InterfaceIndex|InterfaceIndex:u,RegisterThisConnectionsAddress:b,UseSuffixWhenRegistering:b'
        'Profile|MSFT_NetConnectionProfile|InterfaceIndex,NetworkCategory|InterfaceIndex:u,NetworkCategory:c,IPv4Connectivity:e,IPv6Connectivity:e'
        'Legacy|Win32_NetworkAdapterConfiguration|Index,IPEnabled|Index:u,InterfaceIndex:u,IPEnabled:b,DHCPEnabled:b,TcpipNetbiosOptions:n,IPFilterSecurityEnabled:b,IPPortSecurityEnabled:b,WINSEnableLMHostsLookup:b,DNSEnabledForWINSResolution:b,FullDNSRegistrationEnabled:b,DomainDNSRegistrationEnabled:b'
        'DNSGlobal|MSFT_DNSClientGlobalSetting||UseDevolution:b,DevolutionLevel:u'
    )
    foreach($line in $spec){$parts=$line.Split('|')
        if($parts[0] -ceq 'Legacy' -and $CatalogVersion -ceq '1.0.0'){$parts[2]='InterfaceIndex,IPEnabled';$parts[3]=$parts[3].Substring('Index:u,'.Length)}
        [pscustomobject]@{Role=$parts[0];Class=$parts[1];
        Namespace=$(if($parts[0] -ceq 'Legacy'){'root/cimv2'}else{'root/StandardCimv2'});
        Required=@($parts[2].Split(',')|Where-Object {$_});Fields=@(foreach($pair in $parts[3].Split(',')){$p=$pair.Split(':');[pscustomobject]@{Name=$p[0];Kind=$p[1]}});
        Limit=$(if($parts[0] -ceq 'DNSGlobal'){1}else{64})}}
}
function Get-WinSecNetworkConfigurationProvider {
    param([string]$Role,[ValidateSet('1.0.0','1.1.0')][string]$CatalogVersion='1.1.0')
    $found=@(Get-WinSecNetworkConfigurationProviders $CatalogVersion|Where-Object Role -CEQ $Role)
    if($found.Count -ne 1){throw 'Unreviewed network configuration provider.'};$found[0]
}
function Get-WinSecNetworkConfigurationRegistryDefinitions {
    @('EnableMulticast|1','DisableSmartNameResolution|1','DoHPolicy|3')|ForEach-Object {$p=$_.Split('|');[pscustomobject]@{Name=$p[0];Maximum=[long]$p[1]}}
}
function Get-WinSecNetworkConfigurationIssueCodes {
    'PLATFORM_UNAVAILABLE';'REGISTRY_UNAVAILABLE'
    foreach($p in Get-WinSecNetworkConfigurationProviders){$p.Role.ToUpperInvariant()+'_UNAVAILABLE'}
}
function Get-WinSecNetworkConfigurationDiagnosticCodes {
    foreach($provider in Get-WinSecNetworkConfigurationProviders){
        $role=$provider.Role
        foreach($stage in @('QUERY','NORMALIZATION','BATCH')){$role+':'+$stage+':UNAVAILABLE'}
        foreach($reason in @('SCHEMA_INVALID','RECORD_LIMIT','QUERY_FAILED','TIMEOUT','INVALID_ENVELOPE')){$role+':QUERY:NETWORK_'+$reason}
        foreach($field in $provider.Required){$role+':NORMALIZATION:NETWORK_REQUIRED_FIELD_'+$field}
        if($role -ceq 'Legacy'){'Legacy:NORMALIZATION:NETWORK_REQUIRED_FIELD_InterfaceIndex'}
    }
}
function Get-WinSecNetworkConfigurationTechnicalDefinitions {
    $spec=@('CollectionSuccessful|Collection|bool|','CollectionComplete|Collection|bool|','CoverageComplete|Collection coverage|bool|',
        'UnknownFieldCount|Collection coverage|number|','CollectionIssueCount|Collection|number|','CollectionIssueCodes|Collection|networkIssues|',
        'Platform.BuildNumber|Windows context|number|','Platform.OperatingSystemSKU|Windows context|number|','Platform.ProductType|Windows context|number|',
        'RegistryReadState|Machine DNS policies|mode|')
    foreach($p in Get-WinSecNetworkConfigurationProviders){
        $spec+=('Availability.'+$p.Role+'|Provider availability|mode|')
        $spec+=('Counts.'+$p.Role+'|Inventory counts|number|Availability.'+$p.Role)
    }
    foreach($p in Get-WinSecNetworkConfigurationRegistryDefinitions){
        $spec+=('Registry.'+$p.Name+'.State|Machine DNS policies|mode|')
        $spec+=('Registry.'+$p.Name+'.Value|Machine DNS policies|number|Registry.'+$p.Name+'.State')
    }
    foreach($line in $spec){$p=$line.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];StatePath=$p[3];Source='Reviewed local network configuration'}}
}
function ConvertTo-WinSecNetworkConfigurationNumber {
    param([AllowNull()][object]$Value,[long]$Maximum=4294967295)
    if($null -ne $Value -and $Value.GetType() -in @([byte],[uint16],[int16],[int],[uint32],[long],[uint64]) -and
        [decimal]$Value -ge 0 -and [decimal]$Value -le $Maximum){return [long]$Value};return $null
}
function ConvertTo-WinSecNetworkConfigurationAddress {
    param([object]$Value,[switch]$Prefix)
    if($Value -isnot [string] -or $Value.Length -gt 80){throw 'Invalid network address.'}
    $text=$Value;$length=$null
    if($Prefix){if($text -cnotmatch '\A([^/]+)/([0-9]{1,3})\z'){throw 'Invalid network prefix.'};$text=$Matches[1];$length=[int]$Matches[2]}
    $address=$null
    if($text -cnotmatch '\A[0-9A-Fa-f:.%]+\z' -or -not [Net.IPAddress]::TryParse($text,[ref]$address)){throw 'Invalid network address.'}
    $family=if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){2}else{23}
    if($Prefix -and $length -gt $(if($family -eq 2){32}else{128})){throw 'Invalid network prefix length.'}
    $normalized=$address.ToString();if($Prefix){$normalized+='/'+$length}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$token='sha256:'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}
    [pscustomobject]@{Token=$token;Family=$family}
}
function ConvertTo-WinSecNetworkConfigurationRecord {
    param([object]$Record,[string]$Role,[int]$Index,[ValidateSet('1.0.0','1.1.0')][string]$CatalogVersion='1.1.0')
    $p=Get-WinSecNetworkConfigurationProvider $Role $CatalogVersion;$values=[ordered]@{}
    if($Index -lt 1 -or $Index -gt $p.Limit){throw 'Invalid network record index.'}
    foreach($field in $p.Fields){
        $raw=$Record.PSObject.Properties[$field.Name].Value;$value=$null
        if($null -ne $raw){
            switch($field.Kind){
                b {if($raw -is [bool]){$value=$raw}}
                {$_ -cin @('u','l','e','f','p','c','n')} {
                    $max=switch($field.Kind){l {9007199254740991};e {255};p {128};c {2};n {2};default {4294967295}}
                    $value=ConvertTo-WinSecNetworkConfigurationNumber $raw $max
                    if($field.Kind -ceq 'f' -and $value -notin @(2,23)){$value=$null}
                }
                {$_ -cin @('ip','prefix')} {
                    $address=ConvertTo-WinSecNetworkConfigurationAddress $raw -Prefix:($field.Kind -ceq 'prefix')
                    if($null -ne $values.AddressFamily -and $address.Family -ne $values.AddressFamily){throw 'Network address family mismatch.'}
                    $value=$address.Token
                }
                ips {
                    if($raw -isnot [Collections.IList] -or $raw.Count -gt 8){throw 'Invalid DNS server inventory.'}
                    $tokens=@();foreach($entry in $raw){$address=ConvertTo-WinSecNetworkConfigurationAddress $entry
                        if($address.Family -ne $values.AddressFamily){throw 'DNS address family mismatch.'};$tokens+=,$address.Token}
                    $value=$tokens
                }
            }
        }
        if($null -eq $value -and $field.Name -cin $p.Required){throw ('NETWORK_REQUIRED_FIELD_'+$field.Name)}
        $values[$field.Name]=$value
    }
    if($Role -ceq 'Legacy' -and $CatalogVersion -ceq '1.1.0' -and $null -eq $values.InterfaceIndex -and
        ($values.IPEnabled -ceq $true -or $null -ne $Record.PSObject.Properties['InterfaceIndex'].Value)){throw 'NETWORK_REQUIRED_FIELD_InterfaceIndex'}
    if($Role -ceq 'IPAddress' -and $null -ne $values.PrefixLength -and $values.PrefixLength -gt $(if($values.AddressFamily -eq 2){32}else{128})){throw 'Invalid IP prefix length.'}
    [pscustomobject]@{Id=($Role+'-'+('{0:D4}' -f $Index));Values=[pscustomobject]$values}
}
function ConvertTo-WinSecNetworkConfigurationBatch {
    param([string]$Json)
    if($Json.Length -gt 65536){throw 'Network batch too large.'}
    $batch=ConvertFrom-WinSecStoredJson $Json
    Assert-WinSecConfigurationFields $batch @('SchemaVersion','Role','Items')
    if($batch.SchemaVersion -cnotin @('1.0.0','1.1.0') -or $batch.Items -isnot [array] -or $batch.Items.Count -lt 1 -or $batch.Items.Count -gt 16){throw 'Invalid network batch.'}
    $p=Get-WinSecNetworkConfigurationProvider $batch.Role $batch.SchemaVersion
    $seen=@{};$legacyIndices=@{}
    foreach($item in $batch.Items){
        Assert-WinSecConfigurationFields $item @('Id','Values');Assert-WinSecConfigurationFields $item.Values @($p.Fields.Name)
        if($item.Id -isnot [string] -or $item.Id -cnotmatch ('\A'+$p.Role+'-00(?:[0-5][0-9]|6[0-4])\z') -or $item.Id.EndsWith('-0000') -or $seen.ContainsKey($item.Id)){throw 'Invalid network record identity.'}
        if($p.Limit -eq 1 -and $item.Id -cne ($p.Role+'-0001')){throw 'Invalid singleton configuration.'}
        foreach($field in $p.Fields){$v=$item.Values.($field.Name)
            if($null -eq $v){if($field.Name -cin $p.Required){throw 'Stored required network field unavailable.'};continue}
            switch($field.Kind){
                b {if($v -isnot [bool]){throw 'Invalid network Boolean.'}}
                {$_ -cin @('u','l','e','f','p','c','n')} {
                    $max=switch($field.Kind){l {9007199254740991};e {255};p {128};c {2};n {2};default {4294967295}}
                    if($null -eq (ConvertTo-WinSecNetworkConfigurationNumber $v $max) -or ($field.Kind -ceq 'f' -and $v -notin @(2,23))){throw 'Invalid stored network number.'}
                }
                {$_ -cin @('ip','prefix')} {if($v -isnot [string] -or $v -cnotmatch '\Asha256:[a-f0-9]{64}\z'){throw 'Invalid address token.'}}
                ips {if($v -isnot [array] -or $v.Count -gt 8){throw 'Invalid DNS tokens.'};foreach($t in $v){if($t -isnot [string] -or $t -cnotmatch '\Asha256:[a-f0-9]{64}\z'){throw 'Invalid DNS token.'}}}
            }
        }
        if($p.Role -ceq 'Legacy' -and $batch.SchemaVersion -ceq '1.1.0'){
            if($null -eq $item.Values.InterfaceIndex -and $item.Values.IPEnabled -ceq $true){throw 'IP-enabled Legacy configuration lacks an interface index.'}
            $key=[string]$item.Values.Index;if($legacyIndices.ContainsKey($key)){throw 'Duplicate Legacy configuration key.'};$legacyIndices[$key]=$true
        }
        if($p.Role -ceq 'IPAddress' -and $null -ne $item.Values.PrefixLength -and $item.Values.PrefixLength -gt $(if($item.Values.AddressFamily -eq 2){32}else{128})){throw 'Invalid stored IP prefix length.'}
        $seen[$item.Id]=$true
    }
    return $batch
}
function Get-WinSecNetworkConfigurationUnknownCount {
    param([AllowEmptyCollection()][object[]]$Items=@())
    $count=0;foreach($item in $Items){foreach($field in $item.Values.PSObject.Properties){if($null -eq $field.Value){$count++}}};return $count
}
function Assert-WinSecNetworkConfigurationReport {
    param([object]$Report)
    $rows=@{};foreach($row in $Report.Rows){$rows[$row.SettingId]=$row}
    $issues=@();$providers=0;$unknown=0
    foreach($p in (Get-WinSecNetworkConfigurationProviders $Report.CatalogVersion)){
        $items=@();$number=0;$legacyIndices=@{}
        foreach($row in @($Report.Rows|Where-Object {$_.SettingId -clike ('Inventory.'+$p.Role+'.*')})){
            $number++;if($row.State -cne 'OBSERVED' -or $row.SettingId -cne ('Inventory.'+$p.Role+'.'+('{0:D4}' -f $number))){throw 'Missing network inventory batch.'}
            $batch=ConvertTo-WinSecNetworkConfigurationBatch $row.Value
            if($batch.Role -cne $p.Role -or $batch.SchemaVersion -cne $Report.CatalogVersion){throw 'Foreign network inventory role or catalog version.'}
            foreach($item in $batch.Items){
                if($item.Id -cne ($p.Role+'-'+('{0:D4}' -f ($items.Count+1)))){throw 'Missing or duplicate network record.'}
                if($p.Role -ceq 'Legacy' -and $Report.CatalogVersion -ceq '1.1.0'){
                    $key=[string]$item.Values.Index;if($legacyIndices.ContainsKey($key)){throw 'Duplicate Legacy key across batches.'};$legacyIndices[$key]=$true
                };$items+=,$item
            }
        }
        $a=$rows['Availability.'+$p.Role];$c=$rows['Counts.'+$p.Role]
        if($a.State -ceq 'OBSERVED' -and $a.Value -ceq 'OBSERVED'){
            if($items.Count -gt $p.Limit -or ($p.Limit -eq 1 -and $items.Count -ne 1) -or $c.State -cne 'OBSERVED' -or $c.Value -ne $items.Count){throw 'Network inventory count mismatch.'}
            $providers++;$unknown+=Get-WinSecNetworkConfigurationUnknownCount $items
        }else{
            if($a.State -cne 'UNKNOWN' -or $null -ne $a.Value -or $c.State -cne 'UNKNOWN' -or $null -ne $c.Value -or $items.Count){throw 'Unavailable network provider supplies data.'}
            $issues+=($p.Role.ToUpperInvariant()+'_UNAVAILABLE')
        }
    }
    if(@($Report.Rows|Where-Object {$_.SettingId -clike 'Platform.*' -and $_.State -cne 'OBSERVED'}).Count){$issues+='PLATFORM_UNAVAILABLE'}
    elseif($rows['Platform.BuildNumber'].Value -lt 22000 -or $rows['Platform.ProductType'].Value -ne 1 -or $null -eq (ConvertTo-WinSecNetworkConfigurationNumber $rows['Platform.OperatingSystemSKU'].Value)){throw 'Invalid observed network platform.'}
    $registryOk=($rows.RegistryReadState.State -ceq 'OBSERVED' -and $rows.RegistryReadState.Value -ceq 'READ')
    if(-not $registryOk){$issues+='REGISTRY_UNAVAILABLE'}
    foreach($p in Get-WinSecNetworkConfigurationRegistryDefinitions){$s=$rows['Registry.'+$p.Name+'.State'];$v=$rows['Registry.'+$p.Name+'.Value']
        if($registryOk){
            if($s.State -cne 'OBSERVED' -or $s.Value -cnotin @('CONFIGURED','NOT_CONFIGURED')){throw 'Invalid network registry state.'}
            if($s.Value -ceq 'CONFIGURED'){if($v.State -cne 'OBSERVED' -or $null -eq (ConvertTo-WinSecNetworkConfigurationNumber $v.Value $p.Maximum)){throw 'Invalid network registry value.'}}
            elseif($v.State -cne 'NOT_CONFIGURED'){throw 'Unconfigured policy supplies a value.'}
        }elseif($s.State -cne 'UNKNOWN' -or $v.State -cne 'UNKNOWN'){throw 'Unavailable registry supplies policies.'}
    }
    $codes=if($rows.CollectionIssueCodes.Value -ceq 'NONE'){@()}else{@($rows.CollectionIssueCodes.Value.Split(','))}
    $complete=($issues.Count -eq 0)
    if($rows.CollectionIssueCount.Value -ne $issues.Count -or (($codes|Sort-Object)-join '|') -cne (($issues|Sort-Object)-join '|') -or
        $rows.CollectionSuccessful.Value -ne ($providers -gt 0) -or $rows.CollectionComplete.Value -ne $complete -or
        $rows.UnknownFieldCount.Value -ne $unknown -or $rows.CoverageComplete.Value -ne ($complete -and $unknown -eq 0)){throw 'Network completion or diagnostic claim contradicts readings.'}
}
