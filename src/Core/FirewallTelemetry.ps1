# Closed, safe Firewall inventory. Free names, paths, addresses and SIDs are hashed.
function Get-WinSecFirewallProfileFields {
    @('Enabled','DefaultInboundAction','DefaultOutboundAction','AllowInboundRules','AllowLocalFirewallRules',
      'AllowLocalIPsecRules','AllowUserApps','AllowUserPorts','AllowUnicastResponseToMulticast','NotifyOnListen',
      'EnableStealthModeForIPsec','LogAllowed','LogBlocked','LogIgnored','LogMaxSizeKilobytes','DisabledInterfaceAliasesCount')
}
function Get-WinSecFirewallGlobalFields {
    @('CertValidationLevel','EnablePacketQueuing','Exemptions','KeyEncoding','RequireFullAuthSupport',
      'EnableStatefulFtp','EnableStatefulPptp','RemoteMachineTransportAuthorizationListCount','RemoteUserTransportAuthorizationListCount')
}
function Get-WinSecFirewallDigest {
    param([string]$Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace('-','').ToLowerInvariant()}
    finally{$sha.Dispose()}
}
function Get-WinSecFirewallValue {
    param($Object,[string]$Name)
    if($null -eq $Object){return $null}
    $p=$Object.PSObject.Properties[$Name]
    if($null -ne $p){return $p.Value};return $null
}
function ConvertTo-WinSecFirewallScalar {
    param($Value)
    if($null -eq $Value){return $null}
    if($Value -is [bool]){return $Value}
    $s=[string]$Value
    if($s -in @('True','False')){return ($s -eq 'True')}
    if($s -cmatch '\A[0-9]{1,10}\z'){return [long]$s}
    if($s -in @('NotConfigured','Allow','Block','Inbound','Outbound','Any','Domain','Private','Public',
        'Local','GroupPolicy','Dynamic','Generated','Hardcoded','MDM','HostFirewall','HyperV','Running','Stopped','Auto','Manual','Disabled',
        'DeferToApp','AllowBypass','Require','Request','NotRequired','None','NoEncap','IPsec','Transport','Tunnel',
        'NotApplicable','NotRequired','Healthy','OK','Lan','Wireless','RemoteAccess','All','UNKNOWN')){return $s.ToUpperInvariant()}
    return $null
}
function ConvertTo-WinSecFirewallToken {
    param($Value,[ValidateSet('ports','addresses','program','service','interfaces','profiles','protocol','identity')][string]$Kind)
    if($null -eq $Value){return 'UNKNOWN'}
    $parts=@($Value);$text=($parts|ForEach-Object {[string]$_}) -join ','
    if($text.Length -gt 32768 -or $text -match '[\p{C}]'){return 'UNKNOWN'}
    if($text -in @('Any','*')){return 'ANY'}
    if($Kind -ceq 'profiles') {
        $names=@($text.Split(',')|ForEach-Object {$_.Trim().ToUpperInvariant()})
        if(@($names|Where-Object {$_ -cnotin @('DOMAIN','PRIVATE','PUBLIC')}).Count -eq 0){return (($names|Sort-Object -Unique) -join ',')}
    }
    if($Kind -ceq 'ports' -and $text -cmatch '\A(?:[0-9]{1,5}(?:-[0-9]{1,5})?)(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*\z'){
        foreach($part in $text.Split(',','-')){if([int]$part -gt 65535){return 'UNKNOWN'}}
        foreach($range in $text.Split(',')){if($range.Contains('-')){$ends=$range.Split('-');if([int]$ends[0] -gt [int]$ends[1]){return 'UNKNOWN'}}}
        return $text
    }
    if($Kind -ceq 'protocol' -and ($text -in @('TCP','UDP','ICMPv4','ICMPv6','HOPOPT') -or ($text -cmatch '\A[0-9]{1,3}\z' -and [int]$text -le 255))){return $text.ToUpperInvariant()}
    if($Kind -ceq 'addresses' -and $text -in @('LocalSubnet','DNS','DHCP','WINS','DefaultGateway','Internet','Intranet','RemoteCorpNetwork','CaptivePortal')){return $text.ToUpperInvariant()}
    return 'HASH:'+ (Get-WinSecFirewallDigest $text)
}
function ConvertTo-WinSecFirewallBatch {
    param([string]$Value)
    if($Value.Length -gt 262144){throw 'Firewall batch exceeds its bound.'}
    $rows=(ConvertFrom-WinSecStoredJson ('{"Rules":'+$Value+'}')).Rules
    if($rows -isnot [array] -or $rows.Count -gt 64){throw 'Invalid Firewall inventory batch.'}
    $fields=@('Id','Store','Enabled','Direction','Action','Profile','EdgeTraversalPolicy','PolicyStoreSourceType','PrimaryStatus',
        'Protocol','LocalPort','RemotePort','LocalAddress','RemoteAddress','Program','Package','Service','InterfaceAlias','InterfaceType',
        'Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine','FilterState')
    $seen=@{}
    foreach($row in $rows) {
        Assert-WinSecConfigurationFields $row $fields
        if($row.Id -isnot [string] -or $row.Id -cnotmatch '\A[a-f0-9]{64}\z' -or $seen.ContainsKey($row.Id) -or
            $row.Store -cnotin @('ACTIVE','LOCAL','HYPERV','IPSEC') -or $row.FilterState -cnotin @('COMPLETE','PARTIAL','NOT_REQUESTED')){throw 'Invalid Firewall rule identity.'}
        $seen[$row.Id]=$true
        foreach($p in $row.PSObject.Properties) {
            if($null -eq $p.Value){continue}
            if($p.Value -is [bool]){if($p.Name -cne 'Enabled'){throw 'Unexpected Boolean rule field.'};continue}
            if($p.Value -isnot [string] -or $p.Value.Length -gt 1024 -or $p.Value -cnotmatch '\A[A-Za-z0-9,._:-]+\z'){throw 'Unsafe Firewall rule value.'}
            if($p.Name -ceq 'Enabled'){throw 'Firewall Enabled must be Boolean or unknown.'}
            if($p.Name -cin @('LocalPort','RemotePort') -and $p.Value -cnotmatch '\A(?:UNKNOWN|ANY|HASH:[a-f0-9]{64}|[0-9,-]+)\z'){throw 'Invalid Firewall port token.'}
            if($p.Name -ceq 'Protocol' -and $p.Value -cnotmatch '\A(?:UNKNOWN|ANY|TCP|UDP|ICMPV4|ICMPV6|HOPOPT|[0-9]{1,3}|HASH:[a-f0-9]{64})\z'){throw 'Invalid Firewall protocol token.'}
            if($p.Name -cin @('LocalPort','RemotePort') -and $p.Value -cmatch '\A[0-9,-]+\z') {
                if((ConvertTo-WinSecFirewallToken $p.Value ports) -cne $p.Value){throw 'Invalid Firewall port range.'}
                foreach($range in $p.Value.Split(',')){if($range.Contains('-')){$ends=$range.Split('-');if([int]$ends[0] -gt [int]$ends[1]){throw 'Reversed Firewall port range.'}}}
            }
            if($p.Name -ceq 'Protocol' -and $p.Value -cmatch '\A[0-9]+\z' -and [int]$p.Value -gt 255){throw 'Invalid Firewall protocol.'}
            if($p.Name -notin @('Id','Store','FilterState','LocalPort','RemotePort','Protocol')) {
                $allowed=@('UNKNOWN','ANY','DOMAIN','PRIVATE','PUBLIC','DOMAIN,PRIVATE','DOMAIN,PUBLIC','PRIVATE,PUBLIC','DOMAIN,PRIVATE,PUBLIC',
                    'ALLOW','BLOCK','INBOUND','OUTBOUND','LOCAL','GROUPPOLICY','DYNAMIC','GENERATED','HARDCODED','MDM','HOSTFIREWALL','HYPERV',
                    'DEFErTOAPP','ALLOWBYPASS','REQUIRE','REQUEST','NOTREQUIRED','NONE','NOENCAP','IPSEC','TRANSPORT','TUNNEL','NOTAPPLICABLE','HEALTHY','OK',
                    'LOCALSUBNET','DNS','DHCP','WINS','DEFAULTGATEWAY','INTERNET','INTRANET','REMOTECORPNETWORK','CAPTIVEPORTAL')
                if($p.Value -notin $allowed -and $p.Value -cnotmatch '\AHASH:[a-f0-9]{64}\z'){throw 'Unreviewed Firewall rule text.'}
            }
        }
    }
    return ,$rows
}

function Get-WinSecFirewallTechnicalDefinitions {
    $spec=@('CollectionSuccessful|Collection|bool','CollectionComplete|Collection|bool','CollectionIssueCount|Collection|number','CollectionIssueCodes|Collection diagnostics|firewallIssues',
        'Platform.BuildNumber|Observed Windows|number','Platform.OperatingSystemSKU|Observed Windows|number','Platform.ProductType|Observed Windows|number',
        'HyperVState|Version-dependent coverage|firewallScalar')
    foreach($store in @('Active','Local')){foreach($profile in @('Domain','Private','Public')){
        foreach($field in Get-WinSecFirewallProfileFields){$spec+=('Profiles.'+$store+$profile+'.'+$field+'|'+$store+' '+$profile+' profile|firewallScalar')}
    }}
    foreach($field in Get-WinSecFirewallGlobalFields){$spec+=('Global.'+$field+'|Global and IPsec settings|firewallScalar')}
    foreach($service in @('MpsSvc','BFE')){foreach($field in @('State','StartMode')){$spec+=('Services.'+$service+'.'+$field+'|Firewall services|firewallScalar')}}
    foreach($name in @('RulesActive','RulesLocal','IPsec','HyperVRules','DynamicKeywords','HyperVCreators','HyperVSettings','HyperVProfiles')){
        $spec+=('Inventories.'+$name+'Count|Inventory coverage|number')
    }
    foreach($line in $spec){$p=$line.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source='NetSecurity:local';StatePath=''}}
}

function Get-WinSecFirewallIssueCodes {
    @('PLATFORM_UNAVAILABLE','SERVICE_MpsSvc_UNAVAILABLE','SERVICE_BFE_UNAVAILABLE','PROFILE_IDENTITY_INVALID','PROFILE_REQUIRED_FIELDS_UNAVAILABLE')
    foreach($key in @('ProfilesActive','ProfilesLocal','Global','RulesActive','RulesLocal','IPsec','DynamicKeywords','HyperVCreators','HyperVSettings','HyperVProfiles','HyperVRules',
        'Port','Address','Application','Service','Interface','InterfaceType','Security','PortLocal','AddressLocal','ApplicationLocal','ServiceLocal','InterfaceLocal','InterfaceTypeLocal','SecurityLocal')) {
        $key.ToUpperInvariant()+'_UNAVAILABLE'
        if($key -cin @('Port','Address','Application','Service','Interface','InterfaceType','Security','PortLocal','AddressLocal','ApplicationLocal','ServiceLocal','InterfaceLocal','InterfaceTypeLocal','SecurityLocal')){$key.ToUpperInvariant()+'_IDENTITY_INVALID'}
    }
    foreach($store in @('ACTIVE','LOCAL','IPSEC','HYPERV')){$store+'_FILTER_ASSOCIATION_UNRESOLVED'}
}

function Get-WinSecFirewallMetadataFields {
    @('Enabled','DefaultInboundAction','DefaultOutboundAction','LoopbackEnabled','AllowHostPolicyMerge',
      'AllowLocalFirewallRules','AllowLocalIPsecRules','PolicyStoreSourceType','AutoResolve','Addresses',
      'VMCreatorId','PolicyStoreSource','Inbound','Outbound')
}
function ConvertTo-WinSecFirewallMetadataBatch {
    param([string]$Value)
    if($Value.Length -gt 262144){throw 'Firewall metadata exceeds its bound.'}
    $rows=(ConvertFrom-WinSecStoredJson ('{"Rows":'+$Value+'}')).Rows
    if($rows -isnot [array] -or $rows.Count -gt 64){throw 'Invalid Firewall metadata.'}
    foreach($row in $rows) {
        Assert-WinSecConfigurationFields $row @('Id','Kind','Values')
        if($row.Id -cnotmatch '\A[a-f0-9]{64}\z' -or $row.Kind -cnotin @('DYNAMIC','HVCREATOR','HVSETTING','HVPROFILE')){throw 'Invalid metadata identity.'}
        foreach($p in $row.Values.PSObject.Properties) {
            if($p.MemberType -ne 'NoteProperty' -or $p.Name -cnotin @(Get-WinSecFirewallMetadataFields)){throw 'Unknown metadata field.'}
            if($null -eq $p.Value -or $p.Value -is [bool]){continue}
            if(($p.Value -is [int] -or $p.Value -is [long]) -and $p.Value -ge 0 -and $p.Value -le 4294967295){continue}
            if($p.Value -isnot [string]){throw 'Unsafe metadata field.'}
            $scalar=ConvertTo-WinSecFirewallScalar $p.Value
            if($p.Value -cnotmatch '\AHASH:[a-f0-9]{64}\z' -and $p.Value -cnotin @('UNKNOWN','ANY') -and
                ($scalar -isnot [string] -or $scalar -cne $p.Value)){throw 'Unsafe metadata field.'}
        }
    }
    return ,$rows
}
