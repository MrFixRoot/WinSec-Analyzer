# Reviewed IdentityAccess schema. Importing this file performs no Windows queries.
function Get-WinSecIdentityRoles {
    param([string]$CheckId)
    switch -CaseSensitive ($CheckId) {
        WSA-IAM-001 {@('Administrators')}
        WSA-IAM-002 {@('Guest')}
        WSA-IAM-003 {@('Password','Lockout')}
        default {throw 'Unreviewed identity control.'}
    }
}
function Get-WinSecIdentityFields {
    param([string]$Role)
    switch -CaseSensitive ($Role) {
        Administrators {@('MemberCount|number','Members|identityMembers')}
        Guest {@('Present|bool','Disabled|bool','LocalAccount|bool','Lockout|bool','PasswordRequired|bool','PasswordChangeable|bool','PasswordExpires|bool','AccountType|number','SIDType|number')}
        Password {@('MinimumLength|number','MaximumAgeSeconds|number','MinimumAgeSeconds|number','ForceLogoffSeconds|number','HistoryLength|number')}
        Lockout {@('DurationSeconds|number','ObservationWindowSeconds|number','Threshold|number')}
        default {throw 'Unreviewed identity provider.'}
    }
}
function Get-WinSecIdentityTechnicalDefinitions {
    param([string]$CheckId)
    $spec=@('CollectionSuccessful|Collection|bool|','CollectionComplete|Collection|bool|','CoverageComplete|Reading coverage|bool|',
        'UnknownFieldCount|Reading coverage|number|','CollectionIssueCount|Collection|number|','CollectionIssueCodes|Collection|identityIssues|',
        'Platform.BuildNumber|Windows context|number|','Platform.OperatingSystemSKU|Windows context|number|','Platform.ProductType|Windows context|number|')
    foreach($role in @(Get-WinSecIdentityRoles $CheckId)){
        $spec+=('Availability.'+$role+'|Provider availability|mode|')
        foreach($field in @(Get-WinSecIdentityFields $role)){
            $p=$field.Split('|');$spec+=($role+'.'+$p[0]+'|'+$role+' configuration|'+$p[1]+'|Availability.'+$role)
        }
    }
    if($CheckId -ceq 'WSA-IAM-003'){
        $spec+=@('Password.Complexity|Not collected by reviewed API|bool|','Password.ReversibleStorage|Not collected by reviewed API|bool|')
    }
    foreach($line in $spec){$p=$line.Split('|');[pscustomobject]@{Id=$p[0];Group=$p[1];Kind=$p[2];Source='Local SAM / reviewed CIM';StatePath=$p[3]}}
}
function ConvertTo-WinSecIdentityNumber {
    param([AllowNull()][object]$Value)
    if($null -ne $Value -and $Value.GetType() -in @([byte],[uint16],[int16],[int],[uint32],[long],[uint64]) -and [decimal]$Value -ge 0 -and [decimal]$Value -le 4294967295){return [long]$Value}
    return $null
}
function ConvertTo-WinSecIdentityMembers {
    param([string]$Json)
    if($Json.Length -gt 32768){throw 'Identity inventory exceeds budget.'}
    $data=ConvertFrom-WinSecStoredJson $Json
    Assert-WinSecConfigurationFields $data @('SchemaVersion','Items')
    if($data.SchemaVersion -cne '1.0.0' -or $data.Items -isnot [array] -or $data.Items.Count -gt 256){throw 'Invalid member inventory.'}
    $seen=@{}
    foreach($item in $data.Items){
        Assert-WinSecConfigurationFields $item @('Id','PrincipalId')
        if($item.Id -cne ('MEM-'+('{0:D4}' -f ($seen.Count+1))) -or $item.PrincipalId -isnot [string] -or
            $item.PrincipalId -cnotmatch '\Asha256:[a-f0-9]{64}\z' -or $seen.ContainsKey($item.PrincipalId)){throw 'Invalid or duplicate member.'}
        $seen[$item.PrincipalId]=$true
    }
    return ,$data.Items
}
function ConvertTo-WinSecIdentityRecord {
    param([string]$Role,[object[]]$Records)
    if($Role -ceq 'Administrators'){
        if($Records.Count -gt 256){throw 'Member inventory exceeds reviewed limit.'}
        $seen=@{};$items=@()
        foreach($record in $Records){
            $sid=$record.PSObject.Properties['SID'].Value
            if($sid -isnot [string] -or $sid.Length -gt 184 -or $sid -cnotmatch '\AS-1-[0-9]+(?:-[0-9]+){1,15}\z'){throw 'Invalid principal SID.'}
            # Validate without translating the SID or resolving names/domains.
            $parsed=New-Object Security.Principal.SecurityIdentifier $sid
            if($parsed.Value -cne $sid -or $seen.ContainsKey($sid)){throw 'Duplicate or noncanonical principal.'};$seen[$sid]=$true
            $sha=[Security.Cryptography.SHA256]::Create()
            try{$token='sha256:'+([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid))).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}
            $items+=,[pscustomobject]@{Id=('MEM-'+('{0:D4}' -f ($items.Count+1)));PrincipalId=$token}
        }
        $json=ConvertTo-Json -InputObject ([ordered]@{SchemaVersion='1.0.0';Items=@($items)}) -Compress -Depth 4
        $null=ConvertTo-WinSecIdentityMembers $json
        return [pscustomobject]@{MemberCount=$items.Count;Members=$json}
    }
    if($Records.Count -ne 1){throw 'Missing or ambiguous identity configuration.'}
    $raw=$Records[0];$result=[ordered]@{}
    if($Role -ceq 'Guest'){
        $sid=$raw.PSObject.Properties['SID'].Value
        if($sid -isnot [string] -or $sid.Length -gt 184 -or $sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-501\z' -or $raw.LocalAccount -isnot [bool] -or -not $raw.LocalAccount -or $raw.Disabled -isnot [bool]){throw 'Guest identity or state unavailable.'}
        $parsed=New-Object Security.Principal.SecurityIdentifier $sid
        if($parsed.Value -cne $sid){throw 'Noncanonical Guest identity.'}
    }
    foreach($field in @(Get-WinSecIdentityFields $Role)){
        $p=$field.Split('|');$value=if($p[0] -ceq 'Present'){$true}else{$raw.PSObject.Properties[$p[0]].Value}
        $result[$p[0]]=if($p[1] -ceq 'bool'){if($value -is [bool]){$value}else{$null}}else{ConvertTo-WinSecIdentityNumber $value}
        if($Role -cin @('Password','Lockout') -and $null -eq $result[$p[0]]){throw 'Invalid policy DWORD.'}
    }
    [pscustomobject]$result
}
function Assert-WinSecIdentityReport {
    param([object]$Report)
    $rows=@{};foreach($row in $Report.Rows){$rows[$row.SettingId]=$row}
    foreach($name in @('CollectionSuccessful','CollectionComplete','CoverageComplete','UnknownFieldCount','CollectionIssueCount','CollectionIssueCodes')){
        if($rows[$name].State -cne 'OBSERVED'){throw 'Missing identity summary.'}
    }
    foreach($row in $Report.Rows){
        if($row.State -ceq 'OBSERVED' -and $row.Value -is [ValueType] -and $row.Value -isnot [bool] -and $null -eq (ConvertTo-WinSecIdentityNumber $row.Value)){throw 'Invalid identity numeric range.'}
    }
    $issues=@();$unknown=0;$available=0
    foreach($role in @(Get-WinSecIdentityRoles $Report.CheckId)){
        $state=$rows['Availability.'+$role]
        if($state.State -ceq 'OBSERVED' -and $state.Value -ceq 'OBSERVED'){
            $available++
            foreach($field in @(Get-WinSecIdentityFields $role)){
                $name=$field.Split('|')[0];$row=$rows[$role+'.'+$name]
                if($row.State -cne 'OBSERVED'){
                    if($Report.CheckId -cne 'WSA-IAM-002' -or $name -cin @('Present','Disabled','LocalAccount')){throw 'Required identity reading absent.'};$unknown++
                }
            }
            if($role -ceq 'Administrators' -and $rows['Administrators.MemberCount'].Value -ne (ConvertTo-WinSecIdentityMembers $rows['Administrators.Members'].Value).Count){throw 'Member count mismatch.'}
            if($role -ceq 'Guest' -and ($rows['Guest.Present'].Value -cne $true -or $rows['Guest.LocalAccount'].Value -cne $true)){throw 'Guest provenance invalid.'}
        }else{
            if($state.State -cne 'UNKNOWN' -or $null -ne $state.Value){throw 'Invalid identity availability.'}
            $issues+=($role.ToUpperInvariant()+'_UNAVAILABLE')
            foreach($field in @(Get-WinSecIdentityFields $role)){if($rows[$role+'.'+$field.Split('|')[0]].State -cne 'UNKNOWN'){throw 'Unavailable identity provider supplies readings.'}}
        }
    }
    $platform=@('Platform.BuildNumber','Platform.OperatingSystemSKU','Platform.ProductType')
    if(@($platform|Where-Object {$rows[$_].State -cne 'OBSERVED'}).Count){$issues+='PLATFORM_UNAVAILABLE'}
    elseif($rows['Platform.BuildNumber'].Value -lt 22000 -or $rows['Platform.ProductType'].Value -ne 1){throw 'Invalid observed Windows context.'}
    if($Report.CheckId -ceq 'WSA-IAM-003'){
        foreach($field in @('Complexity','ReversibleStorage')){if($rows['Password.'+$field].State -cne 'NOT_COLLECTED'){throw 'Uncollected policy cannot be invented.'}}
        $unknown+=2
    }
    $codes=if($rows.CollectionIssueCodes.Value -ceq 'NONE'){@()}else{@($rows.CollectionIssueCodes.Value.Split(','))}
    if((($codes|Sort-Object) -join '|') -cne (($issues|Sort-Object) -join '|') -or $rows.CollectionIssueCount.Value -ne $issues.Count -or
        $rows.CollectionSuccessful.Value -ne ($available -gt 0) -or $rows.CollectionComplete.Value -ne ($issues.Count -eq 0) -or
        $rows.UnknownFieldCount.Value -ne $unknown -or $rows.CoverageComplete.Value -ne ($issues.Count -eq 0 -and $unknown -eq 0)){throw 'Identity completion or coverage mismatch.'}
}
