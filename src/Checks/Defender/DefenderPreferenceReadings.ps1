# Data-only candidate preference payload. Uses the existing reviewed field catalog and scalar converter.
. (Join-Path $PSScriptRoot 'DefenderTechnicalCatalog.ps1')

function Get-WinSecDefenderPreferenceProjection {
    [CmdletBinding()]param([object]$Schema)
    # Read CLR metadata accessors directly; neither qualifier values nor instance values are inspected.
    try {
        if($Schema -isnot [Microsoft.Management.Infrastructure.CimClass]){throw 'Invalid schema carrier.'}
        $system=[Microsoft.Management.Infrastructure.CimClass].GetProperty('CimSystemProperties').GetValue($Schema,$null)
        $class=$system.GetType().GetProperty('ClassName').GetValue($system,$null)
        $namespace=$system.GetType().GetProperty('Namespace').GetValue($system,$null)
        if($class -ine 'MSFT_MpPreference' -or $namespace.Replace('\','/') -ine 'root/Microsoft/Windows/Defender'){throw 'Foreign schema.'}
        $properties=[Microsoft.Management.Infrastructure.CimClass].GetProperty('CimClassProperties').GetValue($Schema,$null)
        foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)){
            $property=$properties[$field.Property]
            if($null -eq $property){continue}
            $type=[Microsoft.Management.Infrastructure.CimPropertyDeclaration].GetProperty('CimType').GetValue($property,$null)
            if(($field.Kind -ceq 'Boolean' -and $type -eq [Microsoft.Management.Infrastructure.CimType]::Boolean) -or
                ($field.Kind -cin @('UInt32','Percent') -and $type -in @([Microsoft.Management.Infrastructure.CimType]::UInt8,[Microsoft.Management.Infrastructure.CimType]::UInt16,[Microsoft.Management.Infrastructure.CimType]::UInt32))){$field.Property}
        }
    }catch{throw 'Unreviewed Defender preference schema.'}
}

function Assert-WinSecDefenderPreferenceReadings {
    [CmdletBinding()]
    param([object]$Data,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotFields $Data @('ArtifactType','SchemaVersion','Readings')
    if($Data.ArtifactType -isnot [string] -or $Data.ArtifactType -cne 'WinSec.Defender.PreferenceReadings' -or
        $Data.SchemaVersion -isnot [string] -or $Data.SchemaVersion -cne '1.0.0' -or $Data.Readings -isnot [array] -or $Data.Readings.Rank -ne 1){
        throw 'Invalid Defender preference readings payload.'
    }
    $fields=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)
    if($Data.Readings.Count -ne $fields.Count){throw 'Incomplete Defender preference readings payload.'}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    for($i=0;$i -lt $fields.Count;$i++){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $reading=$Data.Readings[$i];$field=$fields[$i]
        Assert-WinSecSnapshotFields $reading @('FieldId','State','Reason','Value')
        if($reading.FieldId -isnot [string] -or $reading.FieldId -cne $field.Id -or $reading.State -isnot [string] -or
            $reading.State -cnotin @('OBSERVED','UNKNOWN') -or $reading.Reason -isnot [string]){throw 'Invalid Defender preference reading.'}
        if($reading.State -ceq 'UNKNOWN'){
            if($reading.Reason -cnotin @('PROVIDER_UNAVAILABLE','INVALID_VALUE') -or $null -ne $reading.Value){throw 'Invalid unknown Defender preference reading.'}
            continue
        }
        if($reading.Reason -cne 'NONE' -or
            ($field.Type -ceq 'Boolean' -and $reading.Value -isnot [bool]) -or
            ($field.Type -ceq 'UInt32' -and $reading.Value -isnot [uint32]) -or
            ($field.Type -ceq 'String' -and $reading.Value -isnot [string])){throw 'Invalid normalized Defender preference type.'}
        $normalized=ConvertTo-WinSecDefenderTechnicalValue $reading.Value $field.Kind
        if(-not $normalized.Valid -or $normalized.Value -cne $reading.Value){throw 'Invalid normalized Defender preference value.'}
    }
}

function New-WinSecDefenderPreferenceReadings {
    [CmdletBinding()]
    param([object]$Data,[string[]]$RequestedProperties,[scriptblock]$CancellationAction)
    Assert-WinSecDefenderCapturedCimSource $Data Preferences
    $allowed=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences|ForEach-Object Property)
    if($null -eq $RequestedProperties -or $RequestedProperties.Count -eq 0 -or $RequestedProperties.Count -gt $allowed.Count){throw 'Invalid preference projection.'}
    $seen=@{};foreach($name in $RequestedProperties){
        if($name -cnotin $allowed -or $seen.ContainsKey($name)){throw 'Unreviewed preference projection.'};$seen[$name]=$true
    }
    $clock=[Diagnostics.Stopwatch]::StartNew();$readings=New-Object 'Collections.Generic.List[object]'
    foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences)){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $state='UNKNOWN';$reason='PROVIDER_UNAVAILABLE';$value=$null
        # Properties not selected from the observed provider schema must never be read.
        $property=if($seen.ContainsKey($field.Property)){Get-WinSecDefenderCapturedProperty $Data $field.Property}else{[pscustomobject]@{Safe=$true;Exists=$false;Value=$null}}
        if(-not $property.Safe){$reason='INVALID_VALUE'}elseif($property.Exists -and $null -ne $property.Value){
            $normalized=ConvertTo-WinSecDefenderTechnicalValue $property.Value $field.Kind
            if($normalized.Valid){$state='OBSERVED';$reason='NONE';$value=$normalized.Value}else{$reason='INVALID_VALUE'}
        }
        $readings.Add([pscustomobject]@{FieldId=$field.Id;State=$state;Reason=$reason;Value=$value})
    }
    $payload=[pscustomobject]@{ArtifactType='WinSec.Defender.PreferenceReadings';SchemaVersion='1.0.0';Readings=$readings.ToArray()}
    Assert-WinSecDefenderPreferenceReadings $payload -CancellationAction $CancellationAction
    return $payload
}
