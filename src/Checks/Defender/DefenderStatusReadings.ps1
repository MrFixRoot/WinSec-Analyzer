# Data-only candidate status payload. Uses the existing reviewed field catalog and scalar converter.
. (Join-Path $PSScriptRoot 'DefenderTechnicalCatalog.ps1')

function Assert-WinSecDefenderStatusReadings {
    [CmdletBinding()]
    param([object]$Data,[scriptblock]$CancellationAction)
    Assert-WinSecSnapshotFields $Data @('ArtifactType','SchemaVersion','Readings')
    if($Data.ArtifactType -isnot [string] -or $Data.ArtifactType -cne 'WinSec.Defender.StatusReadings' -or
        $Data.SchemaVersion -isnot [string] -or $Data.SchemaVersion -cne '1.0.0' -or $Data.Readings -isnot [array] -or $Data.Readings.Rank -ne 1){
        throw 'Invalid Defender status readings payload.'
    }
    $fields=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Status)
    if($Data.Readings.Count -ne $fields.Count){throw 'Incomplete Defender status readings payload.'}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    for($i=0;$i -lt $fields.Count;$i++){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $reading=$Data.Readings[$i];$field=$fields[$i]
        Assert-WinSecSnapshotFields $reading @('FieldId','State','Reason','Value')
        if($reading.FieldId -isnot [string] -or $reading.FieldId -cne $field.Id -or $reading.State -isnot [string] -or
            $reading.State -cnotin @('OBSERVED','UNKNOWN') -or $reading.Reason -isnot [string]){throw 'Invalid Defender status reading.'}
        if($reading.State -ceq 'UNKNOWN'){
            if($reading.Reason -cnotin @('PROVIDER_UNAVAILABLE','INVALID_VALUE') -or $null -ne $reading.Value){throw 'Invalid unknown Defender status reading.'}
            continue
        }
        if($reading.Reason -cne 'NONE' -or
            ($field.Type -ceq 'Boolean' -and $reading.Value -isnot [bool]) -or
            ($field.Type -ceq 'UInt32' -and $reading.Value -isnot [uint32]) -or
            ($field.Type -ceq 'String' -and $reading.Value -isnot [string])){throw 'Invalid normalized Defender status type.'}
        $normalized=ConvertTo-WinSecDefenderTechnicalValue $reading.Value $field.Kind
        if(-not $normalized.Valid -or $normalized.Value -cne $reading.Value){throw 'Invalid normalized Defender status value.'}
    }
}

function New-WinSecDefenderStatusReadings {
    [CmdletBinding()]
    param([object]$Data,[scriptblock]$CancellationAction)
    Assert-WinSecDefenderCapturedCimSource $Data Status
    $clock=[Diagnostics.Stopwatch]::StartNew();$readings=New-Object 'Collections.Generic.List[object]'
    foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Status)){
        Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
        $state='UNKNOWN';$reason='PROVIDER_UNAVAILABLE';$value=$null
        $property=Get-WinSecDefenderCapturedProperty $Data $field.Property
        if(-not $property.Safe){$reason='INVALID_VALUE'}elseif($property.Exists -and $null -ne $property.Value){
            $normalized=ConvertTo-WinSecDefenderTechnicalValue $property.Value $field.Kind
            if($normalized.Valid){$state='OBSERVED';$reason='NONE';$value=$normalized.Value}else{$reason='INVALID_VALUE'}
        }
        $readings.Add([pscustomobject]@{FieldId=$field.Id;State=$state;Reason=$reason;Value=$value})
    }
    $payload=[pscustomobject]@{ArtifactType='WinSec.Defender.StatusReadings';SchemaVersion='1.0.0';Readings=$readings.ToArray()}
    Assert-WinSecDefenderStatusReadings $payload -CancellationAction $CancellationAction
    return $payload
}
