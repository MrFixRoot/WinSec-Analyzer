# Captured data fixtures only. No Windows providers or application-data writes.
function New-WinSecDefenderTechnicalFixture {
    param([int]$RuleCount=1)
    $identity=[pscustomobject]@{DeviceId=('local:hw1-'+('a'*64));ScanId='candidate-defender';SnapshotId=('b'*32);
        CheckId='WSA-SYS-001';SectionKey='SystemSecurity';ScopeType='CONTROL';ScopeKey='WSA-SYS-001'}
    $data=@{Platform=[ordered]@{};Status=[ordered]@{};Preferences=[ordered]@{}}
    foreach($field in @(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CNE ASR)){
        $area=if($field.Inventory -ceq 'ExclusionCounts'){'Preferences'}else{$field.Inventory}
        $value=switch($field.Kind){
            Boolean {$false};Build {'26100'};PlatformVersion {'10.0.26100'};UInt32 {[uint32]0};Percent {[uint32]50}
            Version {'1.2.3.4'};Utc {[datetimeoffset]'2026-10-28T00:00:00Z'};RunningMode {'Normal'};Count {,@('C:\PRIVATE-DEFENDER-CONFIGURATION')}
        }
        $data[$area][$field.Property]=$value
    }
    $data.Platform.OperatingSystemSKU=[uint32]48;$data.Platform.ProductType=[uint32]1
    $data.Status.AntivirusSignatureAge=[uint32]::MaxValue
    $ids=@();$actions=@();for($i=0;$i -lt $RuleCount;$i++){$ids+=([guid]::NewGuid().ToString('D'));$actions+=[uint32]1}
    $data.Preferences.AttackSurfaceReductionRules_Ids=$ids;$data.Preferences.AttackSurfaceReductionRules_Actions=$actions
    $sources=@(foreach($name in @('Platform','Status','Preferences')){
        [pscustomobject]@{SourceId=$name;DeviceId=$identity.DeviceId;ScanId=$identity.ScanId;CollectedAtUTC='2026-10-28T01:02:04.0000000Z';State='OBSERVED';Data=[pscustomobject]$data[$name]}
    })
    [pscustomobject]@{Identity=$identity;Sources=$sources;StartedAtUTC='2026-10-28T01:02:03.0000000Z';CompletedAtUTC='2026-10-28T01:02:05.0000000Z';GeneratedAtUTC='2026-10-28T01:02:06.0000000Z'}
}

function New-WinSecDefenderFixturePackage {
    param($Fixture,[scriptblock]$CancellationAction,[scriptblock]$ProgressCallback)
    New-WinSecDefenderTechnicalSnapshot -Identity $Fixture.Identity -Sources $Fixture.Sources -StartedAtUTC $Fixture.StartedAtUTC `
        -CompletedAtUTC $Fixture.CompletedAtUTC -GeneratedAtUTC $Fixture.GeneratedAtUTC -CancellationAction $CancellationAction -ProgressCallback $ProgressCallback
}

function Get-WinSecDefenderFixtureReading {
    param($Snapshot,[string]$Id)
    @($Snapshot.Batches|ForEach-Object Records|ForEach-Object Readings|Where-Object FieldId -CEQ $Id)[0]
}

function ConvertTo-WinSecDefenderCimFixture {
    # Client-side objects only: no CIM sessions, cmdlets, discovery or Windows queries.
    param([object]$Fixture)
    foreach($source in $Fixture.Sources){
        $class=switch($source.SourceId){Platform {'Win32_OperatingSystem'};Status {'MSFT_MpComputerStatus'};Preferences {'MSFT_MpPreference'}}
        $namespace=if($source.SourceId -ceq 'Platform'){'root/cimv2'}else{'root/Microsoft/Windows/Defender'}
        $instance=[Microsoft.Management.Infrastructure.CimInstance]::new($class,$namespace)
        try {
            foreach($property in $source.Data.PSObject.Properties){
                $value=$property.Value
                if($value -is [datetimeoffset]){$value=$value.UtcDateTime}
                $type=if($property.Name -ceq 'AttackSurfaceReductionRules_Ids' -or $property.Name -cin @('ExclusionPath','ExclusionProcess','ExclusionExtension',
                    'AttackSurfaceReductionOnlyExclusions','ControlledFolderAccessAllowedApplications','ControlledFolderAccessProtectedFolders')){
                    if($null -ne $value){$value=[string[]]$value};[Microsoft.Management.Infrastructure.CimType]::StringArray
                }elseif($property.Name -ceq 'AttackSurfaceReductionRules_Actions'){
                    if($null -ne $value){$value=[uint32[]]$value};[Microsoft.Management.Infrastructure.CimType]::UInt32Array
                }elseif($value -is [bool]){[Microsoft.Management.Infrastructure.CimType]::Boolean
                }elseif($value -is [uint32]){[Microsoft.Management.Infrastructure.CimType]::UInt32
                }elseif($value -is [datetime]){[Microsoft.Management.Infrastructure.CimType]::DateTime
                }else{[Microsoft.Management.Infrastructure.CimType]::String}
                $instance.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($property.Name,$value,$type,[Microsoft.Management.Infrastructure.CimFlags]::None))
            }
            $source.Data=$instance
        }catch{$instance.Dispose();throw}
    }
    return $Fixture
}

function Close-WinSecDefenderCimFixture {
    param([object]$Fixture)
    foreach($source in $Fixture.Sources){if($source.Data -is [Microsoft.Management.Infrastructure.CimInstance]){
        $null=[Microsoft.Management.Infrastructure.CimInstance].GetMethod('Dispose').Invoke($source.Data,$null)
    }}
}

function Set-WinSecDefenderCimFixtureProperty {
    param([object]$Source,[string]$Name,[object]$Value,[Microsoft.Management.Infrastructure.CimType]$Type,[switch]$Remove)
    $old=$Source.Data
    $replacement=[Microsoft.Management.Infrastructure.CimInstance]::new($old.CimSystemProperties.ClassName,$old.CimSystemProperties.Namespace)
    try {
        foreach($property in $old.CimInstanceProperties){if($property.Name -cne $Name){
            $replacement.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($property.Name,$property.Value,$property.CimType,[Microsoft.Management.Infrastructure.CimFlags]::None))
        }}
        if(-not $Remove){$replacement.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($Name,$Value,$Type,[Microsoft.Management.Infrastructure.CimFlags]::None))}
        $Source.Data=$replacement
    }catch{$replacement.Dispose();throw}
    finally{$old.Dispose()}
}
