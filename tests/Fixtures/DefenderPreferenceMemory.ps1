# Client-constructed CIM objects only. All worker providers are replaced before invocation.
function New-WinSecDefenderPreferenceFixtureCarrier {
    $fixture=ConvertTo-WinSecDefenderCimFixture (New-WinSecDefenderTechnicalFixture)
    $source=$fixture.Sources[2]
    foreach($index in @(0,1)){$fixture.Sources[$index].Data.Dispose()}
    return $source
}

function Get-WinSecDefenderPreferenceFixtureSchema {
    [CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec)
    $script:DefenderPreferenceFixtureSchemaQueries++
    if($Namespace -cne 'root/Microsoft/Windows/Defender' -or $ClassName -cne 'MSFT_MpPreference' -or $OperationTimeoutSec -ne 5){throw 'Unreviewed schema query.'}
    $mode=$script:DefenderPreferenceFixtureMode
    if($mode -ceq 'SchemaError'){throw 'PRIVATE-SECRET-SCHEMA'}
    if($mode -ceq 'SchemaEmpty'){return}
    if($mode -ceq 'SchemaPlain'){return [pscustomobject]@{CimClassName=$ClassName}}
    $source=New-WinSecDefenderPreferenceFixtureCarrier
    try{
        switch($mode){
            MissingSchemaOptional {Set-WinSecDefenderCimFixtureProperty $source EnableDnsSinkhole -Remove}
            MissingSchemaRequired {Set-WinSecDefenderCimFixtureProperty $source DisableRealtimeMonitoring -Remove}
            IncompatibleSchema {Set-WinSecDefenderCimFixtureProperty $source DisableRealtimeMonitoring ([uint32]0) UInt32}
            NoProperties {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new($ClassName,$Namespace)}
            WrongSchemaClass {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new('Foreign',$Namespace)}
            WrongSchemaNamespace {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new($ClassName,'root/Foreign')}
        }
        $source.Data.CimClass
        if($mode -ceq 'SchemaDuplicate'){$source.Data.CimClass}
    }finally{$source.Data.Dispose()}
}

function Get-WinSecDefenderPreferenceFixtureData {
    [CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec,[string[]]$Property)
    $script:DefenderPreferenceFixtureQueries++
    $allowed=@(Get-WinSecDefenderTechnicalFields|Where-Object Inventory -CEQ Preferences|ForEach-Object Property)
    if($Namespace -cne 'root/Microsoft/Windows/Defender' -or $ClassName -cne 'MSFT_MpPreference' -or $OperationTimeoutSec -ne 5 -or
        $Property.Count -eq 0 -or @($Property|Where-Object {$_ -cnotin $allowed}).Count){throw 'Unsafe preference query.'}
    $script:DefenderPreferenceFixtureRequested=@($Property)
    $mode=$script:DefenderPreferenceFixtureMode
    if($mode -ceq 'ProviderError'){throw 'PRIVATE-SECRET-PROVIDER'}
    if($mode -ceq 'Empty'){return}
    if($mode -ceq 'Slow'){Start-Sleep -Seconds 30}
    if($mode -ceq 'Noisy'){
        Write-Warning 'PRIVATE-SECRET-WARNING';Write-Information 'PRIVATE-SECRET-INFORMATION'
        Write-Verbose 'PRIVATE-SECRET-VERBOSE' -Verbose;$DebugPreference='Continue';Write-Debug 'PRIVATE-SECRET-DEBUG'
    }
    $source=New-WinSecDefenderPreferenceFixtureCarrier
    switch($mode){
        MissingOptional {Set-WinSecDefenderCimFixtureProperty $source EnableDnsSinkhole -Remove}
        MissingRequired {Set-WinSecDefenderCimFixtureProperty $source DisableRealtimeMonitoring -Remove}
        NullRequired {$source.Data.CimInstanceProperties['DisableRealtimeMonitoring'].Value=$null}
        InvalidBoolean {Set-WinSecDefenderCimFixtureProperty $source DisableRealtimeMonitoring ([uint32]0) UInt32}
        InvalidPercent {$source.Data.CimInstanceProperties['ScanAvgCPULoadFactor'].Value=[uint32]101}
        UIntMax {$source.Data.CimInstanceProperties['IntelTDTEnabled'].Value=[uint32]::MaxValue}
        ByteCode {Set-WinSecDefenderCimFixtureProperty $source RealTimeScanDirection ([byte]99) UInt8}
        PlainCarrier {$source.Data.Dispose();return [pscustomobject]@{DisableRealtimeMonitoring=$false}}
        WrongClass {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new('Foreign',$Namespace)}
        WrongNamespace {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new($ClassName,'root/Foreign')}
        EmptyCarrier {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new($ClassName,$Namespace)}
    }
    # Hostile/over-returned private properties must never be accessed, including through ETS.
    foreach($name in @('ComputerID','ExclusionPath','ExclusionProcess','AttackSurfaceReductionRules_Ids','ProxyServer','SignatureDefinitionUpdateFileSharesSources')){
        Add-Member -InputObject $source.Data -MemberType ScriptProperty -Name $name -Value {throw 'PRIVATE-SECRET-GETTER'} -Force
    }
    $source.Data
    if($mode -ceq 'Duplicate'){[Microsoft.Management.Infrastructure.CimInstance]::new($ClassName,$Namespace)}
}

function Start-WinSecDefenderPreferenceFixtureJob {
    [CmdletBinding()]param([scriptblock]$ScriptBlock,[object[]]$ArgumentList)
    $fixturePath=$PSCommandPath;$memoryPath=Join-Path $PSScriptRoot 'DefenderTechnicalMemory.ps1'
    $job=Microsoft.PowerShell.Core\Start-Job -ScriptBlock {
        param($WorkerText,$WorkerArguments,$FixturePath,$MemoryPath,$Mode)
        $ErrorActionPreference='Stop';. $MemoryPath;. $FixturePath
        $script:DefenderPreferenceFixtureMode=$Mode;$script:DefenderPreferenceFixtureQueries=0;$script:DefenderPreferenceFixtureSchemaQueries=0
        function Get-CimClass {[CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec);Get-WinSecDefenderPreferenceFixtureSchema @PSBoundParameters}
        function Get-CimInstance {[CmdletBinding()]param([string]$Namespace,[string]$ClassName,[uint32]$OperationTimeoutSec,[string[]]$Property);Get-WinSecDefenderPreferenceFixtureData @PSBoundParameters}
        function Get-MpComputerStatus {throw 'Unmocked native status forbidden.'}
        function Get-MpPreference {throw 'Whole preference objects forbidden.'}
        if($Mode -ceq 'NoFrame'){return}
        $frame=& ([scriptblock]::Create($WorkerText)) @WorkerArguments
        if($Mode -ceq 'WrongIdentity'){$frame.ScanId='foreign'}
        $frame
        if($Mode -ceq 'ExtraFrame'){'PRIVATE-SECRET-EXTRA'}
    } -ArgumentList $ScriptBlock.ToString(),$ArgumentList,$fixturePath,$memoryPath,$script:DefenderPreferenceFixtureMode
    $script:DefenderPreferenceFixtureJobIds+=,$job.InstanceId
    return $job
}
