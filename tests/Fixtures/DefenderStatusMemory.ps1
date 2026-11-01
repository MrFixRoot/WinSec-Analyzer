# Construct status carriers locally. No real Defender, CIM query, preferences or detection reads.
function Get-WinSecDefenderStatusFixtureData {
    [CmdletBinding()]param()
    $script:DefenderStatusFixtureQueries++
    $mode=$script:DefenderStatusFixtureMode
    if($mode -ceq 'ProviderError'){throw 'PRIVATE-SECRET-PROVIDER'}
    if($mode -ceq 'Empty'){return}
    if($mode -ceq 'Slow'){Start-Sleep -Seconds 30}
    if($mode -ceq 'Noisy'){
        Write-Warning 'PRIVATE-SECRET-WARNING';Write-Information 'PRIVATE-SECRET-INFORMATION'
        Write-Verbose 'PRIVATE-SECRET-VERBOSE' -Verbose;$DebugPreference='Continue';Write-Debug 'PRIVATE-SECRET-DEBUG'
    }
    $fixture=ConvertTo-WinSecDefenderCimFixture (New-WinSecDefenderTechnicalFixture)
    $data=$fixture.Sources[1].Data
    foreach($index in @(0,2)){$null=[Microsoft.Management.Infrastructure.CimInstance].GetMethod('Dispose').Invoke($fixture.Sources[$index].Data,$null)}
    $source=[pscustomobject]@{Data=$data}
    switch($mode){
        MissingOptional {Set-WinSecDefenderCimFixtureProperty $source AntispywareSignatureAge -Remove}
        MissingRequired {Set-WinSecDefenderCimFixtureProperty $source AntivirusEnabled -Remove}
        NullRequired {$source.Data.CimInstanceProperties['AntivirusEnabled'].Value=$null}
        InvalidBoolean {Set-WinSecDefenderCimFixtureProperty $source AntivirusEnabled ([uint32]0) UInt32}
        InvalidVersion {$source.Data.CimInstanceProperties['FullScanSignatureVersion'].Value='PRIVATE-SECRET-VERSION'}
        UnknownMode {$source.Data.CimInstanceProperties['AMRunningMode'].Value='PRIVATE-SECRET-MODE'}
        Passive {$source.Data.CimInstanceProperties['AMRunningMode'].Value='Passive Mode'}
        EmptyCarrier {
            $source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_MpComputerStatus','root/Microsoft/Windows/Defender')
        }
        PlainCarrier {$source.Data.Dispose();return [pscustomobject]@{AMRunningMode='Normal'}}
        WrongClass {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new('Win32_Process','root/Microsoft/Windows/Defender')}
        WrongNamespace {$source.Data.Dispose();$source.Data=[Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_MpComputerStatus','root/Foreign')}
    }
    $source.Data.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('ComputerID','PRIVATE-SECRET-COMPUTER',[Microsoft.Management.Infrastructure.CimFlags]::None))
    $source.Data.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create('ThreatResources',[string[]]@('PRIVATE-SECRET-PATH'),[Microsoft.Management.Infrastructure.CimType]::StringArray,[Microsoft.Management.Infrastructure.CimFlags]::None))
    $source.Data
    if($mode -ceq 'Duplicate'){
        [Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_MpComputerStatus','root/Microsoft/Windows/Defender')
    }
}

function Start-WinSecDefenderStatusFixtureJob {
    [CmdletBinding()]param([scriptblock]$ScriptBlock,[object[]]$ArgumentList)
    $fixturePath=$PSCommandPath;$memoryPath=Join-Path $PSScriptRoot 'DefenderTechnicalMemory.ps1'
    $job=Microsoft.PowerShell.Core\Start-Job -ScriptBlock {
        param($WorkerText,$WorkerArguments,$FixturePath,$MemoryPath,$Mode)
        $ErrorActionPreference='Stop';. $MemoryPath;. $FixturePath
        $script:DefenderStatusFixtureMode=$Mode;$script:DefenderStatusFixtureQueries=0
        function Get-MpComputerStatus {[CmdletBinding()]param();Get-WinSecDefenderStatusFixtureData}
        function Get-CimInstance {throw 'Unmocked CIM forbidden.'}
        function Get-CimClass {throw 'Unmocked CIM schema forbidden.'}
        function Get-MpPreference {throw 'Preference acquisition forbidden.'}
        if($Mode -ceq 'NoFrame'){return}
        $frame=& ([scriptblock]::Create($WorkerText)) @WorkerArguments
        if($Mode -ceq 'WrongIdentity'){$frame.ScanId='foreign'}
        $frame
        if($Mode -ceq 'ExtraFrame'){'PRIVATE-SECRET-EXTRA'}
    } -ArgumentList $ScriptBlock.ToString(),$ArgumentList,$fixturePath,$memoryPath,$script:DefenderStatusFixtureMode
    $script:DefenderStatusFixtureJobIds+=,$job.InstanceId
    return $job
}
