# Synthetic CIM construction and owned synthetic jobs. Never query Windows.
function Get-WinSecDefenderPlatformFixtureCim {
    [CmdletBinding()]
    param([string]$Namespace,[string]$ClassName,[string[]]$Property,[uint32]$OperationTimeoutSec)
    if($Namespace -cne 'root/cimv2' -or $ClassName -cne 'Win32_OperatingSystem' -or $OperationTimeoutSec -ne 5 -or
        ($Property -join '|') -cne 'Version|BuildNumber|OperatingSystemSKU|ProductType'){throw 'Unexpected fixture query.'}
    $script:DefenderPlatformFixtureQueries++
    $mode=$script:DefenderPlatformFixtureMode
    if($mode -ceq 'ProviderError'){throw 'PRIVATE-SECRET-PROVIDER'}
    if($mode -ceq 'Empty'){return}
    if($mode -ceq 'Slow'){Start-Sleep -Seconds 30}
    if($mode -ceq 'Noisy'){
        Write-Warning 'PRIVATE-SECRET-WARNING';Write-Information 'PRIVATE-SECRET-INFORMATION'
        Write-Verbose 'PRIVATE-SECRET-VERBOSE' -Verbose
        $DebugPreference='Continue';Write-Debug 'PRIVATE-SECRET-DEBUG'
    }
    if($mode -ceq 'PlainCarrier'){return [pscustomobject]@{Version='10.0.26100';BuildNumber='26100';OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}}
    $class=if($mode -ceq 'WrongClass'){'Win32_Process'}else{'Win32_OperatingSystem'}
    $ns=if($mode -ceq 'WrongNamespace'){'root/Foreign'}else{'root/cimv2'}
    $count=if($mode -ceq 'Duplicate'){2}else{1}
    for($i=0;$i -lt $count;$i++){
        $instance=[Microsoft.Management.Infrastructure.CimInstance]::new($class,$ns)
        $build=if($mode -ceq 'OlderWindows'){'19045'}else{'26100'}
        $version=if($mode -ceq 'InvalidValue'){'PRIVATE-SECRET-VERSION'}else{'10.0.'+$build}
        $values=[ordered]@{Version=$version;BuildNumber=$build;OperatingSystemSKU=[uint32]48;ProductType=[uint32]1}
        foreach($name in $values.Keys){
            if($mode -ceq 'MissingValue' -and $name -ceq 'OperatingSystemSKU'){continue}
            $instance.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($name,$values[$name],[Microsoft.Management.Infrastructure.CimFlags]::None))
        }
        foreach($name in @('RegisteredUser','SerialNumber','Name')){
            $instance.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($name,'PRIVATE-SECRET',[Microsoft.Management.Infrastructure.CimFlags]::None))
        }
        if($mode -ceq 'NullValue'){$instance.CimInstanceProperties['ProductType'].Value=$null}
        $instance
    }
}

function Start-WinSecDefenderPlatformFixtureJob {
    [CmdletBinding()]
    param([scriptblock]$ScriptBlock,[object[]]$ArgumentList)
    $script:DefenderPlatformFixtureJobsStarted++
    $fixturePath=$PSCommandPath
    $job=Microsoft.PowerShell.Core\Start-Job -ScriptBlock {
        param($WorkerText,$WorkerArguments,$FixturePath,$Mode)
        $ErrorActionPreference='Stop'
        . $FixturePath
        $script:DefenderPlatformFixtureMode=$Mode;$script:DefenderPlatformFixtureQueries=0
        function Get-CimInstance {
            [CmdletBinding()]param($Namespace,$ClassName,$Property,$OperationTimeoutSec)
            Get-WinSecDefenderPlatformFixtureCim -Namespace $Namespace -ClassName $ClassName -Property $Property -OperationTimeoutSec $OperationTimeoutSec
        }
        if($Mode -ceq 'NoFrame'){return}
        $frame=& ([scriptblock]::Create($WorkerText)) @WorkerArguments
        if($Mode -ceq 'WrongIdentity'){$frame.ScanId='foreign'}
        $frame
        if($Mode -ceq 'ExtraFrame'){'PRIVATE-SECRET-EXTRA'}
    } -ArgumentList $ScriptBlock.ToString(),$ArgumentList,$fixturePath,$script:DefenderPlatformFixtureMode
    $script:DefenderPlatformFixtureJobIds+=,$job.InstanceId
    return $job
}
