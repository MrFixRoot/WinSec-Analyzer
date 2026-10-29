# Isolated local configuration catalog. No RDP queries or production registration.
. (Join-Path $PSScriptRoot '../../Core/TechnicalSnapshotContract.ps1')

function Get-WinSecRdpCandidateAreas {
    [CmdletBinding()]param()
    $base='https://learn.microsoft.com/en-us/windows/win32/termserv/'
    foreach($spec in @(
        'Platform|CIMV2|win32-operatingsystem','Services|CIMV2|win32-service',
        'Global|TERMINALSERVICES|win32-terminalservicesetting','General|TERMINALSERVICES|win32-tsgeneralsetting',
        'Logon|TERMINALSERVICES|win32-tslogonsetting','Session|TERMINALSERVICES|win32-tssessionsetting',
        'Redirection|TERMINALSERVICES|win32-tsclientsetting','Network|TERMINALSERVICES|win32-tsnetworkadaptersetting',
        'Permissions|TERMINALSERVICES|win32-tspermissionssetting',
        'Registry|HKLM_REGISTRY64|registry')){
        $p=$spec.Split('|');$url=if($p[1] -ceq 'CIMV2'){'https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/'+$p[2]}
        elseif($p[2] -ceq 'registry'){'https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotedesktopservices'}else{$base+$p[2]}
        [pscustomobject]@{Id=$p[0];Location=$p[1];Provider=$(if($p[0] -ceq 'Registry'){'REGISTRY'}else{'CIM'});ReferenceUrl=$url;Host=($p[1] -ceq 'TERMINALSERVICES')}
    }
}

function Get-WinSecRdpCandidateRegistry {
    [CmdletBinding()]param()
    $root='SYSTEM\CurrentControlSet\Control\Terminal Server'
    foreach($spec in @('LocalDenyConnections|fDenyTSConnections','LocalSingleSession|fSingleSessionPerUser',
        'ListenerPort|PortNumber','ListenerNLA|UserAuthentication','ListenerSecurityLayer|SecurityLayer','ListenerEncryption|MinEncryptionLevel')){
        $p=$spec.Split('|');[pscustomobject]@{Id=$p[0];Key=($root+$(if($p[0].StartsWith('Listener')){'\WinStations\RDP-Tcp'}else{''}));Name=$p[1];Kind='DWord'}
    }
}

function Get-WinSecRdpCandidateFields {
    [CmdletBinding()]param()
    foreach($a in Get-WinSecRdpCandidateAreas){
        if($a.Host -and $a.Id -cne 'Global'){
            [pscustomobject]@{Id=($a.Id+'.TerminalName');Inventory=$a.Id;Property='TerminalName';Kind='Listener';Type='String';Required=$true;Exposure='IDENTIFIABLE'}
        }
        $groups=switch -CaseSensitive ($a.Id){
            Platform {'Version|Version';'Build|BuildNumber';'UInt32|OperatingSystemSKU,ProductType'}
            Services {'ServiceName|Name';'ServiceState|State';'StartMode|StartMode';'Boolean|Started,DelayedAutoStart';'UInt32|ExitCode,ServiceSpecificExitCode,CheckPoint,WaitHint';'ErrorControl|ErrorControl'}
            Global {'UInt32|AllowTSConnections,PolicySourceAllowTSConnections,SingleSession,TerminalServerMode,DeleteTempFolders,PolicySourceDeleteTempFolders,UseTempFolders,PolicySourceUseTempFolders,UserPermission,PolicySourceSingleSession,TimeZoneRedirection,PolicySourceTimeZoneRedirection,EnableAutomaticReconnection,PolicySourceEnableAutomaticReconnection,UseRDEasyPrintDriver,PolicySourceUseRDEasyPrintDriver,RedirectSmartCards,PolicySourceRedirectSmartCards,DisableForcibleLogoff,PolicySourceDisableForcibleLogoff'}
            General {'UInt32|MinEncryptionLevel,PolicySourceMinEncryptionLevel,SecurityLayer,PolicySourceSecurityLayer,UserAuthenticationRequired,PolicySourceUserAuthenticationRequired,WindowsAuthentication,SSLCertificateSHA1HashType';'Protocol|TerminalProtocol';'Transport|Transport'}
            Logon {'UInt32|ClientLogonInfoPolicy,PromptForPassword,PolicySourcePromptForPassword,PolicySourceDomain,PolicySourceUserName'}
            Session {'UInt32|ActiveSessionLimit,BrokenConnectionAction,BrokenConnectionPolicy,DisconnectedSessionLimit,IdleSessionLimit,PolicySourceActiveSessionLimit,PolicySourceBrokenConnectionAction,PolicySourceDisconnectedSessionLimit,PolicySourceIdleSessionLimit,PolicySourceReconnectionPolicy,ReconnectionPolicy,TimeLimitPolicy,EnableTimeoutWarning'}
            Redirection {'UInt32|ConnectionPolicy,ConnectClientDrivesAtLogon,ConnectPrinterAtLogon,DefaultToClientPrinter,PolicySourceDefaultToClientPrinter,WindowsPrinterMapping,PolicySourceWindowsPrinterMapping,LPTPortMapping,PolicySourceLPTPortMapping,COMPortMapping,PolicySourceCOMPortMapping,DriveMapping,PolicySourceDriveMapping,AudioMapping,PolicySourceAudioMapping,ClipboardMapping,PolicySourceClipboardMapping,ColorDepthPolicy,PolicySourceColorDepthPolicy,ColorDepth,PolicySourceColorDepth,MaxMonitors,MaxXResolution,MaxYResolution,PolicySourceMaxMonitors,PolicySourceMaxResolution,PNPRedirection,PolicySourcePNPRedirection,AudioCaptureRedir,PolicySourceAudioCaptureRedir,VideoPlaybackRedir,PolicySourceVideoPlaybackRedir,AllowDwm,PolicySourceAllowDwm,PolicyAdvancedRemoteAppGraphics,AdvancedRemoteAppGraphics,RemoteSessionProfile,PolicySourceRemoteSessionProfile,AVC444ModePreferred,PolicySourceAvc444ModePreferred,EncodeImageQuality,PolicySourceEncodeImageQuality,HardwareGraphicsAdapter,PolicySourceHardwareGraphicsAdapter,SelectTransport,PolicySourceSelectTransport,SelectNetworkDetect,PolicySourceSelectNetworkDetect'}
            Network {'UInt32|MaximumConnections,NetworkAdapterLanaID,PolicySourceMaximumConnections'}
            Permissions {'UInt32|DenyAdminPermissionForCustomization,PolicySourceDenyAdminPermissionForCustomization'}
            Registry {'RegistryDWord|LocalDenyConnections,LocalSingleSession,ListenerPort,ListenerNLA,ListenerSecurityLayer,ListenerEncryption'}
        }
        foreach($spec in $groups){$p=$spec.Split('|');foreach($name in $p[1].Split(',')){
            $type=switch($p[0]){Boolean {'Boolean'};{$_ -cin @('UInt32','Build','RegistryDWord')} {'UInt32'};default {'String'}}
            $required=($a.Id -cin @('Platform','Registry') -or $p[0] -ceq 'ServiceName' -or
                ($a.Id -ceq 'Services' -and $name -cin @('State','StartMode')) -or ($a.Id -ceq 'Global' -and $name -ceq 'AllowTSConnections') -or
                ($a.Id -ceq 'General' -and $name -cin @('UserAuthenticationRequired','SecurityLayer','MinEncryptionLevel')))
            [pscustomobject]@{Id=($a.Id+'.'+$name);Inventory=$a.Id;Property=$name;Kind=$p[0];Type=$type;Required=$required;Exposure='CONFIGURATION'}
        }}
    }
    foreach($a in Get-WinSecRdpCandidateAreas){foreach($kind in @('Time','SourceState','Location')){
        [pscustomobject]@{Id=('Capture.'+$a.Id+$kind);Inventory='Capture';Property=($a.Id+$kind);Kind=$kind;Type='String';Required=$true;Exposure='CONFIGURATION'}
    }}
    [pscustomobject]@{Id='Capture.Scope';Inventory='Capture';Property='Scope';Kind='Scope';Type='String';Required=$true;Exposure='CONFIGURATION'}
}

function Get-WinSecRdpCandidateApplicability {
    param([string]$Inventory,[string]$Property)
    # A finite support list never authorizes an exclusion for an unknown SKU; the validator checks Home proof separately.
    $hostArea=@(Get-WinSecRdpCandidateAreas|Where-Object {$_.Id -ceq $Inventory -and $_.Host}).Count -eq 1
    $skus=@();if($hostArea){$skus=@(4,27,48,49,121,122,125,126,161,162,164,165,188,191)}
    [pscustomobject]@{MinBuild=22000;MaxBuild=$null;Skus=$skus}
}

function Get-WinSecRdpCandidateCatalog {
    [CmdletBinding()]param()
    $areas=@(Get-WinSecRdpCandidateAreas)
    $sources=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;Provider=$_.Provider;ReferenceUrl=$_.ReferenceUrl}})
    $sources+=,[pscustomobject]@{Id='Capture';Provider='DERIVED';ReferenceUrl='https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access'}
    $inventories=@($areas|ForEach-Object {[pscustomobject]@{Id=$_.Id;SourceId=$_.Id;Required=$true;Singleton=($_.Id -cin @('Platform','Global','Registry'));Applicability=(Get-WinSecRdpCandidateApplicability $_.Id '')}})
    $inventories+=,[pscustomobject]@{Id='Capture';SourceId='Capture';Required=$true;Singleton=$true;Applicability=(Get-WinSecRdpCandidateApplicability Capture '')}
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFieldCatalog';SchemaVersion='1.0.0';CatalogId='WinSec.RDP.Candidate';CatalogVersion='1.0.0';CheckId='WSA-NET-003';Sources=$sources;Inventories=$inventories;
        Fields=@(Get-WinSecRdpCandidateFields|ForEach-Object {[pscustomobject]@{Id=$_.Id;InventoryId=$_.Inventory;Type=$_.Type;Unit='none';Required=$_.Required;Exposure=$_.Exposure;Applicability=(Get-WinSecRdpCandidateApplicability $_.Inventory $_.Property)}})}
}
