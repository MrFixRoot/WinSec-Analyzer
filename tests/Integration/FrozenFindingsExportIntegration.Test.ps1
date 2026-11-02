[CmdletBinding()]param()
$ErrorActionPreference='Stop';$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tempParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$sandbox=Join-Path $tempParent ('wse-'+[guid]::NewGuid().ToString('N').Substring(0,8));$null=[IO.Directory]::CreateDirectory($sandbox)
$passed=0;$failed=0
function Assert-FE {param([bool]$Value);if(-not $Value){throw 'Frozen export assertion failed.'}}
function Reject-FE {param([scriptblock]$Action);$rejected=$false;try{$null=& $Action}catch{$rejected=$true};Assert-FE $rejected}
function Test-FE {param($CaseName,[scriptblock]$Action);try{$null=& $Action;$script:passed++;Write-Host ('[PASS] '+$CaseName)}catch{$script:failed++;Write-Host ('[FAIL] '+$CaseName+': '+$_.Exception.Message);Write-Host $_.ScriptStackTrace}}
function Get-FEFiles {@(Get-ChildItem -LiteralPath (Join-Path $sandbox 'reports') -Recurse -File -ErrorAction SilentlyContinue|ForEach-Object {$_.FullName+'|'+(Get-FileHash -LiteralPath $_.FullName).Hash}) -join "`n"}
try{
    foreach($dir in @('src','config')){Copy-Item -LiteralPath (Join-Path $sourceRoot $dir) -Destination (Join-Path $sandbox $dir) -Recurse}
    foreach($file in @('src/Core/ScanCoordinator.ps1','src/CLI/Invoke-WinSecCLI.ps1','src/CLI/FrameworkWorkflow.ps1','src/UI/Core/NavigationController.ps1','src/UI/Screens/MainMenu.ps1')){. (Join-Path $sandbox $file)}
    . (Join-Path $sourceRoot 'tests/Fixtures/FrameworkWorkflowMemory.ps1')
    . (Join-Path $sourceRoot 'tests/Fixtures/FrozenFindingsMemory.ps1')
    function Get-CimInstance {throw 'Native query forbidden.'}
    function Get-MpPreference {throw 'Native query forbidden.'}
    function Get-FEHardware {'local:hw1-'+('b'*64)}
    Set-Alias Get-WinSecLocalHardwareDeviceId Get-FEHardware -Scope Script
    $null=Register-WinSecLocalDevice $sandbox;$device=(Import-WinSecDeviceInventory $sandbox).targets[0];$id=$device.DeviceId
    $control=New-WinSecFrozenFindingsFixture $sandbox
    $section=New-WinSecFrozenFindingsFixture $sandbox @('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')
    $legacy=New-WinSecFrozenFindingsFixture $sandbox -Legacy
    $exports=New-Object 'Collections.Generic.List[object]'
    foreach($a in @($control,$section,$legacy)){
        Test-FE ('Protected publication and strict saved roundtrip: '+$a.ScopeType+'/'+$a.SchemaVersion) {
            $r=Export-WinSecFrameworkAnalysis $sandbox $a;$exports.Add($r)
            $saved=Read-WinSecFrozenFindingsReport $sandbox $r.Path $id
            Assert-FE ($saved.Analysis.ContentSha256 -ceq $a.ContentSha256 -and $r.FileSha256 -ceq (Get-FileHash -LiteralPath $r.Path).Hash -and
                $r.RelativePath.StartsWith('reports/'+(Get-WinSecSnapshotDeviceKey $id)+'/SystemSecurity/findings/') -and $r.RelativePath.EndsWith('_'+$a.AnalysisId+'.md'))
            $name=if($a.ScopeType -ceq 'SECTION'){'SystemSecurity'}else{'BitLocker'}
            Assert-FE ([IO.Path]::GetFileName($r.Path).Contains($name+'_'))
            Assert-WinSecSnapshotPrivateAcl $r.Path;Assert-WinSecSnapshotPrivateAcl ([IO.Path]::GetDirectoryName($r.Path)) -Directory
            $text=[IO.File]::ReadAllText($r.Path);foreach($row in $a.Rows){Assert-FE ($text.Contains($row.Title) -and $text.Contains($row.Recommendation))}
            Assert-FE ($text -notmatch 'PRIVATE-|RecoveryPassword|NOT_SCORED|/100')
        }
    }
    Test-FE 'Same frozen view can be exported again without overwriting the prior report' {
        $r=Export-WinSecFrameworkAnalysis $sandbox $control;$exports.Add($r)
        Assert-FE ($r.Path -cne $exports[0].Path -and (Read-WinSecFrozenFindingsReport $sandbox $r.Path $id).Analysis.AnalysisId -ceq $control.AnalysisId)
    }
    Test-FE 'The other PowerShell edition reads the exact frozen CONTROL and SECTION reports' {
        $other=if($PSVersionTable.PSEdition -ceq 'Desktop'){'pwsh.exe'}else{'powershell.exe'}
        foreach($report in @($exports[0],$exports[1])){
            $scriptPath=(Join-Path $sandbox 'src/Core/ScanCoordinator.ps1').Replace("'","''")
            $readerRoot=$sandbox.Replace("'","''");$readerPath=$report.Path.Replace("'","''");$readerOwner=$id.Replace("'","''")
            $code="`$ErrorActionPreference='Stop';. '$scriptPath';function Get-CimInstance {throw 'Native queries prohibited.'};"+
                "`$saved=Read-WinSecFrozenFindingsReport '$readerRoot' '$readerPath' '$readerOwner';"+
                "if(`$saved.Analysis.AnalysisId -cne '$($report.AnalysisId)' -or `$saved.FileSha256 -cne '$($report.FileSha256)'){throw 'Cross-runtime frozen report mismatch.'};'FROZEN_REPORT_CONFIRMED'"
            $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
            $result=@(& $other -NoLogo -NoProfile -EncodedCommand $encoded)
            Assert-FE ($LASTEXITCODE -eq 0 -and $result[-1] -ceq 'FROZEN_REPORT_CONFIRMED')
        }
    }
    Test-FE 'Exact time and AnalysisId collision preserves every existing byte' {
        $before=Get-FEFiles
        Reject-FE {Export-WinSecFrozenFindingsReport $sandbox $control -ExportedAtUTC $exports[0].ExportedAtUTC}
        Assert-FE ((Get-FEFiles) -ceq $before)
    }
    Test-FE 'Cancellation before I/O publishes nothing and preserves existing reports' {
        $before=Get-FEFiles;$cancelled=$false
        try{$null=Export-WinSecFrameworkAnalysis $sandbox $control -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-FE ($cancelled -and (Get-FEFiles) -ceq $before)
    }
    foreach($step in @(2,3)){
        Test-FE ('Cancellation at publication step '+$step+' removes only its owned staged file') {
            $before=Get-FEFiles;$flagFE=@{Cancel=$false;Step=$step};$cancelled=$false
            try{$null=Export-WinSecFrameworkAnalysis $sandbox $control -CancellationAction {$flagFE.Cancel}.GetNewClosure() -ProgressCallback {param($e);if($e.Completed -eq $flagFE.Step){$flagFE.Cancel=$true}}.GetNewClosure()}
            catch [OperationCanceledException]{$cancelled=$true}
            Assert-FE ($cancelled -and (Get-FEFiles) -ceq $before -and @(Get-ChildItem (Join-Path $sandbox 'reports') -Recurse -Filter '*.tmp').Count -eq 0)
        }
    }
    Test-FE 'Staging failure does not publish or remove previous reports' {
        $before=Get-FEFiles
        Reject-FE {Export-WinSecFrameworkAnalysis $sandbox $control -ProgressCallback {param($e);if($e.Completed -eq 2){throw 'Synthetic staging failure.'}}}
        Assert-FE ((Get-FEFiles) -ceq $before)
    }
    Test-FE 'Publication finishes before 100 percent and postcommit cancellation cannot remove the report' {
        $eventsFE=New-Object 'Collections.Generic.List[object]';$flagFE=@{Cancel=$false}
        $r=Export-WinSecFrameworkAnalysis $sandbox $control -CancellationAction {$flagFE.Cancel}.GetNewClosure() -ProgressCallback {
            param($e);$eventsFE.Add($e);if($e.Completed -eq 4){$flagFE.Cancel=$true;throw 'Presentation failure after publication.'}
        }.GetNewClosure();$exports.Add($r)
        Assert-FE (($eventsFE.Completed -join ',') -ceq '0,2,3,4' -and [IO.File]::Exists($r.Path) -and (Read-WinSecFrozenFindingsReport $sandbox $r.Path $id).Analysis.ContentSha256 -ceq $control.ContentSha256)
    }
    Test-FE 'Writer freezes input before callbacks and never evaluates or selects a framework again' {
        $copy=Copy-WinSecResultData $control;$digest=$copy.ContentSha256
        function New-WinSecFrameworkAnalysis {throw 'Reevaluation forbidden.'}
        function New-WinSecProjectionFrameworkAnalysis {throw 'Reevaluation forbidden.'}
        function Show-WinSecExportFrameworkSelection {throw 'Framework prompt forbidden.'}
        $r=Export-WinSecFrameworkAnalysis $sandbox $copy -ProgressCallback {param($e);if($e.Completed -eq 0){$copy.DeviceName='CHANGED'}}.GetNewClosure();$exports.Add($r)
        Assert-FE ((Read-WinSecFrozenFindingsReport $sandbox $r.Path $id).Analysis.ContentSha256 -ceq $digest -and $copy.DeviceName -ceq 'CHANGED')
    }
    Test-FE 'Read cancellation preserves the published report' {
        $before=Get-FEFiles;$cancelled=$false
        try{$null=Read-WinSecFrozenFindingsReport $sandbox $exports[0].Path $id -CancellationAction {$true}}catch [OperationCanceledException]{$cancelled=$true}
        Assert-FE ($cancelled -and (Get-FEFiles) -ceq $before)
    }
    Test-FE 'Foreign device, filename, scope and byte corruption are rejected without alteration' {
        $path=$exports[0].Path;$bytes=[IO.File]::ReadAllBytes($path)
        Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $path ('local:hw1-'+('c'*64))}
        $wrong=Join-Path ([IO.Path]::GetDirectoryName($path)) 'foreign.md';[IO.File]::WriteAllBytes($wrong,$bytes)
        try{Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $wrong $id}}finally{Remove-Item -LiteralPath $wrong}
        try{[IO.File]::AppendAllText($path,'corrupt');Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $path $id}}
        finally{[IO.File]::WriteAllBytes($path,$bytes)}
        Assert-FE ((Get-FileHash -LiteralPath $path).Hash -ceq $exports[0].FileSha256)
    }
    Test-FE 'Hard links are rejected by handle validation' {
        $path=$exports[0].Path;$link=Join-Path $sandbox 'linked-report.md';$null=New-Item -ItemType HardLink -Path $link -Target $path
        try{Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $path $id}}finally{Remove-Item -LiteralPath $link}
    }
    Test-FE 'Invalid UTF8 and permissive file ACLs fail closed' {
        $path=$exports[0].Path;$bytes=[IO.File]::ReadAllBytes($path)
        try{[IO.File]::WriteAllBytes($path,[byte[]]@(0xff,0xfe,0xff));Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $path $id}}
        finally{[IO.File]::WriteAllBytes($path,$bytes)}
        $acl=Get-Acl -LiteralPath $path;$original=$acl.Sddl
        $everyone=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($everyone,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
        try{$acl.AddAccessRule($rule);Set-Acl -LiteralPath $path -AclObject $acl;Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $path $id}}
        finally{$acl.SetSecurityDescriptorSddlForm($original);Set-Acl -LiteralPath $path -AclObject $acl}
    }
    Test-FE 'Directory junctions cannot redirect the writer or reader' {
        $directory=[IO.Path]::GetDirectoryName($exports[0].Path);$backup=$directory+'-saved';$foreign=Join-Path $sandbox 'foreign';$null=[IO.Directory]::CreateDirectory($foreign)
        [IO.Directory]::Move($directory,$backup)
        try{
            $null=New-Item -ItemType Junction -Path $directory -Target $foreign
            Reject-FE {Export-WinSecFrameworkAnalysis $sandbox $control}
            Reject-FE {Read-WinSecFrozenFindingsReport $sandbox $exports[0].Path $id}
            Assert-FE (@(Get-ChildItem -LiteralPath $foreign).Count -eq 0)
        }finally{if(Test-Path -LiteralPath $directory){[IO.Directory]::Delete($directory)};[IO.Directory]::Move($backup,$directory)}
    }
    Test-FE 'Unknown staged or foreign files block device deletion without being removed' {
        $c=New-WinSecScanCoordinator $sandbox
        foreach($file in @('.foreign.tmp','foreign.md')){
            $unknown=Join-Path ([IO.Path]::GetDirectoryName($exports[0].Path)) $file;[IO.File]::WriteAllText($unknown,'foreign')
            try{Reject-FE {Get-WinSecDeviceRemovalPlan $sandbox $id -Coordinator $c -Devices @($device)};Assert-FE ([IO.File]::ReadAllText($unknown) -ceq 'foreign')}
            finally{Remove-Item -LiteralPath $unknown}
        }
    }
    Test-FE 'Validated new reports join device removal planning; cancelled deletion preserves them' {
        $c=New-WinSecScanCoordinator $sandbox;$plan=Get-WinSecDeviceRemovalPlan $sandbox $id -Coordinator $c -Devices @($device)
        Assert-FE ($plan.Files.Count -eq $exports.Count)
        $before=Get-FEFiles;$c=New-WinSecScanCoordinator $sandbox
        $result=Remove-WinSecManagedDevice $sandbox $id -Coordinator $c -Devices @($device) -ConfirmAction {$false}
        Assert-FE ($null -eq $result -and (Get-FEFiles) -ceq $before)
    }
    Test-FE 'Confirmed deletion removes only owned fixture reports and leaves unrelated paths untouched' {
        $unrelated=Join-Path $sandbox 'reports/unrelated.md';[IO.File]::WriteAllText($unrelated,'unrelated')
        $c=New-WinSecScanCoordinator $sandbox;$r=Remove-WinSecManagedDevice $sandbox $id -Coordinator $c -Devices @($device) -ConfirmAction {$true}
        Assert-FE ($r.Status -ceq 'REMOVED' -and -not (Test-Path -LiteralPath (Join-Path $sandbox ('reports/'+(Get-WinSecSnapshotDeviceKey $id)))) -and
            [IO.File]::ReadAllText($unrelated) -ceq 'unrelated' -and @((Import-WinSecDeviceInventory $sandbox).targets).Count -eq 0)
        Reject-FE {Export-WinSecFrameworkAnalysis $sandbox $control}
    }
}finally{
    $absolute=[IO.Path]::GetFullPath($sandbox)
    if([IO.Path]::GetDirectoryName($absolute) -cne $tempParent -or [IO.Path]::GetFileName($absolute) -cnotmatch '\Awse-[a-f0-9]{8}\z'){throw 'Unsafe fixture cleanup.'}
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
[Console]::WriteLine('Frozen Findings integration: '+$passed+' passed; '+$failed+' failed.');if($failed){throw 'Frozen Findings integration failed.'}
