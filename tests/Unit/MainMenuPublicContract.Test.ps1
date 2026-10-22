# WinSec Analyzer - MainMenu public display contract, synthetic data only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'src/UI/Components/Table.ps1')
. (Join-Path $root 'src/UI/Screens/MainMenu.ps1')
$script:passed=0; $script:failed=0
function Assert-WinSecMenu {param([bool]$Condition); if(-not $Condition){throw 'MainMenu public contract assertion failed.'}}
function Test-WinSecMenu {
    param([string]$Name,[scriptblock]$Action)
    try {$null=& $Action; $script:passed++; Write-Host "[PASS] $Name"}
    catch {$script:failed++; Write-Host "[FAIL] $Name"; Write-Host $_.Exception.Message}
}
function Assert-WinSecMenuRejected {
    param([scriptblock]$Action)
    $caught=$null; $published=New-Object 'System.Collections.Generic.List[object]'
    try {& $Action | ForEach-Object {$published.Add($_)}} catch {$caught=$_}
    Assert-WinSecMenu ($null -ne $caught -and $published.Count -eq 0)
    Assert-WinSecMenu ($caught.Exception.Message -notlike '*SYNTHETIC-MENU-PRIVATE*')
}
function Get-WinSecLayout {param($Screen,$ReservedRows); [pscustomobject]@{IsTooSmall=$false;Height=26;BannerRows=2;MaxTableRows=5}}
function Clear-WinSecScreen {$script:renderCalls++}
function Write-WinSecText {param($Text,$Color,$Align); $script:lines.Add([string]$Text)}
function Write-WinSecDivider {param($Color)}
function Write-WinSecSectionTitle {param($Title)}
function Get-WinSecStatusColor {param($Status); 'Gray'}
function Write-WinSecTable {param($Columns,$Rows,$SelectedIndex,$MaxRows); $script:rows=$Rows}
function Write-WinSecKeyboardHelp {param($Screen,[switch]$EnableRescan)}

Test-WinSecMenu 'Empty input retains five pending sections and explicitly unscored labels' {
    $rows=@(Get-WinSecMainMenuSections)
    Assert-WinSecMenu ($rows.Count -eq 5 -and @($rows|Where-Object{$_.Score -cne 'NOT_SCORED' -or $_.Status -cne 'PENDING'}).Count -eq 0)
}
foreach($identity in @('Key','SectionKey','Name','Id')) {
    Test-WinSecMenu ("Canonical identity is matched: $identity") {
        $value=switch($identity){'Name'{'System Security'};'Id'{'01'};default{'SystemSecurity'}}
        $rows=@(Get-WinSecMainMenuSections -SectionResults @(@{$identity=$value;Score=$null;Status='NOT_SCORED'}))
        Assert-WinSecMenu ($rows[0].Status -ceq 'NOT_SCORED' -and $rows[0].Score -ceq 'NOT_SCORED' -and $rows[1].Status -ceq 'PENDING')
    }
}
Test-WinSecMenu 'Consistent stable aliases are supported' {
    $rows=@(Get-WinSecMainMenuSections -SectionResults @(@{Key='SystemSecurity';SectionKey='SystemSecurity';Status='NOT_SCORED'}))
    Assert-WinSecMenu ($rows[0].Status -ceq 'NOT_SCORED')
}
foreach($value in @(0,100,'90/100','--/100',$false,@{Value='SYNTHETIC-MENU-PRIVATE'})) {
    Test-WinSecMenu ('Unproven section score rejected: '+$value.GetType().Name) {
        Assert-WinSecMenuRejected {Get-WinSecMainMenuSections -SectionResults @(@{Key='SystemSecurity';Score=$value})}
    }
}
foreach($status in @('PENDING','NOT_SCORED','NOT_EVALUATED','UNKNOWN','ERROR','NOT_SELECTED','NOT_CHECKED','NOT_APPLICABLE','MANUAL','INFORMATIONAL')) {
    Test-WinSecMenu ("Technical or pending status is preserved without a score: $status") {
        $rows=@(Get-WinSecMainMenuSections -SectionResults @(@{Key='SystemSecurity';Status=$status}))
        Assert-WinSecMenu ($rows[0].Status -ceq $status -and $rows[0].Score -ceq 'NOT_SCORED')
    }
}
foreach($status in @('PASS','FAIL','COMPLETE','SYNTHETIC-MENU-PRIVATE',"UNKNOWN`nPASS",@('UNKNOWN'))) {
    Test-WinSecMenu ('Unsupported section status rejected: '+$status.GetType().Name) {
        Assert-WinSecMenuRejected {Get-WinSecMainMenuSections -SectionResults @(@{Key='SystemSecurity';Status=$status})}
    }
}
foreach($records in @(
    ,@(@{Key='SystemSecurity';SectionKey='NetworkSecurity'}),
    ,@(@{Key='invalid'}),
    ,@(@{Key=@('SystemSecurity')}),
    ,@(@{Name='invalid'}),
    ,@(@{Id='invalid'}),
    ,@(@{Status='NOT_SCORED'}),
    ,@(@{Key='SystemSecurity'},@{Key='SystemSecurity'}),
    ,@(@{Key='SystemSecurity'},@{SectionKey='SystemSecurity'})
)) {
    Test-WinSecMenu 'Ambiguous or missing section identity rejected without partial rows' {
        Assert-WinSecMenuRejected {Get-WinSecMainMenuSections -SectionResults $records}
    }
}
foreach($field in @('Key','Status','Score','Name')) {
    Test-WinSecMenu ("Calculated display property rejected without execution: $field") {
        $script:getterCalls=0
        $record=[pscustomobject]@{Key='SystemSecurity';Status='NOT_SCORED';Score=$null;Name='System Security'}
        $record.PSObject.Properties.Remove($field)
        $record|Add-Member -MemberType ScriptProperty -Name $field -Value {$script:getterCalls++;'SYNTHETIC-MENU-PRIVATE'}
        Assert-WinSecMenuRejected {Get-WinSecMainMenuSections -SectionResults @($record)}
        Assert-WinSecMenu ($script:getterCalls -eq 0)
    }
}
Test-WinSecMenu 'Output contains canonical scalar display fields and does not mutate input' {
    $record=[pscustomobject]@{Key='SystemSecurity';Name='SYNTHETIC-MENU-PRIVATE';Status='NOT_SCORED';Score=$null;Metadata=@{Value='original'}}
    $before=ConvertTo-Json -InputObject $record -Depth 5 -Compress
    $rows=@(Get-WinSecMainMenuSections -SectionResults @($record))
    Assert-WinSecMenu ($rows[0].Name -ceq 'System Security' -and
        @($rows[0].PSObject.Properties).Count -eq 5 -and
        (ConvertTo-Json -InputObject $rows -Compress) -notlike '*SYNTHETIC-MENU-PRIVATE*')
    $rows[0].Name='changed'
    Assert-WinSecMenu ($before -ceq (ConvertTo-Json -InputObject $record -Depth 5 -Compress) -and
        $null -eq $rows[0].PSObject.Properties['Metadata'])
}
Test-WinSecMenu 'Summary and table render NOT_SCORED' {
    $script:lines=New-Object 'System.Collections.Generic.List[string]'; $script:renderCalls=0
    Show-WinSecMainMenu -OverallStatus NOT_SCORED
    Assert-WinSecMenu (($script:lines -join '|') -match 'SECURITY SCORE: NOT_SCORED' -and
        ($script:lines -join '|') -notmatch '\d+/100|--/100' -and $script:rows[0].Score -ceq 'NOT_SCORED')
}
foreach($score in @(0,100)) {
    Test-WinSecMenu ("Direct numeric overall score rejected before rendering: $score") {
        $script:renderCalls=0
        Assert-WinSecMenuRejected {Show-WinSecMainMenu -OverallScore $score}
        Assert-WinSecMenu ($script:renderCalls -eq 0)
    }
}
foreach($status in @('PASS','FAIL','COMPLETE','SYNTHETIC-MENU-PRIVATE')) {
    Test-WinSecMenu ("Unsupported overall status rejected before rendering: $status") {
        $script:renderCalls=0
        Assert-WinSecMenuRejected {Show-WinSecMainMenu -OverallStatus $status}
        Assert-WinSecMenu ($script:renderCalls -eq 0)
    }
}
Write-Host "Passed: $script:passed"
Write-Host "Failed: $script:failed"
if($script:failed -gt 0){throw "$script:failed MainMenu public contract test(s) failed."}
