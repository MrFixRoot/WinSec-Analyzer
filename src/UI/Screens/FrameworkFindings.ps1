# Rendering only. Analysis and export are explicit CLI actions, never redraws.
function Show-WinSecFrameworkProgress {
    param($Progress)
    if($Progress.Completed -lt 0 -or $Progress.Total -lt 0 -or $Progress.Completed -gt $Progress.Total){throw 'Invalid analysis progress.'}
    $terminal=Get-WinSecTerminalSize;$width=[Math]::Max(1,[int]$terminal.ContentWidth)
    $percent=if($Progress.Total){[int][Math]::Floor(100.0*$Progress.Completed/$Progress.Total)}else{100}
    $barWidth=[Math]::Max(1,[Math]::Min(30,$width-9));$filled=[int][Math]::Floor($barWidth*$percent/100.0)
    $bar=([string][char]0x2588)*$filled+([string][char]0x2591)*($barWidth-$filled)
    Clear-WinSecScreen
    $phase=if($null -ne $Progress.Phase){$Progress.Phase}else{'Comparing saved readings'}
    $lines=@('WINSEC - FRAMEWORK REVIEW',$phase,('['+$bar+'] '+$percent+'%'),
        ('Saved readings / sources: '+$Progress.Completed+'/'+$Progress.Total),'No Windows queries. [Esc] Cancel')
    foreach($line in @($lines|Select-Object -First ([Math]::Max(0,[int]$terminal.Height-1)))) {
        Write-WinSecText -Text $line.Substring(0,[Math]::Min($width,$line.Length)) -Color Cyan
    }
}

function Get-WinSecWorkflowColumns {
    param([switch]$Findings,[switch]$Devices)
    if($Findings) {
        return @(@{Key='Id';Header='ID';Width=3;MinWidth=2;MaxWidth=5;Priority=1},
            @{Key='Control';Header='Control / criterion';Width=32;MinWidth=12;MaxWidth=64;Priority=2},
            @{Key='Title';Header='Finding';Width=45;MinWidth=16;MaxWidth=100;Expand=$true;Priority=1},
            @{Key='State';Header='State';Width=9;MinWidth=7;MaxWidth=9;Priority=3})
    }
    $columns=@(@{Key='Id';Header='ID';Width=3;MinWidth=2;MaxWidth=5;Priority=1},
        @{Key='Name';Header=if($Devices){'Device'}else{'Section / control'};Width=32;MinWidth=12;MaxWidth=65;Expand=$true;Priority=1},
        @{Key='Status';Header='Status';Width=9;MinWidth=8;MaxWidth=10;Priority=1},
        @{Key='Mode';Header='Mode';Width=8;MinWidth=7;MaxWidth=9;Priority=2})
    if($Devices){$columns+=@{Key='HardwareId';Header='Hardware ID';Width=22;MinWidth=12;MaxWidth=68;Priority=3};
        $columns+=@{Key='LastScan';Header='Last scan';Width=20;MinWidth=10;MaxWidth=28;Priority=4}}
    return $columns
}

function Show-WinSecFrameworkFindings {
    param($State,$Context)
    $scope=Get-WinSecCLIViewScope $State
    $a=Assert-WinSecFrameworkAnalysis (Get-WinSecCLIValue $Context FrameworkFindings) $State.SelectedDeviceId $scope.ScopeType $scope.ScopeKey
    $layout=Get-WinSecLayout -Screen Findings -ReservedRows 16
    Clear-WinSecScreen
    if($layout.IsTooSmall){Write-WinSecText -Text 'Resize the terminal. [Esc] Back' -Color Yellow;return}
    if($layout.BannerRows -gt 2) {
        Show-Banner -Version $Context.Version
    } else {
        Write-WinSecText -Text ('WINSEC ANALYZER v'+$Context.Version) -Color Cyan -Align Center
        Write-WinSecText -Text 'mrRoot | Security Findings' -Color DarkGray -Align Center
    }
    Write-WinSecText -Text ('FINDINGS - '+$a.FrameworkId+' '+$a.FrameworkVersion) -Color Cyan
    Write-WinSecText -Text ('DEVICE: '+$a.DeviceName+' | '+$a.ScopeType+' / '+$a.ScopeKey) -Color Gray
    $coverageColor=if($a.UnknownReadingCount -gt 0){'Yellow'}else{'Gray'}
    Write-WinSecText -Text ('Readings reviewed: '+$a.ReadingCount+' | Unknown/unavailable: '+$a.UnknownReadingCount+' | Warnings: '+$a.Rows.Count) -Color $coverageColor
    if($a.MissingTechnicalCheckIds.Count){Write-WinSecText -Text ('Detailed records unavailable: '+($a.MissingTechnicalCheckIds -join ', ')+'. Only verified historical findings are available.') -Color Yellow}
    $expected=if($a.ScopeType -ceq 'SECTION'){@('WSA-SYS-001','WSA-SYS-002','WSA-SYS-003')}else{@($a.ScopeKey)}
    $unscanned=@($expected|Where-Object {$_ -cnotin @($a.Sources.CheckId)})
    if($unscanned.Count){Write-WinSecText -Text ('Controls without a saved scan: '+($unscanned -join ', ')) -Color Yellow}
    Write-WinSecText -Text 'Review context; not a compliance verdict or evidence of an attack.' -Color DarkGray
    $rows=@($a.Rows|ForEach-Object {[pscustomobject]@{Id=$_.Id;Control=$_.CheckId+' / '+$_.CriterionId;Title=$_.Title;State=$_.State}})
    $index=if($rows.Count){[Math]::Max(0,[Math]::Min([int]$State.FindingsOffset,$rows.Count-1))}else{-1}
    Write-WinSecTable -Columns (Get-WinSecWorkflowColumns -Findings) -Rows $rows -SelectedIndex $index -MaxRows ([Math]::Max(1,[int]$layout.MaxTableRows))
    if($index -ge 0) {
        $row=$a.Rows[$index]
        $details=@(('Setting: '+$row.SettingId),('Observed: '+$row.Observed),('Recommendation: '+$row.Recommendation),
            ('References: '+(($row.References|ForEach-Object {$_.ReferenceId+' - '+$_.Title}) -join '; ')),('Source scan: '+$row.ScanId))
        $width=[Math]::Max(1,[int]$layout.ContentWidth)
        if(-not $width){$width=[Math]::Max(1,(Get-WinSecTerminalSize).ContentWidth)}
        foreach($text in $details){Write-WinSecText -Text $text.Substring(0,[Math]::Min($text.Length,$width)) -Color Gray}
    } else {Write-WinSecText -Text 'No mapped warnings found in the available data. This does not prove complete coverage or compliance.' -Color Gray}
    $message=[string](Get-WinSecCLIValue $Context LastExportMessage)
    if($message){Write-WinSecText -Text $message -Color Yellow}
    Write-WinSecText -Text '[Up/Down] Review | [P] Print report (.md) | [Esc] Back' -Color Cyan
}

function Show-WinSecWorkflowScreen {
    param($State,$Context)
    if($State.Screen -ceq 'Findings'){Show-WinSecFrameworkFindings $State $Context;return}
    $sections=@(Get-WinSecMainMenuSections);$rows=@();$index=0;$title=''
    if($State.Screen -ceq 'Devices') {
        $title='Managed Devices';$index=$State.DeviceIndex
        $base=@(Get-WinSecDeviceRows -Devices $Context.Devices)
        $registry=Get-WinSecCheckRegistry $Context.ProjectRoot
        $ready=@(Get-WinSecExecutableChecks $registry|ForEach-Object CheckId)
        foreach($device in $base) {
            $all=@()
            for($i=0;$i -lt $sections.Count;$i++) {
                $s=[pscustomobject]@{Screen='Section';SectionIndex=$i;SelectedDeviceId=$device.DeviceId;ControlIndex=0}
                $all+=@(Get-WinSecWorkflowControlRows $s $Context|Where-Object {$_.CheckId -cin $ready})
            }
            $history=@($Context.PublicScans.Values|Where-Object DeviceId -CEQ $device.DeviceId|Sort-Object CompletedAtUTC)
            $rows+=,[pscustomobject]@{Id=$device.Id;Name=$device.Device;HardwareId=$device.HardwareId;Status=(Get-WinSecWorkflowAggregateState $all);
                Mode=(Get-WinSecWorkflowAggregateMode $all);
                LastScan=if($history.Count){$history[-1].CompletedAtUTC}else{'Never'}}
        }
    } elseif($State.Screen -ceq 'MainMenu') {
        $title='Security Assessment';$index=$State.SectionIndex
        for($i=0;$i -lt $sections.Count;$i++) {
            $s=[pscustomobject]@{Screen='Section';SectionIndex=$i;SelectedDeviceId=$State.SelectedDeviceId;ControlIndex=0}
            $controls=@(Get-WinSecWorkflowControlRows $s $Context)
            $rows+=,[pscustomobject]@{Id=$sections[$i].Id;Name=$sections[$i].Name;Status=(Get-WinSecWorkflowAggregateState $controls);
                Mode=(Get-WinSecWorkflowAggregateMode $controls)}
        }
    } elseif($State.Screen -cin @('Section','Results')) {
        $title=$sections[$State.SectionIndex].Name;$index=$State.ControlIndex;$rows=@(Get-WinSecWorkflowControlRows $State $Context)
    } else {return}
    $layout=Get-WinSecLayout -Screen $State.Screen -ReservedRows 12
    Clear-WinSecScreen
    if($layout.IsTooSmall){Write-WinSecText -Text 'Resize the terminal. [Esc] Back' -Color Yellow;return}
    if($layout.BannerRows -gt 2) {
        Show-Banner -Version $Context.Version
    } else {
        Write-WinSecText -Text ('WINSEC ANALYZER v'+$Context.Version) -Color Cyan -Align Center
        Write-WinSecText -Text 'mrRoot | Security Assessment' -Color DarkGray -Align Center
    }
    Write-WinSecText -Text ('WINSEC ANALYZER - '+$title) -Color Cyan
    if($State.Screen -cne 'Devices') {
        Write-WinSecText -Text ('DEVICE: '+$State.SelectedDeviceName) -Color Gray
        $label=Get-WinSecCLISystemLabel $State $Context
        if($label){Write-WinSecText -Text ('CURRENT OS: '+$label) -Color Gray}
    }
    Write-WinSecText -Text 'Status describes collection progress. COMPLETE does not mean secure.' -Color DarkGray
    Write-WinSecTable -Columns (Get-WinSecWorkflowColumns -Devices:($State.Screen -ceq 'Devices')) -Rows $rows -SelectedIndex $index -MaxRows ([Math]::Max(1,[int]$layout.MaxTableRows))
    $scan=Get-WinSecCLIScanPresentation $State $Context
    if($scan.EnableRescan){$label=switch($State.Screen){Devices {'Local Device'};MainMenu {'Section'};default {'Control'}};
        Write-WinSecText -Text ('[R] '+$scan.ScanAction+' '+$label) -Color Cyan}
    $message=if($State.Screen -ceq 'Devices'){Get-WinSecCLIValue $Context LastDeviceMessage}else{Get-WinSecCLIValue $Context LastScanMessage}
    if($message){Write-WinSecText -Text $message -Color Yellow}
    Write-WinSecKeyboardHelp -Screen $State.Screen
}
