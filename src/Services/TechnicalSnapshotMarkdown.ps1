# Deterministic projection of a validated technical snapshot; no Windows queries.
function ConvertTo-WinSecSnapshotMarkdownCell {
    param([AllowNull()][object]$Value)
    $text=if($null -eq $Value){'(null)'}elseif($Value -is [bool]){if($Value){'true'}else{'false'}}else{[string]$Value}
    # HTML entities also protect pipes, markup, URLs and raw HTML without losing readings.
    $text=[Net.WebUtility]::HtmlEncode($text)
    return [regex]::Replace($text,'[\\`*_{}\[\]()#+.!|>-]',{param($m)'&#'+[int][char]$m.Value+';'})
}

function ConvertTo-WinSecSnapshotMarkdown {
    [CmdletBinding()]
    param([object]$Snapshot,[object]$Catalog,[string]$CatalogSha256,[object]$ExpectedIdentity,[scriptblock]$CancellationAction)
    Assert-WinSecTechnicalSnapshot $Snapshot $Catalog $CatalogSha256 $ExpectedIdentity -CancellationAction $CancellationAction
    if($Snapshot.SchemaVersion -ceq '2.1.0'){
        $report=ConvertFrom-WinSecProjectionSnapshot $Snapshot
        return '# WinSec Analyzer - Reviewed technical projection'+"`n`n"+'Format: WinSec.TechnicalMarkdown/1.1.0'+"`n`n"+
            'Selected Windows context in the recorded header is not proof of observed platform. Collection and coverage are separate.'+"`n`n"+
            ('SnapshotId: '+$Snapshot.Identity.SnapshotId+'; catalog: '+$Snapshot.CatalogId+'; digest: '+$Snapshot.CatalogSha256)+"`n`n"+(ConvertTo-WinSecTechnicalMarkdown $report)
    }
    $lines=New-Object Text.StringBuilder
    $null=$lines.AppendLine('# WinSec Analyzer - Technical snapshot').AppendLine()
    $null=$lines.AppendLine('Format: WinSec.TechnicalMarkdown/1.0.0').AppendLine()
    $null=$lines.AppendLine('Read-only configuration record. Execution and coverage are separate; this is not a compliance decision.').AppendLine()
    $null=$lines.AppendLine('## Identity and provenance').AppendLine().AppendLine('| Field | Value |').AppendLine('| --- | --- |')
    foreach($p in $Snapshot.Identity.PSObject.Properties){$null=$lines.AppendLine('| '+$p.Name+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $p.Value)+' |')}
    foreach($name in @('SchemaVersion','CatalogId','CatalogVersion','CatalogSha256','CollectorVersion','SelectedProfile','StartedAtUTC','CollectedAtUTC','CompletedAtUTC','GeneratedAtUTC')){
        $null=$lines.AppendLine('| '+$name+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $Snapshot.$name)+' |')
    }
    $null=$lines.AppendLine().AppendLine('## Observed platform').AppendLine().AppendLine('| Field | Value |').AppendLine('| --- | --- |')
    foreach($p in $Snapshot.Platform.PSObject.Properties){$null=$lines.AppendLine('| '+$p.Name+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $p.Value)+' |')}
    $null=$lines.AppendLine().AppendLine('## Collection and coverage').AppendLine().AppendLine('| Field | Value |').AppendLine('| --- | --- |')
    foreach($p in $Snapshot.Collection.PSObject.Properties){$null=$lines.AppendLine('| '+$p.Name+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $p.Value)+' |')}
    $null=$lines.AppendLine().AppendLine('Counts describe retained readings. Unavailable inventories are explicit below; unknown values are not security failures.').AppendLine()
    $null=$lines.AppendLine('## Sources').AppendLine().AppendLine('| Source | Provider | Reference |').AppendLine('| --- | --- | --- |')
    foreach($source in $Catalog.Sources){$null=$lines.AppendLine('| '+$source.Id+' | '+$source.Provider+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $source.ReferenceUrl)+' |')}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    foreach($inventory in $Snapshot.Inventories){
        $def=@($Catalog.Inventories|Where-Object Id -CEQ $inventory.Id)[0]
        $null=$lines.AppendLine().AppendLine('## Inventory: '+$inventory.Id).AppendLine()
        $null=$lines.AppendLine('Source: '+$def.SourceId+'; State: '+$inventory.State+'; Complete: '+$inventory.Complete.ToString().ToLowerInvariant()+'; Retained: '+$inventory.RetainedRecords+'; Reported: '+(ConvertTo-WinSecSnapshotMarkdownCell $inventory.ReportedRecords)+'; Reason: '+$inventory.Reason).AppendLine()
        $null=$lines.AppendLine('| Record | Field | Value | Type | Unit | State | Reason | Exposure |').AppendLine('| --- | --- | --- | --- | --- | --- | --- | --- |')
        foreach($batch in @($Snapshot.Batches|Where-Object InventoryId -CEQ $inventory.Id)){
            foreach($record in $batch.Records){
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
                foreach($reading in $record.Readings){
                    $field=@($Catalog.Fields|Where-Object Id -CEQ $reading.FieldId)[0]
                    $value=if($reading.Value -is [array]){ConvertTo-Json -InputObject $reading.Value -Compress}else{$reading.Value}
                    $null=$lines.AppendLine('| '+$record.Id+' | '+$field.Id+' | '+(ConvertTo-WinSecSnapshotMarkdownCell $value)+' | '+$field.Type+' | '+$field.Unit+' | '+$reading.State+' | '+$reading.Reason+' | '+$field.Exposure+' |')
                }
                if($lines.Length -gt 33554432){throw 'Technical Markdown budget exceeded.'}
            }
        }
        $null=$lines.AppendLine()
    }
    $text=$lines.ToString().Replace("`r`n","`n")
    if([Text.Encoding]::UTF8.GetByteCount($text) -gt 33554432){throw 'Technical Markdown budget exceeded.'}
    return $text
}
