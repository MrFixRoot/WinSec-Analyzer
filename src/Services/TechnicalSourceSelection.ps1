# Isolated selection policy. No production cache mutation, CLI/F/P connection or native acquisition.
. (Join-Path $PSScriptRoot 'TechnicalSourceIndexAdapter.ps1')

function Select-WinSecTechnicalSource {
    [CmdletBinding()]
    param([string]$ProjectRoot,[object]$Index,[string]$DeviceId,[string]$Family,
        [string]$ScopeType,[string]$ScopeKey,[string]$CheckId='WSA-SYS-001',
        [string]$SourcePreference='PREFER_COMPLETE',[object]$PolicyVersion='1.0.0',[scriptblock]$CancellationAction)
    $lease=$null
    try{
        if($PolicyVersion -isnot [string] -or $PolicyVersion -cne '1.0.0' -or
            $SourcePreference -cnotin @('PREFER_COMPLETE','LATEST_ATTEMPT') -or
            $Family -cnotin @('REVIEWED_PROJECTION','DEFENDER_CANDIDATE') -or $CheckId -cne 'WSA-SYS-001'){
            throw 'Unsupported technical source policy, family or control.'
        }
        $control=Get-WinSecSnapshotControl $CheckId
        switch -CaseSensitive ($ScopeType){
            CONTROL {if($ScopeKey -cne $CheckId){throw 'Invalid control selection scope.'}}
            SECTION {if($ScopeKey -cne $control.SectionKey){throw 'Invalid section selection scope.'}}
            DEVICE {if($ScopeKey -cne 'ALL'){throw 'Invalid device selection scope.'}}
            default {throw 'Unknown technical selection scope.'}
        }
        $frozen=Copy-WinSecTechnicalIndexMetadata $ProjectRoot $Index $DeviceId INDEX $CancellationAction
        $ordered=New-Object 'Collections.Generic.SortedDictionary[string,object]' ([StringComparer]::Ordinal)
        $snapshots=@{};$scans=New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
        $retainedBytes=0;$clock=[Diagnostics.Stopwatch]::StartNew()
        foreach($entry in @(Get-WinSecTechnicalIndexEntries $frozen)){
            $view=Get-WinSecTechnicalIndexEntryView $entry
            $owner=$view.Identity;$scopeStamp=$owner.ScopeType+'|'+$owner.ScopeKey
            if($scans.ContainsKey($owner.ScanId) -and $scans[$owner.ScanId] -cne $scopeStamp){throw 'Scan identity reused across contradictory scopes.'}
            $scans[$owner.ScanId]=$scopeStamp
            foreach($source in $view.Sources){
                $ref=$source.Reference;$identity=$ref.Identity
                if($snapshots.ContainsKey($identity.SnapshotId)){throw 'Duplicate technical snapshot identity.'}
                $snapshots[$identity.SnapshotId]=$true
                $resolution=Resolve-WinSecTechnicalSourceVersion $ref $identity
                # CONTROL accepts its exact SECTION/DEVICE ancestors, as historical control selection does.
                # SECTION and DEVICE remain exact: this policy never manufactures a combined session.
                $scopeMatches=($identity.ScopeType -ceq $ScopeType -and $identity.ScopeKey -ceq $ScopeKey)
                if($ScopeType -ceq 'CONTROL' -and
                    (($identity.ScopeType -ceq 'SECTION' -and $identity.ScopeKey -ceq $control.SectionKey) -or
                     ($identity.ScopeType -ceq 'DEVICE' -and $identity.ScopeKey -ceq 'ALL'))){$scopeMatches=$true}
                $eligibility=if(-not $scopeMatches){'OUT_OF_SCOPE'}elseif($resolution.Family -cne $Family){'OTHER_FAMILY'}else{'ELIGIBLE'}
                $row=[pscustomobject]@{SessionIdentity=$owner.PSObject.Copy();SessionContentSha256=$view.ContentSha256;
                    FileSha256=$entry.FileSha256;Source=$source;Family=$resolution.Family;Eligibility=$eligibility;Verification='REFERENCE_ONLY'}
                $retainedBytes+=[Text.Encoding]::UTF8.GetByteCount((Get-WinSecPublicHistoryJson $row))
                if($retainedBytes -gt 33554432){throw 'Technical selection metadata budget exceeded.'}
                $at=ConvertTo-WinSecSnapshotUtc $ref.CollectedAtUTC
                $priority=[array]::IndexOf(@('CONTROL','SECTION','DEVICE'),$identity.ScopeType)
                $reverseTicks=([datetime]::MaxValue.Ticks-$at.Ticks).ToString('D19',[Globalization.CultureInfo]::InvariantCulture)
                # Tokens cannot contain |. Ordinal keys avoid culture-dependent ScanId tie breaking.
                $key=$reverseTicks+'|'+$priority+'|'+$identity.ScanId+'|'+$identity.SnapshotId
                if($ordered.ContainsKey($key)){throw 'Ambiguous technical source ordering.'}
                $ordered.Add($key,[pscustomobject]@{Row=$row;Entry=$entry})
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            }
        }
        $latest=$null;$selected=$null
        foreach($candidate in $ordered.Values){
            if($candidate.Row.Eligibility -cne 'ELIGIBLE'){continue}
            if($null -eq $latest){$latest=$candidate}
            if($null -eq $selected -and ($SourcePreference -ceq 'LATEST_ATTEMPT' -or $candidate.Row.Source.Collection.Status -ceq 'COMPLETE')){
                $selected=$candidate
            }
        }
        $reason=if($null -eq $latest){'NO_ELIGIBLE_SOURCE'}elseif($null -eq $selected){$selected=$latest;'NO_COMPLETE_USE_LATEST'}
            elseif($SourcePreference -ceq 'LATEST_ATTEMPT'){'LATEST_ATTEMPT'}else{'PREFERRED_COMPLETE'}
        $lease=Open-WinSecTechnicalSessionOwner $ProjectRoot ([pscustomobject]@{DeviceId=$DeviceId})
        $verified=@{}
        foreach($candidate in @($latest,$selected)){
            if($null -eq $candidate){continue}
            $id=$candidate.Row.Source.Reference.Identity.SnapshotId
            if(-not $verified.ContainsKey($id)){
                # Reuse D-134's reader under this single inventory lease. Never hide a corrupt newer attempt
                # by falling back to an older complete source; both latest and selected must revalidate.
                $null=Read-WinSecTechnicalIndexEntry $ProjectRoot $candidate.Entry $CancellationAction
                $verified[$id]=$true;$candidate.Row.Verification='VERIFIED_AT_SELECTION'
            }
        }
        Assert-WinSecTechnicalSessionOwnerUnchanged $lease
        [pscustomobject]@{ArtifactType='WinSec.TechnicalSourceSelection';SchemaVersion='1.0.0';PolicyVersion='1.0.0';
            SourcePreference=$SourcePreference;DeviceId=$DeviceId;CheckId=$CheckId;Family=$Family;Origin='RECORDS';
            RequestedScope=[pscustomobject]@{ScopeType=$ScopeType;ScopeKey=$ScopeKey};IndexSha256=$frozen.ContentSha256;
            TemporalBasis='REFERENCE_COLLECTED_AT_UTC';HistoryBasis='INDEX_MANIFEST_ONLY';Reason=$reason;
            Selected=$(if($selected){$selected.Row}else{$null});LatestAttempt=$(if($latest){$latest.Row}else{$null});
            SelectedDiffersFromLatest=($null -ne $latest -and $null -ne $selected -and
                $latest.Row.Source.Reference.Identity.SnapshotId -cne $selected.Row.Source.Reference.Identity.SnapshotId);
            History=@(foreach($candidate in $ordered.Values){$candidate.Row})}
    }catch{
        if($_.Exception -is [OperationCanceledException]){throw}
        throw 'Technical source selection rejected; no selection was published.'
    }finally{if($lease){$lease.Lock.Dispose()}}
}
