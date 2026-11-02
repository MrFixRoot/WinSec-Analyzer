# Device-removal recognition only. No index restoration, repair, collection or deletion here.
. (Join-Path $PSScriptRoot 'TechnicalSourceSessionStore.ps1')

function Add-WinSecTechnicalSessionRemovalFile {
    param([Collections.Generic.List[object]]$Files,[hashtable]$Known,[string]$Path,[string]$Hash)
    if($Hash -cnotmatch '\A[A-F0-9]{64}\z'){throw 'Invalid technical removal digest.'}
    if($Known.ContainsKey($Path)){
        if($Known[$Path] -cne $Hash){throw 'Contradictory shared technical removal source.'}
    }else{$Known[$Path]=$Hash;$Files.Add([pscustomobject]@{Path=$Path;Hash=$Hash})}
}

function Get-WinSecTechnicalSessionRemovalFiles {
    [CmdletBinding()]
    param([string]$ProjectRoot,[string]$DeviceId,[object]$Device,[scriptblock]$CancellationAction)
    $key=Get-WinSecSnapshotDeviceKey $DeviceId
    if($null -eq $Device -or $Device.GetType() -ne [Management.Automation.PSCustomObject]){throw 'Invalid technical removal owner.'}
    $property=$Device.PSObject.Properties['DeviceId']
    if($null -eq $property -or $property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty -or
        $property.Value -isnot [string] -or $property.Value -cne $DeviceId){throw 'Foreign technical removal owner.'}
    $format=Resolve-WinSecTechnicalSessionStorageFormat 'WinSec.TechnicalSourceSession' '1.0.0'
    $probe=Assert-WinSecSnapshotStoragePath $ProjectRoot ('scans/'+$key+'/'+$format.Directory+'/probe.json') -AllowExistingArtifact
    $directory=[IO.Path]::GetDirectoryName($probe);$files=New-Object 'Collections.Generic.List[object]';$known=@{}
    if(-not [IO.Directory]::Exists($directory)){
        if(Test-Path -LiteralPath $directory -ErrorAction Stop){throw 'Invalid technical removal namespace.'}
        return [pscustomobject]@{Files=$files.ToArray()}
    }
    # The confirmed deletion caller owns the inventory lease on its second plan.
    # Never reacquire it here; retain and compare its actual inventory fingerprint instead.
    $fingerprint=Get-WinSecDeviceInventoryFingerprint $ProjectRoot
    $inventory=Import-WinSecDeviceInventory $ProjectRoot
    if(@($inventory.targets|Where-Object DeviceId -CEQ $DeviceId).Count -ne 1 -or
        (Test-WinSecDeviceInventoryRemoval $inventory $DeviceId)){throw 'Technical removal owner is no longer managed.'}
    $layout=[pscustomobject]@{DeviceKey=$key;Directory=$format.Directory};$held=$null;$totalBytes=0
    try{
        $held=Open-WinSecTechnicalSessionDirectories $ProjectRoot $layout
        foreach($file in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)){
            $opened=$null;$headerLease=$null;$clock=[Diagnostics.Stopwatch]::StartNew()
            Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            $relative=$file.FullName.Substring([IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\').Length+1)
            $null=Assert-WinSecSnapshotStoragePath $ProjectRoot $relative -AllowExistingArtifact
            if($file.Name -ceq '.gitkeep'){continue}
            if($file.PSIsContainer -or $file.Name -cnotmatch '\A[a-f0-9]{64}\.json\z'){throw 'Unknown or incomplete technical session blocks deletion.'}
            try{
                $headerLease=[WinSec.SnapshotIO3]::Read($file.FullName)
                $bytes=Read-WinSecSnapshotBytes $file.FullName $format.MaxBytes $CancellationAction;$totalBytes+=$bytes.Length
                # Same aggregate metadata budget as historical session discovery. No truncation.
                if($totalBytes -gt 33554432 -or $files.Count -ge 10000){throw 'Technical removal metadata budget exceeded.'}
                $utf8=New-Object Text.UTF8Encoding($false,$true)
                $metadata=ConvertFrom-WinSecSnapshotPairJson ($utf8.GetString($bytes))
                Assert-WinSecSnapshotFields $metadata @('ArtifactType','SchemaVersion','Identity','Sources','ContentSha256')
                $null=Resolve-WinSecTechnicalSessionStorageFormat $metadata.ArtifactType $metadata.SchemaVersion
                $owner=Copy-WinSecTechnicalSessionIdentity $metadata.Identity
                if($owner.DeviceId -cne $DeviceId){throw 'Foreign technical session in removal namespace.'}
                $expected=Get-WinSecTechnicalSessionStorageLayout $ProjectRoot $owner
                if(-not [string]::Equals($expected.Path,$file.FullName,[StringComparison]::OrdinalIgnoreCase) -or [IO.File]::Exists($expected.Temporary)){
                    throw 'Technical removal path or publication contradicts its identity.'
                }
                $opened=Open-WinSecStoredTechnicalSession $ProjectRoot $file.FullName $owner $null $CancellationAction
                Add-WinSecTechnicalSessionRemovalFile $files $known $file.FullName $opened.FileSha256
                foreach($entry in $opened.Session.Sources){
                    $ref=$entry.Reference;$resolution=Resolve-WinSecTechnicalSourceVersion $ref $ref.Identity
                    if($resolution.Family -ceq 'DEFENDER_CANDIDATE'){
                        . (Join-Path $PSScriptRoot '../Checks/Defender/DefenderTechnicalStorage.ps1')
                        $catalog=Get-WinSecDefenderTechnicalCatalog -CatalogVersion $resolution.CatalogVersion
                    }
                    else{$catalog=Get-WinSecProjectionCatalog $resolution.Identity.CheckId}
                    $pair=Get-WinSecSnapshotPairLayout $ProjectRoot $ref.Identity $ref.CollectedAtUTC
                    $plan=Get-WinSecTechnicalSnapshotRemovalPlan $ProjectRoot $ref.Identity $ref.CollectedAtUTC $catalog $ref.CatalogSha256
                    if($plan.PublicationStatus -cne 'COMMITTED' -or $plan.Files.Count -ne 4){throw 'Incomplete technical removal pair.'}
                    foreach($entryFile in $plan.Files){
                        if($entryFile.Path -cnotin @($pair.Json,$pair.Markdown,$pair.Intent,$pair.Commit)){throw 'Pending technical pair blocks deletion.'}
                        Add-WinSecTechnicalSessionRemovalFile $files $known $entryFile.Path $entryFile.Sha256
                    }
                }
                Assert-WinSecSnapshotValidationBudget $clock $CancellationAction
            }finally{Close-WinSecStoredTechnicalSession $opened;if($headerLease){$headerLease.Dispose()}}
        }
        if((Get-WinSecDeviceInventoryFingerprint $ProjectRoot) -cne $fingerprint){throw 'Technical removal inventory changed.'}
        return [pscustomobject]@{Files=$files.ToArray()}
    }finally{if($held){foreach($handle in $held){$handle.Dispose()}}}
}
