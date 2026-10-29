# Offline, reviewed contextual rules. Importing this file never reads Windows or the network.
function Get-WinSecTechnicalFrameworkRuleCatalog {
    [CmdletBinding()]param()
    $nist='https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf'
    $cis='https://cas8.docs.cisecurity.org/en/latest/source/Controls4/'
    $guest='https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status'
    $smb='https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
    $signing='https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview'
    $frameworks=@(
        [pscustomobject]@{Id='nist-csf';Version='2.0';Purpose='Review configuration in the context of organizational cybersecurity outcomes.';Interpretation='CONTEXT_NOT_COMPLIANCE'},
        [pscustomobject]@{Id='cis-controls';Version='8.0';Purpose='Review default accounts and unnecessary legacy functionality against safeguards.';Interpretation='CONTEXT_NOT_COMPLIANCE'},
        [pscustomobject]@{Id='mitre-attack';Version='REVIEWED_OBJECT_VERSIONS';Purpose='Review configurations relevant to documented mitigations and techniques, without inferring an attack.';Interpretation='CONTEXT_NOT_ATTACK_EVIDENCE'})
    $rules=@(
        [pscustomobject]@{Id='TF-GUEST-001';Version='1.0.0';CheckId='WSA-IAM-002';InventoryId='Guest';Predicate='ALL_BOOLEAN_EQUAL';
            Required=@([pscustomobject]@{FieldId='Guest.Disabled';Expected=$false});MinBuild=22000;ProductType=1;
            Criterion='The observed built-in local Guest account is enabled; Microsoft recommends disabling this account.';
            TechnicalUrl=$guest;TechnicalRevision='Microsoft Learn reviewed 2026-10-29';ResultKind='CONFIGURATION_REVIEW';
            Title='Built-in local Guest account is enabled';Recommendation='Have the administrator review the need for Guest and disable it through the approved change process when not required. This observation does not establish a blank password or usable network access.';
            Relations=@(
                [pscustomobject]@{FrameworkId='nist-csf';ReferenceId='PR.AA-05';ReferenceVersion='2.0';Url=$nist;Context='Review account access against least privilege; this reading cannot establish policy compliance.'},
                [pscustomobject]@{FrameworkId='cis-controls';ReferenceId='4.7';ReferenceVersion='8.0';Url=$cis;Context='Review management of a default account; an enabled account alone does not establish the full safeguard outcome.'},
                [pscustomobject]@{FrameworkId='mitre-attack';ReferenceId='T1078.001';ReferenceVersion='2.0';Url='https://attack.mitre.org/techniques/T1078/001/';Context='Default-account abuse context only; no authentication, use or compromise has been observed.'})},
        [pscustomobject]@{Id='TF-SMB-001';Version='1.0.0';CheckId='WSA-NET-002';InventoryId='Server';Predicate='ALL_BOOLEAN_EQUAL';
            Required=@([pscustomobject]@{FieldId='Server.EnableSMB1Protocol';Expected=$true});MinBuild=22000;ProductType=1;
            Criterion='The SMB server reports SMBv1 enabled; Microsoft strongly discourages use of SMBv1.';
            TechnicalUrl=$smb;TechnicalRevision='Microsoft Learn reviewed 2026-10-29';ResultKind='CONFIGURATION_REVIEW';
            Title='SMB server permits the legacy SMBv1 protocol';Recommendation='Have the administrator identify legacy dependencies and plan their replacement before disabling SMBv1 through the approved change process. This setting does not prove an active listener, remote exposure or an exploitable vulnerability.';
            Relations=@(
                [pscustomobject]@{FrameworkId='nist-csf';ReferenceId='PR.PS-01';ReferenceVersion='2.0';Url=$nist;Context='Configuration-management context; the outcome does not prescribe an SMB-specific value.'},
                [pscustomobject]@{FrameworkId='cis-controls';ReferenceId='4.8';ReferenceVersion='8.0';Url=$cis;Context='Review legacy service functionality and business necessity; no authorized-service inventory was observed.'},
                [pscustomobject]@{FrameworkId='mitre-attack';ReferenceId='M1028';ReferenceVersion='1.3';Url='https://attack.mitre.org/mitigations/M1028/';Context='OS hardening includes disabling unused SMBv1; a configuration observation is not evidence of exploitation.'})},
        [pscustomobject]@{Id='TF-SMB-002';Version='1.0.0';CheckId='WSA-NET-002';InventoryId='Server';Predicate='ALL_BOOLEAN_EQUAL';
            Required=@([pscustomobject]@{FieldId='Server.EnableSMB2Protocol';Expected=$true},[pscustomobject]@{FieldId='Server.RequireSecuritySignature';Expected=$false},[pscustomobject]@{FieldId='Server.EncryptData';Expected=$false});MinBuild=22000;ProductType=1;
            Criterion='SMB2/3 is enabled while server signing is not required and global server encryption is not enabled. Review protection against relay; per-share controls and authentication are not resolved.';
            TechnicalUrl=$signing;TechnicalRevision='Microsoft Learn reviewed 2026-10-29';ResultKind='CONFIGURATION_REVIEW';
            Title='Review SMB server integrity protection';Recommendation='Have the administrator review required SMB signing, per-share encryption, authentication restrictions and approved exceptions. Do not disable protocol protections as a compatibility workaround. These settings do not prove relay feasibility or unsigned traffic.';
            Relations=@([pscustomobject]@{FrameworkId='mitre-attack';ReferenceId='M1037';ReferenceVersion='1.2';Url='https://attack.mitre.org/mitigations/M1037/';Context='The documented SMB-relay mitigation includes signing; observed server settings alone cannot establish an attack path.'})})
    [pscustomobject]@{ArtifactType='WinSec.TechnicalFrameworkRules';SchemaVersion='1.0.0';CatalogVersion='1.0.0';ReviewedAtUTC='2026-10-29T00:00:00.0000000Z';Frameworks=$frameworks;Rules=$rules}
}
