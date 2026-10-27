# Read-only NamedPolicy adapter for PowerShell 5.1 and 7 without WinRT projections.
# Import defines functions only. Compilation/queries occur only when called.
# ABI reference: Microsoft Windows SDK / microsoft/windows-rs Management/Policies.

function Initialize-WinSecWindowsUpdateNamedPolicyReader {
    [CmdletBinding()]
    param()
    if($null -ne ('WinSec.Native.UpdateNamedPolicyV1' -as [type])){return}
    $source=@'
using System;
using System.Runtime.InteropServices;
namespace WinSec.Native {
    public sealed class UpdatePolicyObservation {
        public string Area { get; internal set; }
        public string Name { get; internal set; }
        public int Kind { get; internal set; }
        public bool Managed { get; internal set; }
        public bool UserPolicy { get; internal set; }
        public int? Value { get; internal set; }
    }
    public static class UpdateNamedPolicyV1 {
        [ComImport, Guid("7F793BE7-76C4-4058-8CAD-67662CD05F0D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IPolicyStatics {
            [PreserveSig] int GetIids(out uint count, out IntPtr ids);
            [PreserveSig] int GetRuntimeClassName(out IntPtr name);
            [PreserveSig] int GetTrustLevel(out int level);
            [PreserveSig] int GetPolicyFromPath(IntPtr area, IntPtr name, out IPolicyData data);
        }
        [ComImport, Guid("38DCB198-95AC-4077-A643-8078CAE26400"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IPolicyData {
            [PreserveSig] int GetIids(out uint count, out IntPtr ids);
            [PreserveSig] int GetRuntimeClassName(out IntPtr name);
            [PreserveSig] int GetTrustLevel(out int level);
            [PreserveSig] int GetArea(out IntPtr area);
            [PreserveSig] int GetName(out IntPtr name);
            [PreserveSig] int GetKind(out int kind);
            [PreserveSig] int GetManaged(out byte managed);
            [PreserveSig] int GetUserPolicy(out byte userPolicy);
            [PreserveSig] int GetUser(out IntPtr user);
            [PreserveSig] int GetBoolean(out byte value);
            [PreserveSig] int GetBinary(out IntPtr value);
            [PreserveSig] int GetInt32(out int value);
        }
        [DllImport("combase.dll", ExactSpelling=true)] private static extern int RoInitialize(uint type);
        [DllImport("combase.dll", ExactSpelling=true)] private static extern void RoUninitialize();
        [DllImport("combase.dll", ExactSpelling=true)] private static extern int RoGetActivationFactory(IntPtr name, ref Guid iid, out IntPtr factory);
        [DllImport("combase.dll", ExactSpelling=true, CharSet=CharSet.Unicode)] private static extern int WindowsCreateString(string value, uint length, out IntPtr text);
        [DllImport("combase.dll", ExactSpelling=true)] private static extern int WindowsDeleteString(IntPtr text);
        [DllImport("combase.dll", ExactSpelling=true)] private static extern IntPtr WindowsGetStringRawBuffer(IntPtr text, out uint length);
        private static void Check(int hr) { if(hr < 0) Marshal.ThrowExceptionForHR(hr); }
        private static IntPtr Text(string value) {
            IntPtr text; Check(WindowsCreateString(value, (uint)value.Length, out text)); return text;
        }
        private static string ReadText(IntPtr text) {
            uint length; IntPtr buffer=WindowsGetStringRawBuffer(text, out length);
            if(length > 64) throw new InvalidOperationException();
            return length == 0 ? String.Empty : Marshal.PtrToStringUni(buffer, (int)length);
        }
        public static UpdatePolicyObservation Read(string name) {
            if(name != "AllowAutoUpdate" && name != "ConfigureDeadlineForQualityUpdates" && name != "ConfigureDeadlineForFeatureUpdates" &&
                name != "IgnoreWindowsUpdateGroupPolicies" && name != "SetEDURestart")
                throw new ArgumentException("Unsupported Windows Update policy.");
            IntPtr className=IntPtr.Zero, area=IntPtr.Zero, policyName=IntPtr.Zero, factoryPointer=IntPtr.Zero;
            IntPtr observedArea=IntPtr.Zero, observedName=IntPtr.Zero;
            IPolicyStatics factory=null; IPolicyData data=null;
            bool initialized=false, failed=false;
            UpdatePolicyObservation result=null;
            try {
                int init=RoInitialize(1);
                if(init >= 0) initialized=true;
                // Balance initialization in the existing apartment; do not change it.
                else if(init == unchecked((int)0x80010106)) { Check(RoInitialize(0)); initialized=true; }
                else Check(init);
                className=Text("Windows.Management.Policies.NamedPolicy");
                area=Text("Update"); policyName=Text(name);
                Guid iid=new Guid("7F793BE7-76C4-4058-8CAD-67662CD05F0D");
                Check(RoGetActivationFactory(className, ref iid, out factoryPointer));
                factory=(IPolicyStatics)Marshal.GetObjectForIUnknown(factoryPointer);
                Check(factory.GetPolicyFromPath(area, policyName, out data));
                if(data == null) throw new InvalidOperationException();
                Check(data.GetArea(out observedArea)); Check(data.GetName(out observedName));
                int kind; byte managed, userPolicy;
                Check(data.GetKind(out kind)); Check(data.GetManaged(out managed)); Check(data.GetUserPolicy(out userPolicy));
                string returnedArea=ReadText(observedArea), returnedName=ReadText(observedName);
                if(returnedArea != "Update" || returnedName != name || kind < 0 || kind > 5 || managed > 1 || userPolicy != 0)
                    throw new InvalidOperationException();
                int? value=null;
                if(kind == 3) { int observed; Check(data.GetInt32(out observed)); value=observed; }
                result=new UpdatePolicyObservation { Area=returnedArea, Name=returnedName, Kind=kind,
                    Managed=(managed == 1), UserPolicy=false, Value=value };
            } catch { failed=true; }
            finally {
                // Release only references acquired by this call; never final-release a shared factory.
                try { if(data != null) Marshal.ReleaseComObject(data); } catch { failed=true; }
                try { if(factory != null) Marshal.ReleaseComObject(factory); } catch { failed=true; }
                try { if(factoryPointer != IntPtr.Zero) Marshal.Release(factoryPointer); } catch { failed=true; }
                foreach(IntPtr text in new IntPtr[] {observedName, observedArea, policyName, area, className}) {
                    try { if(text != IntPtr.Zero) Check(WindowsDeleteString(text)); } catch { failed=true; }
                }
                try { if(initialized) RoUninitialize(); } catch { failed=true; }
            }
            if(failed || result == null) throw new InvalidOperationException("Windows Update named policy could not be read or released.");
            return result;
        }
    }
}
'@
    Add-Type -TypeDefinition $source -ErrorAction Stop
}

function Read-WinSecWindowsUpdateNamedPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates',
        'ConfigureDeadlineForFeatureUpdates','IgnoreWindowsUpdateGroupPolicies','SetEDURestart')][string]$Name)
    Initialize-WinSecWindowsUpdateNamedPolicyReader
    return [WinSec.Native.UpdateNamedPolicyV1]::Read($Name)
}

function Get-WinSecWindowsUpdateNamedPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('AllowAutoUpdate','ConfigureDeadlineForQualityUpdates',
        'ConfigureDeadlineForFeatureUpdates','IgnoreWindowsUpdateGroupPolicies','SetEDURestart')][string]$Name)
    try {
        $items=@(Read-WinSecWindowsUpdateNamedPolicy -Name $Name -ErrorAction Stop)
        if($items.Count -ne 1 -or $null -eq $items[0]){throw 'Invalid policy response.'}
        $data=$items[0]
        foreach($field in @('Area','Name','Kind','Managed','UserPolicy','Value')) {
            $property=$data.PSObject.Properties[$field]
            if($null -eq $property -or $property.MemberType -notin @('Property','NoteProperty')){throw 'Invalid policy property.'}
        }
        if($data.Area -isnot [string] -or $data.Area -cne 'Update' -or $data.Name -isnot [string] -or $data.Name -cne $Name -or
            $data.Kind -isnot [int] -or $data.Kind -lt 0 -or $data.Kind -gt 5 -or
            $data.Managed -isnot [bool] -or $data.UserPolicy -isnot [bool] -or $data.UserPolicy -or
            ($data.Kind -eq 3 -and $data.Value -isnot [int]) -or ($data.Kind -ne 3 -and $null -ne $data.Value)) {
            throw 'Invalid policy metadata.'
        }
        $kind=@('Invalid','Binary','Boolean','Int32','Int64','String')[$data.Kind]
        return [pscustomobject]@{Source='WINRT:NamedPolicy';Area='Update';Name=$Name;State='OBSERVED'
            Kind=$kind;Managed=$data.Managed;Value=$data.Value}
    } catch {throw 'Windows Update named policy could not be validated.'}
}
