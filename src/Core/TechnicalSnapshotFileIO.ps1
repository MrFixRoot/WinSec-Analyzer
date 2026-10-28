# Windows filesystem primitives only, compiled lazily. No collector or production import.
function Initialize-WinSecSnapshotFileIO {
    if('WinSec.SnapshotIO2' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace WinSec {
 public static class SnapshotIO2 {
  [StructLayout(LayoutKind.Sequential)] struct Info {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [StructLayout(LayoutKind.Sequential)] struct UnicodeName {public ushort Length,MaximumLength;public IntPtr Buffer;}
  [StructLayout(LayoutKind.Sequential)] struct Attributes {public int Length;public IntPtr Root,Name;public uint Flags;public IntPtr Security,Quality;}
  [StructLayout(LayoutKind.Sequential)] struct StatusBlock {public IntPtr Status;public UIntPtr Information;}
  static readonly Dictionary<string,List<WeakReference>> directories=new Dictionary<string,List<WeakReference>>(StringComparer.OrdinalIgnoreCase);
  [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle h,uint access,ref Attributes attributes,out StatusBlock status,IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,IntPtr ea,uint eaLength);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info info);
  [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle h,out StatusBlock status,IntPtr buffer,uint size,int kind);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr ptr);
  static SafeFileHandle Parent(string path) {
   string parent=Path.GetDirectoryName(Path.GetFullPath(path));
   lock(directories) {List<WeakReference> list;
    if(parent!=null && directories.TryGetValue(parent,out list)) for(int n=list.Count-1;n>=0;n--){SafeFileHandle h=list[n].Target as SafeFileHandle;if(h!=null && !h.IsClosed && !h.IsInvalid)return h;list.RemoveAt(n);}
   }
   throw new IOException("Snapshot parent is not held.");
  }
  static SafeFileHandle Relative(string path,uint access,uint share,uint disposition,uint options,IntPtr security) {
   SafeFileHandle parent=Parent(path);bool retained=false;IntPtr text=IntPtr.Zero,name=IntPtr.Zero;
   try {parent.DangerousAddRef(ref retained);string leaf=Path.GetFileName(path);
    text=Marshal.StringToHGlobalUni(leaf);UnicodeName u=new UnicodeName();u.Length=(ushort)(leaf.Length*2);u.MaximumLength=(ushort)(u.Length+2);u.Buffer=text;
    name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeName)));Marshal.StructureToPtr(u,name,false);
    Attributes a=new Attributes();a.Length=Marshal.SizeOf(typeof(Attributes));a.Root=parent.DangerousGetHandle();a.Name=name;a.Flags=0x1040;a.Security=security;
    SafeFileHandle h;StatusBlock s;int result=NtCreateFile(out h,access|0x00100000,ref a,out s,IntPtr.Zero,128,share,disposition,options|0x00200020,IntPtr.Zero,0);
    if(result<0){if(h!=null)h.Dispose();if(result==unchecked((int)0xC0000034) || result==unchecked((int)0xC000003A))throw new FileNotFoundException("Snapshot component absent.");throw new IOException("Snapshot relative open rejected.");}
    return h;
   } finally {if(name!=IntPtr.Zero)Marshal.FreeHGlobal(name);if(text!=IntPtr.Zero)Marshal.FreeHGlobal(text);if(retained)parent.DangerousRelease();}
  }
  static SafeFileHandle Verify(SafeFileHandle h,bool directory) {
   try {Info i; if(!GetFileInformationByHandle(h,out i) || (i.Attributes&0x400)!=0 || ((i.Attributes&16)!=0)!=directory || (!directory && i.Links!=1)) throw new IOException("Unsafe snapshot component."); return h;}
   catch {h.Dispose();throw;}
  }
  public static SafeFileHandle HoldDirectory(string path) {
   SafeFileHandle h;
   if(Path.GetDirectoryName(path)==null){
    if(new DriveInfo(path).DriveType!=DriveType.Fixed)throw new IOException("Snapshot drive must be local and fixed.");
    h=CreateFileW(path,0x81,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new IOException("Snapshot root open rejected.");}
   }else{h=Relative(path,0x81,3,1,1,IntPtr.Zero);}
   h=Verify(h,true);lock(directories){List<WeakReference> list;if(!directories.TryGetValue(path,out list)){list=new List<WeakReference>();directories.Add(path,list);}
    list.RemoveAll(delegate(WeakReference r){SafeFileHandle old=r.Target as SafeFileHandle;return old==null || old.IsClosed || old.IsInvalid;});list.Add(new WeakReference(h));}return h;
  }
  public static FileStream Read(string path) {return new FileStream(Verify(Relative(path,0x80000000,1,1,0x40,IntPtr.Zero),false),FileAccess.Read,65536,false);}
  public static FileStream Create(string path) {return new FileStream(Verify(Relative(path,0xC0000000,0,2,0x42,IntPtr.Zero),false),FileAccess.ReadWrite,65536,false);}
  public static SafeFileHandle Lock(string path) {return Verify(Relative(path,0xC0010000,0,2,0x1040,IntPtr.Zero),false);}
  public static void CreatePrivateDirectory(string path, string sddl) {
   IntPtr p;uint size;
   if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out p,out size)) throw new IOException("Cannot prepare private storage.");
   try {using(SafeFileHandle h=Verify(Relative(path,0x81,3,3,1,p),true)) {}}
   finally {LocalFree(p);}
  }
  public static void MoveExclusive(string from, string to) {
   using(SafeFileHandle h=Verify(Relative(from,0x80010000,0,1,0x40,IntPtr.Zero),false)) {
    byte[] name=System.Text.Encoding.Unicode.GetBytes(Path.GetFileName(to));
    // FILE_RENAME_INFO: BOOLEAN/union, pointer-aligned HANDLE, DWORD length, WCHAR name.
    int rootOffset=IntPtr.Size==8?8:4, lengthOffset=rootOffset+IntPtr.Size, nameOffset=lengthOffset+4;
    IntPtr p=Marshal.AllocHGlobal(nameOffset+name.Length+2);SafeFileHandle target=Parent(to);bool retained=false;
    try {target.DangerousAddRef(ref retained);for(int n=0;n<nameOffset+name.Length+2;n++) Marshal.WriteByte(p,n,0);
     Marshal.WriteIntPtr(p,rootOffset,target.DangerousGetHandle());Marshal.WriteInt32(p,lengthOffset,name.Length);Marshal.Copy(name,0,IntPtr.Add(p,nameOffset),name.Length);
     StatusBlock status;int result=NtSetInformationFile(h,out status,p,(uint)(nameOffset+name.Length+2),10);
     if(result<0) throw new IOException("Snapshot rename rejected: "+result.ToString("X8")+".");
    } finally {if(retained)target.DangerousRelease();Marshal.FreeHGlobal(p);}
   }
  }
 }
}
'@ -ErrorAction Stop
}

function Assert-WinSecSnapshotPrivateAcl {
    param([string]$Path,[switch]$Directory)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $allowed=@($sid,'S-1-5-18','S-1-5-32-544')
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed -or ($Directory -and -not $acl.AreAccessRulesProtected)){throw 'Unprotected snapshot storage.'}
    $own=$false
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IdentityReference.Value -notin $allowed){throw 'Unprotected snapshot permissions.'}
        if($rule.IdentityReference.Value -eq $sid -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl){$own=$true}
    }
    if(-not $own){throw 'Snapshot owner permissions missing.'}
}

function Open-WinSecSnapshotDirectories {
    param([string]$ProjectRoot,[object]$Layout,[switch]$Create)
    Initialize-WinSecSnapshotFileIO
    $handles=New-Object 'Collections.Generic.List[IDisposable]'
    $root=[IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl='O:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    try {
        $ancestors=New-Object 'Collections.Generic.List[string]';$cursor=$root
        while($cursor){$ancestors.Insert(0,$cursor);$cursor=[IO.Path]::GetDirectoryName($cursor)}
        foreach($dir in $ancestors){$handles.Add([WinSec.SnapshotIO2]::HoldDirectory($dir))}
        foreach($base in @('scans','reports')){
            $dir=$root
            foreach($segment in @($base,$Layout.DeviceKey,$Layout.SectionKey)){
                $dir=Join-Path $dir $segment
                if($Create){[WinSec.SnapshotIO2]::CreatePrivateDirectory($dir,$sddl)}
                $handles.Add([WinSec.SnapshotIO2]::HoldDirectory($dir))
                if($segment -cne $base){Assert-WinSecSnapshotPrivateAcl $dir -Directory}
            }
        }
        return ,$handles
    }catch{foreach($h in $handles){$h.Dispose()};throw 'Cannot secure snapshot directories.'}
}

function Read-WinSecSnapshotBytes {
    param([string]$Path,[int]$MaxBytes,[scriptblock]$CancellationAction)
    $stream=$null
    try {
        $stream=[WinSec.SnapshotIO2]::Read($Path);Assert-WinSecSnapshotPrivateAcl $Path
        if($stream.Length -gt $MaxBytes){throw 'Snapshot file budget exceeded.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0;$clock=[Diagnostics.Stopwatch]::StartNew()
        while($offset -lt $bytes.Length){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$read=$stream.Read($bytes,$offset,[Math]::Min(65536,$bytes.Length-$offset));if($read -eq 0){throw 'Truncated snapshot file.'};$offset+=$read}
        return ,$bytes
    }finally{if($stream){$stream.Dispose()}}
}

function Write-WinSecSnapshotBytes {
    param([string]$Path,[byte[]]$Bytes,[scriptblock]$CancellationAction)
    $stream=$null
    try {
        $stream=[WinSec.SnapshotIO2]::Create($Path);Assert-WinSecSnapshotPrivateAcl $Path
        $clock=[Diagnostics.Stopwatch]::StartNew()
        for($offset=0;$offset -lt $Bytes.Length;$offset+=65536){Assert-WinSecSnapshotValidationBudget $clock $CancellationAction;$stream.Write($Bytes,$offset,[Math]::Min(65536,$Bytes.Length-$offset))}
        $stream.Flush($true)
    }finally{if($stream){$stream.Dispose()}}
}
