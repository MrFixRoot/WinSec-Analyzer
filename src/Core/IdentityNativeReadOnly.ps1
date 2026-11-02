# Fixed source declaration only. Loading this file never compiles or invokes a native API.
function Get-WinSecIdentityNativeSource {
@'
// Local-only SAM readers. No setters, name resolution, credentials or remote server parameter.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace WinSec {
    public static class IdentityNativeReadOnly {
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
        private static extern uint NetLocalGroupGetMembers(string server, string group, uint level,
            out IntPtr buffer, uint preferred, out uint read, out uint total, ref UIntPtr resume);
        [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)]
        private static extern uint NetUserModalsGet(string server, uint level, out IntPtr buffer);
        [DllImport("Netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);
        public static string[] Administrators(string localGroupName) {
            var result = new List<string>();
            UIntPtr resume = UIntPtr.Zero;
            for (int page=0; page<16; page++) {
                IntPtr buffer=IntPtr.Zero; uint read=0, total=0, status=0;
                try {
                    status=NetLocalGroupGetMembers(null, localGroupName, 0, out buffer, 8192, out read, out total, ref resume);
                    if ((status!=0 && status!=234) || total>256 || read>256 || result.Count+read>256 || (read>0 && buffer==IntPtr.Zero))
                        throw new InvalidOperationException("MEMBERS_UNAVAILABLE");
                    for (int i=0; i<read; i++) {
                        IntPtr sid=Marshal.ReadIntPtr(buffer, checked(i*IntPtr.Size));
                        result.Add(new SecurityIdentifier(sid).Value);
                    }
                } finally { if(buffer!=IntPtr.Zero) NetApiBufferFree(buffer); }
                if(status==0) return result.ToArray();
                if(read==0) throw new InvalidOperationException("MEMBERS_UNAVAILABLE");
            }
            throw new InvalidOperationException("MEMBERS_UNAVAILABLE");
        }
        public static uint[] Policy(uint level) {
            if(level!=0 && level!=3) throw new ArgumentException("Unreviewed level");
            IntPtr buffer=IntPtr.Zero;
            try {
                if(NetUserModalsGet(null, level, out buffer)!=0 || buffer==IntPtr.Zero)
                    throw new InvalidOperationException("POLICY_UNAVAILABLE");
                uint[] fields=new uint[level==0?5:3];
                for(int i=0;i<fields.Length;i++) fields[i]=unchecked((uint)Marshal.ReadInt32(buffer,i*4));
                return fields;
            } finally { if(buffer!=IntPtr.Zero) NetApiBufferFree(buffer); }
        }
    }
}
'@
}
