using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;

class SharpNinjaShellcode
{
    static void Main(string[] args)
    {
        if (args.Length < 4 || args[0] != "-t" || args[2] != "-s")
        {
            PrintUsage();
            return;
        }

        string obfuscationType = args[1];
        string shellcodeFilePath = args[3];

        if (!File.Exists(shellcodeFilePath))
        {
            Console.WriteLine("Error: Shellcode file not found.");
            return;
        }

        byte[] shellcode = File.ReadAllBytes(shellcodeFilePath);

        try
        {
            string obfuscatedShellcode = ObfuscateShellcode(shellcode, obfuscationType);
            Console.WriteLine(obfuscatedShellcode);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            PrintAvailableObfuscationTypes();
        }
    }

    static void PrintUsage()
    {
        Console.WriteLine(@"
   _____ _                      _   _ _       _        _____ _          _ _               _      
  / ____| |                    | \ | (_)     (_)      / ____| |        | | |             | |     
 | (___ | |__   __ _ _ __ _ __ |  \| |_ _ __  _  __ _| (___ | |__   ___| | | ___ ___   __| | ___ 
  \___ \| '_ \ / _` | '__| '_ \| . ` | | '_ \| |/ _` |\___ \| '_ \ / _ \ | |/ __/ _ \ / _` |/ _ \
  ____) | | | | (_| | |  | |_) | |\  | | | | | | (_| |____) | | | |  __/ | | (_| (_) | (_| |  __/
 |_____/|_| |_|\__,_|_|  | .__/|_| \_|_|_| |_| |\__,_|_____/|_| |_|\___|_|_|\___\___/ \__,_|\___|
                         | |                _/ |                                                 
                         |_|               |__/                                                  ");
        Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} -t <obfuscation_type> -s <raw_shellcode>");
        PrintAvailableObfuscationTypes();
    }

    static void PrintAvailableObfuscationTypes()
    {
        Console.WriteLine("\nAvailable obfuscation types:");
        Console.WriteLine("  UUID           - Obfuscates the shellcode using UUIDs (each 16 bytes of shellcode is turned into a UUID).");
        Console.WriteLine("  MAC            - Obfuscates the shellcode as MAC addresses (formatted like UUIDs).");
    }

    static string ObfuscateShellcode(byte[] shellcode, string obfuscationType)
    {
        return obfuscationType switch
        {
            "UUID" => UUIDFuscation(shellcode),
            "MAC" => MACFuscation(shellcode),
            _ => throw new ArgumentException("Unknown obfuscation type.")
        };
    }

    static string UUIDFuscation(byte[] shellcode)
    {
        StringBuilder uuidBuilder = new StringBuilder();
        uuidBuilder.AppendLine("/* UUID Obfuscation */");
        uuidBuilder.AppendLine("string[] UUIDArray = new string[]");
        uuidBuilder.AppendLine("{");

        const int chunkSize = 16;

        for (int i = 0; i < shellcode.Length; i += chunkSize)
        {
            byte[] chunk = shellcode.Skip(i).Take(chunkSize).ToArray();

            if (chunk.Length < chunkSize)
            {
                Array.Resize(ref chunk, chunkSize);
                for (int j = shellcode.Length % chunkSize; j < chunkSize; j++)
                {
                    chunk[j] = 0x90;
                }
            }

            Guid guid = new Guid(chunk);
            uuidBuilder.AppendLine($"    \"{guid}\",");
        }

        uuidBuilder.AppendLine("};");

        uuidBuilder.AppendLine();
        uuidBuilder.AppendLine("/* Deobfuscation Function */");
        uuidBuilder.AppendLine("static byte[] DeobfuscateUUID(string[] UUIDArray)");
        uuidBuilder.AppendLine("{");
        uuidBuilder.AppendLine("    var originalBytes = new List<byte>();");
        uuidBuilder.AppendLine("    foreach (var uuid in UUIDArray)");
        uuidBuilder.AppendLine("    {");
        uuidBuilder.AppendLine("        Guid guid = Guid.Parse(uuid);");
        uuidBuilder.AppendLine("        originalBytes.AddRange(guid.ToByteArray());");
        uuidBuilder.AppendLine("    }");
        uuidBuilder.AppendLine("    return originalBytes.ToArray();");
        uuidBuilder.AppendLine("}");

        return uuidBuilder.ToString().TrimEnd(',', '\n', '\r');
    }

    static string MACFuscation(byte[] shellcode)
    {
        StringBuilder macBuilder = new StringBuilder();
        macBuilder.AppendLine("/* MAC Address Obfuscation */");
        macBuilder.AppendLine("string[] MACArray = new string[]");
        macBuilder.AppendLine("{");

        const int chunkSize = 6;

        for (int i = 0; i < shellcode.Length; i += chunkSize)
        {
            byte[] chunk = shellcode.Skip(i).Take(chunkSize).ToArray();

            // Ensure the chunk is exactly 6 bytes by padding with 0x00 if needed
            if (chunk.Length < chunkSize)
            {
                Array.Resize(ref chunk, chunkSize);
                for (int j = shellcode.Length % chunkSize; j < chunkSize; j++)
                {
                    chunk[j] = 0x00;
                }
            }

            macBuilder.AppendLine($"    \"{chunk[0]:X2}-{chunk[1]:X2}-{chunk[2]:X2}-{chunk[3]:X2}-{chunk[4]:X2}-{chunk[5]:X2}\",");
        }

        macBuilder.AppendLine("};");

        // Adding the deobfuscation function to convert MACArray back to the original byte array
        macBuilder.AppendLine();
        macBuilder.AppendLine("/* Deobfuscation Function */");
        macBuilder.AppendLine("static byte[] DeobfusMAC(string[] MACArray)");
        macBuilder.AppendLine("{");
        macBuilder.AppendLine("    var originalBytes = new List<byte>();");
        macBuilder.AppendLine("    foreach (var mac in MACArray)");
        macBuilder.AppendLine("    {");
        macBuilder.AppendLine("        var hexBytes = mac.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();");
        macBuilder.AppendLine("        originalBytes.AddRange(hexBytes);");
        macBuilder.AppendLine("    }");
        macBuilder.AppendLine("    return originalBytes.ToArray();");
        macBuilder.AppendLine("}");

        return macBuilder.ToString().TrimEnd(',', '\n', '\r');
    }

}