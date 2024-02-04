using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace RuntimeApiKey
{
    public struct Chunk
    {
        public Dumper.MEMORY_BASIC_INFORMATION MemoryInformation;
        public byte[] Bytes;
    }

    public class MemoryDump
    {
        public MemoryDump(Chunk[] chunks)
        {
            Chunks = chunks;

            long bytesSum = 0;
            foreach (var chunk in chunks)
                bytesSum += chunk.Bytes.Length;

            Bytes = new byte[bytesSum];

            int byteOffset = 0;
            foreach (var chunk in chunks)
            {
                for (int i = 0; i < chunk.Bytes.Length; i++)
                {
                    Bytes[byteOffset + i] = chunk.Bytes[i];
                }
                byteOffset += chunk.Bytes.Length;
            }
        }

        public readonly Chunk[] Chunks;
        public readonly byte[] Bytes;

        public string BytesString
        {
            get
            {
                byte[] cleansedBytes = Bytes;
                for (int i = 0; i < Bytes.Length; i++)
                    cleansedBytes[i] = (byte)ToChar(cleansedBytes[i]);

                return Encoding.UTF8.GetString(cleansedBytes);
            }
        }

        public static char ToChar(byte bt)
        {
            bool isPrintable = bt >= 32 && bt <= 126;
            return isPrintable ? (char)bt : '.';
        }

        [Flags]
        public enum DumpSaveOptions
        {
            BytesArray = 1,
            BytesString = 2,
            Both = BytesArray | BytesString
        };

        public void Save(string filePath, DumpSaveOptions options = DumpSaveOptions.Both, int bytesPerLine = 56)
        {
            if (!File.Exists(filePath))
                throw new Exception("File '" + filePath + "' doesn't exist");

            bool bytesArray = (options & DumpSaveOptions.BytesArray) != 0;
            bool bytesString = (options & DumpSaveOptions.BytesString) != 0;

            StreamWriter streamWriter = new StreamWriter(filePath);
            for (int i = 0; i < Bytes.Length / bytesPerLine; i++)
            {
                // the bytes for this line
                byte[] lineBytes = new byte[bytesPerLine];
                Array.Copy(Bytes, i * bytesPerLine, lineBytes, 0, bytesPerLine);

                string line = "";
                string dataString = "";
                foreach (byte bt in lineBytes)
                {
                    if (bytesArray)
                    {
                        string b = bt.ToString("X");
                        line += (b.Length == 1 ? "0" + b : b) + " ";
                    }

                    if (bytesString)
                        dataString += ToChar(bt);
                }
                line += (bytesArray && bytesString ? "| " : "") + dataString;

                streamWriter.WriteLine(line);
            }

            streamWriter.Close();
        }
    }

    public class Dumper
    {
        #region IMPORTS
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
           IntPtr hProcess,
           IntPtr lpBaseAddress,
           byte[] lpBuffer,
           int nSize,
           out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        #endregion

        #region ENUMS
        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [Flags]
        enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        #endregion

        #region STRUCTS
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }
        #endregion

        public static MemoryDump Dump(Process process)
        {
            if (process == Process.GetCurrentProcess()) // a recursive memory allocation loop happens in this case until it runs out of memory
                throw new Exception("Cannot dump the memory of this process");

            List<Chunk> chunks = new List<Chunk>();

            SYSTEM_INFO systemInfo = new SYSTEM_INFO();
            GetSystemInfo(out systemInfo);

            IntPtr minimumAddress = systemInfo.minimumApplicationAddress;
            IntPtr maximumAddress = systemInfo.maximumApplicationAddress;

            IntPtr processHandle = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, process.Id);
            if (processHandle == IntPtr.Zero)
                throw new Exception("Cannot get a handle to process");

            while (minimumAddress.ToInt64() < maximumAddress.ToInt64())
            {
                MEMORY_BASIC_INFORMATION memoryInformation = new MEMORY_BASIC_INFORMATION();
                VirtualQueryEx(processHandle, minimumAddress, out memoryInformation, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));

                // check if this chunk is accessible
                if (memoryInformation.Protect == AllocationProtectEnum.PAGE_READWRITE && memoryInformation.State == StateEnum.MEM_COMMIT)
                {
                    byte[] buffer = new byte[memoryInformation.RegionSize.ToInt64()];
                    ReadProcessMemory(processHandle, memoryInformation.BaseAddress, buffer, memoryInformation.RegionSize.ToInt32(), out IntPtr bytesRead);

                    chunks.Add(new Chunk
                    {
                        MemoryInformation = memoryInformation,
                        Bytes = buffer
                    });
                }

                // move to the next chunk
                try
                {
                    minimumAddress = new IntPtr(minimumAddress.ToInt64() + memoryInformation.RegionSize.ToInt64());
                }
                catch (OverflowException)
                {
                    break;
                }
            }

            return new MemoryDump(chunks.ToArray());
        }

    }
}

class Program
{
    static void Main()
    {
        var processName = "launcher";
        Console.WriteLine($"Searching for process: {processName}");
        var processes = Process.GetProcessesByName(processName);

        if (processes.Length == 0)
        {
            Console.WriteLine($"Process '{processName}' not found.");
            WaitForEnterKey();
            return;
        }

        var process = processes[0];
        Console.WriteLine($"Process '{process.ProcessName}' found. PID: {process.Id}");

        var dump = RuntimeApiKey.Dumper.Dump(process);

        string pattern = @"&key=(.*?)&prev=false";
        Regex regex = new Regex(pattern);

        string text = dump.BytesString;

        Match match = regex.Match(text);

        if (match.Success)
        {
            string extractedString = match.Groups[1].Value;
            string[] parts = extractedString.Split(new string[] { "&key=" }, StringSplitOptions.None);
            if (parts.Length > 1)
            {
                string NewExtractedString = parts[parts.Length - 1].Split('&')[0];
                Console.WriteLine("Launcher API key found: " + NewExtractedString);
            }
            else
            {
                Console.WriteLine("Launcher API key found: " + extractedString);
            }
        }
        else
        {
            Console.WriteLine("No match found.");
        }

        WaitForEnterKey();
    }

    static void WaitForEnterKey()
    {
        Console.WriteLine("Press Enter to exit the application...");
        Console.ReadLine();
    }
}
