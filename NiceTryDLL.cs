using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;
using System.Reflection;

public class Utils {

	public static unsafe void Copy(byte[] source, int startIndex, IntPtr destination, int length) {
		if (source == null || source.Length == 0 || destination == IntPtr.Zero || length == 0) {
			throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
		}
		if ((startIndex + length) > source.Length) {
			throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of source bytes!");
		}
		int targetIndex = 0;
		byte* TargetByte = (byte*)(destination.ToPointer());
		for (int sourceIndex = startIndex; sourceIndex < (startIndex + length); sourceIndex++) {
			*(TargetByte + targetIndex) = source[sourceIndex];
			targetIndex++;
		}
	}

	public static unsafe void Copy(IntPtr source, IntPtr destination, int length) {
		if (source == IntPtr.Zero || destination == IntPtr.Zero || length == 0) {
			throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
		}
		byte* SourceByte = (byte*)(source.ToPointer());
		byte* TargetByte = (byte*)(destination.ToPointer());
		for (int i = 0; i < length; i++) {
			*(TargetByte + i) = *(SourceByte + i);
		}
	}
	
	public static byte[] Combine(byte[] a1, byte[] a2, byte[] a3)
    {
        byte[] ret = new byte[a1.Length + a2.Length + a3.Length];
        Array.Copy(a1, 0, ret, 0, a1.Length);
        Array.Copy(a2, 0, ret, a1.Length, a2.Length);
        Array.Copy(a3, 0, ret, a1.Length + a2.Length, a3.Length);
        return ret;
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = OptHeader + (Magic == 0x010b ? 0x60 : 0x70) + 0;

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }
        return FunctionPtr;
    }
}

public class NiceTryDLL {

	[StructLayoutAttribute(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public UInt32 Status;
        public IntPtr Information;
    }

	[DllImport("ntdll.dll", SetLastError=true)] 
	static extern UInt32 NtQueryInformationFile(IntPtr fileHandle, ref IO_STATUS_BLOCK IoStatusBlock, IntPtr pInfoBlock, uint length, int fileInformation); 

	[DllImport("kernel32.dll", SetLastError=true)]
	static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

	[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static UInt32 JITMeDaddy() {
        return new UInt32();
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate UInt32 NtReadFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, IntPtr ioStatusBlockPtr, IntPtr buffer, uint length, ref long byteOffset, IntPtr key);

	public static IntPtr RealNtReadFileAddr = IntPtr.Zero;

	public static void PlantHook(IntPtr TargetFunctionAddr, IntPtr JumpAddr) {
		byte[] jumpAddrBytes = (IntPtr.Size == 4 ? BitConverter.GetBytes((Int32)JumpAddr) : BitConverter.GetBytes((Int64)JumpAddr));
        byte[] jumpStub = Utils.Combine(new byte[] { Convert.ToByte("49", 16), Convert.ToByte("BB", 16) }, jumpAddrBytes, new byte[] { Convert.ToByte("41", 16), Convert.ToByte("FF", 16), Convert.ToByte("E3", 16) }); // move r11, <jump addr>; jmp r11;

        Utils.Copy(jumpStub, 0, TargetFunctionAddr, jumpStub.Length);
	}

	public static UInt32 HookedNtReadFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, IntPtr ioStatusBlockPtr, IntPtr buffer, uint length, ref long byteOffset, IntPtr key) {
		// call NtQueryInformationFile to get FileNameInformation, check if its ntdll.dll
		IO_STATUS_BLOCK IoStatusBlock = new IO_STATUS_BLOCK();
		IntPtr pInfoBlock = Marshal.AllocHGlobal(1024);
		UInt32 status = NtQueryInformationFile(handle, ref IoStatusBlock, pInfoBlock, 1024, 9); // FileNameInformation = 9
		if (status != 0x00000000) {
			Console.WriteLine("[NiceTryDLL v0.1] NtReadFile - NtQueryInformationFile Error! Code : 0x{0}", status.ToString("X4"));
			return 0xc0000001; // unsuccessful
		}
		int fileNameLength = Marshal.ReadInt32(pInfoBlock) / 2;
		string fileName = System.Environment.SystemDirectory.Substring(0,2) + Marshal.PtrToStringUni(pInfoBlock + 4, fileNameLength);
		Console.WriteLine("[NiceTryDLL v0.1] NtReadFile - FileName : {0}", fileName);
		if (fileName.EndsWith("ntdll.dll")) {
			Console.WriteLine("[NiceTryDLL v0.1] NtReadFile - NTDLL DETECTED!");
			Environment.Exit(0);
		}
		Marshal.FreeHGlobal(pInfoBlock);

		// call the real NtReadFile and return
		Console.WriteLine("[NiceTryDLL v0.1] NtReadFile - Executing RealNtReadFile...");		
		NtReadFile RealNtReadFile = (NtReadFile)Marshal.GetDelegateForFunctionPointer(RealNtReadFileAddr, typeof(NtReadFile));
		status = RealNtReadFile(handle, evt, apcRoutine, apcContext, ioStatusBlockPtr, buffer, length, ref byteOffset, key);
		Console.WriteLine("[NiceTryDLL v0.1] NtReadFile - RealNtReadFile status code : 0x{0}", status.ToString("X4"));
		Console.WriteLine("[-----------------------------------------------------------]");

		return status;
	}

	public static void Main() {
		// Find and JIT the method to generate RWX space for the original NtReadFile stub
        MethodInfo method = typeof(NiceTryDLL).GetMethod("JITMeDaddy", BindingFlags.Static | BindingFlags.NonPublic);
        if (method == null) {
            Console.WriteLine("[NiceTryDLL v0.1] Unable to find the method!");
            return;
        }
        RuntimeHelpers.PrepareMethod(method.MethodHandle);
        RealNtReadFileAddr = method.MethodHandle.GetFunctionPointer();

		// locate NtReadFile address
		IntPtr NTDLLAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
		IntPtr NtReadFileAddr = Utils.GetExportAddress(NTDLLAddr, "NtReadFile");

		// save original NtReadFile stub
		Utils.Copy(NtReadFileAddr, RealNtReadFileAddr, 32);

		// change the stub's memory protection to RWX
		uint oldProtect = 0;
		VirtualProtect(NtReadFileAddr, (UIntPtr)32, 0x40, out oldProtect);

		// JIT the JMP method
		MethodInfo JMPmethod = typeof(NiceTryDLL).GetMethod("HookedNtReadFile", BindingFlags.Static | BindingFlags.Public);
		RuntimeHelpers.PrepareMethod(JMPmethod.MethodHandle);

		// plant the hook
		PlantHook(NtReadFileAddr, JMPmethod.MethodHandle.GetFunctionPointer());
		Console.WriteLine("[NiceTryDLL v0.1] Hook planted!");
	}

	public static void Unhook() {
		// locate NtReadFile address
		IntPtr NTDLLAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
		IntPtr NtReadFileAddr = Utils.GetExportAddress(NTDLLAddr, "NtReadFile");

		// revert the stub
		Utils.Copy(RealNtReadFileAddr, NtReadFileAddr, 32);

		// revert mem protection to RX
		uint oldProtect = 0;
		VirtualProtect(NtReadFileAddr, (UIntPtr)32, 0x20, out oldProtect);
		Console.WriteLine("[NiceTryDLL v0.1] Hook removed!");
	}
}