using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Antivenin;

[assembly: CLSCompliant(false)]

namespace Antivenin
{
    public class Helpers
    {
        public delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesRead);

        public delegate IntPtr SymFunctionTableAccess64Delegate(IntPtr hProcess, ulong AddrBase);

        public delegate ulong SymGetModuleBase64Delegate(IntPtr hProcess, ulong Address);

        public delegate ulong TranslateAddressProc64Delegate(IntPtr hProcess, IntPtr hThread, IntPtr lpAddress64);

        public static STACKFRAME64 InitializeStackFrame64(AddressMode AddrMode, ulong OffsetPC, ulong OffsetFrame, ulong OffsetStack, ulong OffsetBStore)
        {
            STACKFRAME64 StackFrame = new STACKFRAME64();
            StackFrame.AddrPC.Mode = AddrMode;
            StackFrame.AddrPC.Offset = OffsetPC;
            StackFrame.AddrReturn.Mode = AddrMode;
            StackFrame.AddrFrame.Mode = AddrMode;
            StackFrame.AddrFrame.Offset = OffsetFrame;
            StackFrame.AddrStack.Mode = AddrMode;
            StackFrame.AddrStack.Offset = OffsetStack;
            StackFrame.AddrBStore.Offset = OffsetBStore;
            StackFrame.AddrBStore.Mode = AddrMode;

            return StackFrame;
        }
    }
    public class Antivenin
    {
        public static SYSTEM_INFO GetSysInfo()
        {
            SYSTEM_INFO lpSystemInfo = new SYSTEM_INFO();
            Kernel32.GetNativeSystemInfo(out lpSystemInfo);
            return lpSystemInfo;
        }

        public static bool IsWow64(IntPtr hProcess)
        {
            bool Wow64Process = false;
            Kernel32.IsWow64Process(hProcess, ref Wow64Process);
            return Wow64Process;
        }

        public static STACKFRAME64 StackWalk(uint ProcessId, uint ThreadId)
        {
            IntPtr hProcess = Kernel32.OpenProcess(ProcessAccess.All, false, ProcessId);
            IntPtr hThread = Kernel32.OpenThread(ThreadAccess.AllAccess, false, ThreadId);
            DbgHelp.SymInitialize(hProcess, null, true);
            uint SymOptions = DbgHelp.SymGetOptions();

            char[] buffer = new char[Constants.MAX_NAMELEN];
            DbgHelp.SymGetSearchPath(hProcess, buffer, Constants.MAX_NAMELEN);

            bool Wow64 = IsWow64(hProcess);

            SYSTEM_INFO SystemInfo = GetSysInfo();
            uint MachineType = Convert.ToUInt32(SystemInfo.ProcessorType.ToString(), 16);

            Helpers.SymFunctionTableAccess64Delegate FunctionTableAccessRoutine = new Helpers.SymFunctionTableAccess64Delegate(DbgHelp.SymFunctionTableAccess64);
            Helpers.SymGetModuleBase64Delegate GetModuleBaseRoutine = new Helpers.SymGetModuleBase64Delegate(DbgHelp.SymGetModuleBase64);

            IntPtr lpContextRecord = new IntPtr();
            STACKFRAME64 StackFrame = new STACKFRAME64();

            if (Wow64 | (MachineType == (uint)ImageFileMachine.I386)) 
            {
                X86_CONTEXT ContextRecord = new X86_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.X86ContextAll;

                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);

                Kernel32.Wow64SuspendThread(hThread);
                Kernel32.Wow64GetThreadContext(hThread, lpContextRecord);

                ContextRecord = (X86_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(X86_CONTEXT));

                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }

            else if (MachineType == (uint)ImageFileMachine.AMD64) 
            {
                AMD64_CONTEXT ContextRecord = new AMD64_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.AMD64ContextAll;

                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);

                Kernel32.SuspendThread(hThread);
                Kernel32.GetThreadContext(hThread, lpContextRecord);

                ContextRecord = (AMD64_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(AMD64_CONTEXT));

                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Rip, ContextRecord.Rsp, ContextRecord.Rsp, new ulong());
            }

            else if (MachineType == (uint)ImageFileMachine.IA64)
            {
                IA64_CONTEXT ContextRecord = new IA64_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.IA64ContextAll;

                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);

                Kernel32.SuspendThread(hThread);
                Kernel32.GetThreadContext(hThread, lpContextRecord);

                ContextRecord = (IA64_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(IA64_CONTEXT));

                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.StIIP, ContextRecord.IntSp, ContextRecord.RsBSP, ContextRecord.IntSp);
            }

            IntPtr lpStackFrame = Marshal.AllocHGlobal(Marshal.SizeOf(StackFrame));
            Marshal.StructureToPtr(StackFrame, lpStackFrame, false);

            DbgHelp.StackWalk64(MachineType, hProcess, hThread, lpStackFrame, lpContextRecord, 
                                null, FunctionTableAccessRoutine, GetModuleBaseRoutine, null);

            DbgHelp.SymCleanup(hProcess);
            StackFrame = (STACKFRAME64)Marshal.PtrToStructure(lpStackFrame, typeof(STACKFRAME64));
            Marshal.FreeHGlobal(lpStackFrame);
            Marshal.FreeHGlobal(lpContextRecord);
            Kernel32.ResumeThread(hThread);
            return StackFrame;
        }

        public static bool LoadModules64(IntPtr hProcess)
        {
            //Initialize parameters for EPM
            IntPtr[] hModules = new IntPtr[128];
            GCHandle gch = GCHandle.Alloc(hModules, GCHandleType.Pinned); // Don't forget to free this later
            IntPtr lphModules = gch.AddrOfPinnedObject();
            uint cb = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hModules.Length));
            uint cbNeeded = 0;

            Psapi.EnumProcessModulesEx(hProcess, out lphModules, cb, out cbNeeded, ListModules.All);
            int NumberOfModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));

            MODULE_INFO ModInfo = new MODULE_INFO();

            for (int i = 0; i < NumberOfModules; i++)
            {
                System.Text.StringBuilder lpFileName = new System.Text.StringBuilder(1024);
                Psapi.GetModuleFileNameExW(hProcess, hModules[i], lpFileName, (uint)(lpFileName.Capacity));
                Psapi.GetModuleInformation(hProcess, hModules[i], out ModInfo, (uint)(Marshal.SizeOf(ModInfo)));
            }
            return false;
        }

        public static bool LoadModules32(int ProcessId)
        {
            Process TargetProcess = Process.GetProcessById(ProcessId);
            IntPtr hProcess = TargetProcess.Handle;
            
            foreach(ProcessModule Module in TargetProcess.Modules)
            {
                DbgHelp.SymLoadModuleEx(hProcess, IntPtr.Zero, Module.FileName, Module.ModuleName, Module.BaseAddress, 
                                        Module.ModuleMemorySize, IntPtr.Zero, 0x4);
            }

            return true;
        }
    }
}
