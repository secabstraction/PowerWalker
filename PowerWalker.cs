using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using PowerWalker.Natives;

[assembly: CLSCompliant(false)]

namespace PowerWalker
{
    public class Helpers
    {
        //StackWalk64 Callback Delegates
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

        public static long UlongToLong(ulong n1)
        {
            byte[] bytes = BitConverter.GetBytes(n1);
            return BitConverter.ToInt64(bytes, 0);
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

        public static bool LoadModules(IntPtr hProcess, ListModules ModuleType)
        {
            //Initialize parameters for EPM
            uint cbNeeded = 0;
            Psapi.EnumProcessModulesEx(hProcess, IntPtr.Zero, 0, out cbNeeded, ModuleType);
            IntPtr[] hModules = new IntPtr[(cbNeeded / IntPtr.Size)];
            GCHandle GCh = GCHandle.Alloc(hModules, GCHandleType.Pinned); // Don't forget to free this later
            IntPtr lphModules = GCh.AddrOfPinnedObject();
            uint cb = cbNeeded;
            Psapi.EnumProcessModulesEx(hProcess, lphModules, cb, out cbNeeded, ModuleType);
            int NumberOfModules = (int)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));
            for (int i = 0; i < NumberOfModules; i++)
            {
                MODULE_INFO ModInfo = new MODULE_INFO();
                System.Text.StringBuilder lpFileName = new System.Text.StringBuilder(256);
                System.Text.StringBuilder lpModuleBaseName = new System.Text.StringBuilder(32);

                Psapi.GetModuleFileNameExW(hProcess, hModules[i], lpFileName, (uint)(lpFileName.Capacity));
                Psapi.GetModuleInformation(hProcess, hModules[i], out ModInfo, (uint)(Marshal.SizeOf(ModInfo)));
                Psapi.GetModuleBaseNameW(hProcess, hModules[i], lpModuleBaseName, (uint)(lpModuleBaseName.Capacity));
                DbgHelp.SymLoadModuleEx(hProcess, IntPtr.Zero, lpFileName.ToString(), lpModuleBaseName.ToString(),
                ModInfo.lpBaseOfDll, (int)ModInfo.SizeOfImage, IntPtr.Zero, 0);
            }
            GCh.Free();
            return false;
        }

        public static IMAGEHLP_SYMBOL64 GetSymbol(IntPtr hProcess, ulong Address)
        {
            //Initialize params for SymGetSymFromAddr64
            IMAGEHLP_SYMBOL64 Symbol = new IMAGEHLP_SYMBOL64();
            Symbol.SizeOfStruct = (uint)Marshal.SizeOf(Symbol);
            Symbol.MaxNameLength = 32;
            IntPtr lpSymbol = Marshal.AllocHGlobal(Marshal.SizeOf(Symbol));
            Marshal.StructureToPtr(Symbol, lpSymbol, false);
            ulong Offset = 0;

            DbgHelp.SymGetSymFromAddr64(hProcess, Address, Offset, lpSymbol);
            Symbol = (IMAGEHLP_SYMBOL64)Marshal.PtrToStructure(lpSymbol, typeof(IMAGEHLP_SYMBOL64));
            Marshal.FreeHGlobal(lpSymbol);
            return Symbol;
        }

        public static bool StackWalk(uint ProcessId, uint ThreadId)
        {
            IntPtr hProcess = Kernel32.OpenProcess(ProcessAccess.All, false, ProcessId);
            IntPtr hThread = Kernel32.OpenThread(ThreadAccess.AllAccess, false, ThreadId);

            DbgHelp.SymInitialize(hProcess, null, false);
            uint SymOptions = DbgHelp.SymGetOptions();

            char[] buffer = new char[Constants.MAX_NAMELEN];
            DbgHelp.SymGetSearchPath(hProcess, buffer, Constants.MAX_NAMELEN);

            //Determine Process/Machine
            bool Wow64 = false;
            SYSTEM_INFO SystemInfo = GetSysInfo();
            uint MachineType = Convert.ToUInt32(SystemInfo.ProcessorType.ToString(), 16);
            if (MachineType == (uint)ImageFileMachine.AMD64 | MachineType == (uint)ImageFileMachine.IA64) { Wow64 = IsWow64(hProcess); }

            //StackWalk64 Callbacks
            Helpers.SymFunctionTableAccess64Delegate FunctionTableAccessRoutine = new Helpers.SymFunctionTableAccess64Delegate(DbgHelp.SymFunctionTableAccess64);
            Helpers.SymGetModuleBase64Delegate GetModuleBaseRoutine = new Helpers.SymGetModuleBase64Delegate(DbgHelp.SymGetModuleBase64);

            IntPtr lpContextRecord = new IntPtr();
            STACKFRAME64 StackFrame = new STACKFRAME64();

            if (Wow64 | (MachineType == (uint)ImageFileMachine.I386))
            {
                MachineType = (uint)ImageFileMachine.I386;

                //Load 32-bit modules for symbol access
                LoadModules(hProcess, ListModules._32Bit);

                //Initialize an X86_CONTEXT
                X86_CONTEXT ContextRecord = new X86_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.X86ContextAll;
                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);

                //Get context of thread
                Kernel32.Wow64SuspendThread(hThread);
                Kernel32.Wow64GetThreadContext(hThread, lpContextRecord);

                //Initialize Stack frame for first call to StackWalk64
                ContextRecord = (X86_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(X86_CONTEXT));
                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }
            else if (MachineType == (uint)ImageFileMachine.AMD64)
            {
                //Load 64-bit modules for symbol access
                LoadModules(hProcess, ListModules._64Bit);

                //Initialize AMD64_CONTEXT
                AMD64_CONTEXT ContextRecord = new AMD64_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.AMD64ContextAll;
                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);
                
                //Get context of thread
                Kernel32.SuspendThread(hThread);
                Kernel32.GetThreadContext(hThread, lpContextRecord);

                //Initialize Stack frame for first call to StackWalk64
                ContextRecord = (AMD64_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(AMD64_CONTEXT));
                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Rip, ContextRecord.Rsp, ContextRecord.Rsp, new ulong());
            }
            else if (MachineType == (uint)ImageFileMachine.IA64)
            {
                //Load 64-bit modules for symbol access
                LoadModules(hProcess, ListModules._64Bit);

                //Initialize IA64_CONTEXT
                IA64_CONTEXT ContextRecord = new IA64_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.IA64ContextAll;
                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);
                
                //Get context of thread
                Kernel32.SuspendThread(hThread);
                Kernel32.GetThreadContext(hThread, lpContextRecord);

                //Initialize Stack frame for first call to StackWalk64
                ContextRecord = (IA64_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(IA64_CONTEXT));
                StackFrame = Helpers.InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.StIIP, ContextRecord.IntSp, ContextRecord.RsBSP, ContextRecord.IntSp);
            }
            //Marshal stack frame to unmanaged memory
            IntPtr lpStackFrame = Marshal.AllocHGlobal(Marshal.SizeOf(StackFrame));
            Marshal.StructureToPtr(StackFrame, lpStackFrame, false);

            //Walk the Stack
            for (int frameNum = 0; ; frameNum++)
            {
                //Initialize param for GetMappedFileNameW
                System.Text.StringBuilder lpFilename = new System.Text.StringBuilder(256);

                //Get stack frame
                DbgHelp.StackWalk64(MachineType, hProcess, hThread, lpStackFrame, lpContextRecord,
                                    null, FunctionTableAccessRoutine, GetModuleBaseRoutine, null);                
                StackFrame = (STACKFRAME64)Marshal.PtrToStructure(lpStackFrame, typeof(STACKFRAME64));

                if (StackFrame.AddrReturn.Offset == 0) { break; } //End of stack reached

                //Grab PC and Return address from stack frame
                IntPtr PcAddress = (IntPtr)Helpers.UlongToLong(StackFrame.AddrPC.Offset);
                IntPtr ReturnAddress = (IntPtr)Helpers.UlongToLong(StackFrame.AddrReturn.Offset);
                
                //Get FileName and Symbol for PC
                Psapi.GetMappedFileNameW(hProcess, PcAddress, lpFilename, (uint)lpFilename.Capacity);
                string PcFileName = lpFilename.ToString();
                IMAGEHLP_SYMBOL64 PcSymbol = GetSymbol(hProcess, StackFrame.AddrPC.Offset);

                //Get FileName and Symbol for Return
                Psapi.GetMappedFileNameW(hProcess, ReturnAddress, lpFilename, (uint)lpFilename.Capacity);
                string ReturnFileName = lpFilename.ToString();
                IMAGEHLP_SYMBOL64 ReturnSymbol = GetSymbol(hProcess, StackFrame.AddrReturn.Offset);

                //Write to console
                Console.WriteLine("PC:     0x" + StackFrame.AddrPC.Offset.ToString("X8") + "\t" + (new string(PcSymbol.Name)) + "\t" + PcFileName.ToString());
                Console.WriteLine("Return: 0x" + StackFrame.AddrReturn.Offset.ToString("X8") + "\t" + (new string(ReturnSymbol.Name)) + "\t" + ReturnFileName.ToString());                
            }
            DbgHelp.SymCleanup(hProcess);
            Marshal.FreeHGlobal(lpStackFrame);
            Marshal.FreeHGlobal(lpContextRecord);
            Kernel32.ResumeThread(hThread);
            Kernel32.CloseHandle(hThread);
            Kernel32.CloseHandle(hProcess);
            return true;
        }        
    }
}
