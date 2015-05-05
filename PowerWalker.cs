using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using PowerWalker.Natives;

[assembly: CLSCompliant(false)]

namespace PowerWalker
{
    public class Functions
    {
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

        public static uint GetProcessorType()
        {
            SYSTEM_INFO SystemInfo = new SYSTEM_INFO();
            Kernel32.GetNativeSystemInfo(out SystemInfo);
            uint ProcessorType = Convert.ToUInt32(SystemInfo.ProcessorType.ToString(), 16);
            return ProcessorType;
        }

        public static bool IsWow64(IntPtr hProcess)
        {
            bool Wow64Process = false;
            Kernel32.IsWow64Process(hProcess, ref Wow64Process);
            return Wow64Process;
        }

        public static IMAGEHLP_SYMBOL64 GetSymbolFromAddress(IntPtr hProcess, ulong Address)
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

        public static StackCall[] GetStackTrace(uint ProcessId, uint ThreadId)
        {
            List<StackCall> StackTrace = new List<StackCall>();

            //StackWalk64 Callbacks
            DbgHelp.SymFunctionTableAccess64Delegate FunctionTableAccessRoutine = new DbgHelp.SymFunctionTableAccess64Delegate(DbgHelp.SymFunctionTableAccess64);
            DbgHelp.SymGetModuleBase64Delegate GetModuleBaseRoutine = new DbgHelp.SymGetModuleBase64Delegate(DbgHelp.SymGetModuleBase64);

            IntPtr lpContextRecord = new IntPtr();
            STACKFRAME64 StackFrame = new STACKFRAME64();

            IntPtr hProcess = Kernel32.OpenProcess(ProcessAccess.All, false, ProcessId);
            IntPtr hThread = Kernel32.OpenThread(ThreadAccess.All, false, ThreadId);

            DbgHelp.SymInitialize(hProcess, null, false);

            //Determine Image & Processor types
            bool Wow64 = false;
            uint ProcessorType = GetProcessorType();
            if (ProcessorType == (uint)ImageFileMachine.AMD64 | ProcessorType == (uint)ImageFileMachine.IA64)
            {
                Wow64 = IsWow64(hProcess);
            }

            if (Wow64)
            {
                ProcessorType = (uint)ImageFileMachine.I386;

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
                StackFrame = InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.I386)
            {
                ProcessorType = (uint)ImageFileMachine.I386;

                //Load 32-bit modules for symbol access
                LoadModules(hProcess, ListModules._32Bit);

                //Initialize an X86_CONTEXT
                X86_CONTEXT ContextRecord = new X86_CONTEXT();
                ContextRecord.ContextFlags = (uint)ContextFlags.X86ContextAll;
                lpContextRecord = Marshal.AllocHGlobal(Marshal.SizeOf(ContextRecord));
                Marshal.StructureToPtr(ContextRecord, lpContextRecord, false);

                //Get context of thread
                Kernel32.SuspendThread(hThread);
                Kernel32.GetThreadContext(hThread, lpContextRecord);

                //Initialize Stack frame for first call to StackWalk64
                ContextRecord = (X86_CONTEXT)Marshal.PtrToStructure(lpContextRecord, typeof(X86_CONTEXT));
                StackFrame = InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.AMD64)
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
                StackFrame = InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.Rip, ContextRecord.Rsp, ContextRecord.Rsp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.IA64)
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
                StackFrame = InitializeStackFrame64
                             (AddressMode.Flat, ContextRecord.StIIP, ContextRecord.IntSp, ContextRecord.RsBSP, ContextRecord.IntSp);
            }
            //Marshal stack frame to unmanaged memory
            IntPtr lpStackFrame = Marshal.AllocHGlobal(Marshal.SizeOf(StackFrame));
            Marshal.StructureToPtr(StackFrame, lpStackFrame, false);

            //Walk the Stack
            for (int frameNum = 0; ; frameNum++)
            {
                //Get stack frame
                DbgHelp.StackWalk64(ProcessorType, hProcess, hThread, lpStackFrame, lpContextRecord,
                                    null, FunctionTableAccessRoutine, GetModuleBaseRoutine, null);
                StackFrame = (STACKFRAME64)Marshal.PtrToStructure(lpStackFrame, typeof(STACKFRAME64));

                if (StackFrame.AddrReturn.Offset == 0) { break; } //End of stack reached

                StackTrace.Add(new StackCall(hProcess, StackFrame.AddrPC.Offset, StackFrame.AddrReturn.Offset));
            }
            DbgHelp.SymCleanup(hProcess);
            Marshal.FreeHGlobal(lpStackFrame);
            Marshal.FreeHGlobal(lpContextRecord);
            Kernel32.ResumeThread(hThread);
            Kernel32.CloseHandle(hThread);
            Kernel32.CloseHandle(hProcess);
            return StackTrace.ToArray();
        }
    }
}
