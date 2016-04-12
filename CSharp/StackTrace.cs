using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using PowerWalker.Natives;

namespace PowerWalker
{
    public class StackTrace
    {
        public readonly StackCall[] Calls;

        public StackTrace(uint ProcessId, uint ThreadId)
        {
            List<StackCall> StackCalls = new List<StackCall>();

            //StackWalk64 Callbacks
            DbgHelp.SymFunctionTableAccess64Delegate FunctionTableAccessRoutine = new DbgHelp.SymFunctionTableAccess64Delegate(DbgHelp.SymFunctionTableAccess64);
            DbgHelp.SymGetModuleBase64Delegate GetModuleBaseRoutine = new DbgHelp.SymGetModuleBase64Delegate(DbgHelp.SymGetModuleBase64);

            IntPtr lpContextRecord = new IntPtr();
            STACKFRAME64 StackFrame = new STACKFRAME64();

            //Get handle for thread and its process
            IntPtr hProcess = Kernel32.OpenProcess(ProcessAccess.All, false, ProcessId);
            IntPtr hThread = Kernel32.OpenThread(ThreadAccess.All, false, ThreadId);

            //Initialize Symbol handler
            DbgHelp.SymInitialize(hProcess, null, false);

            //Determine Image & Processor types
            bool Wow64 = false;
            uint ProcessorType = Functions.GetProcessorType();

            if (ProcessorType == (uint)ImageFileMachine.AMD64 | ProcessorType == (uint)ImageFileMachine.IA64)
            {
                Wow64 = Functions.IsWow64(hProcess);
            }

            //Initialize thread context & stack frame based on architectures
            if (Wow64)
            {
                ProcessorType = (uint)ImageFileMachine.I386;

                //Load 32-bit modules for symbol access
                Functions.LoadModules(hProcess, ListModules._32Bit);

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
                StackFrame = Functions.InitializeStackFrame64
                                       (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.I386)
            {
                ProcessorType = (uint)ImageFileMachine.I386;

                //Load 32-bit modules for symbol access
                Functions.LoadModules(hProcess, ListModules._32Bit);

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
                StackFrame = Functions.InitializeStackFrame64
                                       (AddressMode.Flat, ContextRecord.Eip, ContextRecord.Esp, ContextRecord.Ebp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.AMD64)
            {
                //Load 64-bit modules for symbol access
                Functions.LoadModules(hProcess, ListModules._64Bit);

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
                StackFrame = Functions.InitializeStackFrame64
                                       (AddressMode.Flat, ContextRecord.Rip, ContextRecord.Rsp, ContextRecord.Rsp, new ulong());
            }
            else if (ProcessorType == (uint)ImageFileMachine.IA64)
            {
                //Load 64-bit modules for symbol access
                Functions.LoadModules(hProcess, ListModules._64Bit);

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
                StackFrame = Functions.InitializeStackFrame64
                                       (AddressMode.Flat, ContextRecord.StIIP, ContextRecord.IntSp, ContextRecord.RsBSP, ContextRecord.IntSp);
            }
            //Marshal stack frame to unmanaged memory
            IntPtr lpStackFrame = Marshal.AllocHGlobal(Marshal.SizeOf(StackFrame));
            Marshal.StructureToPtr(StackFrame, lpStackFrame, false);

            //Walk the Stack
            for (int frameNum = 0; ; frameNum++)
            {
                //Get Stack frame
                DbgHelp.StackWalk64(ProcessorType, hProcess, hThread, lpStackFrame, lpContextRecord,
                                    null, FunctionTableAccessRoutine, GetModuleBaseRoutine, null);
                StackFrame = (STACKFRAME64)Marshal.PtrToStructure(lpStackFrame, typeof(STACKFRAME64));

                if (StackFrame.AddrReturn.Offset == 0) { break; } //End of stack reached

                StackCalls.Add(new StackCall(hProcess, StackFrame.AddrPC.Offset, StackFrame.AddrReturn.Offset, (int)ThreadId));
            }

            Calls = StackCalls.ToArray();

            //Cleanup
            DbgHelp.SymCleanup(hProcess);
            Marshal.FreeHGlobal(lpStackFrame);
            Marshal.FreeHGlobal(lpContextRecord);
            Kernel32.ResumeThread(hThread);
            Kernel32.CloseHandle(hThread);
            Kernel32.CloseHandle(hProcess);
        }
    }
}
