using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using PowerWalker.Natives;

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
            long ArraySize = cbNeeded / IntPtr.Size;
            IntPtr[] hModules = new IntPtr[ArraySize];
            GCHandle GCh = GCHandle.Alloc(hModules, GCHandleType.Pinned); // Don't forget to free this later
            IntPtr lphModules = GCh.AddrOfPinnedObject();
            uint cb = cbNeeded;
            Psapi.EnumProcessModulesEx(hProcess, lphModules, cb, out cbNeeded, ModuleType);
            for (int i = 0; i < ArraySize; i++)
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
    }
}
