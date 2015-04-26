using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Permissions;

namespace Antivenin
{
    // SafeHandle to call CloseHandle
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    public sealed class SafeWin32Handle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeWin32Handle() : base(true) { }

        public SafeWin32Handle(IntPtr handle)
            : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return Kernel32.CloseHandle(handle);
        }
    }

    public class Kernel32
    {
        private const string Kernel32Lib = "kernel32.dll";

        //OpenProcess
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint ProcessId);

        //OpenThread
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint ThreadId);

        //CloseHandle
        [DllImport(Kernel32Lib, SetLastError = true, PreserveSig = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        //TerminateThread
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateThread(IntPtr hThread, int ExitCode);

        //Wow64SuspendThread
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint Wow64SuspendThread(IntPtr hThread);

        //SuspendThread
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint SuspendThread(IntPtr hThread);

        //ResumeThread
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint ResumeThread(IntPtr hThread);

        //GetThreadContext
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        //Wow64GetThreadContext
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

        //VirtualQuery
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong VirtualQuery(IntPtr lpAddress, MEMORY_BASIC_INFORMATION lpBuffer, ulong dwLength);

        //VirtualQueryEx
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, MEMORY_BASIC_INFORMATION lpBuffer, ulong dwLength);

        //GetNativeSystemInfo
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

        //ReadProcessMemory
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, 
                                                    uint nSize, IntPtr lpNumberOfBytesRead);

        //IsWow64Process
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess, ref bool Wow64Process);
    }

    public class Psapi 
    {
        private const string PsapiLib = "psapi.dll";

        //EnumProcessModulesEx
        [DllImport(PsapiLib, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, out IntPtr hModuleArray, uint cb, 
                                                       IntPtr cbNeeded, uint FilterFlag);
        
        //GetModuleInformation
        [DllImport(PsapiLib, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULE_INFO lpModInfo, uint cb);

        //GetModuleBaseNameW
        [DllImport(PsapiLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule, out IntPtr lpBaseName, uint nSize);

        //GetModuleFileNameExW
        [DllImport(PsapiLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule, out IntPtr lpFilename, uint nSize);
    }

    public class Advapi32
    {
        //GetUserName
        [DllImport("Advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetUserName(System.Text.StringBuilder UserName, ref int nSize);
    }

    public class DbgHelp 
    {
        private const string DbgHelpLib = "dbghelp.dll";

        //ImagehlpApiVersion
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr ImagehlpApiVersion();

        //SymInitialize
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, 
                                                [MarshalAs(UnmanagedType.Bool)] bool InvadeProcess);

        //SymGetOptions
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint SymGetOptions();

        //SymSetOptions
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint SymSetOptions(uint SymOptions);

        //SymCleanup
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymCleanup(IntPtr hProcess);

        //SymFunctionTableAccess64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr SymFunctionTableAccess64(IntPtr hProcess, ulong AddrBase);

        //SymGetModuleBase64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymGetModuleBase64(IntPtr hProcess, ulong dwAddr);

        //SymGetModuleInfo64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetModuleInfo64(IntPtr hProcess, ulong dwAddr, out IMAGEHLP_MODULE64 ModuleInfo);

        //SymGetSymFromAddr64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetSymFromAddr64(IntPtr hProcess, string Name, ref IMAGEHLP_SYMBOL64 Symbol);

        //SymLoadModule64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymLoadModule64(IntPtr hProcess, IntPtr hFile, string ImageName, string ModuleName, 
                                                   ulong BaseOfDll, uint SizeOfDll);

        //SymGetSearchPath
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetSearchPath(IntPtr hProcess, char[] SearchPath, uint SearchPathLength);
        
        //UnDecorateSymbolName
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint UnDecorateSymbolName(string DecoratedName, out IntPtr UnDecorateName, uint UndecoratedLength, 
                                                       uint Flags);

        //StackWalk64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StackWalk64 
        (
            uint                                        MachineType,                    //In
            IntPtr                                      hProcess,                       //In
            IntPtr                                      hThread,                        //In
            IntPtr                                      StackFrame,                     //In_Out
            IntPtr                                      ContextRecord,                  //In_Out
            Helpers.ReadProcessMemoryDelegate           ReadMemoryRoutine,              //_In_opt_
            Helpers.SymFunctionTableAccess64Delegate    FunctionTableAccessRoutine,     //_In_opt_ 
            Helpers.SymGetModuleBase64Delegate          GetModuleBaseRoutine,           //_In_opt_
            Helpers.TranslateAddressProc64Delegate      TranslateAddress                //_In_opt_
        );
    }
  }
