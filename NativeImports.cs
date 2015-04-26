using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Permissions;

namespace Antivenin
{
    #region Functions

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

    #endregion Functions
    #region Enums
    public enum ImageFileMachine : int
    {
        I386 = 0x014c,      
        IA64 = 0x0200,      
        AMD64 = 0x8664,     
    }

    public enum ProcessAccess : int
    {
        VmRead = 0x000010,
        QueryInformation = 0x000400,
        All = 0x1F0FFF
    }

    [Flags]
    public enum ThreadAccess : int
    {
        None = 0,
        AllAccess = 0x1F03FF,
        DirectImpersonation = 0x200,
        GetContext = 0x008,
        Impersonate = 0x100,
        QueryInformation = 0x040,
        QueryLimitedInformation = 0x800,
        SetContext = 0x010,
        SetInformation = 0x020,
        SetLimitedInformation = 0x400,
        SetThreadToken = 0x080,
        SuspendResume = 0x002,
        Terminate = 0x001,
    }

    [Flags]
    public enum ContextFlags
    {
        None = 0,
        X86Context = 0x10000,
        X86ContextControl = X86Context | 0x1,
        X86ContextInteger = X86Context | 0x2,
        X86ContextSegments = X86Context | 0x4,
        X86ContextFloatingPoint = X86Context | 0x8,
        X86ContextDebugRegisters = X86Context | 0x10,
        X86ContextExtendedRegisters = X86Context | 0x20,
        X86ContextFull = X86Context | X86ContextControl | X86ContextInteger | X86ContextSegments,
        X86ContextAll = X86Context | X86ContextControl | X86ContextInteger | X86ContextSegments | X86ContextFloatingPoint |
                            X86ContextDebugRegisters | X86ContextExtendedRegisters,

        AMD64Context = 0x100000,
        AMD64ContextControl = AMD64Context | 0x1,
        AMD64ContextInteger = AMD64Context | 0x2,
        AMD64ContextSegments = AMD64Context | 0x4,
        AMD64ContextFloatingPoint = AMD64Context | 0x8,
        AMD64ContextDebugRegisters = AMD64Context | 0x10,
        AMD64ContextFull = AMD64Context | AMD64ContextControl | AMD64ContextInteger | AMD64ContextFloatingPoint,
        AMD64ContextAll = AMD64Context | AMD64ContextControl | AMD64ContextInteger | AMD64ContextSegments |
                            AMD64ContextFloatingPoint | AMD64ContextDebugRegisters,

        IA64Context = 0x80000,
        IA64ContextControl = IA64Context | 0x1,
        IA64ContextLowerFloatingPoint = IA64Context | 0x2,
        IA64ContextHigherFloatingPoint = IA64Context | 0x4,
        IA64ContextInteger = IA64Context | 0x8,
        IA64ContextDebug = IA64Context | 0x10,
        IA64ContextIA32Control = IA64Context | 0x20,
        IA64ContextFloatingPoint = IA64Context | IA64ContextLowerFloatingPoint | IA64ContextHigherFloatingPoint,
        IA64ContextFull = IA64Context | IA64ContextControl | IA64ContextFloatingPoint | IA64ContextInteger | IA64ContextIA32Control,
        IA64ContextAll = IA64Context | IA64ContextControl | IA64ContextFloatingPoint | IA64ContextInteger |
                            IA64ContextDebug | IA64ContextIA32Control,
    }

    [Flags]
    public enum MemoryPageProtection : uint
    {
        NoAccess = 0x001,
        Readonly = 0x002,
        ReadWrite = 0x004,
        WriteCopy = 0x008,
        Execute = 0x010,
        ExecuteRead = 0x020,
        ExecuteReadWrite = 0x040,
        ExecuteWriteCopy = 0x080,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
    }

    [Flags]
    public enum MemoryPageState : uint
    {
        Commit = 0x01000,
        Free = 0x10000,
        Reserve = 0x02000,
    }

    [Flags]
    public enum MemoryPageType : uint
    {
        Image = 0x1000000,
        Mapped = 0x0040000,
        Private = 0x0020000,
    }

    [Flags]
    public enum IMAGE_SCN : uint
    {
        TYPE_NO_PAD = 0x00000008,               // Reserved.
        CNT_CODE = 0x00000020,                  // Section contains code.
        CNT_INITIALIZED_DATA = 0x00000040,      // Section contains initialized data.
        CNT_UNINITIALIZED_DATA = 0x00000080,    // Section contains uninitialized data.
        LNK_INFO = 0x00000200,                  // Section contains comments or some other type of information.
        LNK_REMOVE = 0x00000800,                // Section contents will not become part of image.
        LNK_COMDAT = 0x00001000,                // Section contents comdat.
        NO_DEFER_SPEC_EXC = 0x00004000,         // Reset speculative exceptions handling bits in the TLB entries for this section.
        GPREL = 0x00008000,                     // Section content can be accessed relative to GP
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,             // Default alignment if no others are specified.
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000,           // Section contains extended relocations.
        MEM_DISCARDABLE = 0x02000000,           // Section can be discarded.
        MEM_NOT_CACHED = 0x04000000,            // Section is not cachable.
        MEM_NOT_PAGED = 0x08000000,             // Section is not pageable.
        MEM_SHARED = 0x10000000,                // Section is shareable.
        MEM_EXECUTE = 0x20000000,               // Section is executable.
        MEM_READ = 0x40000000,                  // Section is readable.
        MEM_WRITE = 0x80000000                  // Section is writeable.
    }

    public enum AddressMode
    {
        _1616,
        _1632,
        Real,
        Flat,
    }

    public enum SymType
    {
        SymNone = 0,
        SymCoff,
        SymCv,
        SymPdb,
        SymExport,
        SymDeferred,
        SymSym,       // .sym file
        SymDia,
        SymVirtual,
        NumSymTypes
    }

    public enum CallstackEntryType : uint 
    { 
        FirstEntry, 
        NextEntry, 
        LastEntry 
    }

    [Flags]
    public enum ListModules : uint
    {
        Default = 0x0,
        _32Bit = 0x01,
        _64Bit = 0x02,
        All = 0x03,
    }

#endregion Enums
    #region Structs

    [StructLayout(LayoutKind.Sequential)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FLOAT128
    {
        long LowPart;
        long HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct X86_CONTEXT
    {
        public uint ContextFlags; //set this to an appropriate value

        // Retrieved by CONTEXT_DEBUG_REGISTERS
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;

        // Retrieved by CONTEXT_FLOATING_POINT
        public FLOATING_SAVE_AREA FloatSave;

        // Retrieved by CONTEXT_SEGMENTS
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;

        // Retrieved by CONTEXT_INTEGER
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;

        // Retrieved by CONTEXT_CONTROL
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;

        // Retrieved by CONTEXT_EXTENDED_REGISTERS
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    [StructLayout(LayoutKind.Explicit, Size = 1232)]
    public struct AMD64_CONTEXT
    {
        // Register Parameter Home Addresses
        [FieldOffset(0x0)]  public ulong P1Home;
        [FieldOffset(0x8)]  public ulong P2Home;
        [FieldOffset(0x10)] public ulong P3Home;
        [FieldOffset(0x18)] public ulong P4Home;
        [FieldOffset(0x20)] public ulong P5Home;
        [FieldOffset(0x28)] public ulong P6Home;

        // Control Flags
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x34)] public uint MxCsr;

        // Segment Registers and Processor Flags
        [FieldOffset(0x38)] public ushort SegCs;
        [FieldOffset(0x3a)] public ushort SegDs;
        [FieldOffset(0x3c)] public ushort SegEs;
        [FieldOffset(0x3e)] public ushort SegFs;
        [FieldOffset(0x40)] public ushort SegGs;
        [FieldOffset(0x42)] public ushort SegSs;
        [FieldOffset(0x44)] public uint   EFlags;

        // Debug Registers
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x58)] public ulong Dr2;
        [FieldOffset(0x60)] public ulong Dr3;
        [FieldOffset(0x68)] public ulong Dr6;
        [FieldOffset(0x70)] public ulong Dr7;

        // Integer Registers
        [FieldOffset(0x78)] public ulong Rax;
        [FieldOffset(0x80)] public ulong Rcx;
        [FieldOffset(0x88)] public ulong Rdx;
        [FieldOffset(0x90)] public ulong Rbx;
        [FieldOffset(0x98)] public ulong Rsp;
        [FieldOffset(0xa0)] public ulong Rbp;
        [FieldOffset(0xa8)] public ulong Rsi;
        [FieldOffset(0xb0)] public ulong Rdi;
        [FieldOffset(0xb8)] public ulong R8;
        [FieldOffset(0xc0)] public ulong R9;
        [FieldOffset(0xc8)] public ulong R10;
        [FieldOffset(0xd0)] public ulong R11;
        [FieldOffset(0xd8)] public ulong R12;
        [FieldOffset(0xe0)] public ulong R13;
        [FieldOffset(0xe8)] public ulong R14;
        [FieldOffset(0xf0)] public ulong R15;

        // Program Counter
        [FieldOffset(0xf8)] public ulong Rip;

        // Floating Point State
        [FieldOffset(0x100)] public ulong FltSave;
        [FieldOffset(0x120)] public ulong Legacy;
        [FieldOffset(0x1a0)] public ulong Xmm0;
        [FieldOffset(0x1b0)] public ulong Xmm1;
        [FieldOffset(0x1c0)] public ulong Xmm2;
        [FieldOffset(0x1d0)] public ulong Xmm3;
        [FieldOffset(0x1e0)] public ulong Xmm4;
        [FieldOffset(0x1f0)] public ulong Xmm5;
        [FieldOffset(0x200)] public ulong Xmm6;
        [FieldOffset(0x210)] public ulong Xmm7;
        [FieldOffset(0x220)] public ulong Xmm8;
        [FieldOffset(0x230)] public ulong Xmm9;
        [FieldOffset(0x240)] public ulong Xmm10;
        [FieldOffset(0x250)] public ulong Xmm11;
        [FieldOffset(0x260)] public ulong Xmm12;
        [FieldOffset(0x270)] public ulong Xmm13;
        [FieldOffset(0x280)] public ulong Xmm14;
        [FieldOffset(0x290)] public ulong Xmm15;

        // Vector Registers
        [FieldOffset(0x300)] public ulong VectorRegister;
        [FieldOffset(0x4a0)] public ulong VectorControl;

        // Special Debug Control Registers
        [FieldOffset(0x4a8)] public ulong DebugControl;
        [FieldOffset(0x4b0)] public ulong LastBranchToRip;
        [FieldOffset(0x4b8)] public ulong LastBranchFromRip;
        [FieldOffset(0x4c0)] public ulong LastExceptionToRip;
        [FieldOffset(0x4c8)] public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Explicit, Size = 2672)]
    public struct IA64_CONTEXT
    {
        [FieldOffset(0x000)] public ulong ContextFlags;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_DEBUG.
        [FieldOffset(0x010)] public ulong DbI0;
        [FieldOffset(0x018)] public ulong DbI1;
        [FieldOffset(0x020)] public ulong DbI2;
        [FieldOffset(0x028)] public ulong DbI3;
        [FieldOffset(0x030)] public ulong DbI4;
        [FieldOffset(0x038)] public ulong DbI5;
        [FieldOffset(0x040)] public ulong DbI6;
        [FieldOffset(0x048)] public ulong DbI7;

        [FieldOffset(0x050)] public ulong DbD0;
        [FieldOffset(0x058)] public ulong DbD1;
        [FieldOffset(0x060)] public ulong DbD2;
        [FieldOffset(0x068)] public ulong DbD3;
        [FieldOffset(0x070)] public ulong DbD4;
        [FieldOffset(0x078)] public ulong DbD5;
        [FieldOffset(0x080)] public ulong DbD6;
        [FieldOffset(0x088)] public ulong DbD7;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_LOWER_FLOATING_POINT.
        [FieldOffset(0x090)] public FLOAT128 FltS0;
        [FieldOffset(0x0a0)] public FLOAT128 FltS1;
        [FieldOffset(0x0b0)] public FLOAT128 FltS2;
        [FieldOffset(0x0c0)] public FLOAT128 FltS3;

        [FieldOffset(0x0d0)] public FLOAT128 FltT0;
        [FieldOffset(0x0e0)] public FLOAT128 FltT1;
        [FieldOffset(0x0f0)] public FLOAT128 FltT2;
        [FieldOffset(0x100)] public FLOAT128 FltT3;
        [FieldOffset(0x110)] public FLOAT128 FltT4;
        [FieldOffset(0x120)] public FLOAT128 FltT5;
        [FieldOffset(0x130)] public FLOAT128 FltT6;
        [FieldOffset(0x140)] public FLOAT128 FltT7;
        [FieldOffset(0x150)] public FLOAT128 FltT8;
        [FieldOffset(0x160)] public FLOAT128 FltT9;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_HIGHER_FLOATING_POINT.
        [FieldOffset(0x170)] public FLOAT128 FltS4;
        [FieldOffset(0x180)] public FLOAT128 FltS5;
        [FieldOffset(0x190)] public FLOAT128 FltS6;
        [FieldOffset(0x1a0)] public FLOAT128 FltS7;
        [FieldOffset(0x1b0)] public FLOAT128 FltS8;
        [FieldOffset(0x1c0)] public FLOAT128 FltS9;
        [FieldOffset(0x1d0)] public FLOAT128 FltS10;
        [FieldOffset(0x1e0)] public FLOAT128 FltS11;
        [FieldOffset(0x1f0)] public FLOAT128 FltS12;
        [FieldOffset(0x200)] public FLOAT128 FltS13;
        [FieldOffset(0x210)] public FLOAT128 FltS14;
        [FieldOffset(0x220)] public FLOAT128 FltS15;
        [FieldOffset(0x230)] public FLOAT128 FltS16;
        [FieldOffset(0x240)] public FLOAT128 FltS17;
        [FieldOffset(0x250)] public FLOAT128 FltS18;
        [FieldOffset(0x260)] public FLOAT128 FltS19;
            
        [FieldOffset(0x270)] public FLOAT128 FltF32;
        [FieldOffset(0x280)] public FLOAT128 FltF33;
        [FieldOffset(0x290)] public FLOAT128 FltF34;
        [FieldOffset(0x2a0)] public FLOAT128 FltF35;
        [FieldOffset(0x2b0)] public FLOAT128 FltF36;
        [FieldOffset(0x2c0)] public FLOAT128 FltF37;
        [FieldOffset(0x2d0)] public FLOAT128 FltF38;
        [FieldOffset(0x2e0)] public FLOAT128 FltF39;
        [FieldOffset(0x2f0)] public FLOAT128 FltF40;
        [FieldOffset(0x300)] public FLOAT128 FltF41;
        [FieldOffset(0x310)] public FLOAT128 FltF42;
        [FieldOffset(0x320)] public FLOAT128 FltF43;
        [FieldOffset(0x330)] public FLOAT128 FltF44;
        [FieldOffset(0x340)] public FLOAT128 FltF45;
        [FieldOffset(0x350)] public FLOAT128 FltF46;
        [FieldOffset(0x360)] public FLOAT128 FltF47;
        [FieldOffset(0x370)] public FLOAT128 FltF48;
        [FieldOffset(0x380)] public FLOAT128 FltF49;
        [FieldOffset(0x390)] public FLOAT128 FltF50;
        [FieldOffset(0x3a0)] public FLOAT128 FltF51;
        [FieldOffset(0x3b0)] public FLOAT128 FltF52;
        [FieldOffset(0x3c0)] public FLOAT128 FltF53;
        [FieldOffset(0x3d0)] public FLOAT128 FltF54;
        [FieldOffset(0x3e0)] public FLOAT128 FltF55;
        [FieldOffset(0x3f0)] public FLOAT128 FltF56;
        [FieldOffset(0x400)] public FLOAT128 FltF57;
        [FieldOffset(0x410)] public FLOAT128 FltF58;
        [FieldOffset(0x420)] public FLOAT128 FltF59;
        [FieldOffset(0x430)] public FLOAT128 FltF60;
        [FieldOffset(0x440)] public FLOAT128 FltF61;
        [FieldOffset(0x450)] public FLOAT128 FltF62;
        [FieldOffset(0x460)] public FLOAT128 FltF63;
        [FieldOffset(0x470)] public FLOAT128 FltF64;
        [FieldOffset(0x480)] public FLOAT128 FltF65;
        [FieldOffset(0x490)] public FLOAT128 FltF66;
        [FieldOffset(0x4a0)] public FLOAT128 FltF67;
        [FieldOffset(0x4b0)] public FLOAT128 FltF68;
        [FieldOffset(0x4c0)] public FLOAT128 FltF69;
        [FieldOffset(0x4d0)] public FLOAT128 FltF70;
        [FieldOffset(0x4e0)] public FLOAT128 FltF71;
        [FieldOffset(0x4f0)] public FLOAT128 FltF72;
        [FieldOffset(0x500)] public FLOAT128 FltF73;
        [FieldOffset(0x510)] public FLOAT128 FltF74;
        [FieldOffset(0x520)] public FLOAT128 FltF75;
        [FieldOffset(0x530)] public FLOAT128 FltF76;
        [FieldOffset(0x540)] public FLOAT128 FltF77;
        [FieldOffset(0x550)] public FLOAT128 FltF78;
        [FieldOffset(0x560)] public FLOAT128 FltF79;
        [FieldOffset(0x570)] public FLOAT128 FltF80;
        [FieldOffset(0x580)] public FLOAT128 FltF81;
        [FieldOffset(0x590)] public FLOAT128 FltF82;
        [FieldOffset(0x5a0)] public FLOAT128 FltF83;
        [FieldOffset(0x5b0)] public FLOAT128 FltF84;
        [FieldOffset(0x5c0)] public FLOAT128 FltF85;
        [FieldOffset(0x5d0)] public FLOAT128 FltF86;
        [FieldOffset(0x5e0)] public FLOAT128 FltF87;
        [FieldOffset(0x5f0)] public FLOAT128 FltF88;
        [FieldOffset(0x600)] public FLOAT128 FltF89;
        [FieldOffset(0x610)] public FLOAT128 FltF90;
        [FieldOffset(0x620)] public FLOAT128 FltF91;
        [FieldOffset(0x630)] public FLOAT128 FltF92;
        [FieldOffset(0x640)] public FLOAT128 FltF93;
        [FieldOffset(0x650)] public FLOAT128 FltF94;
        [FieldOffset(0x660)] public FLOAT128 FltF95;
        [FieldOffset(0x670)] public FLOAT128 FltF96;
        [FieldOffset(0x680)] public FLOAT128 FltF97;
        [FieldOffset(0x690)] public FLOAT128 FltF98;
        [FieldOffset(0x6a0)] public FLOAT128 FltF99;
        [FieldOffset(0x6b0)] public FLOAT128 FltF100;
        [FieldOffset(0x6c0)] public FLOAT128 FltF101;
        [FieldOffset(0x6d0)] public FLOAT128 FltF102;
        [FieldOffset(0x6e0)] public FLOAT128 FltF103;
        [FieldOffset(0x6f0)] public FLOAT128 FltF104;
        [FieldOffset(0x700)] public FLOAT128 FltF105;
        [FieldOffset(0x710)] public FLOAT128 FltF106;
        [FieldOffset(0x720)] public FLOAT128 FltF107;
        [FieldOffset(0x730)] public FLOAT128 FltF108;
        [FieldOffset(0x740)] public FLOAT128 FltF109;
        [FieldOffset(0x750)] public FLOAT128 FltF110;
        [FieldOffset(0x760)] public FLOAT128 FltF111;
        [FieldOffset(0x770)] public FLOAT128 FltF112;
        [FieldOffset(0x780)] public FLOAT128 FltF113;
        [FieldOffset(0x790)] public FLOAT128 FltF114;
        [FieldOffset(0x7a0)] public FLOAT128 FltF115;
        [FieldOffset(0x7b0)] public FLOAT128 FltF116;
        [FieldOffset(0x7c0)] public FLOAT128 FltF117;
        [FieldOffset(0x7d0)] public FLOAT128 FltF118;
        [FieldOffset(0x7e0)] public FLOAT128 FltF119;
        [FieldOffset(0x7f0)] public FLOAT128 FltF120;
        [FieldOffset(0x800)] public FLOAT128 FltF121;
        [FieldOffset(0x810)] public FLOAT128 FltF122;
        [FieldOffset(0x820)] public FLOAT128 FltF123;
        [FieldOffset(0x830)] public FLOAT128 FltF124;
        [FieldOffset(0x840)] public FLOAT128 FltF125;
        [FieldOffset(0x850)] public FLOAT128 FltF126;
        [FieldOffset(0x860)] public FLOAT128 FltF127;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL.
        [FieldOffset(0x870)] public UInt64 publicStFPSR;     //  FP status

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_INTEGER.
        [FieldOffset(0x870)] public ulong IntGp;      //  r1 = 0x, volatile
        [FieldOffset(0x880)] public ulong IntT0;      //  r2-r3 = 0x; volatile
        [FieldOffset(0x888)] public ulong IntT1;      //
        [FieldOffset(0x890)] public ulong IntS0;      //  r4-r7 = 0x; preserved
        [FieldOffset(0x898)] public ulong IntS1;
        [FieldOffset(0x8a0)] public ulong IntS2;
        [FieldOffset(0x8a8)] public ulong IntS3;
        [FieldOffset(0x8b0)] public ulong IntV0;      //  r8 = 0x; volatile
        [FieldOffset(0x8b8)] public ulong IntT2;      //  r9-r11 = 0x; volatile
        [FieldOffset(0x8c0)] public ulong IntT3;
        [FieldOffset(0x8c8)] public ulong IntT4;
        [FieldOffset(0x8d0)] public ulong IntSp;      //  stack pointer (r12) = 0x; special
        [FieldOffset(0x8d8)] public ulong IntTeb;     //  teb (r13) = 0x; special
        [FieldOffset(0x8e0)] public ulong IntT5;      //  r14-r31 = 0x; volatile
        [FieldOffset(0x8e8)] public ulong IntT6;
        [FieldOffset(0x8f0)] public ulong IntT7;
        [FieldOffset(0x8f8)] public ulong IntT8;
        [FieldOffset(0x900)] public ulong IntT9;
        [FieldOffset(0x908)] public ulong IntT10;
        [FieldOffset(0x910)] public ulong IntT11;
        [FieldOffset(0x918)] public ulong IntT12;
        [FieldOffset(0x920)] public ulong IntT13;
        [FieldOffset(0x928)] public ulong IntT14;
        [FieldOffset(0x930)] public ulong IntT15;
        [FieldOffset(0x938)] public ulong IntT16;
        [FieldOffset(0x940)] public ulong IntT17;
        [FieldOffset(0x948)] public ulong IntT18;
        [FieldOffset(0x950)] public ulong IntT19;
        [FieldOffset(0x958)] public ulong IntT20;
        [FieldOffset(0x960)] public ulong IntT21;
        [FieldOffset(0x968)] public ulong IntT22;
        [FieldOffset(0x970)] public ulong IntNats;    //  Nat bits for r1-r31
        //  r1-r31 in bits 1 thru 31.

        [FieldOffset(0x978)] public ulong Preds;      //  predicates = 0x; preserved

        [FieldOffset(0x980)] public ulong BrRp;       //  return pointer = 0x; b0 = 0x; preserved
        [FieldOffset(0x988)] public ulong BrS0;       //  b1-b5 = 0x; preserved
        [FieldOffset(0x990)] public ulong BrS1;
        [FieldOffset(0x998)] public ulong BrS2;
        [FieldOffset(0x9a0)] public ulong BrS3;
        [FieldOffset(0x9a8)] public ulong BrS4;
        [FieldOffset(0x9b0)] public ulong BrT0;       //  b6-b7 = 0x; volatile
        [FieldOffset(0x9b8)] public ulong BrT1;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_CONTROL.

        // Other application registers
        [FieldOffset(0x9c0)] public ulong ApUNAT;     //  User Nat collection register = 0x; preserved
        [FieldOffset(0x9c8)] public ulong ApLC;       //  Loop counter register = 0x; preserved
        [FieldOffset(0x9d0)] public ulong ApEC;       //  Epilog counter register = 0x; preserved
        [FieldOffset(0x9d8)] public ulong ApCCV;      //  CMPXCHG value register = 0x; volatile
        [FieldOffset(0x9e0)] public ulong ApDCR;      //  Default control register (TBD)

        // Register stack info
        [FieldOffset(0x9e8)] public ulong RsPFS;      //  Previous function state = 0x; preserved
        [FieldOffset(0x9f0)] public ulong RsBSP;      //  Backing store pointer = 0x; preserved
        [FieldOffset(0x9f8)] public ulong RsBSPSTORE;
        [FieldOffset(0xa00)] public ulong RsRSC;      //  RSE configuration = 0x; volatile
        [FieldOffset(0xa08)] public ulong RsRNAT;     //  RSE Nat collection register = 0x; preserved

        // Trap Status Information
        [FieldOffset(0xa10)] public ulong StIPSR;     //  Interruption Processor Status
        [FieldOffset(0xa18)] public ulong StIIP;      //  Interruption IP
        [FieldOffset(0xa20)] public ulong StIFS;      //  Interruption Function State

        // iA32 related control registers
        [FieldOffset(0xa28)] public ulong StFCR;      //  copy of Ar21
        [FieldOffset(0xa30)] public ulong Eflag;      //  Eflag copy of Ar24
        [FieldOffset(0xa38)] public ulong SegCSD;     //  iA32 CSDescriptor (Ar25)
        [FieldOffset(0xa40)] public ulong SegSSD;     //  iA32 SSDescriptor (Ar26)
        [FieldOffset(0xa48)] public ulong Cflag;      //  Cr0+Cr4 copy of Ar27
        [FieldOffset(0xa50)] public ulong StFSR;      //  x86 FP status (copy of AR28)
        [FieldOffset(0xa58)] public ulong StFIR;      //  x86 FP status (copy of AR29)
        [FieldOffset(0xa60)] public ulong StFDR;      //  x86 FP status (copy of AR30)
        [FieldOffset(0xa68)] public ulong UNUSEDPACK; // alignment padding
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULE_INFO
    {
        public IntPtr   lpBaseOfDll;
        public uint     SizeOfImage;
        public IntPtr   EntryPoint;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KDHELP64
    {
        public ulong    Thread;
        public uint     ThCallbackStack;
        public uint     ThCallbackBStore;
        public uint     NextCallback;
        public uint     FramePointer;
        public ulong    KiCallUserMode;
        public ulong    KeUserCallbackDispatcher;
        public ulong    SystemRangeStart;
        public ulong    KiUserExceptionDispatcher;
        public ulong    StackBase;
        public ulong    StackLimit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public ulong[]  Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ADDRESS64
    {
        public ulong       Offset;
        public ushort      Segment;
        public AddressMode Mode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STACKFRAME64
    {
        public ADDRESS64    AddrPC;           //Program Counter EIP, RIP
        public ADDRESS64    AddrReturn;       //Return Address
        public ADDRESS64    AddrFrame;        //Frame Pointer EBP, RBP or RDI
        public ADDRESS64    AddrStack;        //Stack Pointer ESP, RSP
        public ADDRESS64    AddrBStore;       //IA64 Backing Store RsBSP
        public IntPtr       FuncTableEntry;   //x86 = FPO_DATA struct, if none = NULL
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ulong[]      Params;           //possible arguments to the function
        public bool         Far;              //TRUE if this is a WOW far call
        public bool         Virtual;          //TRUE if this is a virtual frame
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public ulong[]      Reserved;         //used internally by StackWalk64
        public KDHELP64     KdHelp;           //specifies helper data for walking kernel callback frames
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FPO_DATA 
    {
        public uint     ulOffStart;
        public uint     cbProcSize;
        public uint     cdwLocals;
        public ushort   cdwParams;
        private ushort  raw_bytes;
        public int      cbProlog { get { return (int)(raw_bytes & 0xFF00) >> 8; } }
        public int      cbRegs { get { return (int)(raw_bytes & 0x00E0) >> 5; } }
        public int      fHasSEH { get { return (int)(raw_bytes & 0x0010) >> 4; } }
        public int      fUseBP { get { return (int)(raw_bytes & 0x0008) >> 3; } }
        public int      reserved { get { return (int)(raw_bytes & 0x0004) >> 2; } }
        public int      cbFrame { get { return (int)(raw_bytes & 0x0003); } }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct GUID
    {
        uint Data1;
        ushort Data2;
        ushort Data3;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        byte[] Data4;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGEHLP_MODULE64 {
        uint            SizeOfStruct;
        ulong           BaseOfImage;
        uint            ImageSize;
        uint            TimeDateStamp;
        uint            CheckSum;
        uint            NumSyms;
        SymType         SymType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        char[]          ModuleName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        char[]          ImageName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        char[]          LoadedImageName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        char[]          LoadedPdbName;
        uint            CVSig;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260*3)]
        char[]          CVData;
        uint            PdbSig;
        GUID            PdbSig70;
        uint            PdbAge;
        bool            PdbUnmatched;
        bool            DbgUnmatched;
        bool            LineNumbers;
        bool            GlobalSymbols;
        bool            TypeInfo;
        bool            SourceIndexed;
        bool            Publics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGEHLP_SYMBOL64 {
        uint    SizeOfStruct;           // set to sizeof(IMAGEHLP_SYMBOLW64)
        ulong   Address;                // virtual address including dll base address
        uint    Size;                   // estimated size of symbol, can be zero
        uint    Flags;                  // info about the symbols, see the SYMF defines
        uint    MaxNameLength;          // maximum size of symbol name in 'Name'
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        char[]  Name;                   // symbol name (null terminated string)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CallstackEntry
    {
        ulong   Offset;  // 0 = invalid entry
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  Name;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  UndecoratedName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  UndecoratedFullName;
        ulong   OffsetFromSmybol;
        uint    OffsetFromLine;
        uint    LineNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  LineFileName;
        uint    SymType;
        string  SymTypeString;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  ModuleName;
        ulong   BaseOfImage;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        char[]  LoadedImageName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct API_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ushort Revision;
        public ushort Reserved;
    }

    //Extracted from ntdll with WinDbg
    [StructLayout(LayoutKind.Explicit)]
    public struct NT_TIB
    {
        [FieldOffset(0x000)] public IntPtr ExceptionList;          // Ptr64 _EXCEPTION_REGISTRATION_RECORD
        [FieldOffset(0x008)] public IntPtr StackBase;              // Ptr64 Void
        [FieldOffset(0x010)] public IntPtr StackLimit;             // Ptr64 Void
        [FieldOffset(0x018)] public IntPtr SubSystemTib;           // Ptr64 Void
        [FieldOffset(0x020)] public IntPtr FiberData;              // Ptr64 Void
        [FieldOffset(0x020)] public uint   Version;                // Uint4B
        [FieldOffset(0x028)] public IntPtr ArbitraryUserPointer;   // Ptr64 Void
        [FieldOffset(0x030)] public IntPtr Self;                   // Ptr64 _NT_TIB
    }
    
    #endregion Structs
    
    public class Constants
    {
        public const uint MAX_NAMELEN                    = 0x00000400;
        public const uint SYMOPT_CASE_INSENSITIVE        = 0x00000001;
        public const uint SYMOPT_UNDNAME                 = 0x00000002;
        public const uint SYMOPT_DEFERRED_LOADS          = 0x00000004;
        public const uint SYMOPT_NO_CPP                  = 0x00000008;
        public const uint SYMOPT_LOAD_LINES              = 0x00000010;
        public const uint SYMOPT_OMAP_FIND_NEAREST       = 0x00000020;
        public const uint SYMOPT_LOAD_ANYTHING           = 0x00000040;
        public const uint SYMOPT_IGNORE_CVREC            = 0x00000080;
        public const uint SYMOPT_NO_UNQUALIFIED_LOADS    = 0x00000100;
        public const uint SYMOPT_FAIL_CRITICAL_ERRORS    = 0x00000200;
        public const uint SYMOPT_EXACT_SYMBOLS           = 0x00000400;
        public const uint SYMOPT_ALLOW_ABSOLUTE_SYMBOLS  = 0x00000800;
        public const uint SYMOPT_IGNORE_NT_SYMPATH       = 0x00001000;
        public const uint SYMOPT_INCLUDE_32BIT_MODULES   = 0x00002000;
        public const uint SYMOPT_PUBLICS_ONLY            = 0x00004000;
        public const uint SYMOPT_NO_PUBLICS              = 0x00008000;
        public const uint SYMOPT_AUTO_PUBLICS            = 0x00010000;
        public const uint SYMOPT_NO_IMAGE_SEARCH         = 0x00020000;
        public const uint SYMOPT_SECURE                  = 0x00040000;
        public const uint SYMOPT_DEBUG                   = 0x80000000;
        public const uint UNDNAME_COMPLETE               = 0x00000000;      // Enable full undecoration
        public const uint UNDNAME_NAME_ONLY              = 0x00001000;      // Crack only the name for primary declaration;
    }
}
