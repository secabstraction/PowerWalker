function Get-StackTrace {
<#
.SYNOPSIS

A bunch of API calls for walking thread stacks.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>
    $Mod = New-InMemoryModule -ModuleName PowerWalker

    #########
    # ENUMS #
    #########

    $ImageFileMachine = 
    psenum $Mod ImageFileMachine Int32 @{
        I386 =  0x014c
        IA64 =  0x0200
        AMD64 = 0x8664
    }

    $ProcessAccess = 
    psenum $Mod ProcessAccess Int32 @{
        None = 0
        Terminate =               0x000001
        CreateThread =            0x000002
        VmRead =                  0x000010
        VmWrite =                 0x000020
        CreateProcess =           0x000080
        QueryInformation =        0x000400
        QueryLimitedInformation = 0x001000
        All =                     0x1F0FFF
    }

    $ThreadAccess = 
    psenum $Mod ThreadAccess Int32 @{
        None = 0
        Terminate =               0x000001
        SuspendResume =           0x000002
        GetContext =              0x000008
        SetContext =              0x000010
        SetInformation =          0x000020
        QueryInformation =        0x000040
        SetThreadToken =          0x000080
        Impersonate =             0x000100
        DirectImpersonation =     0x000200
        SetLimitedInformation =   0x000400
        QueryLimitedInformation = 0x000800
        All =                     0x1F03FF
    }

    $X86ContextFlags = 
    psenum $Mod X86ContextFlags UInt32 @{
        None = 0
        Context =           0x10000
        Control =           0x10001
        Integer =           0x10002
        Segments =          0x10004
        FloatingPoint =     0x10008
        DebugRegisters =    0x10010
        ExtendedRegisters = 0x10020
        Full =              0x10007
        All =               0x1003F
    }
    
    $AMD64ContextFlags = 
    psenum $Mod AMD64ContextFlags UInt32 @{   
        None = 0
        Context =        0x100000
        Control =        0x100001
        Integer =        0x100002
        Segments =       0x100004
        FloatingPoint =  0x100008
        DebugRegisters = 0x100010
        Full =           0x10000B
        All =            0x10003B
    }
    
    $IA64ContextFlags = 
    psenum $Mod IA64ContextFlags UInt64 @{    
        None = 0
        Context =             0x80000
        Control =             0x80001
        LowerFloatingPoint =  0x80002
        HigherFloatingPoint = 0x80004
        Integer =             0x80008
        DebugRegisters =      0x80010
        IA32Control =         0x80020
        FloatingPoint =       0x80006
        Full =                0x8002D
        All =                 0x8003D
    }

    $AddressMode = 
    psenum $Mod AddressMode UInt32 @{
        _1616 = 0
        _1632 = 1
        _Real = 2
        _Flat = 3
    }

    $ListModules = 
    psenum $Mod ListModules UInt32 @{
        Default = 0
        _32Bit =  1
        _64Bit =  2
        All =     3
    }

    $ProcessorArch = 
    psenum $Mod ProcessorArch UInt16 @{
        INTEL =   0
        MIPS =    1
        ALPHA =   2
        PPC =     3
        SHX =     4
        ARM =     5
        IA64 =    6
        ALPHA64 = 7
        AMD64 =   9
        UNKNOWN = 0xFFFF
    }

    ###########
    # STRUCTS #
    ###########

    $MODULE_INFO = 
    struct $Mod MODULE_INFO @{
        lpBaseOfDll = field 0 IntPtr
        SizeOfImage = field 1 UInt32
        EntryPoint = field 2 IntPtr
    }

    $SYSTEM_INFO = 
    struct $Mod SYSTEM_INFO @{
        ProcessorArchitecture = field 0 $ProcessorArch
        Reserved = field 1 Int16
        PageSize = field 2 Int32
        MinimumApplicationAddress = field 3 IntPtr
        MaximumApplicationAddress = field 4 IntPtr
        ActiveProcessorMask = field 5 IntPtr
        NumberOfProcessors = field 6 Int32
        ProcessorType = field 7 Int32
        AllocationGranularity = field 8 Int32
        ProcessorLevel = field 9 Int16
        ProcessorRevision = field 10 Int16
    }

    $FLOAT128 = 
    struct $Mod FLOAT128 @{
        LowPart =  field 0 Int64
        HighPart = field 1 Int64
    }

    $FLOATING_SAVE_AREA = 
    struct $Mod FLOATING_SAVE_AREA @{
        ControlWord =   field 0 UInt32
        StatusWord =    field 1 UInt32
        TagWord =       field 2 UInt32
        ErrorOffset =   field 3 UInt32
        ErrorSelector = field 4 UInt32
        DataOffset =    field 5 UInt32
        DataSelector =  field 6 UInt32
        RegisterArea =  field 7 Byte[] -MarshalAs @('ByValArray', 80)
        Cr0NpxState =   field 8 UInt32
    }

    $X86_CONTEXT = 
    struct $Mod X86_CONTEXT @{
        
        ContextFlags = field 0 UInt32 #set this to an appropriate value
        
        # Retrieved by CONTEXT_DEBUG_REGISTERS
        Dr0 = field 1 UInt32
        Dr1 = field 2 UInt32
        Dr2 = field 3 UInt32
        Dr3 = field 4 UInt32
        Dr6 = field 5 UInt32
        Dr7 = field 6 UInt32
        
        # Retrieved by CONTEXT_FLOATING_POINT
        FloatSave = field 7 $FLOATING_SAVE_AREA
        
        # Retrieved by CONTEXT_SEGMENTS
        SegGs = field 8 UInt32
        SegFs = field 9 UInt32
        SegEs = field 10 UInt32
        SegDs = field 11 UInt32
        
        # Retrieved by CONTEXT_INTEGER
        Edi = field 12 UInt32
        Esi = field 13 UInt32
        Ebx = field 14 UInt32
        Edx = field 15 UInt32
        Ecx = field 16 UInt32
        Eax = field 17 UInt32
        
        # Retrieved by CONTEXT_CONTROL
        Ebp =    field 18 UInt32
        Eip =    field 19 UInt32
        SegCs =  field 20 UInt32
        EFlags = field 21 UInt32
        Esp =    field 22 UInt32
        SegSs =  field 23 UInt32

        #Retrieved by CONTEXT_EXTENDED_REGISTERS
        ExtendedRegisters = field 24 Byte[] -MarshalAs @('ByValArray', 512)
    }

    $AMD64_CONTEXT = 
    struct $Mod AMD64_CONTEXT -ExplicitLayout @{
        
        # Register Parameter Home Addresses
        P1Home = field 0 UInt64 -Offset 0x0
        P2Home = field 1 UInt64 -Offset 0x8
        P3Home = field 2 UInt64 -Offset 0x10
        P4Home = field 3 UInt64 -Offset 0x18
        P5Home = field 4 UInt64 -Offset 0x20
        P6Home = field 5 UInt64 -Offset 0x28

        # Control Flags
        ContextFlags = field 6 UInt32 -Offset 0x30
        MxCsr =        field 7 UInt32 -Offset 0x34

        # Segment Registers and Processor Flags
        SegCs =  field 8 UInt16 -Offset 0x38
        SegDs =  field 9 UInt16 -Offset 0x3a
        SegEs =  field 10 UInt16 -Offset 0x3c
        SegFs =  field 11 UInt16 -Offset 0x3e
        SegGs =  field 12 UInt16 -Offset 0x40
        SegSs =  field 13 UInt16 -Offset 0x42
        EFlags = field 14 UInt32 -Offset 0x44

        # Debug Registers
        Dr0 = field 15 UInt64 -Offset 0x48
        Dr1 = field 16 UInt64 -Offset 0x50
        Dr2 = field 17 UInt64 -Offset 0x58
        Dr3 = field 18 UInt64 -Offset 0x60
        Dr6 = field 19 UInt64 -Offset 0x68
        Dr7 = field 20 UInt64 -Offset 0x70

        # Integer Registers
        Rax = field 21 UInt64 -Offset 0x78
        Rcx = field 22 UInt64 -Offset 0x80
        Rdx = field 23 UInt64 -Offset 0x88
        Rbx = field 24 UInt64 -Offset 0x90
        Rsp = field 25 UInt64 -Offset 0x98
        Rbp = field 26 UInt64 -Offset 0xa0
        Rsi = field 27 UInt64 -Offset 0xa8
        Rdi = field 28 UInt64 -Offset 0xb0
        R8 =  field 29 UInt64 -Offset 0xb8
        R9 =  field 30 UInt64 -Offset 0xc0
        R10 = field 31 UInt64 -Offset 0xc8
        R11 = field 31 UInt64 -Offset 0xd0
        R12 = field 32 UInt64 -Offset 0xd8
        R13 = field 33 UInt64 -Offset 0xe0
        R14 = field 34 UInt64 -Offset 0xe8
        R15 = field 35 UInt64 -Offset 0xf0

        # Program Counter
        Rip = field 36 UInt64 -Offset 0xf8

        # Floating Point State
        FltSave = field 36 UInt64 -Offset 0x100
        Legacy = field 37 UInt64 -Offset 0x120
        Xmm0  = field 38 UInt64 -Offset 0x1a0
        Xmm1  = field 39 UInt64 -Offset 0x1b0
        Xmm2  = field 40 UInt64 -Offset 0x1c0
        Xmm3  = field 41 UInt64 -Offset 0x1d0
        Xmm4  = field 42 UInt64 -Offset 0x1e0
        Xmm5  = field 43 UInt64 -Offset 0x1f0
        Xmm6  = field 44 UInt64 -Offset 0x200
        Xmm7  = field 45 UInt64 -Offset 0x210
        Xmm8  = field 46 UInt64 -Offset 0x220
        Xmm9  = field 47 UInt64 -Offset 0x230
        Xmm10 = field 48 UInt64 -Offset 0x240
        Xmm11 = field 49 UInt64 -Offset 0x250
        Xmm12 = field 50 UInt64 -Offset 0x260
        Xmm13 = field 51 UInt64 -Offset 0x270
        Xmm14 = field 52 UInt64 -Offset 0x280
        Xmm15 = field 53 UInt64 -Offset 0x290

        # Vector Registers
        VectorRegister = field 54 UInt64 -Offset 0x300
        VectorControl = field 55 UInt64 -Offset 0x4a0

        # Special Debug Control Registers
        DebugControl = field 56 UInt64 -Offset 0x4a8
        LastBranchToRip = field 57 UInt64 -Offset 0x4b0
        LastBranchFromRip = field 58 UInt64 -Offset 0x4b8
        LastExceptionToRip = field 59 UInt64 -Offset 0x4c0
        LastExceptionFromRip = field 60 UInt64 -Offset 0x4c8
    }

    ###########
    # IMPORTS #
    ###########

    $FunctionDefinitions = @(
        #Kernel32
        (func kernel32 OpenProcess ([IntPtr]) @([ProcessAccess], [Bool], [UInt32]) -SetLastError),
        (func kernel32 OpenThread ([IntPtr]) @([ThreadAccess], [Bool], [UInt32]) -SetLastError),
        (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
        (func kernel32 Wow64SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 ResumeThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 Wow64GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
        (func kernel32 GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
        (func kernel32 GetNativeSystemInfo ([Void]) @([SYSTEM_INFO].MakeByRefType()) -SetLastError),
        (func kernel32 IsWow64Process ([Bool]) @([IntPtr], [Bool].MakeByRefType()) -SetLastError),

        #Psapi
        (func psapi EnumProcessModulesEx ([Bool]) @([IntPtr], [IntPtr].MakeByRefType(), [UInt32], [UInt32].MakeByRefType(), [ListModules]) -SetLastError),
        (func psapi GetModuleInformation ([Bool]) @([IntPtr], [IntPtr], [MODULE_INFO].MakeByRefType(), [UInt32]) -SetLastError), 
        (func psapi GetModuleBaseNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [UInt32]) -Charset Unicode -SetLastError),
        (func psapi GetModuleFileNameExW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [UInt32]) -Charset Unicode -SetLastError),
        (func psapi GetMappedFileNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [UInt32]) -Charset Unicode -SetLastError),

        #DbgHelp
        (func dbghelp SymInitialize ([Bool]) @([IntPtr], [String], [Bool]) -SetLastError),
        (func dbghelp SymCleanup ([Bool]) @([IntPtr]) -SetLastError),
        (func dbghelp SymFunctionTableAccess64 ([IntPtr]) @([IntPtr], [UInt64]) -SetLastError),
        (func dbghelp SymGetModuleBase64 ([UInt64]) @([IntPtr], [UInt64]) -SetLastError),
        (func dbghelp SymGetSymFromAddr64 ([Bool]) @([IntPtr], [UInt64], [UInt64].MakeByRefType(), [IntPtr]) -SetLastError),
        (func dbghelp SymLoadModuleEx ([UInt64]) @([IntPtr], [IntPtr], [String], [String], [IntPtr], [Int32], [IntPtr], [Int32]) -SetLastError),
        (func dbghelp StackWalk64 ([Bool]) @([UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate]))
    )
    $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'    

    $Kernel32 = [Win32.kernel32]
    $Psapi = [Win32.psapi]
    $Dbghelp = [Win32.dbghelp]

    #StackWalk64 Callback Delegates
    $SymFunctionTableAccess64Delegate = [Func[IntPtr, UInt64, IntPtr]] { param([IntPtr]$hProcess, [UInt64]$AddrBase); $Dbghelp::SymFunctionTableAccess64($hProcess, $AddrBase) }
    $SymGetModuleBase64Delegate = [Func[IntPtr, UInt64, UInt64]] { param([IntPtr]$hProcess, [UInt64]$Address); $Dbghelp::SymGetModuleBase64($hProceess, $Address) }

    $Dbghelp::
}
