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

    $IA64_CONTEXT = 
    struct $Mod IA64_CONTEXT -ExplicitLayout @{
        ContextFlags = field 0 UInt64 -Offset 0x000 

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_DEBUG.
        DbI0 = field 1 UInt64 -Offset 0x010 
        DbI1 = field 2 UInt64 -Offset 0x018 
        DbI2 = field 3 UInt64 -Offset 0x020 
        DbI3 = field 4 UInt64 -Offset 0x028 
        DbI4 = field 5 UInt64 -Offset 0x030 
        DbI5 = field 6 UInt64 -Offset 0x038 
        DbI6 = field 7 UInt64 -Offset 0x040 
        DbI7 = field 8 UInt64 -Offset 0x048 
        DbD0 = field 9 UInt64 -Offset 0x050 
        DbD1 = field 10 UInt64 -Offset 0x058 
        DbD2 = field 11 UInt64 -Offset 0x060 
        DbD3 = field 12 UInt64 -Offset 0x068 
        DbD4 = field 13 UInt64 -Offset 0x070 
        DbD5 = field 14 UInt64 -Offset 0x078 
        DbD6 = field 15 UInt64 -Offset 0x080 
        DbD7 = field 16 UInt64 -Offset 0x088 

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_LOWER_FLOATING_POINT.
        FltS0 = field  $FLOAT128 -Offset 0x090 
        FltS1 = field  $FLOAT128 -Offset 0x0a0 
        FltS2 = field  $FLOAT128 -Offset 0x0b0 
        FltS3 = field  $FLOAT128 -Offset 0x0c0 
        FltT0 = field  $FLOAT128 -Offset 0x0d0 
        FltT1 = field  $FLOAT128 -Offset 0x0e0 
        FltT2 = field  $FLOAT128 -Offset 0x0f0 
        FltT3 = field  $FLOAT128 -Offset 0x100 
        FltT4 = field  $FLOAT128 -Offset 0x110 
        FltT5 = field  $FLOAT128 -Offset 0x120 
        FltT6 = field  $FLOAT128 -Offset 0x130 
        FltT7 = field  $FLOAT128 -Offset 0x140 
        FltT8 = field  $FLOAT128 -Offset 0x150 
        FltT9 = field  $FLOAT128 -Offset 0x160 
        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_HIGHER_FLOATING_POINT.

        FltS4 = field  $FLOAT128 -Offset 0x170 
        FltS5 = field  $FLOAT128 -Offset 0x180 
        FltS6 = field  $FLOAT128 -Offset 0x190 
        FltS7 = field  $FLOAT128 -Offset 0x1a0 
        FltS8 = field  $FLOAT128 -Offset 0x1b0 
        FltS9 = field  $FLOAT128 -Offset 0x1c0 
        FltS10 = field  $FLOAT128 -Offset 0x1d0 
        FltS11 = field  $FLOAT128 -Offset 0x1e0 
        FltS12 = field  $FLOAT128 -Offset 0x1f0 
        FltS13 = field  $FLOAT128 -Offset 0x200 
        FltS14 = field  $FLOAT128 -Offset 0x210 
        FltS15 = field  $FLOAT128 -Offset 0x220 
        FltS16 = field  $FLOAT128 -Offset 0x230 
        field  $FLOAT128 -Offset 0x240 FltS17 = 
        field  $FLOAT128 -Offset 0x250 FltS18 = 
        field  $FLOAT128 -Offset 0x260 FltS19 = 
        field  $FLOAT128 -Offset 0x270 FltF32 = 
        field  $FLOAT128 -Offset 0x280 FltF33 = 
        field  $FLOAT128 -Offset 0x290 FltF34 = 
        field  $FLOAT128 -Offset 0x2a0 FltF35 = 
        field  $FLOAT128 -Offset 0x2b0 FltF36 = 
        field  $FLOAT128 -Offset 0x2c0 FltF37 = 
        field  $FLOAT128 -Offset 0x2d0 FltF38 = 
        field  $FLOAT128 -Offset 0x2e0 FltF39 = 
        field  $FLOAT128 -Offset 0x2f0 FltF40 = 
        field  $FLOAT128 -Offset 0x300 FltF41 = 
        field  $FLOAT128 -Offset 0x310 FltF42 = 
        field  $FLOAT128 -Offset 0x320 FltF43 = 
        field  $FLOAT128 -Offset 0x330 FltF44 = 
        field  $FLOAT128 -Offset 0x340 FltF45 = 
        field  $FLOAT128 -Offset 0x350 FltF46 = 
        field  $FLOAT128 -Offset 0x360 FltF47 = 
        field  $FLOAT128 -Offset 0x370 FltF48 = 
        field  $FLOAT128 -Offset 0x380 FltF49 = 
        field  $FLOAT128 -Offset 0x390 FltF50 = 
        field  $FLOAT128 -Offset 0x3a0 FltF51 = 
        field  $FLOAT128 -Offset 0x3b0 FltF52 = 
        field  $FLOAT128 -Offset 0x3c0 FltF53 = 
        field  $FLOAT128 -Offset 0x3d0 FltF54 = 
        field  $FLOAT128 -Offset 0x3e0 FltF55 = 
        field  $FLOAT128 -Offset 0x3f0 FltF56 = 
        field  $FLOAT128 -Offset 0x400 FltF57 = 
        field  $FLOAT128 -Offset 0x410 FltF58 = 
        field  $FLOAT128 -Offset 0x420 FltF59 = 
        field  $FLOAT128 -Offset 0x430 FltF60 = 
        field  $FLOAT128 -Offset 0x440 FltF61 = 
        field  $FLOAT128 -Offset 0x450 FltF62 = 
        field  $FLOAT128 -Offset 0x460 FltF63 = 
        field  $FLOAT128 -Offset 0x470 FltF64 = 
        field  $FLOAT128 -Offset 0x480 FltF65 = 
        field  $FLOAT128 -Offset 0x490 FltF66 = 
        field  $FLOAT128 -Offset 0x4a0 FltF67 = 
        field  $FLOAT128 -Offset 0x4b0 FltF68 = 
        field  $FLOAT128 -Offset 0x4c0 FltF69 = 
        field  $FLOAT128 -Offset 0x4d0 FltF70 = 
        field  $FLOAT128 -Offset 0x4e0 FltF71 = 
        field  $FLOAT128 -Offset 0x4f0 FltF72 = 
        field  $FLOAT128 -Offset 0x500 FltF73 = 
        field  $FLOAT128 -Offset 0x510 FltF74 = 
        field  $FLOAT128 -Offset 0x520 FltF75 = 
        field  $FLOAT128 -Offset 0x530 FltF76 = 
        field  $FLOAT128 -Offset 0x540 FltF77 = 
        field  $FLOAT128 -Offset 0x550 FltF78 = 
        field  $FLOAT128 -Offset 0x560 FltF79 = 
        field  $FLOAT128 -Offset 0x570 FltF80 = 
        field  $FLOAT128 -Offset 0x580 FltF81 = 
        field  $FLOAT128 -Offset 0x590 FltF82 = 
        field  $FLOAT128 -Offset 0x5a0 FltF83 = 
        field  $FLOAT128 -Offset 0x5b0 FltF84 = 
        field  $FLOAT128 -Offset 0x5c0 FltF85 = 
        field  $FLOAT128 -Offset 0x5d0 FltF86 = 
        field  $FLOAT128 -Offset 0x5e0 FltF87 = 
        field  $FLOAT128 -Offset 0x5f0 FltF88 = 
        field  $FLOAT128 -Offset 0x600 FltF89 = 
        field  $FLOAT128 -Offset 0x610 FltF90 = 
        field  $FLOAT128 -Offset 0x620 FltF91 = 
        field  $FLOAT128 -Offset 0x630 FltF92 = 
        field  $FLOAT128 -Offset 0x640 FltF93 = 
        field  $FLOAT128 -Offset 0x650 FltF94 = 
        field  $FLOAT128 -Offset 0x660 FltF95 = 
        field  $FLOAT128 -Offset 0x670 FltF96 = 
        field  $FLOAT128 -Offset 0x680 FltF97 = 
        field  $FLOAT128 -Offset 0x690 FltF98 = 
        field  $FLOAT128 -Offset 0x6a0 FltF99 = 
        field  $FLOAT128 -Offset 0x6b0 FltF100 = 
        field  $FLOAT128 -Offset 0x6c0 FltF101 = 
        field  $FLOAT128 -Offset 0x6d0 FltF102 = 
        field  $FLOAT128 -Offset 0x6e0 FltF103 = 
        field  $FLOAT128 -Offset 0x6f0 FltF104 = 
        field  $FLOAT128 -Offset 0x700 FltF105 = 
        field  $FLOAT128 -Offset 0x710 FltF106 = 
        field  $FLOAT128 -Offset 0x720 FltF107 = 
        field  $FLOAT128 -Offset 0x730 FltF108 = 
        field  $FLOAT128 -Offset 0x740 FltF109 = 
        field  $FLOAT128 -Offset 0x750 FltF110 = 
        field  $FLOAT128 -Offset 0x760 FltF111 = 
        field  $FLOAT128 -Offset 0x770 FltF112 = 
        field  $FLOAT128 -Offset 0x780 FltF113 = 
        field  $FLOAT128 -Offset 0x790 FltF114 = 
        field  $FLOAT128 -Offset 0x7a0 FltF115 = 
        field  $FLOAT128 -Offset 0x7b0 FltF116 = 
        field  $FLOAT128 -Offset 0x7c0 FltF117 = 
        field  $FLOAT128 -Offset 0x7d0 FltF118 = 
        field  $FLOAT128 -Offset 0x7e0 FltF119 = 
        field  $FLOAT128 -Offset 0x7f0 FltF120 = 
        field  $FLOAT128 -Offset 0x800 FltF121 = 
        field  $FLOAT128 -Offset 0x810 FltF122 = 
        field  $FLOAT128 -Offset 0x820 FltF123 = 
        field  $FLOAT128 -Offset 0x830 FltF124 = 
        field  $FLOAT128 -Offset 0x840 FltF125 = 
        field  $FLOAT128 -Offset 0x850 FltF126 = 
        field  $FLOAT128 -Offset 0x860 FltF127 = 
        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL.

        [FieldOffset(0x870)] public ulong publicStFPSR; # FP status

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_INTEGER.
        [FieldOffset(0x870)] public ulong IntGp; # r1 = 0x, volatile
        [FieldOffset(0x880)] public ulong IntT0; # r2-r3 = 0x; volatile
        [FieldOffset(0x888)] public ulong IntT1; #
        [FieldOffset(0x890)] public ulong IntS0; # r4-r7 = 0x; preserved
        [FieldOffset(0x898)] public ulong IntS1;
        [FieldOffset(0x8a0)] public ulong IntS2;
        [FieldOffset(0x8a8)] public ulong IntS3;
        [FieldOffset(0x8b0)] public ulong IntV0; # r8 = 0x; volatile
        [FieldOffset(0x8b8)] public ulong IntT2; # r9-r11 = 0x; volatile
        [FieldOffset(0x8c0)] public ulong IntT3;
        [FieldOffset(0x8c8)] public ulong IntT4;
        [FieldOffset(0x8d0)] public ulong IntSp; # stack pointer (r12) = 0x; special
        [FieldOffset(0x8d8)] public ulong IntTeb; # teb (r13) = 0x; special
        [FieldOffset(0x8e0)] public ulong IntT5; # r14-r31 = 0x; volatile
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
        [FieldOffset(0x970)] public ulong IntNats; # Nat bits for r1-r31
        # r1-r31 in bits 1 thru 31.

        [FieldOffset(0x978)] public ulong Preds; # predicates = 0x; preserved
        [FieldOffset(0x980)] public ulong BrRp; # return pointer = 0x; b0 = 0x; preserved
        [FieldOffset(0x988)] public ulong BrS0; # b1-b5 = 0x; preserved
        [FieldOffset(0x990)] public ulong BrS1;
        [FieldOffset(0x998)] public ulong BrS2;
        [FieldOffset(0x9a0)] public ulong BrS3;
        [FieldOffset(0x9a8)] public ulong BrS4;
        [FieldOffset(0x9b0)] public ulong BrT0; # b6-b7 = 0x; volatile
        [FieldOffset(0x9b8)] public ulong BrT1;

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_CONTROL.
        # Other application registers
        [FieldOffset(0x9c0)] public ulong ApUNAT; # User Nat collection register = 0x; preserved
        [FieldOffset(0x9c8)] public ulong ApLC; # Loop counter register = 0x; preserved
        [FieldOffset(0x9d0)] public ulong ApEC; # Epilog counter register = 0x; preserved
        [FieldOffset(0x9d8)] public ulong ApCCV; # CMPXCHG value register = 0x; volatile
        [FieldOffset(0x9e0)] public ulong ApDCR; # Default control register (TBD)

        # Register stack info
        [FieldOffset(0x9e8)] public ulong RsPFS; # Previous function state = 0x; preserved
        [FieldOffset(0x9f0)] public ulong RsBSP; # Backing store pointer = 0x; preserved
        [FieldOffset(0x9f8)] public ulong RsBSPSTORE;
        [FieldOffset(0xa00)] public ulong RsRSC; # RSE configuration = 0x; volatile
        [FieldOffset(0xa08)] public ulong RsRNAT; # RSE Nat collection register = 0x; preserved

        # Trap Status Information
        [FieldOffset(0xa10)] public ulong StIPSR; # Interruption Processor Status
        [FieldOffset(0xa18)] public ulong StIIP; # Interruption IP
        [FieldOffset(0xa20)] public ulong StIFS; # Interruption Function State

        # iA32 related control registers
        [FieldOffset(0xa28)] public ulong StFCR; # copy of Ar21
        [FieldOffset(0xa30)] public ulong Eflag; # Eflag copy of Ar24
        [FieldOffset(0xa38)] public ulong SegCSD; # iA32 CSDescriptor (Ar25)
        [FieldOffset(0xa40)] public ulong SegSSD; # iA32 SSDescriptor (Ar26)
        [FieldOffset(0xa48)] public ulong Cflag; # Cr0+Cr4 copy of Ar27
        [FieldOffset(0xa50)] public ulong StFSR; # x86 FP status (copy of AR28)
        [FieldOffset(0xa58)] public ulong StFIR; # x86 FP status (copy of AR29)
        [FieldOffset(0xa60)] public ulong StFDR; # x86 FP status (copy of AR30)
        [FieldOffset(0xa68)] public ulong UNUSEDPACK; # alignment padding
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
