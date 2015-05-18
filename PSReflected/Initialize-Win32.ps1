function Initialize-Win32 {
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

    $ImageFileMachine = `
    psenum $Mod ImageFileMachine Int32 @{
        I386 =  0x014c
        IA64 =  0x0200
        AMD64 = 0x8664
    }

    $ProcessAccess = `
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

    $ThreadAccess = `
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

    $X86ContextFlags = `
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
    
    $AMD64ContextFlags = `
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
    
    $IA64ContextFlags = `
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

    $AddressMode = `
    psenum $Mod AddressMode UInt32 @{
        _1616 = 0
        _1632 = 1
        _Real = 2
        _Flat = 3
    }

    $ListModules = `
    psenum $Mod ListModules UInt32 @{
        Default = 0
        _32Bit =  1
        _64Bit =  2
        All =     3
    }

    $ProcessorArch = `
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

    $MODULE_INFO = `
    struct $Mod MODULE_INFO @{
        lpBaseOfDll = field 0 IntPtr
        SizeOfImage = field 1 UInt32
        EntryPoint = field 2 IntPtr
    }

    $SYSTEM_INFO = `
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

    $FLOAT128 = `
    struct $Mod FLOAT128 @{
        LowPart =  field 0 Int64
        HighPart = field 1 Int64
    }

    $FLOATING_SAVE_AREA = `
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

    $X86_CONTEXT = `
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

    $AMD64_CONTEXT = `
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

    $IA64_CONTEXT = `
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
        FltS0 = field 17 FLOAT128 -Offset 0x090 
        FltS1 = field 18 FLOAT128 -Offset 0x0a0 
        FltS2 = field 19 FLOAT128 -Offset 0x0b0 
        FltS3 = field 20 FLOAT128 -Offset 0x0c0 
        FltT0 = field 21 FLOAT128 -Offset 0x0d0 
        FltT1 = field 22 FLOAT128 -Offset 0x0e0 
        FltT2 = field 23 FLOAT128 -Offset 0x0f0 
        FltT3 = field 24 FLOAT128 -Offset 0x100 
        FltT4 = field 25 FLOAT128 -Offset 0x110 
        FltT5 = field 26 FLOAT128 -Offset 0x120 
        FltT6 = field 27 FLOAT128 -Offset 0x130 
        FltT7 = field 28 FLOAT128 -Offset 0x140 
        FltT8 = field 29 FLOAT128 -Offset 0x150 
        FltT9 = field 30 FLOAT128 -Offset 0x160 
        
        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_HIGHER_FLOATING_POINT.
        FltS4 = field 31 FLOAT128 -Offset 0x170 
        FltS5 = field 32 FLOAT128 -Offset 0x180 
        FltS6 = field 33 FLOAT128 -Offset 0x190 
        FltS7 = field 34 FLOAT128 -Offset 0x1a0 
        FltS8 = field 35 FLOAT128 -Offset 0x1b0 
        FltS9 = field 36 FLOAT128 -Offset 0x1c0 
        FltS10 = field 37 FLOAT128 -Offset 0x1d0 
        FltS11 = field 38 FLOAT128 -Offset 0x1e0 
        FltS12 = field 39 FLOAT128 -Offset 0x1f0 
        FltS13 = field 40 FLOAT128 -Offset 0x200 
        FltS14 = field 41 FLOAT128 -Offset 0x210 
        FltS15 = field 42 FLOAT128 -Offset 0x220 
        FltS16 = field 43 FLOAT128 -Offset 0x230 
        FltS17 = field 44 FLOAT128 -Offset 0x240
        FltS18 = field 45 FLOAT128 -Offset 0x250 
        FltS19 = field 46 FLOAT128 -Offset 0x260 
        FltF32 = field 47 FLOAT128 -Offset 0x270 
        FltF33 = field 48 FLOAT128 -Offset 0x280 
        FltF34 = field 49 FLOAT128 -Offset 0x290 
        FltF35 = field 50 FLOAT128 -Offset 0x2a0 
        FltF36 = field 51 FLOAT128 -Offset 0x2b0 
        FltF37 = field 52 FLOAT128 -Offset 0x2c0 
        FltF38 = field 53 FLOAT128 -Offset 0x2d0 
        FltF39 = field 54 FLOAT128 -Offset 0x2e0 
        FltF40 = field 55 FLOAT128 -Offset 0x2f0 
        FltF41 = field 56 FLOAT128 -Offset 0x300 
        FltF42 = field 57 FLOAT128 -Offset 0x310 
        FltF43 = field 58 FLOAT128 -Offset 0x320 
        FltF44 = field 59 FLOAT128 -Offset 0x330 
        FltF45 = field 60 FLOAT128 -Offset 0x340 
        FltF46 = field 61 FLOAT128 -Offset 0x350 
        FltF47 = field 62 FLOAT128 -Offset 0x360 
        FltF48 = field 63 FLOAT128 -Offset 0x370 
        FltF49 = field 64 FLOAT128 -Offset 0x380 
        FltF50 = field 65 FLOAT128 -Offset 0x390 
        FltF51 = field 66 FLOAT128 -Offset 0x3a0 
        FltF52 = field 67 FLOAT128 -Offset 0x3b0 
        FltF53 = field 68 FLOAT128 -Offset 0x3c0 
        FltF54 = field 69 FLOAT128 -Offset 0x3d0 
        FltF55 = field 70 FLOAT128 -Offset 0x3e0 
        FltF56 = field 71 FLOAT128 -Offset 0x3f0 
        FltF57 = field 72 FLOAT128 -Offset 0x400 
        FltF58 = field 73 FLOAT128 -Offset 0x410 
        FltF59 = field 74 FLOAT128 -Offset 0x420 
        FltF60 = field 75 FLOAT128 -Offset 0x430 
        FltF61 = field 76 FLOAT128 -Offset 0x440 
        FltF62 = field 77 FLOAT128 -Offset 0x450 
        FltF63 = field 78 FLOAT128 -Offset 0x460 
        FltF64 = field 79 FLOAT128 -Offset 0x470 
        FltF65 = field 80 FLOAT128 -Offset 0x480 
        FltF66 = field 81 FLOAT128 -Offset 0x490 
        FltF67 = field 82 FLOAT128 -Offset 0x4a0 
        FltF68 = field 83 FLOAT128 -Offset 0x4b0 
        FltF69 = field 84 FLOAT128 -Offset 0x4c0 
        FltF70 = field 85 FLOAT128 -Offset 0x4d0 
        FltF71 = field 86 FLOAT128 -Offset 0x4e0 
        FltF72 = field 87 FLOAT128 -Offset 0x4f0 
        FltF73 = field 88 FLOAT128 -Offset 0x500 
        FltF74 = field 89 FLOAT128 -Offset 0x510 
        FltF75 = field 90 FLOAT128 -Offset 0x520 
        FltF76 = field 91 FLOAT128 -Offset 0x530 
        FltF77 = field 92 FLOAT128 -Offset 0x540 
        FltF78 = field 93 FLOAT128 -Offset 0x550 
        FltF79 = field 94 FLOAT128 -Offset 0x560 
        FltF80 = field 95 FLOAT128 -Offset 0x570 
        FltF81 = field 96 FLOAT128 -Offset 0x580 
        FltF82 = field 97 FLOAT128 -Offset 0x590 
        FltF83 = field 98 FLOAT128 -Offset 0x5a0 
        FltF84 = field 99 FLOAT128 -Offset 0x5b0 
        FltF85 = field 100 FLOAT128 -Offset 0x5c0 
        FltF86 = field 101 FLOAT128 -Offset 0x5d0 
        FltF87 = field 102 FLOAT128 -Offset 0x5e0 
        FltF88 = field 103 FLOAT128 -Offset 0x5f0 
        FltF89 = field 104 FLOAT128 -Offset 0x600 
        FltF90 = field 105 FLOAT128 -Offset 0x610 
        FltF91 = field 106 FLOAT128 -Offset 0x620 
        FltF92 = field 107 FLOAT128 -Offset 0x630 
        FltF93 = field 108 FLOAT128 -Offset 0x640 
        FltF94 = field 109 FLOAT128 -Offset 0x650 
        FltF95 = field 110 FLOAT128 -Offset 0x660 
        FltF96 = field 111 FLOAT128 -Offset 0x670 
        FltF97 = field 112 FLOAT128 -Offset 0x680 
        FltF98 = field 113 FLOAT128 -Offset 0x690 
        FltF99 = field 114 FLOAT128 -Offset 0x6a0 
        FltF100 = field 115 FLOAT128 -Offset 0x6b0 
        FltF101 = field 116 FLOAT128 -Offset 0x6c0 
        FltF102 = field 117 FLOAT128 -Offset 0x6d0 
        FltF103 = field 118 FLOAT128 -Offset 0x6e0 
        FltF104 = field 119 FLOAT128 -Offset 0x6f0 
        FltF105 = field 120 FLOAT128 -Offset 0x700 
        FltF106 = field 121 FLOAT128 -Offset 0x710 
        FltF107 = field 122 FLOAT128 -Offset 0x720 
        FltF108 = field 123 FLOAT128 -Offset 0x730 
        FltF109 = field 124 FLOAT128 -Offset 0x740 
        FltF110 = field 125 FLOAT128 -Offset 0x750 
        FltF111 = field 126 FLOAT128 -Offset 0x760 
        FltF112 = field 127 FLOAT128 -Offset 0x770 
        FltF113 = field 128 FLOAT128 -Offset 0x780 
        FltF114 = field 129 FLOAT128 -Offset 0x790 
        FltF115 = field 130 FLOAT128 -Offset 0x7a0 
        FltF116 = field 131 FLOAT128 -Offset 0x7b0 
        FltF117 = field 132 FLOAT128 -Offset 0x7c0 
        FltF118 = field 133 FLOAT128 -Offset 0x7d0 
        FltF119 = field 134 FLOAT128 -Offset 0x7e0 
        FltF120 = field 135 FLOAT128 -Offset 0x7f0 
        FltF121 = field 136 FLOAT128 -Offset 0x800 
        FltF122 = field 137 FLOAT128 -Offset 0x810 
        FltF123 = field 138 FLOAT128 -Offset 0x820 
        FltF124 = field 139 FLOAT128 -Offset 0x830 
        FltF125 = field 140 FLOAT128 -Offset 0x840 
        FltF126 = field 141 FLOAT128 -Offset 0x850 
        FltF127 = field 142 FLOAT128 -Offset 0x860 
        
        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL.
        StFPSR = field 143 UInt64 -Offset 0x870 # FP status

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_INTEGER.
        IntGp = field 144 UInt64 -Offset 0x870  # r1 = 0x, volatile
        IntT0 = field 145 UInt64 -Offset 0x880  # r2-r3 = 0x =  volatile
        IntT1 = field 146 UInt64 -Offset 0x888  #
        IntS0 = field 147 UInt64 -Offset 0x890  # r4-r7 = 0x =  preserved
        IntS1 = field 148 UInt64 -Offset 0x898 
        IntS2 = field 149 UInt64 -Offset 0x8a0 
        IntS3 = field 150 UInt64 -Offset 0x8a8 
        IntV0 = field 151 UInt64 -Offset 0x8b0  # r8 = 0x =  volatile
        IntT2 = field 152 UInt64 -Offset 0x8b8  # r9-r11 = 0x =  volatile
        IntT3 = field 153 UInt64 -Offset 0x8c0 
        IntT4 = field 154 UInt64 -Offset 0x8c8 
        IntSp = field 155 UInt64 -Offset 0x8d0   # stack pointer (r12) = 0x =  special
        IntTeb = field 156 UInt64 -Offset 0x8d8  # teb (r13) = 0x =  special
        IntT5 = field 157 UInt64 -Offset 0x8e0   # r14-r31 = 0x =  volatile
        IntT6 = field 158 UInt64 -Offset 0x8e8 
        IntT7 = field 159 UInt64 -Offset 0x8f0 
        IntT8 = field 160 UInt64 -Offset 0x8f8 
        IntT9 = field 161 UInt64 -Offset 0x900 
        IntT10 = field 162 UInt64 -Offset 0x908 
        IntT11 = field 163 UInt64 -Offset 0x910 
        IntT12 = field 164 UInt64 -Offset 0x918 
        IntT13 = field 165 UInt64 -Offset 0x920 
        IntT14 = field 166 UInt64 -Offset 0x928 
        IntT15 = field 167 UInt64 -Offset 0x930 
        IntT16 = field 168 UInt64 -Offset 0x938 
        IntT17 = field 169 UInt64 -Offset 0x940 
        IntT18 = field 170 UInt64 -Offset 0x948 
        IntT19 = field 171 UInt64 -Offset 0x950 
        IntT20 = field 172 UInt64 -Offset 0x958 
        IntT21 = field 173 UInt64 -Offset 0x960 
        IntT22 = field 174 UInt64 -Offset 0x968 
        IntNats = field 175 UInt64 -Offset 0x970  # Nat bits for r1-r31
        # r1-r31 in bits 1 thru 31.

        Preds = field 176 UInt64 -Offset 0x978  # predicates = 0x =  preserved
        BrRp =  field 177 UInt64 -Offset 0x980  # return pointer = 0x =  b0 = 0x =  preserved
        BrS0 =  field 178 UInt64 -Offset 0x988  # b1-b5 = 0x =  preserved
        BrS1 =  field 179 UInt64 -Offset 0x990 
        BrS2 =  field 180 UInt64 -Offset 0x998 
        BrS3 =  field 181 UInt64 -Offset 0x9a0 
        BrS4 =  field 182 UInt64 -Offset 0x9a8 
        BrT0 =  field 183 UInt64 -Offset 0x9b0  # b6-b7 = 0x =  volatile
        BrT1 =  field 184 UInt64 -Offset 0x9b8 

        # This section is specified/returned if the ContextFlags word contains
        # the flag CONTEXT_CONTROL.
        # Other application registers
        ApUNAT = field 185 UInt64 -Offset 0x9c0  # User Nat collection register = 0x =  preserved
        ApLC =   field 186 UInt64 -Offset 0x9c8  # Loop counter register = 0x =  preserved
        ApEC =   field 187 UInt64 -Offset 0x9d0  # Epilog counter register = 0x =  preserved
        ApCCV =  field 188 UInt64 -Offset 0x9d8  # CMPXCHG value register = 0x =  volatile
        ApDCR =  field 189 UInt64 -Offset 0x9e0  # Default control register (TBD)

        # Register stack info
        RsPFS =      field 190 UInt64 -Offset 0x9e8  # Previous function state = 0x =  preserved
        RsBSP =      field 191 UInt64 -Offset 0x9f0  # Backing store pointer = 0x =  preserved
        RsBSPSTORE = field 192 UInt64 -Offset 0x9f8 
        RsRSC =      field 193 UInt64 -Offset 0xa00  # RSE configuration = 0x =  volatile
        RsRNAT =     field 194 UInt64 -Offset 0xa08  # RSE Nat collection register = 0x =  preserved

        # Trap Status Information
        StIPSR = field 195 UInt64 -Offset 0xa10  # Interruption Processor Status
        StIIP =  field 196 UInt64 -Offset 0xa18  # Interruption IP
        StIFS =  field 197 UInt64 -Offset 0xa20  # Interruption Function State

        # iA32 related control registers
        StFCR =  field 198 UInt64 -Offset 0xa28  # copy of Ar21
        Eflag =  field 199 UInt64 -Offset 0xa30  # Eflag copy of Ar24
        SegCSD = field 200 UInt64 -Offset 0xa38  # iA32 CSDescriptor (Ar25)
        SegSSD = field 201 UInt64 -Offset 0xa40  # iA32 SSDescriptor (Ar26)
        Cflag =  field 202 UInt64 -Offset 0xa48  # Cr0+Cr4 copy of Ar27
        StFSR =  field 203 UInt64 -Offset 0xa50  # x86 FP status (copy of AR28)
        StFIR =  field 204 UInt64 -Offset 0xa58  # x86 FP status (copy of AR29)
        StFDR =   field 205 UInt64 -Offset 0xa60  # x86 FP status (copy of AR30)
        UNUSEDPACK = field 206 UInt64 -Offset 0xa68  # alignment padding
    }

    $KDHELP = `
    struct $Mod KDHELP @{
        Thread = field 0 UInt64
        ThCallbackStack = field 1 UInt32
        ThCallbackBStore = field 2 UInt32
        NextCallback = field 3 UInt32
        FramePointer = field 4 UInt32
        KiCallUserMode = field 0 UInt64
        KeUserCallbackDispatcher = field 0 UInt64
        SystemRangeStart = field 0 UInt64
        KiUserExceptionDispatcher = field 0 UInt64
        StackBase = field 0 UInt64
        StackLimit = field 0 UInt64
        Reserved = field 0 UInt64[] -MarshalAs @('ByValArray', 5)
    }

    $ADDRESS64 = `
    struct $Mod ADDRESS64 @{
        Offset = field 0 UInt64
        Segment = field 1 UInt16
        Mode = field 2 AddressMode
    }

    $STACKFRAME64 = `
    struct $Mod STACKFRAME64 @{
        AddrPC = field 0 ADDRESS64                                 #Program Counter EIP, RIP
        AddrReturn = field 1 ADDRESS64                             #Return Address
        AddrFrame = field 2 ADDRESS64                              #Frame Pointer EBP, RBP or RDI
        AddrStack = field 3 ADDRESS64                              #Stack Pointer ESP, RSP
        AddrBStore = field 4 ADDRESS64                             #IA64 Backing Store RsBSP
        FuncTableEntry = field 5 IntPtr                            #x86 = FPO_DATA struct, if none = NULL
        Params = field 6 UInt64[] -MarshalAs @('ByValArray', 4)    #possible arguments to the function
        Far = field 7 Bool                                         #TRUE if this is a WOW far call
        Virtual = field 8 Bool                                     #TRUE if this is a virtual frame
        Reserved = field 9 UInt64[] -MarshalAs @('ByValArray', 3)  #used internally by StackWalk64
        KdHelp = field 10 KDHELP                                   #specifies helper data for walking kernel callback frames
    }

    $IMAGEHLP_SYMBOLW64 = `
    struct $Mod IMAGEHLP_SYMBOLW64 @{
        SizeOfStruct = field 0 UInt32                                 # set to sizeof(IMAGEHLP_SYMBOLW64)
        Address = field 1 UInt64                                      # virtual address including dll base address
        Size = field 2 UInt32                                         # estimated size of symbol, can be zero
        Flags = field 3 UInt32                                        # info about the symbols, see the SYMF defines
        MaxNameLength = field 4 UInt32                                # maximum size of symbol name in 'Name'
        Name = field 5 char[] -MarshalAs @('ByValArray', 33)          # symbol name (null terminated string)
    }

    ###########
    # IMPORTS #
    ###########

    $FunctionDefinitions = @(
        #Kernel32
        (func kernel32 OpenProcess ([IntPtr]) @([ProcessAccess], [Bool], [UInt32]) -SetLastError),
        (func kernel32 OpenThread ([IntPtr]) @([ThreadAccess], [Bool], [UInt32]) -SetLastError),
        (func kernel32 TerminateThread ([Bool]) @([IntPtr], [Int32]) -SetLastError),
        (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
        (func kernel32 Wow64SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 SuspendThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 ResumeThread ([UInt32]) @([IntPtr]) -SetLastError),
        (func kernel32 Wow64GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
        (func kernel32 GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -SetLastError),
        (func kernel32 GetNativeSystemInfo ([Void]) @([SYSTEM_INFO].MakeByRefType()) -SetLastError),
        (func kernel32 IsWow64Process ([Bool]) @([IntPtr], [Bool].MakeByRefType()) -SetLastError),

        #Psapi
        (func psapi EnumProcessModulesEx ([Bool]) @([IntPtr], [IntPtr].MakeArrayType(), [UInt32], [UInt32].MakeByRefType(), [ListModules]) -SetLastError),
        (func psapi GetModuleInformation ([Bool]) @([IntPtr], [IntPtr], [MODULE_INFO].MakeByRefType(), [UInt32]) -SetLastError), 
        (func psapi GetModuleBaseNameW ([UInt32]) @([IntPtr], [IntPtr], [System.Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),
        (func psapi GetModuleFileNameExW ([UInt32]) @([IntPtr], [IntPtr], [System.Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),
        (func psapi GetMappedFileNameW ([UInt32]) @([IntPtr], [IntPtr], [System.Text.StringBuilder], [Int32]) -Charset Unicode -SetLastError),

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
}
