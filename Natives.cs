using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PowerWalker.Natives
{
    #region Enums

    public enum NtStatus : uint
    {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,

        MaximumNtStatus = 0xffffffff
    }

    [Flags]
    public enum ProcessInfo
    {   
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        MaxProcessInfoClass
    }

    [Flags]
    public enum ThreadInfo
    {
        ThreadBasicInformation,             //Output buffer points to THREAD_BASIC_INFORMATION structure.
        ThreadTimes,                        //Output buffer points to THREAD_TIMES_INFORMATION structure.  
        ThreadPriority, 	                //Output buffer points to ULONG value.
        ThreadBasePriority,                 //Output buffer points to ULONG value.
        ThreadAffinityMask,                 //Output buffer points to ULONG value.
        ThreadImpersonationTokenc,          //Output buffer points to HANDLE value.
        ThreadDescriptorTableEntry,         //Output buffer points to DESCRIPTOR_TABLE_ENTRY structure defined in <windbgkd.h> from Win2000 DDK.
        ThreadEnableAlignmentFaultFixup,    //Output buffer points to BOOLEAN value.
        ThreadEventPair,                    //Output buffer points to HANDLE value to EventPair object.
        ThreadQuerySetWin32StartAddress,    //Output buffer points to PVOID value specifing address of thread start routine.
        ThreadZeroTlsCell,                  //Output buffer points to ULONG value. (TlsID. Called from Kernel32.dll TlsFree())
        ThreadPerformanceCount,             //Output buffer points to LARGE_INTEGER value.
        ThreadAmILastThread,                //Output buffer points to Win32 predefined BOOL value.
        ThreadIdealProcessor,               //Output buffer points to ULONG value. (Called from Kernel32.dll SetThreadIdealProcessor())
        ThreadPriorityBoost,                //Output buffer points to BOOLEAN value.
        ThreadSetTlsArrayAddress,           //Output buffer points to PVOID value specifing ThreadLocalStorage array address.
        ThreadIsIoPending,                  //Not implemented - STATUS_INVALID_INFO_CLASS.
        ThreadHideFromDebugger              //Not implemented - STATUS_INVALID_INFO_CLASS.
    }
    
    public enum ImageFileMachine : int
    {
        I386 = 0x014c,
        IA64 = 0x0200,
        AMD64 = 0x8664,
    }
    
    public enum ProcessAccess : int
    {
        Terminate = 0x000001,
        CreateThread = 0x000002,
        VmRead = 0x000010,
        VmWrite = 0x000020,
        CreateProcess = 0x000080,
        QueryInformation = 0x000400,
        QueryLimitedInformation = 0x001000,
        All = 0x1F0FFF
    }
    
    [Flags]
    public enum ThreadAccess : int
    {
        None = 0,
        All = 0x1F03FF,
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
        TYPE_NO_PAD = 0x00000008, // Reserved.
        CNT_CODE = 0x00000020, // Section contains code.
        CNT_INITIALIZED_DATA = 0x00000040, // Section contains initialized data.
        CNT_UNINITIALIZED_DATA = 0x00000080, // Section contains uninitialized data.
        LNK_INFO = 0x00000200, // Section contains comments or some other type of information.
        LNK_REMOVE = 0x00000800, // Section contents will not become part of image.
        LNK_COMDAT = 0x00001000, // Section contents comdat.
        NO_DEFER_SPEC_EXC = 0x00004000, // Reset speculative exceptions handling bits in the TLB entries for this section.
        GPREL = 0x00008000, // Section content can be accessed relative to GP
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000, // Default alignment if no others are specified.
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
        LNK_NRELOC_OVFL = 0x01000000, // Section contains extended relocations.
        MEM_DISCARDABLE = 0x02000000, // Section can be discarded.
        MEM_NOT_CACHED = 0x04000000, // Section is not cachable.
        MEM_NOT_PAGED = 0x08000000, // Section is not pageable.
        MEM_SHARED = 0x10000000, // Section is shareable.
        MEM_EXECUTE = 0x20000000, // Section is executable.
        MEM_READ = 0x40000000, // Section is readable.
        MEM_WRITE = 0x80000000 // Section is writeable.
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
        SymSym, // .sym file
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
        [FieldOffset(0x0)] public ulong P1Home;
        [FieldOffset(0x8)] public ulong P2Home;
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
        [FieldOffset(0x44)] public uint EFlags;

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

        [FieldOffset(0x870)] public UInt64 publicStFPSR; // FP status

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_INTEGER.
        [FieldOffset(0x870)] public ulong IntGp; // r1 = 0x, volatile
        [FieldOffset(0x880)] public ulong IntT0; // r2-r3 = 0x; volatile
        [FieldOffset(0x888)] public ulong IntT1; //
        [FieldOffset(0x890)] public ulong IntS0; // r4-r7 = 0x; preserved
        [FieldOffset(0x898)] public ulong IntS1;
        [FieldOffset(0x8a0)] public ulong IntS2;
        [FieldOffset(0x8a8)] public ulong IntS3;
        [FieldOffset(0x8b0)] public ulong IntV0; // r8 = 0x; volatile
        [FieldOffset(0x8b8)] public ulong IntT2; // r9-r11 = 0x; volatile
        [FieldOffset(0x8c0)] public ulong IntT3;
        [FieldOffset(0x8c8)] public ulong IntT4;
        [FieldOffset(0x8d0)] public ulong IntSp; // stack pointer (r12) = 0x; special
        [FieldOffset(0x8d8)] public ulong IntTeb; // teb (r13) = 0x; special
        [FieldOffset(0x8e0)] public ulong IntT5; // r14-r31 = 0x; volatile
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
        [FieldOffset(0x970)] public ulong IntNats; // Nat bits for r1-r31
        // r1-r31 in bits 1 thru 31.

        [FieldOffset(0x978)] public ulong Preds; // predicates = 0x; preserved
        [FieldOffset(0x980)] public ulong BrRp; // return pointer = 0x; b0 = 0x; preserved
        [FieldOffset(0x988)] public ulong BrS0; // b1-b5 = 0x; preserved
        [FieldOffset(0x990)] public ulong BrS1;
        [FieldOffset(0x998)] public ulong BrS2;
        [FieldOffset(0x9a0)] public ulong BrS3;
        [FieldOffset(0x9a8)] public ulong BrS4;
        [FieldOffset(0x9b0)] public ulong BrT0; // b6-b7 = 0x; volatile
        [FieldOffset(0x9b8)] public ulong BrT1;

        // This section is specified/returned if the ContextFlags word contains
        // the flag CONTEXT_CONTROL.
        // Other application registers
        [FieldOffset(0x9c0)] public ulong ApUNAT; // User Nat collection register = 0x; preserved
        [FieldOffset(0x9c8)] public ulong ApLC; // Loop counter register = 0x; preserved
        [FieldOffset(0x9d0)] public ulong ApEC; // Epilog counter register = 0x; preserved
        [FieldOffset(0x9d8)] public ulong ApCCV; // CMPXCHG value register = 0x; volatile
        [FieldOffset(0x9e0)] public ulong ApDCR; // Default control register (TBD)

        // Register stack info
        [FieldOffset(0x9e8)] public ulong RsPFS; // Previous function state = 0x; preserved
        [FieldOffset(0x9f0)] public ulong RsBSP; // Backing store pointer = 0x; preserved
        [FieldOffset(0x9f8)] public ulong RsBSPSTORE;
        [FieldOffset(0xa00)] public ulong RsRSC; // RSE configuration = 0x; volatile
        [FieldOffset(0xa08)] public ulong RsRNAT; // RSE Nat collection register = 0x; preserved

        // Trap Status Information
        [FieldOffset(0xa10)] public ulong StIPSR; // Interruption Processor Status
        [FieldOffset(0xa18)] public ulong StIIP; // Interruption IP
        [FieldOffset(0xa20)] public ulong StIFS; // Interruption Function State

        // iA32 related control registers
        [FieldOffset(0xa28)] public ulong StFCR; // copy of Ar21
        [FieldOffset(0xa30)] public ulong Eflag; // Eflag copy of Ar24
        [FieldOffset(0xa38)] public ulong SegCSD; // iA32 CSDescriptor (Ar25)
        [FieldOffset(0xa40)] public ulong SegSSD; // iA32 SSDescriptor (Ar26)
        [FieldOffset(0xa48)] public ulong Cflag; // Cr0+Cr4 copy of Ar27
        [FieldOffset(0xa50)] public ulong StFSR; // x86 FP status (copy of AR28)
        [FieldOffset(0xa58)] public ulong StFIR; // x86 FP status (copy of AR29)
        [FieldOffset(0xa60)] public ulong StFDR; // x86 FP status (copy of AR30)
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
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct KDHELP64
    {
        public ulong Thread;
        public uint ThCallbackStack;
        public uint ThCallbackBStore;
        public uint NextCallback;
        public uint FramePointer;
        public ulong KiCallUserMode;
        public ulong KeUserCallbackDispatcher;
        public ulong SystemRangeStart;
        public ulong KiUserExceptionDispatcher;
        public ulong StackBase;
        public ulong StackLimit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public ulong[] Reserved;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct ADDRESS64
    {
        public ulong Offset;
        public ushort Segment;
        public AddressMode Mode;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct STACKFRAME64
    {
        public ADDRESS64 AddrPC; //Program Counter EIP, RIP
        public ADDRESS64 AddrReturn; //Return Address
        public ADDRESS64 AddrFrame; //Frame Pointer EBP, RBP or RDI
        public ADDRESS64 AddrStack; //Stack Pointer ESP, RSP
        public ADDRESS64 AddrBStore; //IA64 Backing Store RsBSP
        public IntPtr FuncTableEntry; //x86 = FPO_DATA struct, if none = NULL
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ulong[] Params; //possible arguments to the function
        public bool Far; //TRUE if this is a WOW far call
        public bool Virtual; //TRUE if this is a virtual frame
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public ulong[] Reserved; //used internally by StackWalk64
        public KDHELP64 KdHelp; //specifies helper data for walking kernel callback frames
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct FPO_DATA
    {
        public uint ulOffStart;
        public uint cbProcSize;
        public uint cdwLocals;
        public ushort cdwParams;
        private ushort raw_bytes;
        public int cbProlog { get { return (int)(raw_bytes & 0xFF00) >> 8; } }
        public int cbRegs { get { return (int)(raw_bytes & 0x00E0) >> 5; } }
        public int fHasSEH { get { return (int)(raw_bytes & 0x0010) >> 4; } }
        public int fUseBP { get { return (int)(raw_bytes & 0x0008) >> 3; } }
        public int reserved { get { return (int)(raw_bytes & 0x0004) >> 2; } }
        public int cbFrame { get { return (int)(raw_bytes & 0x0003); } }
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
    public struct IMAGEHLP_MODULE64
    {
        public uint SizeOfStruct;
        public ulong BaseOfImage;
        public uint ImageSize;
        public uint TimeDateStamp;
        public uint CheckSum;
        public uint NumSyms;
        SymType SymType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public char[] ModuleName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public char[] ImageName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public char[] LoadedImageName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public char[] LoadedPdbName;
        public uint CVSig;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260 * 3)]
        public char[] CVData;
        public uint PdbSig;
        GUID PdbSig70;
        public uint PdbAge;
        public bool PdbUnmatched;
        public bool DbgUnmatched;
        public bool LineNumbers;
        public bool GlobalSymbols;
        public bool TypeInfo;
        public bool SourceIndexed;
        public bool Publics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGEHLP_SYMBOL64
    {
        public uint     SizeOfStruct;   // set to sizeof(IMAGEHLP_SYMBOLW64)
        public ulong    Address;        // virtual address including dll base address
        public uint     Size;           // estimated size of symbol, can be zero
        public uint     Flags;          // info about the symbols, see the SYMF defines
        public uint     MaxNameLength;  // maximum size of symbol name in 'Name'
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 33)]
        public char[]   Name;           // symbol name (null terminated string)
    }
    
    //Extracted from ntdll with WinDbg
    [StructLayout(LayoutKind.Explicit)]
    public struct NT_TIB
    {
        [FieldOffset(0x000)] public IntPtr ExceptionList;           // Ptr64 _EXCEPTION_REGISTRATION_RECORD
        [FieldOffset(0x008)] public IntPtr StackBase;               // Ptr64 Void
        [FieldOffset(0x010)] public IntPtr StackLimit;              // Ptr64 Void
        [FieldOffset(0x018)] public IntPtr SubSystemTib;            // Ptr64 Void
        [FieldOffset(0x020)] public IntPtr FiberData;               // Ptr64 Void
        [FieldOffset(0x020)] public uint   Version;                 // Uint4B
        [FieldOffset(0x028)] public IntPtr ArbitraryUserPointer;    // Ptr64 Void
        [FieldOffset(0x030)] public IntPtr Self;                    // Ptr64 _NT_TIB
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct THREAD_BASIC_INFORMATION {
        public NtStatus     ExitStatus;
        public IntPtr       TebBaseAddress;
        public CLIENT_ID    ClientId;
        public UIntPtr      AffinityMask;
        public int          Priority;
        public int          BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LIST_ENTRY {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct W_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public W_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TEB {
        public NT_TIB       Tib;
        public IntPtr       EnvironmentPointer;
        public CLIENT_ID    Cid;
        public IntPtr       ActiveRpcInfo;
        public IntPtr       ThreadLocalStoragePointer;
        public IntPtr       Peb;
        public uint         LastErrorValue;
        public uint         CountOfOwnedCriticalSections;
        public IntPtr       CsrClientThread;
        public IntPtr       Win32ThreadInfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x1F)]
        public uint[]       Win32ClientInfo;
        public IntPtr       WOW32Reserved;
        public uint         CurrentLocale;
        public uint         FpSoftwareStatusRegister;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x36)]
        public IntPtr[]     SystemReserved1;
        public IntPtr       Spare1;
        public uint         ExceptionCode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x28)]
        public uint[]       SpareBytes1;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0xA)]
        public IntPtr[]     SystemReserved2;
        public uint         GdiRgn;
        public uint         GdiPen;
        public uint         GdiBrush;
        public CLIENT_ID    RealClientId;
        public IntPtr       GdiCachedProcessHandle;
        public uint         GdiClientPID;
        public uint         GdiClientTID;
        public IntPtr       GdiThreadLocaleInfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public IntPtr[]     UserReserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x118)]
        public IntPtr[]     GlDispatchTable;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x1A)]
        public uint[]       GlReserved1;
        public IntPtr       GlReserved2;
        public IntPtr       GlSectionInfo;
        public IntPtr       GlSection;
        public IntPtr       GlTable;
        public IntPtr       GlCurrentRC;
        public IntPtr       GlContext;
        public NtStatus     LastStatusValue;
        public W_STRING     StaticUnicodeString;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x105)]
        public char[]       StaticUnicodeBuffer;
        public IntPtr       DeallocationStack;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        public IntPtr[]     TlsSlots;
        public LIST_ENTRY   TlsLinks;
        public IntPtr       Vdm;
        public IntPtr       ReservedForNtRpc;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x2)]
        public IntPtr[]     DbgSsReserved;
        public uint         HardErrorDisabled;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        public IntPtr[]     Instrumentation;
        public IntPtr       WinSockData;
        public uint         GdiBatchCount;
        public uint         Spare2;
        public uint         Spare3;
        public uint         Spare4;
        public IntPtr       ReservedForOle;
        public uint         WaitingOnLoaderLock;
        public IntPtr       StackCommit;
        public IntPtr       StackCommitMax;
        public IntPtr       StackReserved;
}

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr  ExitStatus;
        public IntPtr  PebBaseAddress;
        public IntPtr  AffinityMask;
        public IntPtr  BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr  InheritedFromUniqueProcessId;
        public int     Size
        {
            get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PEB {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[]      Reserved1;
        public byte        BeingDebugged;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[]      Reserved2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[]    Reserved3;
        public IntPtr      Ldr;                    //PEB_LDR_DATA
        public IntPtr      ProcessParameters;      //RTL_USER_PROCESS_PARAMETERS
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 104)]
        public byte[]      Reserved4;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 52)]
        public IntPtr[]    Reserved5;
        public IntPtr      PostProcessInitRoutine; //PS_POST_PROCESS_INIT_ROUTINE
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[]      Reserved6;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public IntPtr[]    Reserved7;
        public uint        SessionId;
}
 
    #endregion Structs
    
    #region Functions

    public class NtDll
    {
        private const string NtLib = "ntdll.dll";

        [DllImport(NtLib, SetLastError = true)]
        public static extern NtStatus NtQueryInformationProcess(IntPtr hProcess, ProcessInfo ProcessInformationClass, IntPtr ProcessInfoBuffer, uint ProcessInformationLength, IntPtr ReturnLength);

        [DllImport(NtLib, SetLastError = true)]
        public static extern NtStatus NtQueryInformationThread(IntPtr hThread, ThreadInfo ThreadInformationClass, IntPtr ThreadInfoBuffer, uint ThreadInformationLength, IntPtr ReturnLength);
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
        
        //SetThreadContext
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
        
        //Wow64GetThreadContext
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);
        
        //Wow64SetThreadContext
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);
        
        //QueryThreadCycleTime
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryThreadCycleTime(IntPtr hThread, [Out] UInt64 CycleTime);

        //VirtualQueryEx
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, MEMORY_BASIC_INFORMATION lpBuffer, ulong dwLength);
        
        //VirtualProtectEx
        [DllImport(Kernel32Lib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, MemoryPageProtection flNewProtect, out MemoryPageProtection flOldProtect);
        
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
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr lphModuleArray, uint cb,
        out uint cbNeeded, ListModules FilterFlags);
        
        //GetModuleInformation
        [DllImport(PsapiLib, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULE_INFO lpModInfo, uint cb);
        
        //GetModuleBaseNameW
        [DllImport(PsapiLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule, StringBuilder lpBaseName, uint nSize);
        
        //GetModuleFileNameExW
        [DllImport(PsapiLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);
        
        ////GetMappedFileNameW
        [DllImport(PsapiLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetMappedFileNameW(IntPtr hProcess, IntPtr lpAddress, StringBuilder lpFilename, uint nSize);
    }
    public class DbgHelp
    {
        private const string DbgHelpLib = "dbghelp.dll";
        
        //SymInitialize
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Ansi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, [MarshalAs(UnmanagedType.Bool)] bool InvadeProcess);
        
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
        public static extern bool SymGetSymFromAddr64(IntPtr hProcess, ulong Address, [Out] ulong OffestFromSymbol, IntPtr Symbol);

        //SymFromAddr
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromAddr(IntPtr hProcess, ulong Address, [Out] ulong OffestFromSymbol, IntPtr Symbol);
        
        //SymLoadModuleEx
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern ulong SymLoadModuleEx(IntPtr hProcess, IntPtr hFile, string ImageName, string ModuleName,
        IntPtr BaseOfDll, int DllSize, IntPtr Data, int Flags);
        
        //StackWalk64
        [DllImport(DbgHelpLib, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StackWalk64
        (
        uint MachineType, //In
        IntPtr hProcess, //In
        IntPtr hThread, //In
        IntPtr StackFrame, //In_Out
        IntPtr ContextRecord, //In_Out
        ReadProcessMemoryDelegate ReadMemoryRoutine, //_In_opt_
        SymFunctionTableAccess64Delegate FunctionTableAccessRoutine, //_In_opt_
        SymGetModuleBase64Delegate GetModuleBaseRoutine, //_In_opt_
        TranslateAddressProc64Delegate TranslateAddress //_In_opt_
        );
        
        //StackWalk64 Callback Delegates
        public delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesRead);
        public delegate IntPtr SymFunctionTableAccess64Delegate(IntPtr hProcess, ulong AddrBase);
        public delegate ulong SymGetModuleBase64Delegate(IntPtr hProcess, ulong Address);
        public delegate ulong TranslateAddressProc64Delegate(IntPtr hProcess, IntPtr hThread, IntPtr lpAddress64);
    }
    
    #endregion Functions
    
    public class Constants
    {
        public const uint MAX_NAMELEN = 0x00000400;
        public const uint SYMOPT_CASE_INSENSITIVE = 0x00000001;
        public const uint SYMOPT_UNDNAME = 0x00000002;
        public const uint SYMOPT_DEFERRED_LOADS = 0x00000004;
        public const uint SYMOPT_NO_CPP = 0x00000008;
        public const uint SYMOPT_LOAD_LINES = 0x00000010;
        public const uint SYMOPT_OMAP_FIND_NEAREST = 0x00000020;
        public const uint SYMOPT_LOAD_ANYTHING = 0x00000040;
        public const uint SYMOPT_IGNORE_CVREC = 0x00000080;
        public const uint SYMOPT_NO_UNQUALIFIED_LOADS = 0x00000100;
        public const uint SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200;
        public const uint SYMOPT_EXACT_SYMBOLS = 0x00000400;
        public const uint SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = 0x00000800;
        public const uint SYMOPT_IGNORE_NT_SYMPATH = 0x00001000;
        public const uint SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000;
        public const uint SYMOPT_PUBLICS_ONLY = 0x00004000;
        public const uint SYMOPT_NO_PUBLICS = 0x00008000;
        public const uint SYMOPT_AUTO_PUBLICS = 0x00010000;
        public const uint SYMOPT_NO_IMAGE_SEARCH = 0x00020000;
        public const uint SYMOPT_SECURE = 0x00040000;
        public const uint SYMOPT_DEBUG = 0x80000000;
        public const uint UNDNAME_COMPLETE = 0x00000000; // Enable full undecoration
        public const uint UNDNAME_NAME_ONLY = 0x00001000; // Crack only the name for primary declaration;
    }
}
