function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func {
# A helper function used to reduce typing while defining function prototypes for Add-Win32Type.
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type {
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field {
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct {
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

Function Get-DelegateType {
#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Param
	(
	    [OutputType([Type])]
	        
	    [Parameter( Position = 0)]
	    [Type[]]
	    $Parameters = (New-Object Type[](0)),
	        
	    [Parameter( Position = 1 )]
	    [Type]
	    $ReturnType = [Void]
	)

	$Domain = [AppDomain]::CurrentDomain
	$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	$TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	$ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	$MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	$MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	Write-Output $TypeBuilder.CreateType()
}

function Convert-UIntToInt {
	Param(
	    [Parameter(Position = 0, Mandatory = $true)]
	    [UInt64]
	    $Value
	)
		
	[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
	return ([BitConverter]::ToInt64($ValueBytes, 0))
}

function Initialize-Win32 {
<#
.SYNOPSIS

A bunch of structs, enums, and function imports.

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

    $MemoryPageProtection = `
    psenum $Mod MemoryPageProtection UInt32 @{
        NoAccess         = 0x001
        Readonly         = 0x002
        ReadWrite        = 0x004
        WriteCopy        = 0x008
        Execute          = 0x010
        ExecuteRead      = 0x020
        ExecuteReadWrite = 0x040
        ExecuteWriteCopy = 0x080
        Guard            = 0x100
        NoCache          = 0x200
        WriteCombine     = 0x400
    } -Bitfield
    
    $MemoryPageState = `
    psenum $Mod MemoryPageState UInt32 @{
        Commited = 0x01000
        Free     = 0x10000
        Reserved = 0x02000
    } -Bitfield

    $MemoryPageType = `
    psenum $Mod MemoryPageType UInt32 @{
        Image   = 0x1000000
        Mapped  = 0x0040000
        Private = 0x0020000
    } -Bitfield

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
        FloatSave = field 7 FLOATING_SAVE_AREA
        
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
        R11 = field 32 UInt64 -Offset 0xd0
        R12 = field 33 UInt64 -Offset 0xd8
        R13 = field 34 UInt64 -Offset 0xe0
        R14 = field 35 UInt64 -Offset 0xe8
        R15 = field 36 UInt64 -Offset 0xf0

        # Program Counter
        Rip = field 37 UInt64 -Offset 0xf8

        # Floating Point State
        FltSave = field 38 UInt64 -Offset 0x100
        Legacy = field 39 UInt64 -Offset 0x120
        Xmm0  = field 40 UInt64 -Offset 0x1a0
        Xmm1  = field 41 UInt64 -Offset 0x1b0
        Xmm2  = field 42 UInt64 -Offset 0x1c0
        Xmm3  = field 43 UInt64 -Offset 0x1d0
        Xmm4  = field 44 UInt64 -Offset 0x1e0
        Xmm5  = field 45 UInt64 -Offset 0x1f0
        Xmm6  = field 46 UInt64 -Offset 0x200
        Xmm7  = field 47 UInt64 -Offset 0x210
        Xmm8  = field 48 UInt64 -Offset 0x220
        Xmm9  = field 49 UInt64 -Offset 0x230
        Xmm10 = field 50 UInt64 -Offset 0x240
        Xmm11 = field 51 UInt64 -Offset 0x250
        Xmm12 = field 52 UInt64 -Offset 0x260
        Xmm13 = field 53 UInt64 -Offset 0x270
        Xmm14 = field 54 UInt64 -Offset 0x280
        Xmm15 = field 55 UInt64 -Offset 0x290

        # Vector Registers
        VectorRegister = field 56 UInt64 -Offset 0x300
        VectorControl = field 57 UInt64 -Offset 0x4a0

        # Special Debug Control Registers
        DebugControl = field 58 UInt64 -Offset 0x4a8
        LastBranchToRip = field 59 UInt64 -Offset 0x4b0
        LastBranchFromRip = field 60 UInt64 -Offset 0x4b8
        LastExceptionToRip = field 61 UInt64 -Offset 0x4c0
        LastExceptionFromRip = field 62 UInt64 -Offset 0x4c8
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
        KiCallUserMode = field 5 UInt64
        KeUserCallbackDispatcher = field 6 UInt64
        SystemRangeStart = field 7 UInt64
        KiUserExceptionDispatcher = field 8 UInt64
        StackBase = field 9 UInt64
        StackLimit = field 10 UInt64
        Reserved = field 11 UInt64[] -MarshalAs @('ByValArray', 5)
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

    if ([IntPtr]::Size -eq 4) {
        $MEMORY_BASIC_INFORMATION = `
        struct $Mod MEMORY_BASIC_INFO @{
            BaseAddress = field 0 Int32
            AllocationBase = field 1 Int32
            AllocationProtect = field 2 MemoryPageProtection
            RegionSize = field 3 Int32
            State = field 4 MemoryPageState
            Protect = field 5 MemoryPageProtection
            Type = field 6 MemoryPageType
        }
    } else {
        $MEMORY_BASIC_INFORMATION = `
        struct $Mod MEMORY_BASIC_INFO @{
            BaseAddress = field 0 Int64
            AllocationBase = field 1 Int64
            AllocationProtect = field 2 MemoryPageProtection
            Alignment1 = field 3 Int32
            RegionSize = field 4 Int64
            State = field 5 MemoryPageState
            Protect = field 6 MemoryPageProtection
            Type = field 7 MemoryPageType
            Alignment2 = field 8 Int32
        }
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
        (func kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [Byte].MakeArrayType(), [Int32], [Int32].MakeByRefType()) -SetLastError),
        (func kernel32 VirtualQueryEx ([Int64]) @([IntPtr], [IntPtr], [MEMORY_BASIC_INFO].MakeByRefType(), [Int32]) -SetLastError),
        
        #IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, [Out] int lpNumberOfBytesRead);

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

function Export-ModuleFromMemory {
    Param (
        [Parameter(ParameterSetName = "ByProcessHandle", Position = 0, Mandatory = $True)] 
        [IntPtr] 
        $hProcess,

        [Parameter(ParameterSetName = "ByProcessId", Position = 0, Mandatory = $True)]
        [Int32] 
        $ProcessId,

        [Parameter(Position = 1, Mandatory = $True)] 
        [IntPtr] 
        $ModuleAddress,

        [Parameter()] 
        [String] 
        $ToFile
    )

    if (!$PSBoundParameters['hProcess']) 
    {
        $hProcess = [Win32.kernel32]::OpenProcess([ProcessAccess]::All, $false, $ProcessId)
    }
    $SystemInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    $null = [Win32.kernel32]::GetNativeSystemInfo([ref]$SystemInfo)
    
    $MemoryInfo = [Activator]::CreateInstance([MEMORY_BASIC_INFO])
    $null = [Win32.kernel32]::VirtualQueryEx($hProcess, $ModuleAddress, [ref]$MemoryInfo, $SystemInfo.PageSize)

    $BytesRead = 0
    $ByteArray = [Activator]::CreateInstance([Byte[]], [Int32]$MemoryInfo.RegionSize)
    $null = [Win32.kernel32]::ReadProcessMemory($hProcess, $MemoryInfo.BaseAddress, $ByteArray, $MemoryInfo.RegionSize, [ref]$BytesRead)

    if($ToFile)
    {  
        if ($FilePath = Split-Path $ToFile)
        {
            if (Test-Path $FilePath)
            {
                $File = "$(Resolve-Path $FilePath)\$ToFile"
            }
            else
            {
                throw "Invalid file path!"
            }
        }
        else
        {
            $File = "$(Resolve-Path .)\$ToFile"
        }
        
        $Stream = New-Object System.IO.FileStream($File, [System.IO.FileMode]::OpenOrCreate)
        $Stream.Write($ByteArray, 0, [Int32]$MemoryInfo.RegionSize)
        $Stream.Close()
    }
    else { Write-Output $ByteArray }
}

function Initialize-Stackframe ($OffsetPC, $OffsetFrame, $OffsetStack, $OffsetBStore) {

    $StackFrame = [Activator]::CreateInstance([STACKFRAME64])
    $Addr64 = [Activator]::CreateInstance([ADDRESS64])
    $Addr64.Mode = [AddressMode]::_Flat
    
    $Addr64.Offset = $OffsetPC
    $StackFrame.AddrPC = $Addr64

    $Addr64.Offset = $OffsetFrame
    $StackFrame.AddrFrame = $Addr64

    $Addr64.Offset = $OffsetStack
    $StackFrame.AddrStack = $Addr64

    $Addr64.Offset = $OffsetBStore
    $StackFrame.AddrBStore = $Addr64
    
    return $StackFrame
}

function Import-ModuleSymbols ($hProcess, $ModuleType) {

    #Initialize parameters for EPM
    [UInt32]$cbNeeded = 0
    $null = [Win32.psapi]::EnumProcessModulesEx($hProcess, $null, 0, [ref]$cbNeeded, $ModuleType)
    [UInt64]$ArraySize = $cbNeeded / [IntPtr]::Size

    $hModules = [Activator]::CreateInstance([IntPtr[]], [Int32]$ArraySize)

    $cb = $cbNeeded;
    $null = [Win32.psapi]::EnumProcessModulesEx($hProcess, $hModules, $cb, [ref]$cbNeeded, $ModuleType);
    for ($i = 0; $i -lt $ArraySize; $i++)
    {
        $ModInfo = [Activator]::CreateInstance([MODULE_INFO])
        $lpFileName = [Activator]::CreateInstance([System.Text.StringBuilder], 256)
        $lpModuleBaseName = [Activator]::CreateInstance([System.Text.StringBuilder], 32)

        $null = [Win32.psapi]::GetModuleFileNameExW($hProcess, $hModules[$i], $lpFileName, $lpFileName.Capacity)
        $null = [Win32.psapi]::GetModuleBaseNameW($hProcess, $hModules[$i], $lpModuleBaseName, $lpModuleBaseName.Capacity)
        $null = [Win32.psapi]::GetModuleInformation($hProcess, $hModules[$i], [ref]$ModInfo,  [MODULE_INFO]::GetSize())
        $null = [Win32.dbghelp]::SymLoadModuleEx($hProcess, [IntPtr]::Zero, $lpFileName.ToString(), $lpModuleBaseName.ToString(), $ModInfo.lpBaseOfDll, [Int32]$ModInfo.SizeOfImage, [IntPtr]::Zero, 0);
    }
}

function Get-SymbolFromAddress ($hProcess, $Address) {
    
    #Initialize params for SymGetSymFromAddr64
    $Symbol = [Activator]::CreateInstance([IMAGEHLP_SYMBOLW64])
    $Symbol.SizeOfStruct = [IMAGEHLP_SYMBOLW64]::GetSize()
    $Symbol.MaxNameLength = 32

    $lpSymbol = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Symbol))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Symbol, $lpSymbol, $false)
    [UInt64]$Offset = 0

    $null = [Win32.dbgHelp]::SymGetSymFromAddr64($hProcess, $Address, [ref]$Offset, $lpSymbol)
            
    $Symbol = [IMAGEHLP_SYMBOLW64]$lpSymbol
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpSymbol)

    return $Symbol
}

function Get-ProcessTrace {
Param(
        [Parameter(ParameterSetName = 'ByName', Position = 0)]
        [String]
        $Name,

        [Parameter(ParameterSetName = 'ByPipe', ValueFromPipeline = $true, Position = 0)]
        [System.Diagnostics.Process[]]
        $Process
     )
        if ($PSBoundParameters['Name'])
        {
            foreach ($Process in ( Get-Process -Name $Name ))
            {
                $Process.Threads | ForEach-Object { Trace-Thread -ProcessId $Process.Id -ThreadId $_.Id }
            }
        }

        if ($PSBoundParameters['Process'])
        {
            foreach ($p in $Process)
            {
                $p.Threads | ForEach-Object { Trace-Thread -ProcessId $p.Id -ThreadId $_.Id }
            }
        }
}

function Trace-Thread {
<#
.SYNOPSIS

A bunch of API calls for walking thread stacks.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>

    Param(
        [Parameter(Position = 0, Mandatory = $true)]
	    [Int32]
	    $ProcessId,
    
        [Parameter(Position = 1, Mandatory = $true)] 
        [Int32]
        $ThreadId
	)

    #def StackWalk64 Callback Delegates
    $SymFunctionTableAccess64Delegate = Get-DelegateType @([IntPtr], [UInt64]) ([IntPtr])
    $Action = { Param([IntPtr]$hProcess, [UInt64]$AddrBase)
                [Win32.dbghelp]::SymFunctionTableAccess64($hProcess, $AddrBase) }
    $FunctionTableAccess = $Action -as $SymFunctionTableAccess64Delegate

    $SymGetModuleBase64Delegate = Get-DelegateType @([IntPtr], [UInt64]) ([UInt64])
    $Action = { Param([IntPtr]$hProcess, [UInt64]$Address)
                [Win32.dbghelp]::SymGetModuleBase64($hProcess, $Address) }
    $GetModuleBase = $Action -as $SymGetModuleBase64Delegate

    #Initialize variables
    $lpContextRecord = [Activator]::CreateInstance([IntPtr])
    $Stackframe = [Activator]::CreateInstance([STACKFRAME64])
    [UInt32]$ImageType = 0

    #Get Process/Thread handles
    $hProcess = [Win32.kernel32]::OpenProcess([ProcessAccess]::All, $false, $ProcessId)
    $hThread = [Win32.kernel32]::OpenThread([ThreadAccess]::All, $false, $ThreadId)

    #Initialize Symbol handler
    $null = [Win32.dbghelp]::SymInitialize($hProcess, $null, $false)

    $Wow64 = $false
    $SysInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    [Win32.kernel32]::GetNativeSystemInfo([ref] $SysInfo)

    #Determine Image/Processor type and configure setup accordingly
    if ($SysInfo.ProcessorArchitecture -ne [ProcessorArch]::INTEL) { $null = [Win32.kernel32]::IsWow64Process($hProcess, [ref]$Wow64) }

    if ($Wow64) {

        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::Wow64SuspendThread($hThread)
        $null = [Win32.kernel32]::Wow64GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::INTEL) {

        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::SuspendThread($hThread)
        $null = [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::AMD64) {

        [UInt32]$ImageType = [ImageFileMachine]::AMD64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = [Activator]::CreateInstance([AMD64_CONTEXT])
        $ContextRecord.ContextFlags = [AMD64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([AMD64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::SuspendThread($hThread)
        $null = [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [AMD64_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Rip $ContextRecord.Rsp $ContextRecord.Rsp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::IA64) {

        [UInt32]$ImageType = [ImageFileMachine]::IA64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = [Activator]::CreateInstance([IA64_CONTEXT])
        $ContextRecord.ContextFlags = [IA64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IA64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::SuspendThread($hThread)
        $null = [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [IA64_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.StIIP $ContextRecord.IntSp $ContextRecord.RsBSP $ContextRecord.IntSp
    }

    #Marshal Stackframe to pointer
    $lpStackFrame = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Stackframe))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Stackframe, $lpStackFrame, $false)

    #Walk the Stack
    for ($i = 0; ; $i++)
    {
        #Get Stack frame
        $null = [Win32.dbghelp]::StackWalk64($ImageType, $hProcess, $hThread, $lpStackFrame, $lpContextRecord, $null, $FunctionTableAccess, $GetModuleBase, $null)
        $Stackframe = [STACKFRAME64]$lpStackFrame

        if ($Stackframe.AddrReturn.Offset -eq 0) { break } #End of stack reached

        $MappedFile = [Activator]::CreateInstance([System.Text.StringBuilder], 256)
        $null = [Win32.psapi]::GetMappedFileNameW($hProcess, (Convert-UIntToInt $Stackframe.AddrPC.Offset), $MappedFile, $MappedFile.Capacity)

        $Symbol = Get-SymbolFromAddress $hProcess $Stackframe.AddrPC.Offset
        $SymbolName = (([String]$Symbol.Name).Replace(' ','')).TrimEnd([Byte]0)

        $CallStackEntry = New-Object PSObject -Property @{
                            ProcessId = $ProcessId
                            ThreadId = $ThreadId
                            AddrPC = $Stackframe.AddrPC.Offset
                            AddrReturn = $Stackframe.AddrReturn.Offset
                            Symbol = $SymbolName
                            MappedFile = $MappedFile
                          }

        Write-Output $CallStackEntry
    }

    #Cleanup
    $null = [Win32.dbghelp]::SymCleanup($hProcess)
    $null = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpStackFrame)
    $null = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpContextRecord)
    $null = [Win32.kernel32]::ResumeThread($hThread)
    $null = [Win32.kernel32]::CloseHandle($hProcess)
    $null = [Win32.kernel32]::CloseHandle($hThread)
}
