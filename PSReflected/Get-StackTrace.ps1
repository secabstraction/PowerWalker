#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
Function Get-DelegateType
{
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

function Convert-UIntToInt
{
	Param(
	    [Parameter(Position = 0, Mandatory = $true)]
	    [UInt64]
	    $Value
	)
		
	[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
	return ([BitConverter]::ToInt64($ValueBytes, 0))
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

    #StackWalk64 Callback Delegates
    $SymFunctionTableAccess64Delegate = Get-DelegateType @([IntPtr], [UInt64]) ([IntPtr])
    $Action = { Param([IntPtr]$hProcess, [UInt64]$AddrBase)
                [Win32.dbghelp]::SymFunctionTableAccess64($hProcess, $AddrBase) }
    $FunctionTableAccess = $Action -as $SymFunctionTableAccess64Delegate

    $SymGetModuleBase64Delegate = Get-DelegateType @([IntPtr], [UInt64]) ([UInt64])
    $Action = { Param([IntPtr]$hProcess, [UInt64]$Address)
                [Win32.dbghelp]::SymGetModuleBase64($hProcess, $Address) }
    $GetModuleBase = $Action -as $SymGetModuleBase64Delegate

    $lpContextRecord = [Activator]::CreateInstance([IntPtr])
    $Stackframe = [Activator]::CreateInstance([STACKFRAME64])
    [UInt32]$ImageType = 0

    $hProcess = [Win32.kernel32]::OpenProcess([ProcessAccess]::All, $false, $ProcessId)
    $hThread = [Win32.kernel32]::OpenThread([ThreadAccess]::All, $false, $ThreadId)

    $null = [Win32.dbghelp]::SymInitialize($hProcess, $null, $false)

    $Wow64 = $false
    $SysInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    [Win32.kernel32]::GetNativeSystemInfo([ref] $SysInfo)

    if ($SysInfo.ProcessorArchitecture -ne [ProcessorArch]::INTEL) { $null = [Win32.kernel32]::IsWow64Process($hProcess, [ref]$Wow64) }

    if ($Wow64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::Wow64GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::INTEL)
    {
        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::AMD64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::AMD64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = [Activator]::CreateInstance([AMD64_CONTEXT])
        $ContextRecord.ContextFlags = [AMD64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([AMD64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [AMD64_CONTEXT]$lpContextRecord
        $Stackframe = Initialize-Stackframe $ContextRecord.Rip $ContextRecord.Rsp $ContextRecord.Rsp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::IA64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::IA64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = [Activator]::CreateInstance([IA64_CONTEXT])
        $ContextRecord.ContextFlags = [IA64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IA64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

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
    $null = [Win32.kernel32]::CloseHandle($hProcess)
    $null = [Win32.kernel32]::CloseHandle($hThread)
}
