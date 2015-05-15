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

function Get-StackTrace ($ProcessId, $ThreadId) {
<#
.SYNOPSIS

A bunch of API calls for walking thread stacks.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>

    #StackWalk64 Callback Delegates
    $SymFunctionTableAccess64Delegate = [Func[IntPtr, UInt64, IntPtr]] { param([IntPtr]$hProcess, [UInt64]$AddrBase); [Win32.dbghelp]::SymFunctionTableAccess64($hProcess, $AddrBase) }
    $SymGetModuleBase64Delegate = [Func[IntPtr, UInt64, UInt64]] { param([IntPtr]$hProcess, [UInt64]$Address); [Win32.dbghelp]::SymGetModuleBase64($hProceess, $Address) }

    $lpContextRecord = New-Object IntPtr
    $Stackframe = New-Object STACKFRAME64
    [UInt32]$ImageType = 0

    $hProcess = [Win32.kernel32]::OpenProcess([ProcessAccess]::All, $false, $ProcessId)
    $hThread = [Win32.kernel32]::OpenThread([ThreadAccess]::All, $false, $ThreadId)

    [Win32.dbghelp]::SymInitialize($hProcess, $null, $false)

    $Wow64 = $false
    $SysInfo = New-Object SYSTEM_INFO
    [Win32.kernel32]::GetNativeSystemInfo([ref] $SysInfo)

    if ($SysInfo.ProcessorArchitecture -ne [ProcessorArch]::INTEL) { [Win32.kernel32]::IsWow64Process($hProcess, [ref]$Wow64) }

    if ($Wow64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = New-Object X86_CONTEXT
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        [Win32.kernel32]::Wow64SuspendThread($hThread)
        [Win32.kernel32]::Wow64GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][X86_CONTEXT])
        $Stackframe = Initialize-Stackframe ([AddressMode]::_Flat) $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp (New-Object UInt64)
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::INTEL)
    {
        [UInt32]$ImageType = [ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([ListModules]::_32Bit)

        $ContextRecord = New-Object X86_CONTEXT
        $ContextRecord.ContextFlags = [X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([X86_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        [Win32.kernel32]::SuspendThread($hThread)
        [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [X86_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][X86_CONTEXT])
        $Stackframe = Initialize-Stackframe ([AddressMode]::_Flat) $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp (New-Object UInt64)
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::AMD64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::AMD64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = New-Object AMD64_CONTEXT
        $ContextRecord.ContextFlags = [AMD64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([AMD64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        [Win32.kernel32]::SuspendThread($hThread)
        [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [AMD64_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][AMD64_CONTEXT])
        $Stackframe = Initialize-Stackframe ([AddressMode]::_Flat) $ContextRecord.Rip $ContextRecord.Rsp $ContextRecord.Rsp (New-Object UInt64)
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [ProcessorArch]::IA64)
    {
        [UInt32]$ImageType = [ImageFileMachine]::IA64

        Import-ModuleSymbols $hProcess ([ListModules]::_64Bit)

        $ContextRecord = New-Object IA64_CONTEXT
        $ContextRecord.ContextFlags = [IA64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IA64_CONTEXT]::GetSize())
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        [Win32.kernel32]::SuspendThread($hThread)
        [Win32.kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [IA64_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][IA64_CONTEXT])
        $Stackframe = Initialize-Stackframe ([AddressMode]::_Flat) $ContextRecord.StIIP $ContextRecord.IntSp $ContextRecord.RsBSP $ContextRecord.IntSp
    }
    #Marshal Stackframe to pointer
    $lpStackFrame = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Stackframe))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Stackframe, $lpStackFrame, $false)

    #Walk the Stack
    for ($i = 0; ; $i++)
    {
        #Get Stack frame
        [Win32.dbghelp]::StackWalk64($ImageType, $hProcess, $hThread, $lpStackFrame, $lpContextRecord, $null, $SymFunctionTableAccess64Delegate, $SymGetModuleBase64Delegate, $null)
        $Stackframe = [STACKFRAME64][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpStackFrame, [Type][STACKFRAME64])

        if ($Stackframe.AddrReturn.Offset -eq 0) { break } #End of stack reached

        $ModulePath = New-Object System.Text.StringBuilder(256)

        [Win32.psapi]::GetMappedFileNameW($hProcess, (Convert-UIntToInt $Stackframe.AddrPC.Offset), $ModulePath, $ModulePath.Capacity) 
        $ModulePath = $ModulePath.ToString().TrimEnd([Byte]0)

        $Symbol = Get-SymbolFromAddress $hProcess $Stackframe.AddrPC.Offset
        $SymbolName = $Symbol.Name.ToString().TrimEnd([Byte]0)
    }
}
