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
        $hProcess = [Kernel32]::OpenProcess([ProcessAccess]::All, $false, $ProcessId)
    }
    $SystemInfo = [Activator]::CreateInstance([My.SYSTEM_INFO])
    $null = [Kernel32]::GetNativeSystemInfo([ref]$SystemInfo)
    
    $MemoryInfo = [Activator]::CreateInstance([My.MEMORY_BASIC_INFORMATION])
    $null = [Kernel32]::VirtualQueryEx($hProcess, $ModuleAddress, [ref]$MemoryInfo, $SystemInfo.PageSize)

    $BytesRead = 0
    $ByteArray = [Activator]::CreateInstance([Byte[]], [Int32]$MemoryInfo.RegionSize)
    $null = [Kernel32]::ReadProcessMemory($hProcess, $MemoryInfo.BaseAddress, $ByteArray, $MemoryInfo.RegionSize, [ref]$BytesRead)

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

    $StackFrame = [Activator]::CreateInstance([My.STACKFRAME64])
    $Addr64 = [Activator]::CreateInstance([My.ADDRESS64])
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
    $cbNeeded = 0
    $null = [Psapi]::EnumProcessModulesEx($hProcess, $null, 0, [ref]$cbNeeded, $ModuleType)
    $ArraySize = $cbNeeded / [IntPtr]::Size

    $hModules = [Activator]::CreateInstance([IntPtr[]], $ArraySize)

    $cb = $cbNeeded;
    $null = [Psapi]::EnumProcessModulesEx($hProcess, $hModules, $cb, [ref]$cbNeeded, $ModuleType);
    for ($i = 0; $i -lt $ArraySize; $i++)
    {
        $ModInfo = [Activator]::CreateInstance([My.MODULE_INFO])
        $lpFileName = [Activator]::CreateInstance([System.Text.StringBuilder], 256)
        $lpModuleBaseName = [Activator]::CreateInstance([System.Text.StringBuilder], 32)

        $null = [Psapi]::GetModuleFileNameExW($hProcess, $hModules[$i], $lpFileName, $lpFileName.Capacity)
        $null = [Psapi]::GetModuleBaseNameW($hProcess, $hModules[$i], $lpModuleBaseName, $lpModuleBaseName.Capacity)
        $null = [Psapi]::GetModuleInformation($hProcess, $hModules[$i], [ref]$ModInfo, [System.Runtime.InteropServices.Marshal]::SizeOf([My.MODULE_INFO]))
        $null = [DbgHelp]::SymLoadModuleEx($hProcess, [IntPtr]::Zero, $lpFileName.ToString(), $lpModuleBaseName.ToString(), $ModInfo.lpBaseOfDll, $ModInfo.SizeOfImage, [IntPtr]::Zero, 0);
    }
}

function Get-SymbolFromAddress ($hProcess, $Address) {
    
    #Initialize params for SymGetSymFromAddr64
    $Symbol = [Activator]::CreateInstance([My.IMAGEHLP_SYMBOLW64])
    $Symbol.SizeOfStruct = [My.IMAGEHLP_SYMBOLW64]::GetSize()
    $Symbol.MaxNameLength = 32

    $lpSymbol = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Symbol))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Symbol, $lpSymbol, $false)
    $Offset = 0

    $null = [Win32.dbgHelp]::SymGetSymFromAddr64($hProcess, $Address, [ref]$Offset, $lpSymbol)
            
    $Symbol = [My.IMAGEHLP_SYMBOLW64][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpSymbol, [Type][My.IMAGEHLP_SYMBOLW64])
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

    $EncodedCompressedFile = @'
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
'@
    $DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
    $UncompressedFileBytes = New-Object Byte[](36352)
    $DeflatedStream.Read($UncompressedFileBytes, 0, 36352) | Out-Null
    [Reflection.Assembly]::Load($UncompressedFileBytes)

    #StackWalk64 Callback Delegates
    $Action = { Param([IntPtr]$hProcess, [UInt64]$AddrBase)[DbgHelp]::SymFunctionTableAccess64($hProcess, $AddrBase) }
    $FunctionTableAccess = $Action -as [DbgHelp+SymFunctionTableAccess64Delegate]

    $Action = { Param([IntPtr]$hProcess, [UInt64]$Address) [DbgHelp]::SymGetModuleBase64($hProcess, $Address) }
    $GetModuleBase = $Action -as [DbgHelp+SymGetModuleBase64Delegate]

    $lpContextRecord = New-Object IntPtr
    $Stackframe = New-Object STACKFRAME64
    [UInt32]$ImageType = 0

    $hProcess = [Kernel32]::OpenProcess([My.ProcessAccess]::All, $false, $ProcessId)
    $hThread = [Kernel32]::OpenThread([My.ThreadAccess]::All, $false, $ThreadId)

    $null = [DbgHelp]::SymInitialize($hProcess, $null, $false)

    $Wow64 = $false
    $SysInfo = New-Object SYSTEM_INFO
    [Kernel32]::GetNativeSystemInfo([ref]$SysInfo)

    if ($SysInfo.ProcessorArchitecture -ne [My.ProcessorType]::INTEL) { $null = [Kernel32]::IsWow64Process($hProcess, [ref]$Wow64) }

    if ($Wow64)
    {
        $ImageType = [My.ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([My.ListModules]::_32Bit)

        $ContextRecord = New-Object My.X86_CONTEXT
        $ContextRecord.ContextFlags = [My.X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([My.X86_CONTEXT]))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Kernel32]::Wow64SuspendThread($hThread)
        $null = [Kernel32]::Wow64GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [My.X86_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][My.X86_CONTEXT])
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [My.ProcessorType]::INTEL)
    {
        $ImageType = [My.ImageFileMachine]::I386

        Import-ModuleSymbols $hProcess ([My.ListModules]::_32Bit)

        $ContextRecord = New-Object My.X86_CONTEXT
        $ContextRecord.ContextFlags = [My.X86ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([My.X86_CONTEXT]))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Kernel32]::SuspendThread($hThread)
        $null = [Kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [My.X86_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][My.X86_CONTEXT])
        $Stackframe = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [My.ProcessorType]::AMD64)
    {
        $ImageType = [My.ImageFileMachine]::AMD64

        Import-ModuleSymbols $hProcess ([My.ListModules]::_64Bit)

        $ContextRecord = New-Object My.AMD64_CONTEXT
        $ContextRecord.ContextFlags = [My.AMD64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([My.AMD64_CONTEXT]))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Kernel32]::SuspendThread($hThread)
        $null = [Kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [My.AMD64_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][My.AMD64_CONTEXT])
        $Stackframe = Initialize-Stackframe $ContextRecord.Rip $ContextRecord.Rsp $ContextRecord.Rsp $null
    }

    elseif ($SysInfo.ProcessorArchitecture -eq [My.ProcessorType]::IA64)
    {
        $ImageType = [My.ImageFileMachine]::IA64

        Import-ModuleSymbols $hProcess ([My.ListModules]::_64Bit)

        $ContextRecord = New-Object My.IA64_CONTEXT
        $ContextRecord.ContextFlags = [My.IA64ContextFlags]::All
        $lpContextRecord = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([My.IA64_CONTEXT]))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        $null = [Kernel32]::SuspendThread($hThread)
        $null = [Kernel32]::GetThreadContext($hThread, $lpContextRecord)

        $ContextRecord = [My.IA64_CONTEXT][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][My.IA64_CONTEXT])
        $Stackframe = Initialize-Stackframe $ContextRecord.StIIP $ContextRecord.IntSp $ContextRecord.RsBSP $ContextRecord.IntSp
    }
    #Marshal Stackframe to pointer
    $lpStackFrame = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Stackframe))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Stackframe, $lpStackFrame, $false)

    #Walk the Stack
    for ($i = 0; ; $i++)
    {
        #Get Stack frame
        $null = [DbgHelp]::StackWalk64($ImageType, $hProcess, $hThread, $lpStackFrame, $lpContextRecord, $null, $FunctionTableAccess, $GetModuleBase, $null)
        $Stackframe = [My.STACKFRAME64][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpStackFrame, [Type][My.STACKFRAME64])

        if ($Stackframe.AddrReturn.Offset -eq 0) { break } #End of stack reached

        $MappedFile = New-Object System.Text.StringBuilder(256)
        $null = [Psapi]::GetMappedFileNameW($hProcess, (Convert-UIntToInt $Stackframe.AddrPC.Offset), $MappedFile, $MappedFile.Capacity)

        $Symbol = Get-SymbolFromAddress $hProcess $Stackframe.AddrPC.Offset
        $SymbolName = (([String]$Symbol.Name).Replace(' ','')).TrimEnd([Byte]0)

        $CallStackEntry = New-Object PSObject -Property @{
                            ThreadId = $ThreadId
                            AddrPC = $Stackframe.AddrPC.Offset
                            AddrReturn = $Stackframe.AddrReturn.Offset
                            Symbol = $SymbolName
                            MappedFile = $MappedFile
                            }

        Write-Output $CallStackEntry
    }

    #Cleanup
    $null = [DbgHelp]::SymCleanup($hProcess)
    $null = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpStackFrame)
    $null = [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpContextRecord)
    $null = [Kernel32]::ResumeThread($hThread)
    $null = [Kernel32]::CloseHandle($hProcess)
    $null = [Kernel32]::CloseHandle($hThread)
}
