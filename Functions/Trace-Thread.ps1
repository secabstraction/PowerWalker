function Trace-Thread {
[CmdletBinding()]
    Param (                     
        [Parameter(Mandatory = $true)]
        [Int16]$ProcessId,

        [Parameter(Mandatory = $true)]
        [Int16]$ThreadId,

        [Parameter()]
        [IntPtr]$ProcessHandle
    ) 

    if (!$PSBoundParameters['ProcessHandle']) {
        # Get process handle
        $ProcessAllAccess = 0x1F0FFF
        if (($ProcessHandle = [Win32.kernel32]::OpenProcess($ProcessAllAccess, $false, $ProcessId)) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception
            return
        }

        if (![Win32.Dbghelp]::SymInitialize($ProcessHandle, $null, $false)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception
            return
        }
    }

    # Get thread handle
    $ThreadAllAccess = 0x1F03FF
    if (($hThread = [Win32.Kernel32]::OpenThread($ThreadAllAccess, $false, $ThreadId)) -eq 0) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception
        return
    }
            
    $SymFunctionTableAccess64Delegate = New-DelegateType @([IntPtr], [UInt64]) ([IntPtr])
    $Action = { Param ([IntPtr]$ProcessHandle, [UInt64]$AddrBase) [Win32.Dbghelp]::SymFunctionTableAccess64($ProcessHandle, $AddrBase) }
    $FunctionTableAccess = $Action -as $SymFunctionTableAccess64Delegate

    $SymGetModuleBase64Delegate = New-DelegateType @([IntPtr], [UInt64]) ([UInt64])
    $Action = { Param ([IntPtr]$ProcessHandle, [UInt64]$Address) [Win32.Dbghelp]::SymGetModuleBase64($ProcessHandle, $Address) }
    $GetModuleBase = $Action -as $SymGetModuleBase64Delegate

    # Initialize some things
    $lpContextRecord = [IntPtr]::Zero
    $StackFrame = [Activator]::CreateInstance([STACKFRAME64])
    $ImageType = 0
    $Wow64 = $false
    try { $SystemInfo = Get-NativeSystemInfo }
    catch { $SystemInfo = Get-SystemInfo }

    # If not x86 processor, check for Wow64
    if ($SystemInfo.ProcessorArchitecture -ne 0) {
        if (![Win32.Kernel32]::IsWow64Process($ProcessHandle, [ref]$Wow64)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }
    }

    if ($Wow64) {
        $ImageType = 0x014C # I386/x86

        Import-ModuleSymbols -ProcessHandle $ProcessHandle

        # Initialize x86 context in memory
        $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
        $ContextRecord.ContextFlags = 0x1003F #All
        $lpContextRecord = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($ContextRecord))
        [Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

        if ([Win32.Kernel32]::Wow64SuspendThread($hThread) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
            return
        }
        if (![Win32.Kernel32]::Wow64GetThreadContext($hThread, $lpContextRecord)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }

        $ContextRecord = [Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][X86_CONTEXT])
        $StackFrame = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
    }

    else {
        switch ($SystemInfo.ProcessorArchitecture.value__) { 
                
            0 { # x86 processor
                $ImageType = 0x014C # I386/x86

                Import-ModuleSymbols -ProcessHandle $ProcessHandle

                # Initialize x86 context in memory
                $ContextRecord = [Activator]::CreateInstance([X86_CONTEXT])
                $ContextRecord.ContextFlags = 0x1003F #All
                $lpContextRecord = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($ContextRecord))
                [Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

                if ($Kernel32::SuspendThread($hThread) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }
                if (!$Kernel32::GetThreadContext($hThread, $lpContextRecord)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }

                $ContextRecord = [Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][X86_CONTEXT])
                $StackFrame = Initialize-Stackframe $ContextRecord.Eip $ContextRecord.Esp $ContextRecord.Ebp $null
            }
            
            9 { # AMD64 processor
                $ImageType = 0x8664 # AMD64

                Import-ModuleSymbols -ProcessHandle $ProcessHandle

                # Initialize AMD64 context in memory
                $ContextRecord = [Activator]::CreateInstance([AMD64_CONTEXT])
                $ContextRecord.ContextFlags = 0x10003B #All
                $lpContextRecord = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($ContextRecord))
                [Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

                if ([Win32.Kernel32]::SuspendThread($hThread) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }
                if (![Win32.Kernel32]::GetThreadContext($hThread, $lpContextRecord)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }

                $ContextRecord = [Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][AMD64_CONTEXT])
                $StackFrame = Initialize-Stackframe $ContextRecord.Rip $ContextRecord.Rsp $ContextRecord.Rsp $null
            }
                            
            6 { # IA64 processor
                $ImageType = 0x0200 # IA64

                Import-ModuleSymbols -ProcessHandle $ProcessHandle

                # Initialize IA64 context in memory
                $ContextRecord = [Activator]::CreateInstance([IA64_CONTEXT])
                $ContextRecord.ContextFlags = 0x8003D #All
                $lpContextRecord = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($ContextRecord))
                [Runtime.InteropServices.Marshal]::StructureToPtr($ContextRecord, $lpContextRecord, $false)

                if ($Kernel32::SuspendThread($hThread) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }
                if (!$Kernel32::GetThreadContext($hThread, $lpContextRecord)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }

                $ContextRecord = [Runtime.InteropServices.Marshal]::PtrToStructure($lpContextRecord, [Type][IA64_CONTEXT])
                $StackFrame = Initialize-Stackframe $ContextRecord.StIIP $ContextRecord.IntSp $ContextRecord.RsBSP $ContextRecord.IntSp
            }
        }
    }

    Remove-Variable SystemInfo

    # Marshal Stackframe to pointer
    $lpStackFrame = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf($StackFrame))
    [Runtime.InteropServices.Marshal]::StructureToPtr($StackFrame, $lpStackFrame, $false)

    # Walk the Stack
    do {
        # Get Stackframe
        if (![Win32.Dbghelp]::StackWalk64($ImageType, $ProcessHandle, $hThread, $lpStackFrame, $lpContextRecord, $null, $FunctionTableAccess, $GetModuleBase, $null)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }

        $StackFrame = [Runtime.InteropServices.Marshal]::PtrToStructure($lpStackFrame, [Type][STACKFRAME64]) 

        $FileName = New-Object Text.StringBuilder -ArgumentList 256
        [IntPtr]$VerifyAddress = Convert-UIntToInt $StackFrame.AddrPC.Offset

        if(![Win32.Psapi]::GetMappedFileNameW($ProcessHandle, $VerifyAddress, $FileName, $FileName.Capacity)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }

        $Symbol = $null
        $Symbol = Get-SymbolFromAddress -ProcessHandle $ProcessHandle -Address $StackFrame.AddrPC.Offset -ErrorAction SilentlyContinue
        if ($Symbol) { $SymbolName = (([String]$Symbol.Name).Replace(' ','')).TrimEnd([Byte]0) }
        else { $SymbolName = $null }
        
        $Properties = @{
            ProcessId  = $ProcessId
            ThreadId   = $ThreadId
            AddrPC     = $StackFrame.AddrPC.Offset
            AddrReturn = $StackFrame.AddrReturn.Offset
            Symbol     = $SymbolName
            MappedFile = $FileName
        }

        New-Object psobject -Property $Properties

    } until ($StackFrame.AddrReturn.Offset -eq 0) # End of stack

    # Cleanup
    [Runtime.InteropServices.Marshal]::FreeHGlobal($lpStackFrame)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($lpContextRecord)

    if ([Win32.Kernel32]::ResumeThread($hThread) -eq -1) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception 
    }
    if (![Win32.Kernel32]::CloseHandle($hThread)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception 
    }
    if (!$PSBoundParameters['ProcessHandle']) {
        if (![Win32.Dbghelp]::SymCleanup($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }
        if (![Win32.Kernel32]::CloseHandle($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception 
        }
    }
    [GC]::Collect()
}
