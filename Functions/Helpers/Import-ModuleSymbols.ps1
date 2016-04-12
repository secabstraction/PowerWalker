function Import-ModuleSymbols {
    Param (
        [Parameter(Mandatory = $true)]
        [IntPtr]$ProcessHandle
    )
                 
    # Initialize parameters for EPM
    $cbNeeded = 0
    if (![Win32.Psapi]::EnumProcessModulesEx($ProcessHandle, $null, 0, [ref]$cbNeeded, 3)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception
        return
    }

    $ArraySize = $cbNeeded / [IntPtr]::Size
    $hModules = New-Object IntPtr[] -ArgumentList $ArraySize

    $cb = $cbNeeded
    if (![Win32.Psapi]::EnumProcessModulesEx($ProcessHandle, $hModules, $cb, [ref]$cbNeeded, 3)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error() 
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception
        return
    }
    for ($i = 0; $i -lt $ArraySize; $i++)
    {
        $ModInfo = [Activator]::CreateInstance([MODULE_INFO])
        $lpFileName = New-Object Text.StringBuilder -ArgumentList 256
        $lpModuleBaseName = New-Object Text.StringBuilder -ArgumentList 32

        if (![Win32.Psapi]::GetModuleFileNameExW($ProcessHandle, $hModules[$i], $lpFileName, $lpFileName.Capacity)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception
            continue
        }
        if (![Win32.Psapi]::GetModuleBaseNameW($ProcessHandle, $hModules[$i], $lpModuleBaseName, $lpModuleBaseName.Capacity)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception
            continue
        }
        if (![Win32.Psapi]::GetModuleInformation($ProcessHandle, $hModules[$i], [ref]$ModInfo,  [Runtime.InteropServices.Marshal]::SizeOf($ModInfo))) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
            Write-Error $Exception
            continue
        }
        if (![Win32.Dbghelp]::SymLoadModuleEx($ProcessHandle, [IntPtr]::Zero, $lpFileName.ToString(), $lpModuleBaseName.ToString(), $ModInfo.lpBaseOfDll, [Int32]$ModInfo.SizeOfImage, [IntPtr]::Zero, 0)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq 0) { continue } # Module already loaded
            else { 
                $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                Write-Error $Exception
            }
        }
    }
    Remove-Variable hModules
}