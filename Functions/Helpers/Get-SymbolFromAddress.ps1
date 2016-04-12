function Get-SymbolFromAddress {
    Param (
        [Parameter(Mandatory = $true)]
        [IntPtr]$ProcessHandle, 
                    
        [Parameter(Mandatory = $true)]
        $Address
    )

    # Initialize params for SymGetSymFromAddr64
    $Symbol = [Activator]::CreateInstance([IMAGEHLP_SYMBOLW64])
    $Symbol.SizeOfStruct = [Runtime.InteropServices.Marshal]::SizeOf($Symbol)
    $Symbol.MaxNameLength = 32

    $lpSymbol = [Runtime.InteropServices.Marshal]::AllocHGlobal($Symbol.SizeOfStruct)
    [Runtime.InteropServices.Marshal]::StructureToPtr($Symbol, $lpSymbol, $false)

    if(![Win32.Dbghelp]::SymGetSymFromAddr64($ProcessHandle, $Address, [UIntPtr]::Zero, $lpSymbol)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
        Write-Error $Exception
        return
    }
            
    $Symbol = [Runtime.InteropServices.Marshal]::PtrToStructure($lpSymbol, [Type][IMAGEHLP_SYMBOLW64])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($lpSymbol)

    Write-Output $Symbol
}