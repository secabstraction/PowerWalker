function Get-SymbolFromAddress ($hProcess, $Address) {
    
    #Initialize params for SymGetSymFromAddr64
    $Symbol = New-Object IMAGEHLP_SYMBOLW64
    $Symbol.SizeOfStruct = [IMAGEHLP_SYMBOLW64]::GetSize()
    $Symbol.MaxNameLength = 32

    $lpSymbol = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($Symbol))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($Symbol, $lpSymbol, $false)
    [UInt64]$Offset = 0

    $null = [Win32.dbgHelp]::SymGetSymFromAddr64($hProcess, $Address, [ref]$Offset, $lpSymbol)
            
    $Symbol = [IMAGEHLP_SYMBOLW64][System.Runtime.InteropServices.Marshal]::PtrToStructure($lpSymbol, [Type][IMAGEHLP_SYMBOLW64])
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpSymbol)

    return $Symbol
}
