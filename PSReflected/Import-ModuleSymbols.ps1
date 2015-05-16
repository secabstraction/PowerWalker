function Import-ModuleSymbols ($hProcess, $ModuleType) {

    #Initialize parameters for EPM
    [UInt32]$cbNeeded = 0
    $null = [Win32.psapi]::EnumProcessModulesEx($hProcess, $null, 0, [ref]$cbNeeded, $ModuleType)
    [UInt64]$ArraySize = $cbNeeded / [IntPtr]::Size

    $hModules = New-Object IntPtr[]($ArraySize)

    $cb = $cbNeeded;
    $null = [Win32.psapi]::EnumProcessModulesEx($hProcess, $hModules, $cb, [ref]$cbNeeded, $ModuleType);
    for ($i = 0; $i -lt $ArraySize; $i++)
    {
        $ModInfo = New-Object MODULE_INFO
        $lpFileName = New-Object System.Text.StringBuilder(256)
        $lpModuleBaseName = New-Object System.Text.StringBuilder(32)

        $null = [Win32.psapi]::GetModuleFileNameExW($hProcess, $hModules[$i], $lpFileName, $lpFileName.Capacity)
        $null = [Win32.psapi]::GetModuleBaseNameW($hProcess, $hModules[$i], $lpModuleBaseName, $lpModuleBaseName.Capacity)
        $null = [Win32.psapi]::GetModuleInformation($hProcess, $hModules[$i], [ref]$ModInfo,  [MODULE_INFO]::GetSize())
        $null = [Win32.dbghelp]::SymLoadModuleEx($hProcess, [IntPtr]::Zero, $lpFileName.ToString(), $lpModuleBaseName.ToString(), $ModInfo.lpBaseOfDll, [Int32]$ModInfo.SizeOfImage, [IntPtr]::Zero, 0);
    }
}
