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
