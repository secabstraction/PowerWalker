function Get-NativeSystemInfo {
    $SystemInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    [Win32.Kernel32]::GetNativeSystemInfo([ref]$SystemInfo)

    Write-Output $SystemInfo
}