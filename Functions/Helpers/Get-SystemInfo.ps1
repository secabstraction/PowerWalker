function Get-SystemInfo {
    $SystemInfo = [Activator]::CreateInstance([SYSTEM_INFO])
    [Win32.Kernel32]::GetSystemInfo([ref]$SystemInfo)

    Write-Output $SystemInfo
}