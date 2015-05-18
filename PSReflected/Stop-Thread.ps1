function Stop-Thread ($ThreadId) {
<#
.SYNOPSIS

A wrapper for kernel32!TerminateThread

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>
    $hThread = [Win32.kernel32]::OpenThread(1, $false, $ThreadId)
    
    if([Win32.kernel32]::TerminateThread($hThread, 0)) 
         { Write-Verbose "Thread $ThreadId terminated." }
    
    else { Write-Verbose "Thread $ThreadId not terminated." }
    
    $null = [Win32.kernel32]::CloseHandle($hThread)
}
