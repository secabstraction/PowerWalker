function Initialize-Stackframe {
    Param (
        [Parameter(Mandatory = $true)]
        $OffsetPC, 

        [Parameter(Mandatory = $true)]
        $OffsetFrame,
                     
        [Parameter(Mandatory = $true)]
        $OffsetStack, 

        [Parameter()]
        $OffsetBStore
    )
                 
    $StackFrame = [Activator]::CreateInstance([STACKFRAME64])
    $Addr64 = [Activator]::CreateInstance([ADDRESS64])
    $Addr64.Mode = 0x03 # Flat
    
    $Addr64.Offset = $OffsetPC
    $StackFrame.AddrPC = $Addr64

    $Addr64.Offset = $OffsetFrame
    $StackFrame.AddrFrame = $Addr64

    $Addr64.Offset = $OffsetStack
    $StackFrame.AddrStack = $Addr64

    $Addr64.Offset = $OffsetBStore
    $StackFrame.AddrBStore = $Addr64
    
    Write-Output $StackFrame
}