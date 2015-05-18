function Initialize-Stackframe ($OffsetPC, $OffsetFrame, $OffsetStack, $OffsetBStore) {

    $StackFrame = [Activator]::CreateInstance([STACKFRAME64])
    $Addr64 = [Activator]::CreateInstance([ADDRESS64])
    $Addr64.Mode = [AddressMode]::_Flat
    
    $Addr64.Offset = $OffsetPC
    $StackFrame.AddrPC = $Addr64

    $Addr64.Offset = $OffsetFrame
    $StackFrame.AddrFrame = $Addr64

    $Addr64.Offset = $OffsetStack
    $StackFrame.AddrStack = $Addr64

    $Addr64.Offset = $OffsetBStore
    $StackFrame.AddrBStore = $Addr64
    
    return $StackFrame
}
