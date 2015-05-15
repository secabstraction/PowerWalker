function Initialize-Stackframe ($AddrMode, $OffsetPC, $OffsetFrame, $OffsetStack, $OffsetBStore) {

    $StackFrame = New-Object STACKFRAME64
    $StackFrame.AddrPC.Mode = $AddrMode
    $StackFrame.AddrPC.Offset = $OffsetPC
    $StackFrame.AddrReturn.Mode = $AddrMode
    $StackFrame.AddrFrame.Mode = $AddrMode
    $StackFrame.AddrFrame.Offset = $OffsetFrame
    $StackFrame.AddrStack.Mode = $AddrMode
    $StackFrame.AddrStack.Offset = $OffsetStack
    $StackFrame.AddrBStore.Offset = $OffsetBStore
    $StackFrame.AddrBStore.Mode = $AddrMode
    
    return $StackFrame
}
