function Convert-UIntToInt {
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]$Value
    )
		
    [Byte[]]$Bytes = [BitConverter]::GetBytes($Value)
    $Int64 = [BitConverter]::ToInt64($Bytes, 0)

    Write-Output $Int64
}
