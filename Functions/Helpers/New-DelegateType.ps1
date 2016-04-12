function New-DelegateType {
    Param (
        [OutputType([Type])]
            
        [Parameter(Position = 0)]
        [Type[]]
        $Parameters = (New-Object -TypeName Type[] -ArgumentList 0),
            
        [Parameter(Position = 1)]
        [Type]
        $ReturnType = [Void]
    )
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyName = New-Object Reflection.AssemblyName -ArgumentList ('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($AssemblyName, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')        
    $TypeBuilder.CreateType()
}