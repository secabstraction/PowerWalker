function Trace-ProcessThreads {
[CmdletBinding(DefaultParameterSetName = 'Id')]
    Param ()
    DynamicParam {
        $Processes = Get-Process
        $ProcessNames = $Processes | foreach { $_.Name } | Sort-Object -Unique
        $ProcessIds = $Processes | foreach { $_.Id }

        $ParameterDictionary = New-Object Management.Automation.RuntimeDefinedParameterDictionary

        New-RuntimeParameter -ValidateSet $ProcessNames -Type String -Name Name -Position 0 -ParameterSetName Name -ParameterDictionary $ParameterDictionary
        New-RuntimeParameter -ValidateSet $ProcessIds -Type Int16 -Name Id -Position 0 -ParameterSetName Id -ParameterDictionary $ParameterDictionary

        return $ParameterDictionary
    }

    Begin {
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
             Write-Warning 'This script should be ran with administrative priviliges.'
        }
    }

    Process {
        $ScriptBlock = {
            Param (
                [Parameter()]
                [String]$Name, 

                [Parameter()]
                [Int16]$Id = 0
            )

            $ProcessAllAccess = 0x1F0FFF
    
            if ($Name -ne '') {
                
                foreach ($Process in (Get-Process -Name $Name)) {
                    if (($ProcessHandle = [Win32.Kernel32]::OpenProcess($ProcessAllAccess, $false, $Process.Id)) -eq 0) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                        Write-Error $Exception
                        continue
                    }
                    if (![Win32.Dbghelp]::SymInitialize($ProcessHandle, $null, $false)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                        Write-Error $Exception
                        
                        if (![Win32.Kernel32]::CloseHandle($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                            Write-Error $Exception
                            continue
                        }
                    }

                    $Process.Threads | foreach { Trace-Thread -ProcessHandle $ProcessHandle -ThreadId $_.Id -ProcessId $Process.Id }
                    
                    if (![Win32.Dbghelp]::SymCleanup($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                        Write-Error $Exception 
                    }
                    if (![Win32.Kernel32]::CloseHandle($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                        Write-Error $Exception 
                    }
                } 
            }
            else {
                $Process = Get-Process -Id $Id
            
                if (($ProcessHandle = [Win32.Kernel32]::OpenProcess($ProcessAllAccess, $false, $Process.Id)) -eq 0) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception
                    return
                }
                if (![Win32.Dbghelp]::SymInitialize($ProcessHandle, $null, $false)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception
                        
                    if (![Win32.Kernel32]::CloseHandle($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                        Write-Error $Exception
                        continue
                    }
                }

                $Process.Threads | foreach { Trace-Thread -ProcessHandle $ProcessHandle -ThreadId $_.Id -ProcessId $Process.Id }
                    
                if (![Win32.Dbghelp]::SymCleanup($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception 
                }
                if (![Win32.Kernel32]::CloseHandle($ProcessHandle)) { $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $Exception = New-Object ComponentModel.Win32Exception -ArgumentList $ErrorCode
                    Write-Error $Exception
                }
            }
        }
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList @($PSBoundParameters.Name,$PSBoundParameters.Id)
    }
    
    End {}
}