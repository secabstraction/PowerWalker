using System;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Management.Automation;
using PowerWalker.Natives;

namespace PowerWalker
{
    //OpenProcess
    [Cmdlet(VerbsCommon.Get, "ProcessHandle")]
    public class GetProcessHandle : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "ID of process whose threads will be traced."
        )]
        [Alias("Pid")]
        public int[] Id
        {
            get { return ProcessIds; }
            set { ProcessIds = value; }
        }
        private int[] ProcessIds;

        [Parameter(
            Mandatory = true,
            Position = 1,
            HelpMessage = "Level of access for this process handle."
            )]
        [Alias("Access")]
        [ValidateNotNullOrEmpty]
        public ProcessAccess AccessLevel;

        protected override void ProcessRecord()
        {
            // If no process ids are passed to the cmdlet, get handles to all processes.
            if (Id == null)
            {
                // Write the process handle to the pipeline making them available to the next cmdlet. 
                Process[] Processes = Process.GetProcesses();
                foreach (Process p in Processes) {
                    IntPtr Handle = Kernel32.OpenProcess(AccessLevel, false, (uint)p.Id);
                    WriteObject(Handle, true);
                }                   
            }
            else
            {
                // If process ids are passed to the cmdlet, get a handle to the process.
                foreach (int i in Id)
                {
                    IntPtr Handle = Kernel32.OpenProcess(AccessLevel, false, (uint)i);
                    WriteObject(Handle, true);
                } 
            }
        }
    }

    [Cmdlet(VerbsCommon.Get, "ProcessModules")]
    public class GetProcessModules : PSCmdlet { }
    //EnumProcessModulesEx
    //32, 64, All

    [Cmdlet(VerbsCommon.Set, "SymbolPath")]
    public class SetSymbolPath : PSCmdlet { }
    //http, Microsoft Public
    //do more work here...

    [Cmdlet(VerbsData.Initialize, "SymbolHandler")]
    public class InitializeSymbolHandler : PSCmdlet { }
    //SymInit
    //SymGetOptions
    //SymSetOptions
    //SetSymserver

    [Cmdlet(VerbsData.Import, "ProcessModules")]
    public class ImportProcessModules : PSCmdlet { }
    //psapi
    //toolhelp32

    [Cmdlet(VerbsCommon.Get, "ModuleInformation")]
    public class GetModuleInformation : PSCmdlet { }
    //SymGetModuleInfo
    //GetModuleInfo

    [Cmdlet(VerbsCommon.Get, "StackTrace")]
    public class GetStackTrace : PSCmdlet
    //Addr
    //Symbol: name (SymGetSymFromAddr64), undName, undFullName
    //Line: Number, filename (both SymGetLineFromAddr64)
    //File
    {
        [Parameter
            (
                Mandatory = true,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "ID of process whose threads will be traced."
            )
        ]
        [Alias("Pid", "p")]
        uint ProcessId;

        [Parameter
            (
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 1,
                HelpMessage = "ID of thread whose stack will be traced."
            )
        ]
        [Alias("Tid", "t")]
        uint ThreadId;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
        }
        protected override void EndProcessing()
        {
            base.EndProcessing();
        }
    }
}
