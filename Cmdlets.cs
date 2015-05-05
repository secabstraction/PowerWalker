using System;
using System.Text;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Management.Automation;
using PowerWalker.Natives;

namespace PowerWalker
{
    //OpenProcess
    [Cmdlet(VerbsCommon.Get, "ProcessHandle")]
    public class GetProcessHandle : Cmdlet
    {
        #region Parameters

        private int[] ProcessIds;

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

        [Parameter(
            Mandatory = true,
            Position = 1,
            HelpMessage = "Level of access for the process handle."
            )]
        [Alias("Access")]
        [ValidateNotNullOrEmpty]
        public ProcessAccess AccessLevel;
        #endregion Parameters

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            foreach (int i in Id)
            {
                IntPtr Handle = Kernel32.OpenProcess(AccessLevel, false, (uint)i);
                WriteObject(Handle, true);
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
        #region Parameters 

        private List<string> processName = new List<string>();
        private List<int> processId = new List<int>();
        private List<int> threadId = new List<int>();

        [Parameter(
            Mandatory = true,
            ParameterSetName = "ByName",
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "ID of process whose threads will be evaluated."
        )]
        public List<string> ProcessName
        {
            get { return this.processName; }
            set { this.processName = value; }
        }

        [Parameter(
            Mandatory = true,
            ParameterSetName = "ById",
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "ID of process whose threads will be evaluated."
        )]
        public List<int> ProcessId
        {
            get { return this.processId; }
            set { this.processId = value; }
        }

        [Parameter(
            ParameterSetName = "ById",
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "ID of thread whose stack will be traced."
        )]
        public List<int> ThreadId
        {
            get { return this.threadId; }
            set { this.threadId = value; }
        }

        #endregion Parameters

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (MyInvocation.BoundParameters.ContainsKey("ProcessName"))
            {
                foreach (string name in processName)
                {
                    processId.Concat(Process.GetProcessesByName(name).Select(x => x.Id).ToList());
                }
            }
        }
        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            foreach (int pid in processId)
            {
                Process current = Process.GetProcessById(pid);
                foreach (ProcessThread thread in current.Threads) 
                {
                    Functions.GetStackTrace((uint)pid, (uint)thread.Id);
                }
            }
            if (MyInvocation.BoundParameters.ContainsKey("ThreadId"))
            {
                Functions.GetStackTrace((uint)processId[0], (uint)threadId[0]);
            }
        }
        protected override void EndProcessing()
        {
            base.EndProcessing();
        }
    }
}
