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
    public class GetProcessModules : Cmdlet { }
    //EnumProcessModulesEx
    //32, 64, All

    [Cmdlet(VerbsCommon.Set, "SymbolPath")]
    public class SetSymbolPath : Cmdlet { }
    //http, Microsoft Public
    //do more work here...

    [Cmdlet(VerbsLifecycle.Stop, "Thread")]
    public class StopThread : Cmdlet
    {
        private uint threadId;

        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "ID of thread whose stack will be traced."
        )]
        public uint ThreadId
        {
            get { return this.threadId; }
            set { this.threadId = value; }
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            IntPtr hThread = Kernel32.OpenThread(ThreadAccess.Terminate, false, threadId);
            Kernel32.TerminateThread(hThread, 0);
        }
    }

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

    [Cmdlet(VerbsDiagnostic.Trace, "Thread")]
    public class TraceThread : Cmdlet
    {
        #region Parameters

        private uint processId;
        private uint threadId;

        [Parameter(
            Mandatory = true,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "ID of process whose threads will be evaluated."
        )]
        public uint ProcessId
        {
            get { return this.processId; }
            set { this.processId = value; }
        }

        [Parameter(
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "ID of thread whose stack will be traced."
        )]
        public uint ThreadId
        {
            get { return this.threadId; }
            set { this.threadId = value; }
        }

        #endregion Parameters

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            if (processId != 0 & threadId == 0)
            {
                Process p = Process.GetProcessById((int)processId);
                foreach (ProcessThread thread in p.Threads)
                {
                    StackTrace StackTrace = new StackTrace(processId, (uint)thread.Id);
                    foreach (StackCall Call in StackTrace.Calls)
                {
                    WriteObject(Call);
                }
                } 
            }

            if (processId != 0 & threadId != 0)
            {
                StackTrace StackTrace = new StackTrace(processId, threadId);
                foreach (StackCall Call in StackTrace.Calls)
                {
                    WriteObject(Call);
                }
            }
        }
    }
}
