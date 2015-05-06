using System;
using PowerWalker.Natives;
using System.Collections.Generic;
namespace PowerWalker
{
    public class StackCall
    {
        public int ThreadId { get; private set; }
        public ulong AddrPC { get; private set; }
        public ulong AddrReturn { get; private set; }
        public string Symbol { get; private set; }
        public string MappedFile { get; private set; }
        
        public StackCall(IntPtr hProcess, ulong AddrPC, ulong AddrReturn, int ThreadId)
        {
            this.ThreadId = ThreadId;
            this.AddrPC = AddrPC;
            this.AddrReturn = AddrReturn;

            System.Text.StringBuilder ReturnedString = new System.Text.StringBuilder(256);

            IntPtr PcOffset = (IntPtr)Functions.UlongToLong(AddrPC);
            Psapi.GetMappedFileNameW(hProcess, PcOffset, ReturnedString, (uint)ReturnedString.Capacity);
            MappedFile = ReturnedString.ToString();

            IMAGEHLP_SYMBOL64 PcSymbol = Functions.GetSymbolFromAddress(hProcess, AddrPC);
            Symbol = new string(PcSymbol.Name);
        }
    }
}
