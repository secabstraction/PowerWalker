using System;
using PowerWalker.Natives;
using System.Collections.Generic;

namespace PowerWalker
{
    public class StackCall
    {
        public ulong Offset { get; private set; }
        public ulong ReturnAddress { get; private set; }
        public string Symbol { get; private set; }
        public string SymbolFile { get; private set; }

        public StackCall(IntPtr hProcess, ulong AddrPC, ulong AddrReturn)
        {
            System.Text.StringBuilder ReturnedString = new System.Text.StringBuilder(256);

            IntPtr PcOffset = (IntPtr)Functions.UlongToLong(AddrPC);

            Psapi.GetMappedFileNameW(hProcess, PcOffset, ReturnedString, (uint)ReturnedString.Capacity);
            SymbolFile = ReturnedString.ToString();

            IMAGEHLP_SYMBOL64 PcSymbol = Functions.GetSymbolFromAddress(hProcess, AddrPC);
            Symbol = new string(PcSymbol.Name);

            Offset = AddrPC;
            ReturnAddress = AddrReturn;
        }
    }
}
