using System;
using System.Collections.Generic;

namespace RockLib.Interop
{
    partial class EmbeddedNativeLibrary
    {
        private interface ILibraryLoader
        {
            string[] CandidateWritableLocations { get; }
            IEnumerable<string> GetInstallPathCandidates(string libraryName);
            MaybeIntPtr LoadLibrary(string libraryPath);
            void FreeLibrary(IntPtr libraryPointer);
            MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName);
        }
    }
}
