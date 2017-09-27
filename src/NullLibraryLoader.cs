using System;
using System.Collections.Generic;

namespace RockLib.Interop
{
    partial class EmbeddedNativeLibrary
    {
        private class NullLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _empty = new string[0];

            public string[] CandidateWritableLocations
            {
                get { return _empty; }
            }

            public IEnumerable<string> GetInstallPathCandidates(string libraryName) { return _empty; }

            public void FreeLibrary(IntPtr libraryPointer)
            {
            }

            public MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName)
            {
                throw new NotImplementedException();
            }

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                return new MaybeIntPtr(IntPtr.Zero);
            }
        }
    }
}
