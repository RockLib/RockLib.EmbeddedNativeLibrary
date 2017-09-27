using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace RockLib.Interop
{
    partial class EmbeddedNativeLibrary
    {
        private class WindowsLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _candidateWritableLocations;

            static WindowsLibraryLoader()
            {
                var candidateLocations = new List<string>();
                var localAppData = Environment.GetEnvironmentVariable("LocalAppData");
                if (!string.IsNullOrEmpty(localAppData))
                {
                    candidateLocations.Add(localAppData);
                }

                var tmpDirectory = Environment.GetEnvironmentVariable("TMP");
                if (!string.IsNullOrEmpty(tmpDirectory))
                {
                    candidateLocations.Add(tmpDirectory);
                }

                var tempDirectory = Environment.GetEnvironmentVariable("TEMP");
                if (!string.IsNullOrEmpty(tempDirectory))
                {
                    candidateLocations.Add(tempDirectory);
                }

                _candidateWritableLocations = candidateLocations.ToArray();
            }

            public string[] CandidateWritableLocations { get { return _candidateWritableLocations; } }

            public IEnumerable<string> GetInstallPathCandidates(string libraryName)
            {
                var fullName = libraryName + ".dll";

                var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
                var potentialInstallPath = Path.Combine(Path.GetDirectoryName(assembly.Location), fullName);
                if (File.Exists(potentialInstallPath))
                {
                    yield return potentialInstallPath;
                }

                yield return fullName;
            }

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                var libraryPointer = NativeMethods.LoadLibrary(libraryPath);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                var exceptions = new List<Exception>();

                exceptions.Add(new Win32Exception());

                libraryPointer = NativeMethods.LoadLibraryEx(libraryPath, IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                exceptions.Add(new Win32Exception());

                var originalPathVariable = Environment.GetEnvironmentVariable("PATH");
                var pathVariable = originalPathVariable + ";" + Path.GetDirectoryName(libraryPath);
                Environment.SetEnvironmentVariable("PATH", pathVariable);

                libraryPointer = NativeMethods.LoadLibrary(libraryPath);

                Environment.SetEnvironmentVariable("PATH", originalPathVariable);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                exceptions.Add(new Win32Exception());

                return new MaybeIntPtr(exceptions.ToArray());
            }

            public void FreeLibrary(IntPtr libraryPointer)
            {
                NativeMethods.FreeLibrary(libraryPointer);
            }

            public MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName)
            {
                var functionPointer = NativeMethods.GetProcAddress(libraryPointer, functionName);

                if (functionPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(functionPointer);
                }

                return new MaybeIntPtr(new Exception[] { new Win32Exception() });
            }

            private static class NativeMethods
            {
                [DllImport("kernel32.dll", EntryPoint = "LoadLibraryEx", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
                public static extern IntPtr LoadLibraryEx([MarshalAs(UnmanagedType.LPStr)] string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

                [DllImport("kernel32.dll", EntryPoint = "LoadLibrary", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
                public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpLibFileName);

                [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
                public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

                [DllImport("kernel32.dll", EntryPoint = "FreeLibrary", SetLastError = true)]
                public static extern bool FreeLibrary(IntPtr hModule);
            }

            [Flags]
            private enum LoadLibraryFlags : uint
            {
                DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
                LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
                LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008,
                LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
                LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
                LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
                LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
                LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            }
        }
    }
}
