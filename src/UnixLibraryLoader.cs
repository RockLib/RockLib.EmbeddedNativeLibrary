using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace RockLib.Interop
{
    partial class EmbeddedNativeLibrary
    {
        private class UnixLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _candidateWritableLocations = new[] { "/tmp", "/var/tmp" };

            private readonly bool _isMac;

            public UnixLibraryLoader(bool isMac)
            {
                _isMac = isMac;
            }

            public string[] CandidateWritableLocations { get { return _candidateWritableLocations; } }

            public IEnumerable<string> GetInstallPathCandidates(string libraryName)
            {
                var fullName = libraryName + (_isMac ? ".dylib" : ".so");

                var assembly = Assembly.GetEntryAssembly() ?? typeof(UnixLibraryLoader).GetTypeInfo().Assembly;
                var potentialInstallPath = Path.Combine(Path.GetDirectoryName(assembly.Location), fullName);
                if (File.Exists(potentialInstallPath))
                {
                    yield return potentialInstallPath;
                }

                yield return fullName;
            }

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                var libraryPointer = dlopen(libraryPath, dlopenFlags.RTLD_LAZY | dlopenFlags.RTLD_GLOBAL);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                var error = dlerror();
                if (string.IsNullOrEmpty(error))
                {
                    error = "Null pointer was returned from dlopen.";
                }
                return new MaybeIntPtr(new[] { new Exception(error) });
            }

            public void FreeLibrary(IntPtr libraryPointer)
            {
                dlclose(libraryPointer);
            }

            public MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName)
            {
                var functionPointer = dlsym(libraryPointer, functionName);

                if (functionPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(functionPointer);
                }

                return new MaybeIntPtr(new Exception[] { new Exception(dlerror()) });
            }

#pragma warning disable IDE1006 // Naming Styles
            private IntPtr dlopen(string filename, dlopenFlags flags) =>
                 _isMac ? Mac.NativeMethods.dlopen(filename, flags) : Linux.NativeMethods.dlopen(filename, flags);

            private string dlerror() =>
                _isMac ? Mac.NativeMethods.dlerror() : Linux.NativeMethods.dlerror();

            private IntPtr dlsym(IntPtr handle, string symbol) =>
                _isMac ? Mac.NativeMethods.dlsym(handle, symbol) : Linux.NativeMethods.dlsym(handle, symbol);

            private IntPtr dlclose(IntPtr handle) =>
                _isMac ? Mac.NativeMethods.dlclose(handle) : Linux.NativeMethods.dlclose(handle);

            private static class Mac
            {
                internal static class NativeMethods
                {
                    [DllImport("libSystem.dylib")]
                    public static extern IntPtr dlopen(string filename, dlopenFlags flags);

                    [DllImport("libSystem.dylib")]
                    public static extern string dlerror();

                    [DllImport("libSystem.dylib")]
                    public static extern IntPtr dlsym(IntPtr handle, string symbol);

                    [DllImport("libSystem.dylib")]
                    public static extern IntPtr dlclose(IntPtr handle);
                }
            }

            private static class Linux
            {
                internal static class NativeMethods
                {// libdl.so libcoreclr.so
                    [DllImport("libdl.so")]
                    public static extern IntPtr dlopen(string filename, dlopenFlags flag);

                    [DllImport("libdl.so")]
                    public static extern string dlerror();

                    [DllImport("libdl.so")]
                    public static extern IntPtr dlsym(IntPtr handle, string name);

                    [DllImport("libdl.so")]
                    public static extern IntPtr dlclose(IntPtr handle);
                }
            }

            [Flags]
            private enum dlopenFlags
            {
                RTLD_LAZY = 0x1,
                RTLD_NOW = 0x2,
                RTLD_LOCAL = 0x4,
                RTLD_GLOBAL = 0x8,
                RTLD_NOLOAD = 0x10,
                RTLD_NODELETE = 0x80,
            }
#pragma warning restore IDE1006 // Naming Styles
        }
    }
}
