using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

// ReSharper disable once CheckNamespace
namespace Rock.Reflection
{
    /// <summary>
    /// A class that provides access to the functions of a native DLL when the DLL is
    /// embedded as a resource in the same assembly that <see cref="EmbeddedNativeLibrary"/>
    /// is defined.
    /// </summary>
    internal sealed class EmbeddedNativeLibrary : IDisposable
    {
        private const bool _defaultPreferEmbeddedOverInstalled = true;

        private static readonly RuntimeOS _runtimeOS = GetRuntimeOS();
        private static readonly ILibraryLoader _libraryLoader = GetLibraryLoader(_runtimeOS);

        private readonly Lazy<IntPtr> _libraryPointer;

        /// <summary>
        /// Loads the native library defined by a list of <see cref="DllInfo"/> objects.
        /// </summary>
        /// <param name="libraryName">The name of the library.</param>
        /// <param name="dllInfos">A collection of <see cref="DllInfo"/> objects.</param>
        /// <returns>True, if the native library was loaded, or false if the library failed to load.</returns>
        public static bool Load(string libraryName, params DllInfo[] dllInfos)
        {
            return Load(libraryName, _defaultPreferEmbeddedOverInstalled, dllInfos);
        }

        /// <summary>
        /// Loads the native library defined by a list of <see cref="DllInfo"/> objects.
        /// </summary>
        /// <param name="libraryName">The name of the library.</param>
        /// <param name="preferEmbeddedOverInstalled">
        /// If true, loading the embedded native library is attempted first and if it fails, then loading
        /// the native library from the operating system's default load paths is attempted. If false,
        /// the installed library is attempted first and the embedded library is attempted second.
        /// </param>
        /// <param name="dllInfos">A collection of <see cref="DllInfo"/> objects.</param>
        /// <returns>True, if the native library was loaded, or false if the library failed to load.</returns>
        public static bool Load(string libraryName, bool preferEmbeddedOverInstalled, params DllInfo[] dllInfos)
        {
            if (_runtimeOS != RuntimeOS.Windows)
            {
                return false;
            }

            var library = new EmbeddedNativeLibrary(libraryName, preferEmbeddedOverInstalled, dllInfos);

            try
            {
                var libraryPointer = library._libraryPointer.Value;
                return libraryPointer != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmbeddedNativeLibrary"/> class.
        /// </summary>
        /// <param name="libraryName">The name of the library.</param>
        /// <param name="dllInfos">
        /// A collection of <see cref="DllInfo"/> objects that describe the native library.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="libraryName"/> is null.
        /// or
        /// <paramref name="dllInfos"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="libraryName"/> is empty.
        /// or
        /// <paramref name="dllInfos"/> is empty.
        /// </exception>
        public EmbeddedNativeLibrary(string libraryName, params DllInfo[] dllInfos)
            : this(libraryName, _defaultPreferEmbeddedOverInstalled, dllInfos)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmbeddedNativeLibrary"/> class.
        /// </summary>
        /// <param name="libraryName">The name of the library.</param>
        /// <param name="preferEmbeddedOverInstalled">
        /// If true, loading the embedded native library is attempted first and if it fails, then loading
        /// the native library from the operating system's default load paths is attempted. If false,
        /// the installed library is attempted first and the embedded library is attempted second.
        /// </param>
        /// <param name="dllInfos">
        /// A collection of <see cref="DllInfo"/> objects that describe the native library.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="libraryName"/> is null.
        /// or
        /// <paramref name="dllInfos"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="libraryName"/> is empty.
        /// or
        /// <paramref name="dllInfos"/> is empty.
        /// </exception>
        public EmbeddedNativeLibrary(string libraryName, bool preferEmbeddedOverInstalled, params DllInfo[] dllInfos)
        {
            if (libraryName == null) throw new ArgumentNullException("libraryName");
            if (dllInfos == null) throw new ArgumentNullException("dllInfos");
            if (libraryName == "") throw new ArgumentException("'libraryName' must not be empty.", "libraryName");
            if (dllInfos.Length == 0) throw new ArgumentException("'dllInfos' must not be empty.", "dllInfos");

            _libraryPointer = new Lazy<IntPtr>(() =>
            {
                var exceptions = new List<Exception>();

                IntPtr libraryPointer;

                if (preferEmbeddedOverInstalled)
                {
                    libraryPointer = LoadFromDllInfos(libraryName, dllInfos, exceptions);
                    if (libraryPointer != IntPtr.Zero)
                    {
                        return libraryPointer;
                    }
                }

                libraryPointer = LoadFromInstall(libraryName);
                if (libraryPointer != IntPtr.Zero)
                {
                    return libraryPointer;
                }

                if (!preferEmbeddedOverInstalled)
                {
                    libraryPointer = LoadFromDllInfos(libraryName, dllInfos, exceptions);
                    if (libraryPointer != IntPtr.Zero)
                    {
                        return libraryPointer;
                    }
                }

                throw new AggregateException(
                    "Unable to load library from resources: " + string.Join(", ", dllInfos.Select(dll => dll.ResourceName)),
                    exceptions.ToArray());
            });
        }

        private IntPtr LoadFromDllInfos(string libraryName, DllInfo[] dllInfos, List<Exception> exceptions)
        {
            foreach (var dllInfo in dllInfos.Where(info => RuntimeMatchesTarget(info.TargetRuntime)))
            {
                var libraryPath = GetLibraryPath(libraryName, dllInfo);
                var maybePointer = _libraryLoader.LoadLibrary(libraryPath);

                if (maybePointer.HasValue)
                {
                    return maybePointer.Value;
                }
                
                exceptions.Add(new AggregateException(
                    string.Format(
                        "The load library operation for '{0}' failed and reported {1} exception{2}.",
                        dllInfo.ResourceName,
                        maybePointer.Exceptions.Length,
                        maybePointer.Exceptions.Length > 1 ? "s" : ""),
                    maybePointer.Exceptions));
            }

            return IntPtr.Zero;
        }

        private IntPtr LoadFromInstall(string libraryName)
        {
            foreach (var installPath in _libraryLoader.GetInstallPathCandidates(libraryName))
            {
                var maybePointer = _libraryLoader.LoadLibrary(installPath);

                if (maybePointer.HasValue)
                {
                    return maybePointer.Value;
                }
            }

            return IntPtr.Zero;
        }

        private bool RuntimeMatchesTarget(TargetRuntime targetRuntime)
        {
            switch (targetRuntime)
            {
                case TargetRuntime.Windows:
                    return _runtimeOS == RuntimeOS.Windows;
                case TargetRuntime.Win32:
                    return _runtimeOS == RuntimeOS.Windows && IntPtr.Size == 4;
                case TargetRuntime.Win64:
                    return _runtimeOS == RuntimeOS.Windows && IntPtr.Size == 8;
                case TargetRuntime.Mac:
                    return _runtimeOS == RuntimeOS.Mac;
                case TargetRuntime.Linux:
                    return _runtimeOS == RuntimeOS.Linux;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="EmbeddedNativeLibrary"/> class.
        /// </summary>
        ~EmbeddedNativeLibrary()
        {
            FreeLibrary();
        }

        /// <summary>
        /// Unloads the native libarary, rendering any functions created by the
        /// <see cref="GetDelegate{TDelegate}"/> method unusable.
        /// </summary>
        public void Dispose()
        {
            FreeLibrary();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Gets a delegate that executes the native function identified by
        /// <paramref name="functionName"/>.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="functionName">The name of the native function.</param>
        /// <returns>A delegate that executes the native function.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="functionName"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="functionName"/> is empty.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// TDelegate is not delegate.
        /// </exception>
        /// <exception cref="AggregateException">
        /// Unable to load the native library.
        /// or
        /// Unable to get a pointer to the function.
        /// </exception>
        public TDelegate GetDelegate<TDelegate>(string functionName)
        {
            ValidateGetDelegate<TDelegate>(functionName);

            var maybePointer = _libraryLoader.GetFunctionPointer(_libraryPointer.Value, functionName);

            if (!maybePointer.HasValue)
            {
                throw new AggregateException(
                    "Unable to load function: " + functionName,
                    maybePointer.Exceptions);
            }

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(maybePointer.Value);
        }

        /// <summary>
        /// Gets a lazy object that, when unwrapped, returns a delegate that executes
        /// the native function identified by <paramref name="functionName"/>.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="functionName">The name of the native function.</param>
        /// <returns>A delegate that executes the native function.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="functionName"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="functionName"/> is empty.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// TDelegate is not delegate.
        /// </exception>
        /// <exception cref="AggregateException">
        /// When the lazy object unwrapped:
        /// Unable to load the native library.
        /// or
        /// Unable to get a pointer to the function.
        /// </exception>
        public Lazy<TDelegate> GetLazyDelegate<TDelegate>(string functionName)
        {
            ValidateGetDelegate<TDelegate>(functionName);

            return new Lazy<TDelegate>(() => GetDelegate<TDelegate>(functionName));
        }

        private static void ValidateGetDelegate<TDelegate>(string functionName)
        {
            if (functionName == null) throw new ArgumentNullException("functionName");
            if (functionName == "") throw new ArgumentException("'functionName' must not be empty.", "functionName");

            if (!typeof(Delegate).GetTypeInfo().IsAssignableFrom(typeof(TDelegate)))
            {
                throw new InvalidOperationException("TDelegate must be a delegate.");
            }
        }

        private static ILibraryLoader GetLibraryLoader(RuntimeOS os)
        {
            switch (os)
            {
                case RuntimeOS.Windows:
                    return new WindowsLibraryLoader();
                case RuntimeOS.Mac:
                    return new MacLibraryLoader();
                case RuntimeOS.Linux:
                    return new LinuxLibraryLoader();
                default:
                    return new NullLibraryLoader();
            }
        }

        private static RuntimeOS GetRuntimeOS()
        {
            string windir = Environment.GetEnvironmentVariable("windir");
            if (!string.IsNullOrEmpty(windir) && windir.Contains(@"\") && Directory.Exists(windir))
            {
                return RuntimeOS.Windows;
            }
            else if (File.Exists(@"/proc/sys/kernel/ostype"))
            {
                string osType = File.ReadAllText(@"/proc/sys/kernel/ostype");
                if (osType.StartsWith("Linux", StringComparison.OrdinalIgnoreCase))
                {
                    // Note: Android gets here too
                    return RuntimeOS.Linux;
                }
                else
                {
                    throw new PlatformNotSupportedException(osType);
                }
            }
            else if (File.Exists(@"/System/Library/CoreServices/SystemVersion.plist"))
            {
                // Note: iOS gets here too
                return RuntimeOS.Mac;
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
        }

        private static string GetLibraryPath(string libraryName, DllInfo dllInfo)
        {
            byte[] dllData = LoadResource(dllInfo.ResourceName);
            string hash = GetHash(dllData);

            string directory = null;

            var exceptions = new List<Exception>();
            foreach (var candidateLocation in _libraryLoader.CandidateLocations)
            {
                Exception exception = null;
                if (TryGetWritableDirectory(
                    candidateLocation, libraryName, hash, out directory, ref exception))
                {
                    Debug.Assert(directory != null, "'directory' must not be null if TryGetWritableDirectory returns true.");
                    break;
                }
                exceptions.Add(exception);
            }

            if (directory == null)
            {
                throw new AggregateException(
                    string.Format(
                        "Unable to obtain writable file path in candidate locations: {0}.",
                        string.Join(", ", _libraryLoader.CandidateLocations.Select(x => "'" + x + "'"))),
                    exceptions.ToArray());
            }

            var path = WriteDll(dllData, dllInfo.ResourceName, directory);

            foreach (var resourceName in dllInfo.AdditionalResourceNames)
            {
                dllData = LoadResource(resourceName);
                WriteDll(dllData, resourceName, directory);
            }

            return path;
        }

        private static bool TryGetWritableDirectory(
            string root, string libraryName, string hash, out string directory, ref Exception exception)
        {
            var dir = Path.Combine(root, libraryName, hash);
            if (!Directory.Exists(dir))
            {
                try
                {
                    Directory.CreateDirectory(dir);
                }
                catch (UnauthorizedAccessException ex)
                {
                    exception = ex;
                    directory = null;
                    return false;
                }
            }

            try
            {
                var filePath = Path.Combine(dir, Path.GetRandomFileName());
                using (var stream = File.Create(filePath)) stream.WriteByte(1);
                File.Delete(filePath);
            }
            catch (UnauthorizedAccessException ex)
            {
                exception = ex;
                directory = null;
                return false;
            }

            directory = dir;
            return true;
        }

        private static string WriteDll(byte[] dllData, string resourceName, string directory)
        {
            var fileName = Regex.Match(resourceName, @"[^.]+\.(?:dll|exe|so|dylib)").Value;
            var path = Path.Combine(directory, fileName);

            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, dllData);
            }
            else
            {
                var fileDllData = File.ReadAllBytes(path);
                if (dllData.Length != fileDllData.Length
                    || GetHash(dllData) != GetHash(fileDllData))
                {
                    File.Delete(path);
                    File.WriteAllBytes(path, dllData);
                }
            }

            return path;
        }

        private static byte[] LoadResource(string resourceName)
        {
            var stream = typeof(EmbeddedNativeLibrary).GetTypeInfo().Assembly.GetManifestResourceStream(resourceName);

            if (stream == null)
            {
                throw new DllNotFoundException("Unable to locate resource: " + resourceName);
            }

            var buffer = new byte[stream.Length];
            stream.Read(buffer, 0, buffer.Length);
            return buffer;
        }

        private static string GetHash(byte[] dllData)
        {
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(dllData);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (var b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private void FreeLibrary()
        {
            if (_libraryPointer.IsValueCreated)
            {
                _libraryLoader.FreeLibrary(_libraryPointer.Value);
            }
        }

        private interface ILibraryLoader
        {
            string[] CandidateLocations { get; }
            IEnumerable<string> GetInstallPathCandidates(string libraryName);
            MaybeIntPtr LoadLibrary(string libraryPath);
            void FreeLibrary(IntPtr libraryPointer);
            MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName);
        }

        private class MaybeIntPtr
        {
            public MaybeIntPtr(IntPtr value)
            {
                Debug.Assert(value != IntPtr.Zero, "MaybeIntPtr.ctor(IntPtr value): value must be non-zero.");
                Value = value;
            }

            public MaybeIntPtr(Exception[] exceptions)
            {
                Debug.Assert(exceptions != null, "MaybeIntPtr.ctor(Exception[] exceptions): exceptions parameter must not be null.");
                Debug.Assert(exceptions.Length >= 1, "MaybeIntPtr.ctor(Exception[] exceptions): exceptions must contain at least one element.");
                Exceptions = exceptions;
            }

            public IntPtr Value { get; private set; }
            public Exception[] Exceptions { get; private set; }
            public bool HasValue { get { return Value != IntPtr.Zero; } }
        }

        private class WindowsLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _candidateLocations;

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

                _candidateLocations = candidateLocations.ToArray();
            }

            public string[] CandidateLocations { get { return _candidateLocations; } }

            public IEnumerable<string> GetInstallPathCandidates(string libraryName) { return Enumerable.Empty<string>(); }

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                var exceptions = new List<Exception>();

                var libraryPointer = NativeMethods.LoadLibraryEx(libraryPath, IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LoadLibraryFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

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

        private class MacLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _candidateLocations = new[] { "/tmp", "/var/tmp", "/private/tmp" };

            public string[] CandidateLocations { get { return _candidateLocations; } } // TODO: Implement

            public IEnumerable<string> GetInstallPathCandidates(string libraryName) => Enumerable.Empty<string>();

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                var exceptions = new List<Exception>();

                var libraryPointer = NativeMethods.dlopen(libraryPath, dlopenFlags.RTLD_LAZY | dlopenFlags.RTLD_GLOBAL);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                exceptions.Add(new Exception(NativeMethods.dlerror()));
                return new MaybeIntPtr(exceptions.ToArray());
            }

            public void FreeLibrary(IntPtr libraryPointer)
            {
                NativeMethods.dlclose(libraryPointer);
            }

            public MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName)
            {   
                var functionPointer = NativeMethods.dlsym(libraryPointer, functionName);

                if (functionPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(functionPointer);
                }

                return new MaybeIntPtr(new Exception[] { new Exception(NativeMethods.dlerror()) });
            }

            private static class NativeMethods
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
        }

        private class LinuxLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _candidateLocations;
            private static readonly string[] _installLocations;

            static LinuxLibraryLoader()
            {
                _candidateLocations = new[] { "/tmp", "/var/tmp" };
            }

            public string[] CandidateLocations { get { return _candidateLocations; } }

            public IEnumerable<string> GetInstallPathCandidates(string libraryName)
            {
                string potentialInstallPath;
                var fullName = libraryName + ".so";

                var installLocations = new List<string>();

                potentialInstallPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), fullName);
                if (File.Exists(potentialInstallPath))
                {
                    installLocations.Add(potentialInstallPath);
                }

                var ldLibraryPath = Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
                if (!string.IsNullOrEmpty(ldLibraryPath))
                {
                    foreach (var path in ldLibraryPath.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        potentialInstallPath = Path.Combine(path, fullName);
                        if (File.Exists(potentialInstallPath))
                        {
                            installLocations.Add(potentialInstallPath);
                        }
                    }
                }

                var process = Process.Start(new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = "ldconfig -p",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                var ldconfigResult = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                var ldconfigMatch = Regex.Match(ldconfigResult, libraryName + @"\.so.*?=>\s*(.*)");
                if (ldconfigMatch.Success)
                {
                    potentialInstallPath = ldconfigMatch.Groups[1].Value;
                    if (File.Exists(potentialInstallPath))
                    {
                        installLocations.Add(potentialInstallPath);
                    }
                }

                potentialInstallPath = Path.Combine("/lib", fullName);
                if (File.Exists(potentialInstallPath))
                {
                    installLocations.Add(potentialInstallPath);
                }

                potentialInstallPath = Path.Combine("/usr/lib", fullName);
                if (File.Exists(potentialInstallPath))
                {
                    installLocations.Add(potentialInstallPath);
                }
                
                return installLocations;
            }

            public MaybeIntPtr LoadLibrary(string libraryPath)
            {
                var exceptions = new List<Exception>();

                // NativeMethods.dlerror();
                var libraryPointer = NativeMethods.dlopen(libraryPath, dlopenFlags.RTLD_LAZY | dlopenFlags.RTLD_GLOBAL);

                if (libraryPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(libraryPointer);
                }

                exceptions.Add(new Exception(NativeMethods.dlerror()));

                return new MaybeIntPtr(exceptions.ToArray());
            }

            public void FreeLibrary(IntPtr libraryPointer)
            {
                NativeMethods.dlclose(libraryPointer);
            }

            public MaybeIntPtr GetFunctionPointer(IntPtr libraryPointer, string functionName)
            {
                var functionPointer = NativeMethods.dlsym(libraryPointer, functionName);

                if (functionPointer != IntPtr.Zero)
                {
                    return new MaybeIntPtr(functionPointer);
                }

                return new MaybeIntPtr(new [] { new Exception(NativeMethods.dlerror()) });
            }

            private static class NativeMethods
            {// libdl.so libcoreclr.so
                [DllImport("libdl.so")]
                public static extern IntPtr dlopen(string filename, dlopenFlags flag);

                [DllImport("libdl.so")]
                public static extern string dlerror();

                [DllImport("libdl.so")]
                public static extern IntPtr dlsym(IntPtr handle, string name);

                [DllImport("libdl.so")]
                public static extern int dlclose(IntPtr handle);
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
        }

        private class NullLibraryLoader : ILibraryLoader
        {
            private static readonly string[] _empty = new string[0];

            public string[] CandidateLocations
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

        private enum RuntimeOS
        {
            Windows,
            Mac,
            Linux
        }
    }

    /// <summary>
    /// Contains resource names for the DLLs that are embedded in this assembly. The DLLs
    /// must all be of the same architecture (x86 or x64).
    /// </summary>
    internal sealed class DllInfo
    {
        private static readonly IReadOnlyCollection<string> _assemblyManifestResourceNames = typeof(DllInfo).GetTypeInfo().Assembly.GetManifestResourceNames().Select(n => n.ToLowerInvariant()).ToList().AsReadOnly();

        private readonly TargetRuntime _targetRuntime;
        private readonly string _resourceName;
        private readonly string[] _additionalResourceNames;

        /// <summary>
        /// Initializes a new instance of the <see cref="DllInfo"/> class, assuming the target runtime to be
        /// <see cref="TargetRuntime.Windows"/>.
        /// </summary>
        /// <param name="resourceName">The resource name of the main DLL to be loaded.</param>
        /// <param name="additionalResourceNames">
        /// The resource names of any additional DLLs that neede to be loaded.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="resourceName"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="resourceName"/> is empty.
        /// or
        /// <paramref name="resourceName"/> is not found in this assembly's manifest resource names.
        /// or
        /// <paramref name="additionalResourceNames"/> has any null elements.
        /// or
        /// <paramref name="additionalResourceNames"/> has any empty elements.
        /// or
        /// <paramref name="additionalResourceNames"/> has any elements that are not found in this assembly's manifest resource names.
        /// </exception>
        public DllInfo(string resourceName, params string[] additionalResourceNames)
            : this(TargetRuntime.Windows, resourceName, additionalResourceNames)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DllInfo"/> class.
        /// </summary>
        /// <param name="targetRuntime">The runtime that this <see cref="DllInfo"/> targets.</param>
        /// <param name="resourceName">The resource name of the main DLL to be loaded.</param>
        /// <param name="additionalResourceNames">
        /// The resource names of any additional DLLs that neede to be loaded.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="resourceName"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="resourceName"/> is empty.
        /// or
        /// <paramref name="resourceName"/> is not found in this assembly's manifest resource names.
        /// or
        /// <paramref name="additionalResourceNames"/> has any null elements.
        /// or
        /// <paramref name="additionalResourceNames"/> has any empty elements.
        /// or
        /// <paramref name="additionalResourceNames"/> has any elements that are not found in this assembly's manifest resource names.
        /// </exception>
        public DllInfo(TargetRuntime targetRuntime, string resourceName, params string[] additionalResourceNames)
        {
            if (resourceName == null) throw new ArgumentNullException("resourceName");
            if (resourceName == "") throw new ArgumentException("'resourceName' must not be empty.", "resourceName");
            if (!_assemblyManifestResourceNames.Contains(resourceName.ToLowerInvariant()))
                throw new ArgumentException(string.Format("Resource '{0}' was not found in the assembly manifest resource names: {1}",
                    resourceName, string.Join(", ", _assemblyManifestResourceNames.Select(n => "'" + n + "'"))), "resourceName");

            if (additionalResourceNames != null)
            {
                foreach (var additionalResourceName in additionalResourceNames)
                {
                    if (additionalResourceName == null) throw new ArgumentException("Elements of 'additionalResourceNames' must not be null.", "additionalResourceNames");
                    if (additionalResourceName == "") throw new ArgumentException("Elements of 'additionalResourceNames' must not be empty.", "additionalResourceNames");
                    if (!_assemblyManifestResourceNames.Contains(additionalResourceName.ToLowerInvariant()))
                        throw new ArgumentException(string.Format("Additional resource '{0}' was not found in the assembly manifest resource names: {1}",
                            additionalResourceName, string.Join(", ", _assemblyManifestResourceNames.Select(n => "'" + n + "'"))), "additionalResourceNames");
                }
            }

            _targetRuntime = targetRuntime;
            _resourceName = resourceName;
            _additionalResourceNames = additionalResourceNames ?? new string[0];
        }

        /// <summary>
        /// Gets the runtime that this <see cref="DllInfo"/> targets.
        /// </summary>
        public TargetRuntime TargetRuntime
        {
            get { return _targetRuntime; }
        }

        /// <summary>
        /// Gets the resource name of the main DLL to be loaded.
        /// </summary>
        public string ResourceName
        {
            get { return _resourceName; }
        }

        /// <summary>
        /// Gets the resource names of any additional DLLs that need to be loaded.
        /// </summary>
        public string[] AdditionalResourceNames
        {
            get { return _additionalResourceNames; }
        }
    }

    /// <summary>
    /// Defines the target runtimes that are supported by the <see cref="DllInfo"/> class.
    /// </summary>
    internal enum TargetRuntime
    {
        /// <summary>
        /// A windows environment. Whether it is 32-bit or 64-bit is unspecified.
        /// </summary>
        Windows,

        /// <summary>
        /// A windows 32-bit environment.
        /// </summary>
        Win32,

        /// <summary>
        /// A Windows 64-bit environment.
        /// </summary>
        Win64,

        /// <summary>
        /// A Mac environment.
        /// </summary>
        Mac,

        /// <summary>
        /// A Linux environment.
        /// </summary>
        Linux,
    }
}