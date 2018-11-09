using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RockLib.Interop
{
    /// <summary>
    /// A class that provides access to the functions of a native DLL when the DLL is
    /// embedded as a resource in the same assembly that <see cref="EmbeddedNativeLibrary"/>
    /// is defined.
    /// </summary>
#if ROCKLIB_EMBEDDEDNATIVELIBRARY
    public sealed partial class EmbeddedNativeLibrary : IDisposable
#else
    internal sealed partial class EmbeddedNativeLibrary : IDisposable
#endif
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
            if (dllInfos != null && dllInfos.Any(info => info.TargetRuntime == TargetRuntime.Linux || info.TargetRuntime == TargetRuntime.Mac))
            {
                throw new ArgumentException("Embedding a Mac or Linux native library is not supported with the Load method: one or more DllInfo object had a TargetRuntime with a non-windows value.", "dllInfos");
            }

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

#if BEFORE_NET451
            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(maybePointer.Value, typeof(TDelegate));
#else
            return Marshal.GetDelegateForFunctionPointer<TDelegate>(maybePointer.Value);
#endif
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

            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
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
                    return new UnixLibraryLoader(true);
                case RuntimeOS.Linux:
                    return new UnixLibraryLoader(false);
                default:
                    throw new ArgumentOutOfRangeException("os");
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
            foreach (var candidateLocation in _libraryLoader.CandidateWritableLocations)
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
                        string.Join(", ", _libraryLoader.CandidateWritableLocations.Select(x => "'" + x + "'"))),
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
            var stream = typeof(EmbeddedNativeLibrary).Assembly.GetManifestResourceStream(resourceName);

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
    }
}