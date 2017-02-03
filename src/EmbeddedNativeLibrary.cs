using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
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
        private readonly Lazy<IntPtr> _libraryPointer;

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
        {
            if (libraryName == null) throw new ArgumentNullException("libraryName");
            if (dllInfos == null) throw new ArgumentNullException("dllInfos");
            if (libraryName == "") throw new ArgumentException("'libraryName' must not be empty.", "libraryName");
            if (dllInfos.Length == 0) throw new ArgumentException("'dllInfos' must not be empty.", "dllInfos");

            _libraryPointer = new Lazy<IntPtr>(() =>
            {
                var exceptions = new List<Exception>();

                foreach (var dllInfo in dllInfos)
                {
                    var libraryPath = GetLibraryPath(libraryName, dllInfo);
                    var libraryPointer = NativeMethods.LoadLibrary(libraryPath);

                    if (libraryPointer != IntPtr.Zero)
                    {
                        return libraryPointer;
                    }

                    exceptions.Add(new Win32Exception());
                }

                throw new EmbeddedNativeLibraryException(
                    "Unable to load library from resources: " + string.Join(", ", dllInfos.Select(dll => dll.ResourceName)),
                    exceptions.ToArray());
            });
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
        /// <exception cref="System.InvalidOperationException">
        /// TDelegate is not delegate.
        /// </exception>
        /// <exception cref="EmbeddedNativeLibraryException">
        /// Unable to load the native library.
        /// or
        /// Unable to get a pointer to the function.
        /// </exception>
        public TDelegate GetDelegate<TDelegate>(string functionName)
        {
            if (functionName == null) throw new ArgumentNullException("functionName");
            if (functionName == "") throw new ArgumentException("'functionName' must not be empty.", "functionName");

            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
            {
                throw new InvalidOperationException("TDelegate must be a delegate.");
            }

            var functionPointer = NativeMethods.GetProcAddress(_libraryPointer.Value, functionName);

            if (functionPointer == IntPtr.Zero)
            {
                throw new EmbeddedNativeLibraryException(
                    "Unable to load function: " + functionName,
                    new Win32Exception());
            }

            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(
                functionPointer, typeof(TDelegate));
        }

        private static string GetLibraryPath(string libraryName, DllInfo dllInfo)
        {
            var dllData = LoadResource(dllInfo.ResourceName);
            var hash = GetHash(dllData);

            string directory;
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Exception localApplicationDataException = null;
            if (!TryGetWritableDirectory(
                    localAppData, libraryName, hash, out directory, ref localApplicationDataException))
            {
                var tempDirectory = Environment.GetEnvironmentVariable("TMP");
                if (tempDirectory == null)
                {
                    tempDirectory = Environment.GetEnvironmentVariable("TEMP");
                    if (tempDirectory == null)
                    {
                        throw new EmbeddedNativeLibraryException(
                            string.Format("Unable to write to %LOCALAPPDATA% ({0}) and no TEMP directory exists.", localAppData),
                            localApplicationDataException);
                    }
                }

                Exception tempException = null;
                if (!TryGetWritableDirectory(
                        tempDirectory, libraryName, hash, out directory, ref tempException))
                {
                    throw new EmbeddedNativeLibraryException(
                        string.Format("Unable to write to %LOCALAPPDATA% ({0}) or the TEMP directory ({1}).", localAppData, tempDirectory),
                        localApplicationDataException, tempException);
                }
            }

            var path = WriteDll(dllData, dllInfo.ResourceName, directory);

            var pathVariable = Environment.GetEnvironmentVariable("PATH");
            pathVariable = pathVariable + ";" + directory;
            Environment.SetEnvironmentVariable("PATH", pathVariable);

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
            var fileName = Regex.Match(resourceName, @"[^.]+\.(?:dll|exe)").Value;
            var path = Path.Combine(directory, fileName);

            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, dllData);
            }

            return path;
        }

        private static byte[] LoadResource(string resourceName)
        {
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);

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
                return new SoapHexBinary(md5.ComputeHash(dllData)).ToString();
            }
        }

        private void FreeLibrary()
        {
            if (_libraryPointer.IsValueCreated)
            {
                NativeMethods.FreeLibrary(_libraryPointer.Value);
            }
        }

        private static class NativeMethods
        {
            [DllImport("kernel32.dll", EntryPoint = "LoadLibrary", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
            public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpLibFileName);

            [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

            [DllImport("kernel32.dll", EntryPoint = "FreeLibrary", SetLastError = true)]
            public static extern bool FreeLibrary(IntPtr hModule);
        }
    }

    /// <summary>
    /// Contains resource names for the DLLs that are embedded in this assembly. The DLLs
    /// must all be of the same architecture (x86 or x64).
    /// </summary>
    internal sealed class DllInfo
    {
        private readonly string _resourceName;
        private readonly string[] _additionalResourceNames;

        /// <summary>
        /// Initializes a new instance of the <see cref="DllInfo"/> class.
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
        /// <paramref name="additionalResourceNames"/> has any null elements.
        /// or
        /// <paramref name="additionalResourceNames"/> has any empty elements.
        /// </exception>
        public DllInfo(string resourceName, params string[] additionalResourceNames)
        {
            if (resourceName == null) throw new ArgumentNullException("resourceName");
            if (resourceName == "") throw new ArgumentException("'resourceName' must not be empty.", "resourceName");

            if (additionalResourceNames != null)
            {
                foreach (var additionalResourceName in additionalResourceNames)
                {
                    if (additionalResourceName == null) throw new ArgumentException("Elements of 'additionalResourceNames' must not be null.", "additionalResourceNames");
                    if (additionalResourceName == "") throw new ArgumentException("Elements of 'additionalResourceNames' must not be empty.", "additionalResourceNames");
                }
            }

            _resourceName = resourceName;
            _additionalResourceNames = additionalResourceNames ?? new string[0];
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
    /// An exception thrown when a problem is encountered when loading a native library or
    /// a native library's function.
    /// </summary>
    [Serializable]
    public sealed class EmbeddedNativeLibraryException : AggregateException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EmbeddedNativeLibraryException"/> class
        /// with a specified error message and references to the inner exceptions that are the
        /// cause of this exception. 
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="exceptions">The exceptions that are the cause of the current exception.</param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="exceptions"/> argument is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="exceptions"/> has any null elements.
        /// </exception>
        internal EmbeddedNativeLibraryException(string message, params Exception[] exceptions)
            : base(message, exceptions)
        {
        }
    }
}