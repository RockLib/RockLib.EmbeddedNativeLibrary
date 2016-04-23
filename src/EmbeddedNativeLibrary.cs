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
        public EmbeddedNativeLibrary(string libraryName, params DllInfo[] dllInfos)
        {
            if (libraryName == null) throw new ArgumentNullException("libraryName");
            if (dllInfos == null) throw new ArgumentNullException("dllInfos");
            if (libraryName == "") throw new ArgumentException("'libraryName' must not be empty.", "libraryName");
            if (dllInfos.Length == 0) throw new ArgumentException("'dllInfos' must not be empty.", "dllInfos");

            _libraryPointer = new Lazy<IntPtr>(() =>
            {
                var win32Exceptions = new List<Exception>();

                foreach (var dllInfo in dllInfos)
                {
                    var libraryPath = GetLibraryPath(libraryName, dllInfo);
                    var libraryPointer = LoadLibrary(libraryPath);

                    if (libraryPointer != IntPtr.Zero)
                    {
                        return libraryPointer;
                    }

                    win32Exceptions.Add(new Win32Exception());
                }

                throw new EmbeddedNativeLibraryException(
                    "Unable to load library from resources: " + string.Join(", ", dllInfos.Select(dll => dll.ResourceName)),
                    win32Exceptions.ToArray());
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
        /// <exception cref="System.InvalidOperationException">
        /// TDelegate is not delegate.
        /// or
        /// Unable to locate functionName.
        /// </exception>
        public TDelegate GetDelegate<TDelegate>(string functionName)
        {
            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
            {
                throw new InvalidOperationException("TDelegate must be a delegate.");
            }

            var functionPointer = GetProcAddress(_libraryPointer.Value, functionName);

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

            var directory =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    libraryName,
                    GetHash(dllData));

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
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
                FreeLibrary(_libraryPointer.Value);
            }
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);
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
        public DllInfo(string resourceName, params string[] additionalResourceNames)
        {
            if (resourceName == null) throw new ArgumentNullException("resourceName");

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
    public sealed class EmbeddedNativeLibraryException : AggregateException
    {
        internal EmbeddedNativeLibraryException(string message, params Exception[] win32Exceptions)
            : base(message, win32Exceptions)
        {
        }
    }
}