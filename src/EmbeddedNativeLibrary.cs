using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;

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
        /// <param name="nativeDllResourceName">
        /// The name of the native DLL embedded resource.
        /// </param>
        public EmbeddedNativeLibrary(string libraryName, string nativeDllResourceName)
            : this(libraryName, () => nativeDllResourceName)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EmbeddedNativeLibrary"/> class.
        /// </summary>
        /// <param name="libraryName">The name of the library.</param>
        /// <param name="getNativeDllResourceName">
        /// A function that returns the name of the native DLL embedded resource.
        /// </param>
        public EmbeddedNativeLibrary(string libraryName, Func<string> getNativeDllResourceName)
        {
            _libraryPointer = new Lazy<IntPtr>(() =>
                LoadLibrary(GetPathToNativeDll(libraryName, getNativeDllResourceName())));
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
                throw new InvalidOperationException("Unable to locate function: " + functionName);
            }

            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(
                functionPointer, typeof(TDelegate));
        }

        private static string GetPathToNativeDll(string libraryName, string nativeDllResourceName)
        {
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(nativeDllResourceName);

            if (stream == null)
            {
                throw new DllNotFoundException("Unable to locate resource: " + nativeDllResourceName);
            }

            var buffer = new byte[stream.Length];
            stream.Read(buffer, 0, buffer.Length);

            var dir =
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    libraryName,
                    GetHash(buffer));

            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var path = Path.Combine(dir, libraryName + ".dll");

            if (!File.Exists(path))
            {
                File.WriteAllBytes(path, buffer);
            }

            return path;
        }

        private static string GetHash(byte[] buffer)
        {
            using (var md5 = MD5.Create())
            {
                return new SoapHexBinary(md5.ComputeHash(buffer)).ToString();
            }
        }

        private void FreeLibrary()
        {
            if (_libraryPointer.IsValueCreated)
            {
                FreeLibrary(_libraryPointer.Value);
            }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        private static extern bool FreeLibrary(IntPtr hModule);
    }
}
