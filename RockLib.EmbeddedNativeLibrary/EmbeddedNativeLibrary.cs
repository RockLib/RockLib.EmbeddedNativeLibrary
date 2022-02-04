using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
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
   public sealed partial class EmbeddedNativeLibrary : IDisposable
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
            throw new ArgumentException("Embedding a Mac or Linux native library is not supported with the Load method: one or more DllInfo object had a TargetRuntime with a non-windows value.", nameof(dllInfos));
         }

         if (_runtimeOS != RuntimeOS.Windows)
         {
            return false;
         }

         using var library = new EmbeddedNativeLibrary(libraryName, preferEmbeddedOverInstalled, dllInfos!);
         var libraryPointer = library._libraryPointer.Value;
         return libraryPointer != IntPtr.Zero;
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
         if (libraryName == null) throw new ArgumentNullException(nameof(libraryName));
         if (dllInfos == null) throw new ArgumentNullException(nameof(dllInfos));
         if (libraryName.Length == 0) throw new ArgumentException("'libraryName' must not be empty.", nameof(libraryName));
         if (dllInfos.Length == 0) throw new ArgumentException("'dllInfos' must not be empty.", nameof(dllInfos));

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
               $"Unable to load library from resources: {string.Join(", ", dllInfos.Select(dll => dll.ResourceName))}",
               exceptions.ToArray());
         });
      }

      private static IntPtr LoadFromDllInfos(string libraryName, DllInfo[] dllInfos, List<Exception> exceptions)
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
               $"The load library operation for '{dllInfo.ResourceName}' failed and reported {maybePointer.Exceptions.Length} exception{(maybePointer.Exceptions.Length > 1 ? "s" : "")}.",
               maybePointer.Exceptions));
         }

         return IntPtr.Zero;
      }

      private static IntPtr LoadFromInstall(string libraryName)
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

      private static bool RuntimeMatchesTarget(TargetRuntime targetRuntime)
      {
         return targetRuntime switch
         {
            TargetRuntime.Windows => _runtimeOS == RuntimeOS.Windows,
            TargetRuntime.Win32 => _runtimeOS == RuntimeOS.Windows && IntPtr.Size == 4,
            TargetRuntime.Win64 => _runtimeOS == RuntimeOS.Windows && IntPtr.Size == 8,
            TargetRuntime.Mac => _runtimeOS == RuntimeOS.Mac,
            TargetRuntime.Linux => _runtimeOS == RuntimeOS.Linux,
            _ => false,
         };
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
         if (functionName == null) throw new ArgumentNullException(nameof(functionName));
         if (functionName.Length == 0) throw new ArgumentException("'functionName' must not be empty.", nameof(functionName));

         if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
         {
            throw new InvalidOperationException("TDelegate must be a delegate.");
         }
      }

      private static ILibraryLoader GetLibraryLoader(RuntimeOS os)
      {
         return os switch
         {
            RuntimeOS.Windows => new WindowsLibraryLoader(),
            RuntimeOS.Mac => new UnixLibraryLoader(true),
            RuntimeOS.Linux => new UnixLibraryLoader(false),
            _ => throw new ArgumentOutOfRangeException(nameof(os)),
         };
      }

      private static RuntimeOS GetRuntimeOS()
      {
         var windir = Environment.GetEnvironmentVariable("windir");

#if NET48
         if (!string.IsNullOrEmpty(windir) && windir.Contains('\\') && Directory.Exists(windir))
#else
         if (!string.IsNullOrEmpty(windir) && windir.Contains('\\', StringComparison.OrdinalIgnoreCase) && Directory.Exists(windir))
#endif
         {
            return RuntimeOS.Windows;
         }
         else if (File.Exists(@"/proc/sys/kernel/ostype"))
         {
            var osType = File.ReadAllText(@"/proc/sys/kernel/ostype");
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
         var dllData = LoadResource(dllInfo.ResourceName);
         var hash = GetHash(dllData);

         string? directory = null;

         var exceptions = new List<Exception>();
         foreach (var candidateLocation in _libraryLoader.CandidateWritableLocations)
         {
            if (TryGetWritableDirectory(
                candidateLocation, libraryName, hash, out directory, out var exception))
            {
               Debug.Assert(directory != null, "'directory' must not be null if TryGetWritableDirectory returns true.");
               break;
            }
            exceptions.Add(exception!);
         }

         if (directory == null)
         {
            throw new AggregateException(
               $"Unable to obtain writable file path in candidate locations: {string.Join(", ", _libraryLoader.CandidateWritableLocations.Select(x => "'" + x + "'"))}.",
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
          string root, string libraryName, string hash, out string? directory, out Exception? exception)
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
         exception = null;
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
         using var algorithm = SHA256.Create();
         var hash = algorithm.ComputeHash(dllData);
         var builder = new StringBuilder(hash.Length * 2);

         foreach (var value in hash)
         {
            builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
         }

         return builder.ToString();
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