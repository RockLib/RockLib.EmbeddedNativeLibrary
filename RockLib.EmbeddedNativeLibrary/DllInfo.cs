using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace RockLib.Interop
{
   /// <summary>
   /// Contains resource names for the DLLs that are embedded in this assembly. The DLLs
   /// must all be of the same architecture (x86 or x64).
   /// </summary>
   public sealed class DllInfo
   {
      private static readonly ReadOnlyCollection<string> _assemblyManifestResourceNames = typeof(DllInfo).Assembly.GetManifestResourceNames().ToList().AsReadOnly();

      private readonly TargetRuntime _targetRuntime;
      private readonly string _resourceName;
      private readonly string[] _additionalResourceNames;

      /// <summary>
      /// Initializes a new instance of the <see cref="DllInfo"/> class, assuming the target runtime to be
      /// <see cref="Interop.TargetRuntime.Windows"/>.
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
         if (resourceName == null) throw new ArgumentNullException(nameof(resourceName));
         if (resourceName.Length == 0) throw new ArgumentException("'resourceName' must not be empty.", nameof(resourceName));
         if (!_assemblyManifestResourceNames.Contains(resourceName))
         {
            var resourceNames = string.Join(", ", _assemblyManifestResourceNames.Select(n => "'" + n + "'"));
            throw new ArgumentException($"Resource '{resourceName}' was not found in the assembly manifest resource names: {resourceNames}", nameof(resourceName));
         }

         if (additionalResourceNames != null)
         {
            foreach (var additionalResourceName in additionalResourceNames)
            {
               if (additionalResourceName == null) throw new ArgumentException("Elements of 'additionalResourceNames' must not be null.", nameof(additionalResourceNames));
               if (additionalResourceName.Length == 0) throw new ArgumentException("Elements of 'additionalResourceNames' must not be empty.", nameof(additionalResourceNames));
               if (!_assemblyManifestResourceNames.Contains(additionalResourceName))
               {
                  var resourceNames = string.Join(", ", _assemblyManifestResourceNames.Select(n => "'" + n + "'"));
                  throw new ArgumentException($"Additional resource '{additionalResourceName}' was not found in the assembly manifest resource names: {resourceNames}",
                      nameof(additionalResourceNames));
               }
            }
         }

         _targetRuntime = targetRuntime;
         _resourceName = resourceName;
         _additionalResourceNames = additionalResourceNames ?? Array.Empty<string>();
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
#pragma warning disable CA1819 // Properties should not return arrays
      public string[] AdditionalResourceNames
#pragma warning restore CA1819 // Properties should not return arrays
      {
         get { return _additionalResourceNames; }
      }
   }
}
