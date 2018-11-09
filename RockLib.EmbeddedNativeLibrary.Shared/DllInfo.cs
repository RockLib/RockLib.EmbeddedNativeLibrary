using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace RockLib.Interop
{
    /// <summary>
    /// Contains resource names for the DLLs that are embedded in this assembly. The DLLs
    /// must all be of the same architecture (x86 or x64).
    /// </summary>
#if ROCKLIB_EMBEDDEDNATIVELIBRARY
    public sealed class DllInfo
#else
    internal sealed class DllInfo
#endif
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
            if (resourceName == null) throw new ArgumentNullException("resourceName");
            if (resourceName == "") throw new ArgumentException("'resourceName' must not be empty.", "resourceName");
            if (!_assemblyManifestResourceNames.Contains(resourceName))
                throw new ArgumentException(string.Format("Resource '{0}' was not found in the assembly manifest resource names: {1}",
                    resourceName, string.Join(", ", _assemblyManifestResourceNames.Select(n => "'" + n + "'"))), "resourceName");

            if (additionalResourceNames != null)
            {
                foreach (var additionalResourceName in additionalResourceNames)
                {
                    if (additionalResourceName == null) throw new ArgumentException("Elements of 'additionalResourceNames' must not be null.", "additionalResourceNames");
                    if (additionalResourceName == "") throw new ArgumentException("Elements of 'additionalResourceNames' must not be empty.", "additionalResourceNames");
                    if (!_assemblyManifestResourceNames.Contains(additionalResourceName))
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
}
