namespace RockLib.Interop
{
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
