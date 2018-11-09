using System;
using System.Diagnostics;

namespace RockLib.Interop
{
    partial class EmbeddedNativeLibrary
    {
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
    }
}
