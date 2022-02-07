using System;

namespace RockLib.Interop
{
   partial class EmbeddedNativeLibrary
   {
      private class MaybeIntPtr
      {
         public MaybeIntPtr(IntPtr value)
         {
            if (value == IntPtr.Zero)
            {
               throw new ArgumentException("value must be non-zero.", nameof(value));
            }

            Exceptions = Array.Empty<Exception>();
            Value = value;
         }

         public MaybeIntPtr(Exception[] exceptions)
         {
            if(exceptions is null)
            {
               throw new ArgumentNullException(nameof(exceptions));
            }

            if(exceptions.Length == 0)
            {
               throw new ArgumentException("exceptions must contain at least one element.", nameof(exceptions));
            }

            Exceptions = exceptions;
         }

         public IntPtr Value { get; private set; }
         public Exception[] Exceptions { get; private set; }
         public bool HasValue { get { return Value != IntPtr.Zero; } }
      }
   }
}
