using System;
using System.Runtime.Serialization;

namespace RockLib.Interop
{
   /// <summary>
   /// Exception that is created when a library cannot be loaded.
   /// </summary>
   [Serializable]
   public sealed class GetFunctionPointerException
      : Exception
   {
      /// <summary>
      /// Creates a new <see cref="GetFunctionPointerException" />
      /// </summary>
      public GetFunctionPointerException() { }

      /// <summary>
      /// Creates a new <see cref="GetFunctionPointerException" />
      /// </summary>
      /// <param name="message">
      /// The message that describes the error.
      /// </param>
      public GetFunctionPointerException(string message) : base(message) { }

      /// <summary>
      /// Creates a new <see cref="GetFunctionPointerException" />
      /// </summary>
      /// <param name="message">
      /// The message that describes the error.
      /// </param>
      /// <param name="inner">
      /// The exception that is the cause of the current exception, or <c>null</c>
      /// if no inner exception is specified.
      /// </param>
      public GetFunctionPointerException(string message, Exception? inner) : base(message, inner) { }

      private GetFunctionPointerException(SerializationInfo serializationInfo, StreamingContext streamingContext)
         : base(serializationInfo, streamingContext) { }
   }
}
