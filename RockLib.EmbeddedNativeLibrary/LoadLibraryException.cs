using System;
using System.Runtime.Serialization;

namespace RockLib.Interop
{
   /// <summary>
   /// Exception that is created when a library cannot be loaded.
   /// </summary>
   [Serializable]
   public sealed class LoadLibraryException 
      : Exception
   {
      /// <summary>
      /// Creates a new <see cref="LoadLibraryException" />
      /// </summary>
      public LoadLibraryException() { }

      /// <summary>
      /// Creates a new <see cref="LoadLibraryException" />
      /// </summary>
      /// <param name="message">
      /// The message that describes the error.
      /// </param>
      public LoadLibraryException(string message) : base(message) { }

      /// <summary>
      /// Creates a new <see cref="LoadLibraryException" />
      /// </summary>
      /// <param name="message">
      /// The message that describes the error.
      /// </param>
      /// <param name="inner">
      /// The exception that is the cause of the current exception, or <c>null</c>
      /// if no inner exception is specified.
      /// </param>
      public LoadLibraryException(string message, Exception? inner) : base(message, inner) { }

      private LoadLibraryException(SerializationInfo serializationInfo, StreamingContext streamingContext)
         : base(serializationInfo, streamingContext) { }
   }
}
