RockLib.EmbeddedNativeLibrary
==========================

Consuming third-party native DLLs (usually C libraries) can be tricky in .NET - especially when your project is deployed as a NuGet package. The RockLib.EmbeddedNativeLibrary NuGet package makes this sort of native interop easy.

```
PM> Install-Package RockLib.EmbeddedNativeLibrary
```

Problem
--------

The "normal" way to use a native DLL is to declare an `extern` function, also known as P/Invoke, like this:

```c#
[DllImport("libsodium.dll", EntryPoint = "sodium_init", CallingConvention = CallingConvention.Cdecl)]
private static extern void SodiumInit();
```

Since `libsodium.dll` is not part of the operating system (like `kernel32.dll` or `user32.dll`), the DLL file will need to be in the same directory as the assembly where the extern function is defined - just like a .NET DLL. However, unlike a .NET DLL, a native DLL cannot be referenced by a .NET project. The implications of this difference are significant.

Since the native DLL cannot be referenced by a .NET project, it isn't recognized by MSBuild or other build tools. That means that the native DLL won't be copied to a build's output directory. This means that the application will fail when it tries to invoke the extern function.

Solution
--------

1. Add the `RockLib.EmbeddedNativeLibrary` nuget package to your project.
2. Add the native DLL to the project as an [embedded resource](https://support.microsoft.com/en-us/kb/319292).
3. Create an instance of `EmbeddedNativeLibrary`, and call its `GetDelegate` method to obtain a delegate that invokes that native function.

1 and 2 are pretty self-explanatory. But 3... not so much. An example should help. The following class exposes libsodium's `crypto_secretbox` method (the numbers refer to the descriptions below):

```c#
public static class Sodium
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] // 2
    private delegate int SecretBoxDelegate(
        byte[] buffer, byte[] payload, long payloadLength, byte[] nonce, byte[] key); // 1

    private static readonly SecretBoxDelegate _cryptoSecretbox;

    static Sodium()
    {
        var sodiumLibrary = new EmbeddedNativeLibrary(
            "sodium",
            new DllInfo("MyLibrary.Native64.libsodium.dll", "MyLibrary.Native64.msvcr120.dll"),
            new DllInfo("MyLibrary.Native32.libsodium.dll", "MyLibrary.Native32.msvcr120.dll")); // 3
        _cryptoSecretbox = sodiumLibrary.GetDelegate<SecretBoxDelegate>("crypto_secretbox"); // 4
    }

    public static int crypto_secretbox(byte[] buffer, byte[] message, long messageLength, byte[] nonce, byte[] key)
    {
        return _cryptoSecretbox(buffer, message, messageLength, nonce, key); // 5
    }
}
```

There are several things going on here.

1. Declare a non-generic delegate that match the native function's signature.
  - You'll get a run-time error if you try to use a generic delegate. (Why? See the Exceptions section in [this MSDN article](https://msdn.microsoft.com/en-us/library/vstudio/zdx6dyyh.aspx) for details.)
2. Decorate that delegate with an `[UnmanagedFunctionPointer]` attribute.
  - You may get a run-time error if you don't decorate the delegate with this attribute.
  - You'll need to know the calling convention of the native function (libsodium in the example uses the CDECL calling convention).
3. Create an instance of `EmbeddedNativeLibrary`, passing it the name of the library, and one or more `DllInfo` objects.
  - A `DllInfo` object allows you to specify resource name of the DLL
    - Additional DLLs may also be specified when the primary DLL has dependencies on another DLLs.
    - All DLLs should all target the same architecture (x86 or x64).
  - `EmbeddedNativeLibrary` is able to handle multiple architectures by passing multiple `DllInfo` objects into its constructor. However, it doesn't actually track or check the architecture of the embedded DLLs. During loading, this is what `EmbeddedNativeLibrary` does:
    - Attempt to load the DLL specified by the first `DllInfo`.
    - If that DLL cannot be loaded, try the DLL specified by the second `DllInfo`.
    - Keep going until a DLL is successfully loaded.
    - If no DLL is successfully loaded, throw an exception.
4. Call the `GetDelegate` method, caching the resulting delegate in a private field.
5. Invoke the cached delegate.
  - _This_ is what you've wanted all along - a delegate that, when invoked, calls the native function.
