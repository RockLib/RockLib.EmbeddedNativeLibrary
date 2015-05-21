Rock.EmbeddedNativeLibrary
==========================

Consuming native DLLs (usually C libraries) can be tricky in .NET - especially when you're dealing with a NuGet package. This package is a solution to the problem.

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

1. Add the `Rock.EmbeddedNativeLibrary` nuget package to your project.
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
        var sodiumLibrary = new EmbeddedNativeLibrary("sodium", "MyLibrary.libsodium.dll"); // 3
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
  - You'll get a run-time error if you try to use a generic delegate.
2. Decorate that delegate with the `[UnmanagedFunctionPointer(CallingConvention.Cdecl)]` attribute.
  - You'll get a run-time error if you don't decorate the delegate with this attribute.
3. Create an instance of `EmbeddedNativeLibrary`, passing it the name of the library, and the name of the resource.
  - There is another constructor that allows you to choose the "correct" resource. This is useful for differentiating between 32-bit and 64-bit native DLLs.
4. Call the `GetDelegate` method, caching the resulting delegate in a private field.
5. Invoke the cached delegate.
  - _This_ is what you've wanted all along - a delegate that, when invoked, calls the native function.
