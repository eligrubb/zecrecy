# Zecrecy: a simple secret handling library for Zig

## Overview

[Zeroing](https://eprint.iacr.org/2023/1713)
[memory](https://www.cl.cam.ac.uk/archive/rja14/Papers/whatyouc.pdf)
[is](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/yang)
[hard](https://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html).
Zecrecy is a small Zig library that aims to make securely handling secrets
a little easier.

Inspired by Rust's `secrecy` crate and other, similar `SecretString` libraries,
`zecrecy` provides types for wrapping sensitive data (like cryptographic keys,
passwords, API tokens) that automatically zero out the data when no longer
needed. This helps prevent accidental secret leakage through vulnerabilities
like [buffer overflows](https://en.wikipedia.org/wiki/Heartbleed) and memory
dump attacks.[^1]

As the papers linked above conclude, using a tool like `zecrecy` will not
prevent all security vulnerabilities. However, the goal of this project is to
minimize the risk of accidental exposure, while providing an API that makes the
safest option the easiest one.

>[!WARNING]
>Zecrecy is currently in development and is not ready for production use.

## Why Zecrecy?[^2]

Traditional string and memory handling can leave sensitive data scattered
throughout memory, even after it's no longer needed. `zecrecy` addresses this
by:

- **Automatic Secure Cleanup**: Uses `std.crypto.secureZero` to overwrite
memory before deallocation
- **Controlled Access**: Explicit patterns for accessing secrets prevent
accidental exposure
- **Memory Safety**: Follows Zig's philosophy of explicit memory management
- **Zero-Cost Security**: Minimal runtime overhead for security guarantees

## Features

- **Automatic Zeroing**: Sensitive data is automatically zeroed when dropped
using `std.crypto.secureZero`
- **Destructive Initialization**: `initDestructive` securely zeros source data
after copying, preventing secrets from existing in multiple memory locations
- **Memory Safety**: Follows Zig's memory management philosophy by giving
control to the user
- **Flexible Access**: `Exposed` pattern allows safe access to secrets with
explicit mutability
- **Two Memory Models**: Choose between managed (like `std.ArrayList`) or unmanaged
(like `std.ArrayListUnmanaged`) memory handling
- **Type Safety**: Compile-time prevention of accidental secret copying or
exposure
- **Composable Design**: Clean separation between secret storage and access
patterns

## Installation

**Requirements**: Zig 0.14.1 or later

Add to your `build.zig.zon` dependencies using `zig fetch`:

```bash
zig fetch --save git+https://github.com/eligrubb/zecrecy.git
```

which will add something like the following to your `build.zig.zon`:

```zig
.dependencies = .{
    .zecrecy = .{
        .url = "git+https://github.com/eligrubb/zecrecy.git",
        .hash = "...", // Will be filled by zig fetch
    },
},
```

Then in your `build.zig`:

```zig
const zecrecy = b.dependency("zecrecy", .{
    .target = target,
});
exe.root_module.addImport("zecrecy", zecrecy.module("zecrecy"));
```

and then you can import the zecrecy library into your application:

```zig
const std = @import("std");
const zecrecy = @import("zecrecy");

const SecretString: type = zecrecy.SecretString;
```

## Usage

### Basic Usage

```zig
const std = @import("std");
const zecrecy = @import("zecrecy");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize a secret string (managed version)
    var secret_string: zecrecy.SecretString = try .init(allocator, "my_secret_key");
    defer secret_string.deinit(); // Critical: ensures secure memory AND secret cleanup

    // Access secret through read-only callback - secret never leaves the callback
    try secret_string.readWith(null, struct {
        fn printLength(_: @TypeOf(null), secret: []const u8) !void {
            std.debug.print("Secret length: {}", .{secret.len});
        }
    }.printLength);

    // For operations that need to modify the secret in-place
    try secret_string.mutateWith(null, struct {
        fn makeUppercase(_: @TypeOf(null), secret: []u8) !void {
            // Convert first two characters to uppercase
            if (secret.len >= 2) {
                secret[0] = std.ascii.toUpper(secret[0]);
                secret[1] = std.ascii.toUpper(secret[1]);
            }
        }
    }.makeUppercase);
}
```

### Initialization from Functions

```zig
// Useful for reading from environment variables or generating keys
fn getApiKeyFromEnv() []const u8 {
    return std.posix.getenv("API_KEY") orelse "default_key";
}

var secret: zecrecy.SecretString = try .initFromFunction(allocator, getApiKeyFromEnv);
defer secret.deinit();

// Use the secret through controlled access
try secret.readWith(null, struct {
    fn performAuth(_: @TypeOf(null), api_key: []const u8) !void {
        // Use api_key for authentication
        std.debug.print("Authenticating with key of length: {}", .{api_key.len});
    }
}.performAuth);
```

### Destructive Initialization

When you have sensitive data in a mutable buffer and want to ensure it's
completely wiped after creating the secret, use `initDestructive`:

```zig
// Example: securely handling a password from user input
var password_buffer = [_]u8{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

// Create secret and automatically zero the source buffer
var secret: zecrecy.SecretString = try .initDestructive(allocator, &password_buffer);
defer secret.deinit();

// password_buffer is now securely zeroed - the secret only exists in one location
// *note*: if &password_buffer is not securely zeroed, this is a potential side-channel
// attack vector, using `std.mem.eql` instead of `std.crypto.timing_safe.eql`
assert(std.mem.eql(u8, &password_buffer, &[_]u8{0} ** 8));

// Use the secret safely
try secret.readWith(null, struct {
    fn validatePassword(_: @TypeOf(null), pwd: []const u8) !void {
        // Perform password validation
        performPasswordCheck(pwd);
        // *Important*: It is the developer's responsibility to ensure that the secret
        // data is handled securely and not copied onto the stack or other memory
        // without additional zeroing.
    }
}.validatePassword);
```

### Unmanaged Memory Model

For more control over memory allocation, use the unmanaged variants:

```zig
// Unmanaged version - you control the allocator
var secret: zecrecy.SecretStringUnmanaged = try .init(allocator, "my_secret");
defer secret.deinit(allocator); // Must pass allocator to deinit

// Same callback interface works with both managed and unmanaged
try secret.readWith(null, struct {
    fn useSecret(_: @TypeOf(null), data: []const u8) !void {
        // Process secret data here
        performCryptoOperation(data);
    }
}.useSecret);

// Destructive initialization also available for unmanaged
var temp_key = [_]u8{'k', 'e', 'y', '_', 'd', 'a', 't', 'a'};
var unmanaged_secret: zecrecy.SecretStringUnmanaged = try .initDestructive(allocator, &temp_key);
defer unmanaged_secret.deinit(allocator);
// temp_key is now securely zeroed
```

### Working with Generic Secrets

```zig
// For odd secret types like obscure cryptographic keys
const KeyType = [32]u12;
var crypto_key: zecrecy.Secret(KeyType) = try .init(allocator, &my_key_bytes);
defer crypto_key.deinit();

// Access the key through callback
try crypto_key.readWith(null, struct {
    fn useCryptoKey(_: @TypeOf(null), key_data: []const u8) !void {
        // Use key_data for encryption/decryption
        assert(key_data.len == 32);
        performEncryption(key_data);
    }
}.useCryptoKey);
```

### Helper Functions for Common Operations

```zig
// Copy secret into a buffer (useful for C interop)
var buffer: [32]u8 = undefined;
try zecrecy.copySecretInto(&secret, &buffer);
defer std.crypto.secureZero(u8, &buffer); // Clean up when done

// Compare secret with expected value (constant-time comparison)
const is_correct = try zecrecy.eql(&secret, "expected_password");
if (is_correct) {
    // Authentication successful
}
```

## Design Philosophy

The library is built around two key concepts:

1. **Secret Types**: `SecretString`, `Secret(T)` and their unmanaged variants
   wrap your sensitive data and handle secure cleanup
2. **Callback-Based Access**: All access to secret data happens through
   controlled callback functions (`readWith`/`mutateWith`) that prevent
   accidental data leakage

### Callback-Based Security

This design ensures secret data never leaves the controlled access boundary:

```zig
// Function that works with any secret type through callbacks
fn performCryptoOperation(secret: anytype) !void {
    try secret.readWith(null, struct {
        fn encrypt(_: @TypeOf(null), key_data: []const u8) !void {
            // Use key_data for cryptographic operations
            // Secret data cannot be stored or copied outside this callback
            encryptWithKey(key_data);
        }
    }.encrypt);
}

// Works with both managed and unmanaged:
try performCryptoOperation(&managed_secret);
try performCryptoOperation(&unmanaged_secret);
```

## Architecture & Design Decisions

### Memory Management Philosophy

The library provides two approaches to memory management, following Zig's
standard library patterns (like `std.ArrayList` vs `std.ArrayListUnmanaged`):

- **Managed** (`SecretString`, `Secret(T)`): Stores an allocator and handles
all memory management internally
- **Unmanaged** (`SecretStringUnmanaged`, `SecretUnmanaged(T)`): Requires
passing an allocator to memory management functions

**Choose managed when:**

- You want simpler code with automatic memory handling
- The secret lifetime matches your allocator lifetime
- You're building applications where convenience is prioritized

**Choose unmanaged when:**

- You're working with complicated lifetimes and need more control over memory
allocation strategies
- You're integrating with existing memory management systems
- You're building performance-critical code where allocator passing is
preferred
- You want to minimize struct size (no stored allocator)

### Security Through Design

The callback-based approach provides several security benefits:

- **No Direct Access**: Secret data can never be accessed directly, preventing
accidental copying or exposure
- **Controlled Scope**: Secret data only exists within callback functions,
limiting its lifetime
- **Compile-Time Safety**: The type system prevents secret data from escaping
the controlled access boundary
- **Explicit Intent**: Mutable vs immutable access is clearly expressed through
`readWith` vs `mutateWith`

## Development

### Building

```bash
zig build
```

### Testing

Majority of tests are located in `src/secret.zig`.

```bash
zig build test
```

The test suite demonstrates both initialization methods and memory management patterns:

```bash
# Run tests with verbose output
zig build test --summary all
```

## Security Considerations

This library helps prevent common security issues with sensitive data:

### Automatic Memory Zeroing

- Uses `std.crypto.secureZero` to overwrite memory on cleanup
- Prevents secrets from lingering in memory after use
- Protects against memory dump attacks and similar vulnerabilities

### Controlled Access Patterns

- Callback-based access prevents secret data from leaving controlled boundaries
- Explicit mutable vs immutable access through `readWith` vs `mutateWith`
- Compile-time guarantees that secret data cannot be copied or stored outside callbacks
- Helper functions like `copySecretInto` and `secretEql` provide safe common operations

### Memory Management Integration

- Compatible with custom allocators for secure memory regions
- Allows for specialized allocation strategies

### Critical Security Notes

⚠️ **Always call `.deinit()`**: Forgetting to call `.deinit()` results in both
memory leaks AND secret leaks. The sensitive data will remain in memory without
being securely zeroed.

⚠️ **Original data cleanup**: When initializing from existing data with
`.init()`, you're responsible for securely zeroing the original data if it
contains sensitive information. Use `.initDestructive()` to automatically
handle this.

⚠️ **Mutable access**: Use `.mutateWith()` sparingly and with care. Secret data
can only be modified within the callback scope.

## Inspiration & Related Work

This library draws inspiration from:

- **Rust's [`secrecy`](https://crates.io/crates/secrecy) and
[`zeroize`](https://crates.io/crates/zeroize) crates**: The concept of wrapping
secrets with controlled access
- **C#
[SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-9.0)**:
Automatic memory protection for sensitive strings
- **Zig's stdlib patterns**: The managed/unmanaged memory model (like
`std.ArrayList`/`std.ArrayListUnmanaged`)
- **Functional programming**: Callback-based access patterns to contain scope
of data access

## License

MIT License - see [LICENSE](LICENSE) for details.

[^1]: "Helps" is doing a lot of heavy lifting here; this is not a substitute
    for proper security practices, but it can help prevent common
vulnerabilities.
[^2]: Why the name zecrecy? zig + secrecy = zecrecy 🤯
