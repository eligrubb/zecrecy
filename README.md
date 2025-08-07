# Zecrecy: a simple secret sanitization library for Zig 🧼

![Zig
Version](https://img.shields.io/badge/Zig-0.14.1-color?logo=zig&color=%23f3ab20)
[![Tests](https://github.com/eligrubb/zecrecy/actions/workflows/main.yml/badge.svg)](https://github.com/eligrubb/zecrecy/actions/workflows/main.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

[Zeroing](https://eprint.iacr.org/2023/1713)
[memory](https://www.cl.cam.ac.uk/archive/rja14/Papers/whatyouc.pdf)
[is](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/yang)
[hard](https://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html).
Zecrecy is a small Zig library that aims to make securely handling secrets
a little easier.

Inspired by Rust's `secrecy` crate and other, similar `SecureString` libraries,
`zecrecy` provides types for wrapping sensitive data (like cryptographic keys,
passwords, API tokens) that automatically zero out the data when no longer
needed. This helps prevent accidental secret leakage through vulnerabilities
like [buffer overflows](https://en.wikipedia.org/wiki/Heartbleed) and memory
dump attacks.[^1]

As the papers linked above conclude, using a tool like `zecrecy` will not
prevent all memory-leak-style security vulnerabilities. The goal of this
project is to minimize the risk of accidental exposure, while providing an API
that makes the safest option the easiest one.

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
- **Direct Access**: `expose()` and `exposeMutable()` methods provide controlled
access to secret data with explicit mutability
- **Secure Comparison**: `.eql()` method enables constant-time comparison between
any secret types (managed, unmanaged, different element types)
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

    // Access secret data as read-only slice
    const secret_data = secret_string.expose();
    std.debug.print("Secret length: {}\n", .{secret_data.len});

    // For operations that need to modify the secret in-place
    const mutable_data = secret_string.exposeMutable();
    if (mutable_data.len >= 2) {
        mutable_data[0] = std.ascii.toUpper(mutable_data[0]);
        mutable_data[1] = std.ascii.toUpper(mutable_data[1]);
    }
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

// Access the secret data directly
const api_key = secret.expose();
std.debug.print("Authenticating with key of length: {}\n", .{api_key.len});
// Use api_key for authentication operations
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
std.testing.expectEqualSlices(u8, &[_]u8{0} ** 8, &password_buffer) catch unreachable;

// Access the secret data for validation
const password_data = secret.expose();
performPasswordCheck(password_data);
// *Important*: Avoid storing references to the exposed slice
```

### Unmanaged Memory Model

For more control over memory allocation, use the unmanaged variants:

```zig
// Unmanaged version - you control the allocator
var secret: zecrecy.SecretStringUnmanaged = try .init(allocator, "my_secret");
defer secret.deinit(allocator); // Must pass allocator to deinit

// Same access methods work with both managed and unmanaged
const secret_data = secret.expose();
performCryptoOperation(secret_data);

// Destructive initialization also available for unmanaged
var temp_key = [_]u8{'k', 'e', 'y', '_', 'd', 'a', 't', 'a'};
var unmanaged_secret: zecrecy.SecretStringUnmanaged = try .initDestructive(allocator, &temp_key);
defer unmanaged_secret.deinit(allocator);
// temp_key is now securely zeroed
```

### Working with Generic Secrets

```zig
// For custom secret types like cryptographic keys
const KeyType = u32;
var key_data = [_]KeyType{0x12345678} ** 8; // 32 bytes
var crypto_key: zecrecy.Secret(KeyType) = try .init(allocator, &key_data);
defer crypto_key.deinit();

// Access the key data directly
const key_slice = crypto_key.expose();
std.debug.assert(key_slice.len == 8);
performEncryption(key_slice);
```

### Helper Functions for Common Operations

```zig
// Compare secrets using constant-time comparison (works between managed and unmanaged types)
var secret1: zecrecy.SecretString = try .init(allocator, "password123");
defer secret1.deinit();
var secret2: zecrecy.SecretString = try .init(allocator, "password123");
defer secret2.deinit();

// Compare managed secrets
if (secret1.eql(secret2)) {
    // Managed secrets match - authentication successful
    std.debug.print("Authentication successful\n");
}

// Compare with unmanaged secret
var unmanaged_secret: zecrecy.SecretStringUnmanaged = try .init(allocator, "password123");
defer unmanaged_secret.deinit(allocator);

if (secret1.eql(unmanaged_secret)) {
    // Mixed type comparison works seamlessly
    std.debug.print("Cross-type comparison successful\n");
}

// Copy secret data for use with external APIs
const secret_data = secret1.expose();
var buffer: [32]u8 = undefined;
if (secret_data.len <= buffer.len) {
    @memcpy(buffer[0..secret_data.len], secret_data);
    defer std.crypto.secureZero(u8, buffer[0..secret_data.len]); // Clean up when done
    performExternalOperation(buffer[0..secret_data.len]);
}
```

## Design Philosophy

The library is built around two key concepts:

1. **Secret Types**: `SecretString`, `Secret(T)` and their unmanaged variants
   wrap your sensitive data and handle secure cleanup
2. **Controlled Access**: Access to secret data happens through explicit
   `expose()` and `exposeMutable()` methods that return slices for immediate use

### Direct Access Security

This design provides controlled access while maintaining performance:

```zig
// Function that works with any secret type
fn performCryptoOperation(secret: anytype) !void {
    const key_data = secret.expose();
    encryptWithKey(key_data);
    // Use key_data immediately - avoid storing references
}

// Works with both managed and unmanaged:
try performCryptoOperation(&managed_secret);
try performCryptoOperation(&unmanaged_secret);

// Generic comparison function using the eql method
fn compareSecrets(a: anytype, b: anytype) bool {
    return a.eql(b);
}
```

In tying the secret's lifetime to the lifetime of the underlying memory,
`zecrecy` makes the simple contract: **manage memory correctly, get secure
secrets automatically**.

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
- The secret lifetime matches your `allocator` lifetime
- You're building applications where convenience is prioritized

**Choose unmanaged when:**

- You're working with complicated lifetimes and need more control over memory
allocation strategies
- You're integrating with existing memory management systems
- You're building performance-critical code where allocator passing is
preferred
- You want to minimize struct size (no stored allocator)

### Security Through Design

The direct access approach provides several security benefits:

- **Controlled Access**: Secrets are only accessible through explicit
`.expose()` and `.exposeMutable()` method calls
- **Clear Intent**: Mutable vs immutable access is clearly expressed through
different method calls
- **Immediate Use**: Returned slices are intended for immediate use, discouraging
storing references
- **Automatic Cleanup**: All secret data is securely zeroed on `.deinit()`

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

- Direct access through `.expose()` and `.exposeMutable()` methods
- Explicit mutable vs immutable access patterns
- Built-in `.eql()` method provides constant-time secret comparison
- Exposed slices should be used immediately to minimize exposure time

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

⚠️ **Mutable access**: Use `.exposeMutable()` sparingly and with care. Avoid
storing references to the returned mutable slice.

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
for proper security practices, but it can help prevent common vulnerabilities.

[^2]: For anyone asking literally: zig + secrecy = zecrecy 🔥🖋️🤓
