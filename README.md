# zecrecy

A Zig library for securely handling sensitive memory with automatic zeroing to prevent secret leakage.

Inspired by Rust's `secrecy` crate and similar SecureString libraries in languages like C#, `zecrecy` provides types for wrapping sensitive data (like cryptographic keys, passwords, API tokens) that automatically zero out the data when no longer needed. This helps prevent accidental secret leakage through vulnerabilities like Heartbleed or other memory access issues.

## Why zecrecy?

Traditional string and memory handling can leave sensitive data scattered throughout memory, even after it's no longer needed. `zecrecy` addresses this by:

- **Automatic Secure Cleanup**: Uses `std.crypto.secureZero` to overwrite memory on cleanup
- **Controlled Access**: Explicit patterns for accessing secrets prevent accidental exposure
- **Memory Safety**: Follows Zig's philosophy of explicit memory management
- **Zero-Cost Security**: Minimal runtime overhead for security guarantees

## Features

- **Automatic Zeroing**: Sensitive data is automatically zeroed when dropped using `std.crypto.secureZero`
- **Memory Safety**: Follows Zig's memory management philosophy by giving control to the user
- **Flexible Access**: `Exposed` pattern allows safe access to secrets with explicit mutability
- **Two Memory Models**: Choose between managed (like `ArrayList`) or unmanaged (like `ArrayListUnmanaged`) memory handling
- **Type Safety**: Compile-time prevention of accidental secret copying or exposure
- **Composable Design**: Clean separation between secret storage and access patterns

## Installation

Add to your `build.zig.zon` dependencies:

```zig
.dependencies = .{
    .zecrecy = .{
        .url = "https://github.com/your-username/zecrecy/archive/[version].tar.gz",
        .hash = "[hash]",
    },
},
```

Then in your `build.zig`:

```zig
const zecrecy = b.dependency("zecrecy", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zecrecy", zecrecy.module("zecrecy"));
```

**Requirements**: Zig 0.14.1 or later

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
    var secret_string = try zecrecy.SecretString.init(allocator, "my_secret_key");
    defer secret_string.deinit(); // Critical: ensures secure cleanup

    // Get access to the secret through the Exposed interface
    const exposed = secret_string.exposeSecret();

    // Access the secret (immutable) - safe for crypto operations
    const secret_data = exposed.secret();
    std.log.info("Secret length: {}", .{secret_data.len});

    // For mutable access (when you need to modify the secret)
    const mutable_secret = exposed.secretMutable();
    // Example: overwrite part of the secret
    @memcpy(mutable_secret[0..2], "MY");
}
```

### Initialization from Functions

```zig
// Useful for reading from environment variables or generating keys
fn getApiKeyFromEnv() []const u8 {
    return std.posix.getenv("API_KEY") orelse "default_key";
}

var secret = try zecrecy.SecretString.initFromFunction(allocator, getApiKeyFromEnv);
defer secret.deinit();
```

### Unmanaged Memory Model

For more control over memory allocation, use the unmanaged variants:

```zig
// Unmanaged version - you control the allocator
var secret = try zecrecy.SecretStringUnmanaged.init(allocator, "my_secret");
defer secret.deinit(allocator); // Must pass allocator to deinit

// Same Exposed interface works with both managed and unmanaged
const exposed = secret.exposeSecret();
const data = exposed.secret();
```

### Working with Generic Secrets

```zig
// For non-string secrets like cryptographic keys
const KeyType = [32]u8;
var crypto_key = try zecrecy.SecretAny(KeyType).init(allocator, &my_key_bytes);
defer crypto_key.deinit();

const exposed_key = crypto_key.exposeSecret();
const key_data = exposed_key.secret(); // []const KeyType
```

## Design Philosophy

The library is built around three key concepts:

1. **Secret Types**: `SecretString`, `SecretAny(T)` and their unmanaged variants wrap your sensitive data and handle secure cleanup
2. **Exposed Pattern**: `Exposed(T)` - A lightweight accessor that allows controlled access to secrets without carrying around the full secret management overhead
3. **Unified Interface**: The same `Exposed` type works with both managed and unmanaged secret containers, allowing easy switching between memory management strategies

### The Exposed Pattern

This design allows functions to accept just the `Exposed` type when they need access to a secret, without requiring knowledge of the underlying memory management:

```zig
// Function that works with any secret type
fn performCryptoOperation(secret: *const zecrecy.ExposedString) !void {
    const key_data = secret.secret();
    // Use key_data for cryptographic operations
    // No need to know if it's managed or unmanaged
}

// Works with both:
performCryptoOperation(managed_secret.exposeSecret());
performCryptoOperation(unmanaged_secret.exposeSecret());
```

## Architecture & Design Decisions

### Memory Management Philosophy

The library provides two approaches to memory management, following Zig's standard library patterns (like `ArrayList` vs `ArrayListUnmanaged`):

- **Managed** (`SecretString`, `SecretAny(T)`): Stores an allocator and handles all memory management internally
- **Unmanaged** (`SecretStringUnmanaged`, `SecretAnyUnmanaged(T)`): Requires passing an allocator to memory management functions

**Choose managed when:**
- You want simpler code with automatic memory handling
- The secret lifetime matches your allocator lifetime
- You're building applications where convenience is prioritized

**Choose unmanaged when:**
- You need more control over memory allocation strategies
- You're integrating with existing memory management systems
- You're building performance-critical code where allocator passing is preferred
- You want to minimize struct size (no stored allocator)

### The `@fieldParentPtr` Technique

The `Exposed` pattern uses `@fieldParentPtr` to maintain a connection back to the parent secret container without storing a direct reference. This technique, inspired by Zig's recent `Io.Writer` changes, provides several benefits:

- **Memory Efficiency**: No additional pointer storage in the `Exposed` type
- **Type Safety**: Compile-time guarantee of correct parent-child relationships
- **Flexibility**: Same interface works with different underlying storage types

```zig
// The magic happens here (simplified):
fn expose(e: *const Exposed(T)) []T {
    const secret: *Secret = @fieldParentPtr("_exposed_buffer", e);
    return secret.secret;
}
```

## Development

### Building

```bash
zig build
```

### Testing

```bash
zig build test
```

The test suite demonstrates both initialization methods and memory management patterns:

```bash
# Run tests with verbose output
zig build test --summary all
```

### Example Integration

Here's a complete example showing how to integrate `zecrecy` with a crypto library:

```zig
const std = @import("std");
const zecrecy = @import("zecrecy");

fn hashPassword(password: *const zecrecy.ExposedString, salt: []const u8) ![32]u8 {
    const pwd_data = password.secret();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(pwd_data);
    hasher.update(salt);
    return hasher.finalResult();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get password securely (in real code, from secure input)
    var password = try zecrecy.SecretString.init(allocator, "user_password");
    defer password.deinit(); // Ensures password is zeroed

    const salt = "random_salt_bytes";
    const hash = try hashPassword(password.exposeSecret(), salt);
    
    std.log.info("Password hash computed: {any}", .{hash});
    // password memory is automatically zeroed on scope exit
}
```

## Security Considerations

This library helps prevent common security issues with sensitive data:

### Automatic Memory Zeroing
- Uses `std.crypto.secureZero` to overwrite memory on cleanup
- Prevents secrets from lingering in memory after use
- Protects against memory dump attacks and similar vulnerabilities

### Controlled Access Patterns
- Explicit mutable vs immutable access prevents accidental modifications
- `Exposed` pattern prevents accidental copying of secret data
- Compile-time guarantees about secret access patterns

### Memory Management Integration
- Compatible with custom allocators for secure memory regions
- Supports integration with memory protection mechanisms
- Allows for specialized allocation strategies (e.g., locked memory pages)

### Critical Security Notes

⚠️ **Always call `deinit()`**: Forgetting to call `deinit()` results in both memory leaks AND secret leaks. The sensitive data will remain in memory without being securely zeroed.

⚠️ **Original data cleanup**: When initializing from existing data, you're responsible for securely zeroing the original data if it contains sensitive information.

⚠️ **Mutable access**: Use `secretMutable()` sparingly and with care to avoid accidental exposure of sensitive data.

## Inspiration & Related Work

This library draws inspiration from:
- **Rust's `secrecy` crate**: The concept of wrapping secrets with controlled access
- **C# SecureString**: Automatic memory protection for sensitive strings  
- **Zig's stdlib patterns**: The managed/unmanaged memory model (like `ArrayList`/`ArrayListUnmanaged`)
- **Zig's `Io.Writer`**: The `@fieldParentPtr` technique for lightweight interfaces

## License

MIT License - see [LICENSE](LICENSE) for details.
