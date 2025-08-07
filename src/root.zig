//! # zecrecy - Secure Memory Management for Zig
//!
//! A Zig library for securely handling sensitive memory with automatic zeroing
//! to prevent secret leakage. Inspired by Rust's `secrecy` crate and similar
//! SecureString libraries in other languages, designed specifically around
//! Zig's memory management philosophy.
//!
//! ## Core Design Principles
//!
//! 1. **Explicit Memory Management**: Following Zig's philosophy of giving control to the user
//! 2. **Secure by Default**: Automatic zeroing prevents accidental secret leakage
//! 3. **Zero-Cost Abstractions**: Minimal runtime overhead for security features
//! 4. **Controlled Access**: Secrets accessed through explicit exposure methods
//!
//! ## Key Types
//!
//! - `Secret(T)` / `SecretString`: Managed secret containers (store allocator internally)
//! - `SecretUnmanaged(T)` / `SecretStringUnmanaged`: Unmanaged containers (pass allocator to methods)
//!
//! ## Quick Start
//!
//! ```zig
//! const std = @import("std");
//! const zecrecy = @import("zecrecy");
//!
//! // Secure initialization from environment variable
//! const getApiKey = struct {
//!     fn get() []const u8 {
//!         return std.posix.getenv("API_KEY") orelse "fallback_key";
//!     }
//! }.get;
//!
//! // Managed version (stores allocator internally)
//! var secret = try zecrecy.SecretString.initFromFunction(allocator, getApiKey);
//! defer secret.deinit(); // Critical: ensures secure cleanup
//!
//! // Read-only access to secret data
//! const key_data = secret.expose();
//! performCryptoOperation(key_data);
//!
//! // Mutable access for in-place transformations
//! const mutable_data = secret.exposeMutable();
//! transformKey(mutable_data);
//!
//! // Secure initialization with source destruction
//! var temp_key = [_]u8{'t', 'e', 'm', 'p', '_', 'k', 'e', 'y'};
//! var destructive_secret = try zecrecy.SecretString.initDestructive(allocator, &temp_key);
//! defer destructive_secret.deinit();
//! // temp_key is now securely zeroed
//!
//! // Compare secrets securely (works between managed and unmanaged types)
//! const is_equal = secret.eql(destructive_secret);
//! ```
//!
//! ## Unmanaged Version
//!
//! ```zig
//! // Secure initialization from function
//! const getToken = struct {
//!     fn get() []const u8 {
//!         return std.posix.getenv("AUTH_TOKEN") orelse "default_token";
//!     }
//! }.get;
//!
//! // Unmanaged version (pass allocator to methods)
//! var secret = try zecrecy.SecretStringUnmanaged.initFromFunction(allocator, getToken);
//! defer secret.deinit(allocator); // Pass allocator to deinit
//!
//! const key_data = secret.expose();
//! performCryptoOperation(key_data);
//! ```
//!
//! ## Initialization Options
//!
//! - `init(allocator, data)`: Copy data into secret (original data unchanged)
//! - `initDestructive(allocator, data)`: Copy data and securely zero the source
//! - `initFromFunction(allocator, func)`: Initialize from a function that returns secret data
//!
//! ## Security Guarantees
//!
//! - Secrets are automatically zeroed on `deinit()` using `std.crypto.secureZero`
//! - Secret data accessible through explicit `.expose()` and `.exposeMutable()` methods
//! - Controlled access patterns prevent accidental copying of secret data
//! - Constant-time comparison with `.eql()` method prevents timing attacks

// Re-export secret types
pub const Secret = @import("secret.zig").Secret;
pub const SecretString = @import("secret.zig").SecretString;
pub const SecretUnmanaged = @import("secret.zig").SecretUnmanaged;
pub const SecretStringUnmanaged = @import("secret.zig").SecretStringUnmanaged;

test "run all test" {
    const std = @import("std");
    _ = @import("secret.zig");

    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("secret.zig"));
}
