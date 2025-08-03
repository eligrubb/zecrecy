//! # zecrecy - Secure Memory Management for Zig
//!
//! A Zig library for securely handling sensitive memory with automatic zeroing to prevent
//! secret leakage. Inspired by Rust's `secrecy` crate and similar SecureString libraries
//! in other languages, but designed specifically for Zig's memory management philosophy.
//!
//! ## Core Design Principles
//!
//! 1. **Explicit Memory Management**: Following Zig's philosophy of giving control to the user
//! 2. **Secure by Default**: Automatic zeroing prevents accidental secret leakage
//! 3. **Zero-Cost Abstractions**: Minimal runtime overhead for security features
//! 4. **Controlled Access**: Secrets can only be accessed through callback functions
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
//! // Managed version (easier to use)
//! var secret = try zecrecy.SecretString.init(allocator, "my_api_key");
//! defer secret.deinit(); // Critical: ensures secure cleanup
//!
//! // Access the secret data through controlled callbacks
//! try secret.readWith(null, struct {
//!     fn useSecret(_: @TypeOf(null), data: []const u8) !void {
//!         // Use secret data here - it's only accessible within this callback
//!         std.log.info("Secret length: {}", .{data.len});
//!     }
//! }.useSecret);
//!
//! // For simple operations, use utility functions
//! const is_match = try zecrecy.secretEql(&secret, "my_api_key");
//! ```
//!
//! ## Security Guarantees
//!
//! - Secrets are automatically zeroed on `deinit()` using `std.crypto.secureZero`
//! - Secret data is only accessible through controlled callback functions
//! - No direct access to secret memory prevents accidental copying
//! - Explicit mutable vs immutable access controls (`readWith` vs `mutateWith`)

// Re-export secret types
pub const Secret = @import("secret.zig").Secret;
pub const SecretString = @import("secret.zig").SecretString;
pub const SecretUnmanaged = @import("secret.zig").SecretUnmanaged;
pub const SecretStringUnmanaged = @import("secret.zig").SecretStringUnmanaged;

pub const copySecretInto = @import("secret.zig").copySecretInto;
pub const eql = @import("secret.zig").eql;

test "run all test" {
    const std = @import("std");
    _ = @import("secret.zig");

    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("secret.zig"));
}
