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
//! 4. **Composable Architecture**: Clean separation between storage and access patterns
//!
//! ## Key Types
//!
//! - `Exposed(T)`: Lightweight accessor providing controlled access to secrets
//! - `SecretAny(T)` / `SecretString`: Managed secret containers (store allocator)
//! - `SecretAnyUnmanaged(T)` / `SecretStringUnmanaged`: Unmanaged containers (pass allocator)
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
//! // Access the secret through the Exposed interface
//! const exposed = secret.exposeSecret();
//! const key_data = exposed.secret(); // Use for crypto operations
//! ```
//!
//! ## Security Guarantees
//!
//! - Secrets are automatically zeroed on `deinit()` using `std.crypto.secureZero`
//! - Memory is not accessible after cleanup
//! - Explicit mutable vs immutable access controls
//! - No accidental copying of secret data

pub const Exposed = @import("secret.zig").Exposed;
pub const SecretAny = @import("secret.zig").SecretAny;
pub const SecretString = @import("secret.zig").SecretString;
pub const SecretAnyUnmanaged = @import("secret.zig").SecretAnyUnmanaged;
pub const SecretStringUnmanaged = @import("secret.zig").SecretStringUnmanaged;

test "run all test" {
    const std = @import("std");
    _ = @import("secret.zig");

    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("secret.zig"));
}
