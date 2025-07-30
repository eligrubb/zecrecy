const std = @import("std");
const mem = std.mem;
const secureZero = std.crypto.secureZero;

/// A lightweight accessor type that provides controlled access to secrets without carrying
/// the full secret management overhead. This design allows functions to accept just the
/// `Exposed` type when they need access to a secret, promoting a clean separation between
/// secret storage and secret access.
///
/// The `Exposed` pattern is inspired by Zig's recent Io.Writer changes and uses
/// `@fieldParentPtr` to maintain a connection back to the parent secret container.
///
/// ## Design Benefits
/// - **Generic Access**: Provides a unified interface for accessing secrets regardless
///   of whether they're managed or unmanaged
/// - **Type Safety**: Enforces explicit choice between mutable and immutable access
/// - **Memory Efficiency**: Lightweight wrapper that doesn't duplicate secret data
///
/// ## Usage
/// ```zig
/// fn processSecret(exposed: *const Exposed(u8)) void {
///     const secret_data = exposed.secret(); // immutable access
///     // Use secret_data for cryptographic operations
/// }
/// ```
pub fn Exposed(comptime T: type) type {
    return struct {
        expose: *const fn (self: *const ExposedType) []T,

        const ExposedType = @This();

        /// Returns immutable access to the secret data.
        /// Use this for read-only operations like cryptographic functions that consume secrets.
        pub fn secret(self: *const ExposedType) []const T {
            return self.expose(self);
        }

        /// Returns mutable access to the secret data.
        /// Use this when you need to modify the secret in-place, such as when receiving
        /// secret data from external sources or performing in-place transformations.
        ///
        /// **Security Note**: Mutable access should be used sparingly and with care
        /// to avoid accidental exposure of sensitive data.
        pub fn secretMutable(self: *const ExposedType) []T {
            return self.expose(self);
        }
    };
}

/// Convenience type alias for `Exposed(u8)`, commonly used for string secrets
/// like API keys, passwords, and tokens.
pub const ExposedString = Exposed(u8);

/// A managed secret container that automatically handles memory allocation and cleanup.
/// This type follows the same pattern as Zig's `ArrayList` - it stores an allocator
/// internally and manages all memory operations automatically.
///
/// **Critical**: You must call `.deinit()` when finished with the secret. Forgetting
/// to call `deinit()` results in both a memory leak AND a secret leak, as the sensitive
/// data will remain in memory without being securely zeroed.
///
/// ## Memory Management
/// This struct stores an internal `mem.Allocator` to handle memory management.
/// For manual memory management control, use `SecretAnyUnmanaged` instead.
///
/// ## Security Features
/// - Automatic secure zeroing of memory on `deinit()`
/// - Controlled access through the `Exposed` pattern
/// - Explicit mutable vs immutable access
///
/// ## Example
/// ```zig
/// var secret = try SecretAny(u8).init(allocator, "my_api_key");
/// defer secret.deinit(); // Critical: ensures secure cleanup
///
/// const exposed = secret.exposeSecret();
/// const key_data = exposed.secret(); // Use for crypto operations
/// ```
pub fn SecretAny(comptime T: type) type {
    return struct {
        secret: []T,
        allocator: mem.Allocator,
        _exposed_buffer: Exposed(T),

        const Secret = @This();

        /// Initialize a secret from a slice of data.
        /// The data is copied into newly allocated memory, so the original slice
        /// can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the caller
        /// if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
                .allocator = allocator,
                ._exposed_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        /// Initialize a secret from a function that returns the secret data.
        /// This is useful when the secret is generated or retrieved from an external
        /// source and you want to avoid having the secret exist in multiple memory
        /// locations simultaneously.
        ///
        /// **Use Cases**:
        /// - Reading secrets from environment variables
        /// - Generating cryptographic keys
        /// - Retrieving secrets from secure storage
        ///
        /// **Note**: The function will be called exactly once during initialization.
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return .{
                .secret = secret_ptr,
                .allocator = allocator,
                ._exposed_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing allocation.
        /// This function uses `std.crypto.secureZero` to ensure the secret data
        /// is properly overwritten and cannot be recovered from memory.
        ///
        /// **Critical**: Failing to call this function results in both memory
        /// and secret leakage.
        pub fn deinit(self: *Secret) void {
            secureZero(T, self.secret);
            self.allocator.free(self.secret);
        }

        /// Internal function that implements the expose mechanism using `@fieldParentPtr`.
        /// This technique, inspired by Zig's Io.Writer changes, allows the `Exposed`
        /// type to access its parent secret container without storing a direct reference.
        fn expose(e: *const Exposed(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposed_buffer", @constCast(e)));
            return s.secret;
        }

        /// Returns an `Exposed` accessor for this secret.
        /// The returned accessor provides controlled access to the secret data
        /// and can be passed to functions that need to work with secrets without
        /// requiring knowledge of the underlying memory management strategy.
        pub fn exposeSecret(self: *const Secret) *const Exposed(T) {
            return &self._exposed_buffer;
        }
    };
}

/// Convenience type alias for `SecretAny(u8)`, the most common use case
/// for handling string-based secrets like API keys, passwords, and tokens.
pub const SecretString = SecretAny(u8);

/// An unmanaged secret container that requires explicit allocator management.
/// This type follows the same pattern as Zig's `ArrayListUnmanaged` - it does not
/// store an allocator internally, requiring you to pass one to memory management functions.
///
/// **Critical**: You must call `.deinit(allocator)` when finished with the secret.
/// Forgetting to call `deinit()` results in both a memory leak AND a secret leak.
///
/// ## When to Use Unmanaged
/// Choose `SecretAnyUnmanaged` when you:
/// - Want more control over memory allocation strategies
/// - Are integrating with existing memory management systems
/// - Need to minimize struct size (no stored allocator)
/// - Are building performance-critical applications where allocator passing is preferred
///
/// ## Security Features
/// - Automatic secure zeroing of memory on `deinit()`
/// - Controlled access through the `Exposed` pattern
/// - Explicit mutable vs immutable access
///
/// ## Example
/// ```zig
/// var secret = try SecretAnyUnmanaged(u8).init(allocator, "my_api_key");
/// defer secret.deinit(allocator); // Critical: pass allocator to deinit
///
/// const exposed = secret.exposeSecret();
/// const key_data = exposed.secret(); // Use for crypto operations
/// ```
pub fn SecretAnyUnmanaged(comptime T: type) type {
    return struct {
        secret: []T,
        _exposed_buffer: Exposed(T),

        const Secret = @This();

        /// Initialize a secret from a slice of data.
        /// The data is copied into newly allocated memory, so the original slice
        /// can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the caller
        /// if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
                ._exposed_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        /// Initialize a secret from a function that returns the secret data.
        /// This is useful when the secret is generated or retrieved from an external
        /// source and you want to avoid having the secret exist in multiple memory
        /// locations simultaneously.
        ///
        /// **Use Cases**:
        /// - Reading secrets from environment variables
        /// - Generating cryptographic keys
        /// - Retrieving secrets from secure storage
        ///
        /// **Note**: The function will be called exactly once during initialization.
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return .{
                .secret = secret_ptr,
                ._exposed_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing allocation.
        /// This function uses `std.crypto.secureZero` to ensure the secret data
        /// is properly overwritten and cannot be recovered from memory.
        ///
        /// **Critical**: You must pass the same allocator used during `init()`.
        /// Failing to call this function results in both memory and secret leakage.
        pub fn deinit(self: *Secret, allocator: mem.Allocator) void {
            secureZero(T, self.secret);
            allocator.free(self.secret);
        }

        /// Internal function that implements the expose mechanism using `@fieldParentPtr`.
        /// This technique, inspired by Zig's Io.Writer changes, allows the `Exposed`
        /// type to access its parent secret container without storing a direct reference.
        fn expose(e: *const Exposed(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposed_buffer", @constCast(e)));
            return s.secret;
        }

        /// Returns an `Exposed` accessor for this secret.
        /// The returned accessor provides controlled access to the secret data
        /// and can be passed to functions that need to work with secrets without
        /// requiring knowledge of the underlying memory management strategy.
        pub fn exposeSecret(self: *const Secret) *const Exposed(T) {
            return &self._exposed_buffer;
        }
    };
}

/// Convenience type alias for `SecretAnyUnmanaged(u8)`, the most common use case
/// for handling string-based secrets like API keys, passwords, and tokens in
/// unmanaged memory scenarios.
pub const SecretStringUnmanaged = SecretAnyUnmanaged(u8);

test "secret string basic" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretString.init(allocator, "secret");
    defer secret_string.deinit();
    const exposed = secret_string.exposeSecret();

    try std.testing.expectEqualSlices(u8, "secret", exposed.secret());
}

test "secret string unmanaged" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretStringUnmanaged.init(allocator, "secret");
    defer secret_string.deinit(allocator);
    const exposed = secret_string.exposeSecret();

    try std.testing.expectEqualSlices(u8, "secret", exposed.secret());
}

test "secret string mutable" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretString.init(allocator, "secret");
    defer secret_string.deinit();

    const exposed = secret_string.exposeSecret();
    const secret_mut = exposed.secretMutable();

    @memcpy(secret_mut, "s3cret");

    // causes a compile error:
    // const secret = exposed.secret();
    // @memcpy(secret, "s3cret");

    try std.testing.expectEqualSlices(u8, "s3cret", secret_string.secret);
}
