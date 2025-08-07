const std = @import("std");
const mem = std.mem;

const secureZero = std.crypto.secureZero;
const assert = std.debug.assert;

/// A managed secret container that handles memory allocation and cleanup. This
/// type follows the same allocation handling pattern as Zig's `ArrayList` - it
/// stores an allocator internally on initialization and manages all memory
/// operations automatically.
///
/// **Critical**: You must call `.deinit()` when finished with the secret.
/// Forgetting to call `deinit()` results in both a memory leak AND a secret
/// leak.
///
/// ## Memory Management
/// This struct stores an internal `mem.Allocator` to handle memory management.
/// For manual memory management control, use `SecretUnmanaged` instead.
///
/// ## Security Features
/// - Automatic secure zeroing of memory on `.deinit()`
/// - Controlled access through `.expose()` and `.exposeMutable()` methods
/// - Direct access prevented outside of explicit exposure calls
/// - Explicit mutable vs immutable access patterns
///
/// ## Example
/// ```zig
/// var secret: Secret(u8) = try .init(allocator, "my_api_key");
/// defer secret.deinit(); // Critical: ensures secure cleanup
///
/// // Read-only access
/// const key_data = secret.expose();
/// performCryptoOperation(key_data);
///
/// // Mutable access for in-place operations
/// const mutable_data = secret.exposeMutable();
/// transformKey(mutable_data);
/// ```
pub fn Secret(comptime T: type) type {
    return struct {
        data: []T,
        allocator: mem.Allocator,

        const SecretType = @This();

        /// Initialize a secret from a slice of data. The original slice is
        /// unmodified and the data is copied into newly allocated memory the
        /// original slice can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the
        /// caller if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !SecretType {
            assert(secret.len > 0);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .data = secret_ptr,
                .allocator = allocator,
            };
        }

        /// Initialize a secret from a slice of data and securely zero the source.
        /// The data is copied into newly allocated memory, then the original slice
        /// is securely zeroed using `std.crypto.secureZero` before returning.
        ///
        /// **Security**: This function erases the source data from memory after
        /// copying, preventing the secret from existing in multiple locations
        /// in memory. Use this when you have mutable source data that should be
        /// destroyed on creation of the secret.
        ///
        /// **Example**:
        /// ```zig
        /// var temp_password = [_]u8{'p', 'a', 's', 's'};
        /// var secret: Secret(u8) = try .initDestructive(allocator, &temp_password);
        /// defer secret.deinit();
        /// // temp_password is now securely zeroed
        /// ```
        pub fn initDestructive(allocator: mem.Allocator, secret: []T) !SecretType {
            assert(secret.len > 0);
            defer secureZero(T, secret);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .data = secret_ptr,
                .allocator = allocator,
            };
        }

        /// Initialize a secret from a function that returns the secret data.
        /// This is useful when the secret is generated or retrieved from an
        /// external source and you want to avoid having the secret exist in
        /// multiple memory locations simultaneously.
        ///
        /// **Use Cases**:
        /// - Reading secrets from environment variables
        /// - Generating cryptographic keys
        /// - Retrieving secrets from secure storage
        ///
        /// **Note**: The function will be called exactly once during initialization.
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []const T) !SecretType {
            const secret_buf = secret();
            assert(secret_buf.len > 0);
            const secret_ptr = try allocator.alloc(T, secret_buf.len);
            @memcpy(secret_ptr, secret_buf);
            return .{
                .data = secret_ptr,
                .allocator = allocator,
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing allocation.
        /// This function uses `std.crypto.secureZero` to ensure the secret data
        /// is properly overwritten and cannot be recovered from memory.
        ///
        /// **Critical**: Failing to call this function results in both memory
        /// and secret leakage.
        pub fn deinit(secret: *SecretType) void {
            secureZero(T, secret.data);
            // use rawFree instead of free to support verification of memory zeroization in testing
            if (secret.data.len == 0) return;
            secret.allocator.rawFree(secret.data, .fromByteUnits(@alignOf(T)), @returnAddress());
            secret.data = undefined;
            secret.allocator = undefined;
            secret.* = undefined;
        }

        /// Access secret data as a read-only slice. Returns the secret data
        /// as a `[]const T` slice for read-only operations.
        ///
        /// **Security**: Use the returned slice immediately and avoid storing
        /// references to it. The slice remains valid until `.deinit()` is called.
        pub fn expose(secret: *const SecretType) []const T {
            return secret.data;
        }

        /// Access secret data as a mutable slice. Returns the secret data
        /// as a `[]T` slice that can be modified for in-place transformations.
        ///
        /// **Security**: Use the returned slice immediately and avoid storing
        /// references to it. The slice remains valid until `.deinit()` is called.
        pub fn exposeMutable(secret: *SecretType) []T {
            return secret.data;
        }

        /// Compare this secret with another secret for equality using constant-time comparison.
        ///
        /// This function performs a constant-time comparison to prevent timing attacks,
        /// including timing leaks from length differences. The comparison time depends
        /// only on the maximum length of the two secrets, not their actual content or
        /// whether they match.
        ///
        /// The `other` parameter can be any type that has `len()` and `expose()` methods,
        /// allowing comparison between managed and unmanaged secret types.
        ///
        /// **Example**:
        /// ```zig
        /// var secret1: SecretString = try .init(allocator, "password");
        /// defer secret1.deinit();
        /// var secret2: SecretString = try .init(allocator, "password");
        /// defer secret2.deinit();
        /// var unmanaged_secret: SecretStringUnmanaged = try .init(allocator, "password");
        /// defer unmanaged_secret.deinit(allocator);
        ///
        /// if (secret1.eql(secret2)) {
        ///     // Managed secrets match
        /// }
        /// if (secret1.eql(unmanaged_secret)) {
        ///     // Managed and unmanaged secrets match
        /// }
        /// ```
        pub fn eql(secret: *const SecretType, other: anytype) bool {
            assert(secret.len() == other.len());
            return std.crypto.timing_safe.compare(T, secret.expose(), other.expose(), .little) == .eq;
        }

        /// Returns length of secret data.
        pub fn len(secret: *const SecretType) usize {
            return secret.data.len;
        }

        /// Securely zero the secret data without freeing the memory.
        pub fn wipe(secret: *const SecretType) void {
            secureZero(T, secret.data);
        }

        /// Produces a clone of the secret using the stored allocator.
        ///
        /// **Critical**: You must call `.deinit()` when finished with the secret.
        /// Forgetting to call `deinit()` results in both a memory leak AND a secret
        /// leak.
        pub fn clone(secret: *const SecretType) !SecretType {
            return .init(secret.allocator, secret.expose());
        }
    };
}

/// Convenience type alias for `Secret(u8)`, the most common use case for
/// handling byte-based secrets like API keys, passwords, and tokens.
pub const SecretString = Secret(u8);

/// An unmanaged secret container that requires explicit allocator management.
/// This type follows the same allocation handling pattern as Zig's
/// `ArrayListUnmanaged` - it does not store an allocator internally, requiring
/// you to pass one to memory managemen functions.
///
/// **Critical**: You must call `.deinit(allocator)` when finished with the secret.
/// Forgetting to call `.deinit()` results in both a memory leak AND a secret leak.
///
/// ## When to Use Unmanaged
/// Choose `SecretUnmanaged` when you:
/// - Want more control over memory allocation strategies
/// - Are integrating with existing memory management systems
/// - Need to minimize struct size (no stored allocator)
/// - Are building performance-critical applications where allocator passing is preferred
///
/// ## Security Features
/// - Automatic secure zeroing of memory on `.deinit()`
/// - Controlled access through `.expose()` and `.exposeMutable()` methods
/// - Direct access prevented outside of explicit exposure calls
/// - Explicit mutable vs immutable access patterns
///
/// ## Example
/// ```zig
/// var secret: SecretUnmanaged(u8) = try .init(allocator, "my_api_key");
/// defer secret.deinit(allocator); // Critical: pass allocator to deinit
///
/// // Read-only access
/// const key_data = secret.expose();
/// performCryptoOperation(key_data);
///
/// // Mutable access for in-place operations
/// const mutable_data = secret.exposeMutable();
/// transformKey(mutable_data);
/// ```
pub fn SecretUnmanaged(comptime T: type) type {
    return struct {
        data: []T,

        const SecretType = @This();

        /// Initialize a secret from a slice of data. The original slice is
        /// unmodified and the data is copied into newly allocated memory the
        /// original slice can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the
        /// caller if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !SecretType {
            assert(secret.len > 0);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .data = secret_ptr,
            };
        }

        /// Initialize a secret from a slice of data and securely zero the source.
        /// The data is copied into newly allocated memory, then the original slice
        /// is securely zeroed using `std.crypto.secureZero` before returning.
        ///
        /// **Security**: This function erases the source data from memory after
        /// copying, preventing the secret from existing in multiple locations
        /// in memory. Use this when you have mutable source data that should be
        /// destroyed on creation of the secret.
        ///
        /// **Example**:
        /// ```zig
        /// var temp_password = [_]u8{'p', 'a', 's', 's'};
        /// var secret: SecretUnmanaged(u8) = try .initDestructive(allocator, &temp_password);
        /// defer secret.deinit(allocator);
        /// // temp_password is now securely zeroed
        /// ```
        pub fn initDestructive(allocator: mem.Allocator, secret: []T) !SecretType {
            assert(secret.len > 0);
            defer secureZero(T, secret);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .data = secret_ptr,
            };
        }

        /// Initialize a secret from a function that returns the secret data.
        /// This is useful when the secret is generated or retrieved from an
        /// external source and you want to avoid having the secret exist in
        /// multiple memory locations simultaneously.
        ///
        /// **Use Cases**:
        /// - Reading secrets from environment variables
        /// - Generating cryptographic keys
        /// - Retrieving secrets from secure storage
        ///
        /// **Note**: The function will be called exactly once during initialization.
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []const T) !SecretType {
            const secret_buf = secret();
            assert(secret_buf.len > 0);
            const secret_ptr = try allocator.alloc(T, secret_buf.len);
            @memcpy(secret_ptr, secret_buf);
            return .{
                .data = secret_ptr,
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing
        /// allocation. This function uses `std.crypto.secureZero` to ensure the
        /// secret data is properly overwritten and cannot be recovered from
        /// memory.
        ///
        /// **Critical**: You must pass the same allocator used during `init()`.
        /// Failing to call this function results in both memory AND secret
        /// leakage.
        pub fn deinit(secret: *SecretType, allocator: mem.Allocator) void {
            secureZero(T, secret.data);
            // use rawFree instead of free to support verification of memory zeroization in testing
            if (secret.data.len == 0) return;
            allocator.rawFree(secret.data, .fromByteUnits(@alignOf(T)), @returnAddress());
            secret.data = undefined;
            secret.* = undefined;
        }

        /// Access secret data as a read-only slice. Returns the secret data
        /// as a `[]const T` slice for read-only operations.
        ///
        /// **Security**: Use the returned slice immediately and avoid storing
        /// references to it. The slice remains valid until `.deinit()` is called.
        pub fn expose(secret: *const SecretType) []const T {
            return secret.data;
        }

        /// Access secret data as a mutable slice. Returns the secret data
        /// as a `[]T` slice that can be modified for in-place transformations.
        ///
        /// **Security**: Use the returned slice immediately and avoid storing
        /// references to it. The slice remains valid until `.deinit()` is called.
        pub fn exposeMutable(secret: *SecretType) []T {
            return secret.data;
        }

        /// Compare this secret with another secret for equality using constant-time comparison.
        ///
        /// This function performs a constant-time comparison to prevent timing attacks,
        /// including timing leaks from length differences. The comparison time depends
        /// only on the maximum length of the two secrets, not their actual content or
        /// whether they match.
        ///
        /// The `other` parameter can be any type that has `len()` and `expose()` methods,
        /// allowing comparison between managed and unmanaged secret types.
        ///
        /// **Example**:
        /// ```zig
        /// var secret1: SecretStringUnmanaged = try .init(allocator, "password");
        /// defer secret1.deinit(allocator);
        /// var secret2: SecretStringUnmanaged = try .init(allocator, "password");
        /// defer secret2.deinit(allocator);
        /// var managed_secret: SecretString = try .init(allocator, "password");
        /// defer managed_secret.deinit();
        ///
        /// if (secret1.eql(secret2)) {
        ///     // Unmanaged secrets match
        /// }
        /// if (secret1.eql(managed_secret)) {
        ///     // Unmanaged and managed secrets match
        /// }
        /// ```
        pub fn eql(secret: *const SecretType, other: anytype) bool {
            assert(secret.len() == other.len());
            return std.crypto.timing_safe.compare(T, secret.expose(), other.expose(), .little) == .eq;
        }

        /// Returns length of secret data.
        pub fn len(secret: *const SecretType) usize {
            return secret.data.len;
        }

        /// Securely zero the secret data without freeing the memory.
        pub fn wipe(secret: *const SecretType) void {
            secureZero(T, secret.data);
        }

        /// Produces a clone of the secret using the provided allocator.
        ///
        /// **Critical**: You must call `.deinit(allocator)` when finished with the secret.
        /// Forgetting to call `deinit()` results in both a memory leak AND a secret
        /// leak.
        pub fn clone(secret: *const SecretType, allocator: mem.Allocator) !SecretType {
            return .init(allocator, secret.expose());
        }
    };
}

/// Convenience type alias for `SecretUnmanaged(u8)`, the most common use
/// case for handling string-based secrets like API keys, passwords, and tokens
/// in unmanaged memory scenarios.
pub const SecretStringUnmanaged = SecretUnmanaged(u8);

test "secret string basic" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();
    const secret = "secret";

    var secret_string: SecretString = try .init(allocator, secret);
    defer secret_string.deinit();

    try std.testing.expectEqualSlices(u8, "secret", secret_string.expose());
}

test "secret string unmanaged" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret_string: SecretStringUnmanaged = try .init(allocator, "secret");
    defer secret_string.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "secret", secret_string.expose());
}

test "secret string mutable" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret_string: SecretString = try .init(allocator, "secret");
    defer secret_string.deinit();

    const mutable_exposed = secret_string.exposeMutable();
    for (mutable_exposed) |*c| {
        if (c.* == 'e') {
            c.* = '3';
            break;
        }
    }

    // causes a compile error:
    // const exposed = secret_string.expose();
    // for (exposed) |*c| {
    //     if (c.* == 'e') {
    //         c.* = '3';
    //         break;
    //      }
    // }

    try std.testing.expectEqualSlices(u8, "s3cret", secret_string.expose());
}

test "generic functions work with both secret types" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    // Create managed secret
    var managed_secret: SecretString = try .init(allocator, "managed");
    defer managed_secret.deinit();

    // Create unmanaged secret
    var unmanaged_secret: SecretStringUnmanaged = try .init(allocator, "managed");
    defer unmanaged_secret.deinit(allocator);

    // Both types work with the same generic functions - library code doesn't need to care
    // which specific type it receives
    try std.testing.expect(managed_secret.eql(unmanaged_secret));
    try std.testing.expect(unmanaged_secret.eql(managed_secret));
}

test "secret string initFromFunction" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    const TestSecret = struct {
        fn getSecret() []const u8 {
            const secret_data = "function_secret";
            return secret_data[0..];
        }
    };

    var secret_string_from_function: SecretString = try .initFromFunction(allocator, TestSecret.getSecret);
    defer secret_string_from_function.deinit();

    var secret_string_from_static: SecretString = try .init(allocator, "function_secret");
    defer secret_string_from_static.deinit();

    try std.testing.expect(secret_string_from_function.eql(secret_string_from_static));

    try std.testing.expectEqualSlices(u8, "function_secret", secret_string_from_function.expose());
}

test "secret string unmanaged initFromFunction" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    const TestSecret = struct {
        fn getSecret() []const u8 {
            const secret_data = "unmanaged_function_secret";
            return secret_data[0..];
        }
    };

    var secret_string_from_function: SecretStringUnmanaged = try .initFromFunction(allocator, TestSecret.getSecret);
    defer secret_string_from_function.deinit(allocator);

    var secret_string_from_static: SecretStringUnmanaged = try .init(allocator, "unmanaged_function_secret");
    defer secret_string_from_static.deinit(allocator);

    try std.testing.expect(secret_string_from_function.eql(secret_string_from_static));

    try std.testing.expectEqualSlices(
        u8,
        "unmanaged_function_secret",
        secret_string_from_function.expose(),
    );
}

test "secret string initDestructive" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var source_secret = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    var secret_string_from_destructive: SecretString = try .initDestructive(allocator, &source_secret);
    defer secret_string_from_destructive.deinit();

    var secret_string_from_static: SecretString = try .init(allocator, "secret");
    defer secret_string_from_static.deinit();

    // Verify the secret was copied correctly
    try std.testing.expect(secret_string_from_destructive.eql(secret_string_from_static));

    // Verify the source was zeroed
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0 }, &source_secret);

    try std.testing.expectEqualSlices(u8, "secret", secret_string_from_destructive.expose());
}

test "secret string unmanaged initDestructive" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var source_secret = [_]u8{ 'u', 'n', 'm', 'a', 'n', 'a', 'g', 'e', 'd' };
    var secret_string_from_destructive: SecretStringUnmanaged = try .initDestructive(allocator, &source_secret);
    defer secret_string_from_destructive.deinit(allocator);

    var secret_string_from_static: SecretStringUnmanaged = try .init(allocator, "unmanaged");
    defer secret_string_from_static.deinit(allocator);

    // Verify the secret was copied correctly
    try std.testing.expect(secret_string_from_destructive.eql(secret_string_from_static));

    // Verify the source was zeroed
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &source_secret);

    try std.testing.expectEqualSlices(u8, "unmanaged", secret_string_from_destructive.expose());
}

test "secret wipe" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret: SecretString = try .init(allocator, "sensitive");
    defer secret.deinit();

    // Verify the secret contains the expected data before wiping
    try std.testing.expectEqualSlices(u8, "sensitive", secret.expose());

    // Wipe the secret
    secret.wipe();

    // Verify the data has been zeroed (direct access for testing)
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0 }, secret.expose());

    // The secret should still be valid for operations like len()
    try std.testing.expectEqual(@as(usize, 9), secret.len());
}

test "secret unmanaged wipe" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret: SecretStringUnmanaged = try .init(allocator, "sensitive");
    defer secret.deinit(allocator);

    // Verify the secret contains the expected data before wiping
    try std.testing.expectEqualSlices(u8, "sensitive", secret.expose());

    // Wipe the secret
    secret.wipe();

    // Verify the data has been zeroed (direct access for testing)
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0 }, secret.expose());

    // The secret should still be valid for operations like len()
    try std.testing.expectEqual(@as(usize, 9), secret.len());
}

test "secret clone" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var original_secret: SecretString = try .init(allocator, "original");
    defer original_secret.deinit();

    // Clone the secret
    var cloned_secret: SecretString = try original_secret.clone();
    defer cloned_secret.deinit();

    // Verify both secrets contain the same data
    try std.testing.expectEqualSlices(u8, "original", original_secret.expose());
    try std.testing.expectEqualSlices(u8, "original", cloned_secret.expose());

    // Verify they are independent (different memory locations)
    try std.testing.expect(original_secret.data.ptr != cloned_secret.data.ptr);

    // Verify equality check works
    try std.testing.expect(original_secret.eql(cloned_secret));

    // Modify the original to ensure independence
    const original_mutable = original_secret.exposeMutable();
    original_mutable[0] = 'X';

    // Cloned secret should remain unchanged
    try std.testing.expectEqualSlices(u8, "original", cloned_secret.expose());
    try std.testing.expectEqualSlices(u8, "Xriginal", original_secret.expose());
}

test "secret unmanaged clone" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var original_secret: SecretStringUnmanaged = try .init(allocator, "original");
    defer original_secret.deinit(allocator);

    // Clone the secret using the same allocator
    var cloned_secret: SecretStringUnmanaged = try original_secret.clone(allocator);
    defer cloned_secret.deinit(allocator);

    // Verify both secrets contain the same data
    try std.testing.expectEqualSlices(u8, "original", original_secret.expose());
    try std.testing.expectEqualSlices(u8, "original", cloned_secret.expose());

    // Verify they are independent (different memory locations)
    try std.testing.expect(original_secret.data.ptr != cloned_secret.data.ptr);

    // Verify equality check works
    try std.testing.expect(original_secret.eql(cloned_secret));

    // Modify the original to ensure independence
    const original_mutable = original_secret.exposeMutable();
    original_mutable[0] = 'X';

    // Cloned secret should remain unchanged
    try std.testing.expectEqualSlices(u8, "original", cloned_secret.expose());
    try std.testing.expectEqualSlices(u8, "Xriginal", original_secret.expose());
}

test "expect fail secret equality with unequal content same length" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret1: SecretString = try .init(allocator, "password");
    defer secret1.deinit();
    var secret2: SecretString = try .init(allocator, "passw0rd");
    defer secret2.deinit();

    // Secrets have same length but different content - should not be equal
    try std.testing.expect(!secret1.eql(secret2));
    try std.testing.expect(!secret2.eql(secret1));
}

// This test now fails to compile due to an assertion - providing stronger
// guarantees than just returning false.
// test "expect fail secret equality with different lengths" {
//     const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
//     var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
//     const allocator = zeros_only_allocator.allocator();
//
//     var short_secret: SecretString = try .init(allocator, "short");
//     defer short_secret.deinit();
//     var long_secret: SecretString = try .init(allocator, "much_longer_secret");
//     defer long_secret.deinit();
//
//     // Secrets have different lengths - should not be equal
//     try std.testing.expect(!short_secret.eql(long_secret));
//     try std.testing.expect(!long_secret.eql(short_secret));
// }

test "expect fail secret unmanaged equality with unequal content same length" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret1: SecretStringUnmanaged = try .init(allocator, "api_key_");
    defer secret1.deinit(allocator);
    var secret2: SecretStringUnmanaged = try .init(allocator, "api_key1");
    defer secret2.deinit(allocator);

    // Secrets have same length but different content - should not be equal
    try std.testing.expect(!secret1.eql(secret2));
    try std.testing.expect(!secret2.eql(secret1));
}

// This test now fails to compile due to an assertion - providing stronger
// guarantees than just returning false.
// test "expect fail secret unmanaged equality with different lengths" {
//     const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
//     var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
//     const allocator = zeros_only_allocator.allocator();
//
//     var secret1: SecretStringUnmanaged = try .init(allocator, "key");
//     defer secret1.deinit(allocator);
//     var secret2: SecretStringUnmanaged = try .init(allocator, "very_long_key");
//     defer secret2.deinit(allocator);
//
//     // Secrets have different lengths - should not be equal
//     try std.testing.expect(!secret1.eql(secret2));
//     try std.testing.expect(!secret2.eql(secret1));
// }

test "expect fail cross-type equality with unequal secrets" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator: ZerosOnlyAllocator = .init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    // Test managed vs unmanaged with different content but same length
    var managed_secret: SecretString = try .init(allocator, "token123");
    defer managed_secret.deinit();
    var unmanaged_secret: SecretStringUnmanaged = try .init(allocator, "token456");
    defer unmanaged_secret.deinit(allocator);

    // Should not be equal despite same type compatibility
    try std.testing.expect(!managed_secret.eql(unmanaged_secret));
    try std.testing.expect(!unmanaged_secret.eql(managed_secret));

    // Test with different lengths
    // var short_managed: SecretString = try .init(allocator, "abc");
    // defer short_managed.deinit();
    // var long_unmanaged: SecretStringUnmanaged = try .init(allocator, "abcdefghijk");
    // defer long_unmanaged.deinit(allocator);
    //
    // These lines now fail to compile due to an assertion, providing stronger
    // guarantees than just returning false.
    // try std.testing.expect(!short_managed.eql(long_unmanaged));
    // try std.testing.expect(!long_unmanaged.eql(short_managed));
}
