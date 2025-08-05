const std = @import("std");
const mem = std.mem;

const secureZero = std.crypto.secureZero;
const assert = std.debug.assert;

/// Copy secret data into a provided buffer.
///
/// **Safety**: The destination buffer must be at least as large as the secret.
/// The buffer will contain the secret data after this call - ensure you securely
/// zero it when no longer needed.
///
/// **Example**:
/// ```zig
/// var buffer: [32]u8 = undefined;
/// try copySecretInto(&secret, &buffer);
/// defer std.crypto.secureZero(u8, &buffer); // Clean up when done
/// ```
pub fn copySecretInto(secret: anytype, buffer: []@TypeOf(secret.secret[0])) !void {
    return secret.readWith(buffer, struct {
        fn copy(dest: []@TypeOf(secret.secret[0]), src: []const @TypeOf(secret.secret[0])) !void {
            assert(dest.len >= src.len);
            @memcpy(dest[0..src.len], src);
        }
    }.copy);
}

/// Compare a secret with a provided buffer for equality.
///
/// This function performs a constant-time comparison to prevent timing attacks.
/// The secret data never leaves the controlled access boundary.
///
/// **Example**:
/// ```zig
/// const is_correct = try secretEql(&secret, "expected_password");
/// if (is_correct) {
///     // Authentication successful
/// }
/// ```
pub fn eql(secret: anytype, buffer: []const @TypeOf(secret.secret[0])) !bool {
    var result = false;
    try secret.readWith(.{ buffer, &result }, struct {
        fn equivalent(context: struct { []const @TypeOf(secret.secret[0]), *bool }, a: []const @TypeOf(secret.secret[0])) !void {
            context[1].* = (context[0].len == a.len) and (std.crypto.timing_safe.compare(@TypeOf(secret.secret[0]), context[0], a, .little) == .eq);
        }
    }.equivalent);
    return result;
}

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
/// - Automatic secure zeroing of memory on `deinit()`
/// - Controlled access through callback functions only (`readWith`,
/// `mutateWith`)
/// - No direct access to secret data prevents accidental copying
/// - Explicit mutable vs immutable access
///
/// ## Example
/// ```zig
/// var secret = try Secret(u8).init(allocator, "my_api_key");
/// defer secret.deinit(); // Critical: ensures secure cleanup
///
/// // Read-only access through callback
/// try secret.readWith(null, struct {
///     fn useKey(_: @TypeOf(null), key: []const u8) !void {
///         // Use key for crypto operations here
///         performCryptoOperation(key);
///     }
/// }.useKey);
/// ```
pub fn Secret(comptime T: type) type {
    return struct {
        secret: []T,
        allocator: mem.Allocator,

        const Self = @This();

        /// Initialize a secret from a slice of data. The original slice is
        /// unmodified and the data is copied into newly allocated memory the
        /// original slice can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the
        /// caller if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !Self {
            assert(secret.len > 0);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
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
        /// var secret = try Secret(u8).initDestructive(allocator, &temp_password);
        /// defer secret.deinit();
        /// // temp_password is now securely zeroed
        /// ```
        pub fn initDestructive(allocator: mem.Allocator, secret: []T) !Self {
            assert(secret.len > 0);
            defer secureZero(T, secret);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
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
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []const T) !Self {
            const secret_buf = secret();
            assert(secret_buf.len > 0);
            const secret_ptr = try allocator.alloc(T, secret_buf.len);
            @memcpy(secret_ptr, secret_buf);
            return .{
                .secret = secret_ptr,
                .allocator = allocator,
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing allocation.
        /// This function uses `std.crypto.secureZero` to ensure the secret data
        /// is properly overwritten and cannot be recovered from memory.
        ///
        /// **Critical**: Failing to call this function results in both memory
        /// and secret leakage.
        pub fn deinit(self: *Self) void {
            secureZero(T, self.secret);
            // use rawFree instead of free to support verification of memory zeroization in testing
            self.allocator.rawFree(self.secret, .fromByteUnits(@alignOf(T)), @returnAddress());
            self.secret = undefined;
            self.allocator = undefined;
            self.* = undefined;
        }

        /// Access secret data through a read-only callback function. The secret
        /// data is passed to your callback as a `[]const T` slice.
        ///
        /// **Security**: Secret data only exists within the callback scope and
        /// cannot be stored or copied outside of it.
        pub fn readWith(self: Self, context: anytype, comptime callback: fn (@TypeOf(context), []const T) anyerror!void) !void {
            return callback(context, self.secret);
        }

        /// Access secret data through a mutable callback function. The secret
        /// data is passed to your callback as a `[]T` slice that can be
        /// modified. Use this for operations that need to transform the secret
        /// in-place.
        ///
        /// **Security**: Secret data only exists within the callback scope and
        /// cannot be stored or copied outside of it.
        pub fn mutateWith(self: *Self, context: anytype, comptime callback: fn (@TypeOf(context), []T) anyerror!void) !void {
            return callback(context, self.secret);
        }
    };
}

/// Convenience type alias for `SecretAny(u8)`, the most common use case for
/// handling string-based secrets like API keys, passwords, and tokens.
pub const SecretString = Secret(u8);

/// An unmanaged secret container that requires explicit allocator management.
/// This type follows the same allocation handling pattern as Zig's
/// `ArrayListUnmanaged` - it does not store an allocator internally, requiring
/// you to pass one to memory managemen functions.
///
/// **Critical**: You must call `.deinit(allocator)` when finished with the secret.
/// Forgetting to call `deinit()` results in both a memory leak AND a secret leak.
///
/// ## When to Use Unmanaged
/// Choose `SecretUnmanaged` when you:
/// - Want more control over memory allocation strategies
/// - Are integrating with existing memory management systems
/// - Need to minimize struct size (no stored allocator)
/// - Are building performance-critical applications where allocator passing is preferred
///
/// ## Security Features
/// - Automatic secure zeroing of memory on `deinit()`
/// - Controlled access through callback functions only (`readWith`, `mutateWith`)
/// - No direct access to secret data prevents accidental copying
/// - Explicit mutable vs immutable access
///
/// ## Example
/// ```zig
/// var secret = try SecretUnmanaged(u8).init(allocator, "my_api_key");
/// defer secret.deinit(allocator); // Critical: pass allocator to deinit
///
/// // Read-only access through callback
/// try secret.readWith(null, struct {
///     fn useKey(_: @TypeOf(null), key: []const u8) !void {
///         // Use key for crypto operations here
///         performCryptoOperation(key);
///     }
/// }.useKey);
/// ```
pub fn SecretUnmanaged(comptime T: type) type {
    return struct {
        secret: []T,

        const Self = @This();

        /// Initialize a secret from a slice of data. The original slice is
        /// unmodified and the data is copied into newly allocated memory the
        /// original slice can be safely discarded after this call.
        ///
        /// **Security**: The original data should be securely zeroed by the
        /// caller if it contains sensitive information.
        pub fn init(allocator: mem.Allocator, secret: []const T) !Self {
            assert(secret.len > 0);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
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
        /// var secret = try SecretUnmanaged(u8).initDestructive(allocator, &temp_password);
        /// defer secret.deinit(allocator);
        /// // temp_password is now securely zeroed
        /// ```
        pub fn initDestructive(allocator: mem.Allocator, secret: []T) !Self {
            assert(secret.len > 0);
            defer secureZero(T, secret);
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
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
        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []const T) !Self {
            const secret_buf = secret();
            assert(secret_buf.len > 0);
            const secret_ptr = try allocator.alloc(T, secret_buf.len);
            @memcpy(secret_ptr, secret_buf);
            return .{
                .secret = secret_ptr,
            };
        }

        /// Securely clean up the secret by zeroing memory and freeing
        /// allocation. This function uses `std.crypto.secureZero` to ensure the
        /// secret data is properly overwritten and cannot be recovered from
        /// memory.
        ///
        /// **Critical**: You must pass teh same allocator used during `init()`.
        /// Failing to call this function results in both memory AND secret
        /// leakage.
        pub fn deinit(self: *Self, allocator: mem.Allocator) void {
            secureZero(T, self.secret);
            // use rawFree instead of free to support verification of memory zeroization in testing
            allocator.rawFree(self.secret, .fromByteUnits(@alignOf(T)), @returnAddress());
            self.secret = undefined;
            self.* = undefined;
        }

        /// Access secret data through a read-only callback function. The secret
        /// data is passed to your callback as a `[]const T` slice.
        ///
        /// **Security**: Secret data only exists within the callback scope and
        /// cannot be stored or copied outside of it.
        pub fn readWith(self: Self, context: anytype, comptime callback: fn (@TypeOf(context), []const T) anyerror!void) !void {
            return callback(context, self.secret);
        }

        /// Access secret data through a mutable callback function. The secret
        /// data is passed to your callback as a `[]T` slice that can be
        /// modified. Use this for operations that need to transform the secret
        /// in-place.
        ///
        /// **Security**: Secret data only exists within the callback scope and
        /// cannot be stored or copied outside of it.
        pub fn mutateWith(self: *Self, context: anytype, comptime callback: fn (@TypeOf(context), []T) anyerror!void) !void {
            return callback(context, self.secret);
        }
    };
}

/// Convenience type alias for `SecretAnyUnmanaged(u8)`, the most common use
/// case for handling string-based secrets like API keys, passwords, and tokens
/// in unmanaged memory scenarios.
pub const SecretStringUnmanaged = SecretUnmanaged(u8);

test "secret string basic" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();
    const secret = "secret";

    var secret_string = try SecretString.init(allocator, secret);
    defer secret_string.deinit();
    var buffer = [_]u8{0} ** 10;
    try copySecretInto(&secret_string, &buffer);

    try std.testing.expectEqualSlices(u8, "secret", buffer[0..secret.len]);
}

test "secret string unmanaged" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret_string = try SecretStringUnmanaged.init(allocator, "secret");
    defer secret_string.deinit(allocator);
    var buffer = [_]u8{0} ** 10;
    try copySecretInto(&secret_string, &buffer);

    try std.testing.expectEqualSlices(u8, "secret", buffer[0.."secret".len]);
}

test "secret string mutable" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var secret_string = try SecretString.init(allocator, "secret");
    defer secret_string.deinit();

    secret_string.mutateWith(null, struct {
        fn threeFromE(_: @TypeOf(null), old: []u8) !void {
            for (old) |*c| {
                if (c.* == 'e') {
                    c.* = '3';
                    break;
                }
            }
        }
    }.threeFromE) catch unreachable;

    // causes a compile error:
    // const secret = exposed.secret();
    // @memcpy(secret, "s3cret");

    try std.testing.expectEqualSlices(u8, "s3cret", secret_string.secret);
}

test "generic functions work with both secret types" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    // Test with managed secret
    var managed_secret = try SecretString.init(allocator, "managed");
    defer managed_secret.deinit();

    try std.testing.expect(try eql(&managed_secret, "managed"));

    // Test with unmanaged secret
    var unmanaged_secret = try SecretStringUnmanaged.init(allocator, "unmanaged");
    defer unmanaged_secret.deinit(allocator);

    try std.testing.expect(try eql(&unmanaged_secret, "unmanaged"));

    // Test copyInto
    var buffer: [20]u8 = undefined;
    try copySecretInto(&managed_secret, &buffer);
    try std.testing.expectEqualSlices(u8, "managed", buffer[0.."managed".len]);

    // Both types work with the same generic functions - library code doesn't need to care
    // which specific type it receives
}

test "secret string initFromFunction" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    const TestSecret = struct {
        fn getSecret() []const u8 {
            const secret_data = "function_secret";
            return secret_data[0..];
        }
    };

    var secret_string = try SecretString.initFromFunction(allocator, TestSecret.getSecret);
    defer secret_string.deinit();

    try std.testing.expect(try eql(&secret_string, "function_secret"));

    var buffer: [20]u8 = undefined;
    try copySecretInto(&secret_string, &buffer);
    try std.testing.expectEqualSlices(u8, "function_secret", buffer[0.."function_secret".len]);
}

test "secret string unmanaged initFromFunction" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    const TestSecret = struct {
        fn getSecret() []const u8 {
            const secret_data = "unmanaged_function_secret";
            return secret_data[0..];
        }
    };

    var secret_string = try SecretStringUnmanaged.initFromFunction(allocator, TestSecret.getSecret);
    defer secret_string.deinit(allocator);

    try std.testing.expect(try eql(&secret_string, "unmanaged_function_secret"));

    var buffer: [30]u8 = undefined;
    try copySecretInto(&secret_string, &buffer);
    try std.testing.expectEqualSlices(u8, "unmanaged_function_secret", buffer[0.."unmanaged_function_secret".len]);
}

test "secret string initDestructive" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var source_secret = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    var secret_string = try SecretString.initDestructive(allocator, &source_secret);
    defer secret_string.deinit();

    // Verify the secret was copied correctly
    try std.testing.expect(try eql(&secret_string, "secret"));

    // Verify the source was zeroed
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0 }, &source_secret);

    var buffer: [10]u8 = undefined;
    try copySecretInto(&secret_string, &buffer);
    try std.testing.expectEqualSlices(u8, "secret", buffer[0.."secret".len]);
}

test "secret string unmanaged initDestructive" {
    const ZerosOnlyAllocator = @import("testing/ZerosOnlyAllocator.zig");
    var zeros_only_allocator = ZerosOnlyAllocator.init(std.testing.allocator);
    const allocator = zeros_only_allocator.allocator();

    var source_secret = [_]u8{ 'u', 'n', 'm', 'a', 'n', 'a', 'g', 'e', 'd' };
    var secret_string = try SecretStringUnmanaged.initDestructive(allocator, &source_secret);
    defer secret_string.deinit(allocator);

    // Verify the secret was copied correctly
    try std.testing.expect(try eql(&secret_string, "unmanaged"));

    // Verify the source was zeroed
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &source_secret);

    var buffer: [15]u8 = undefined;
    try copySecretInto(&secret_string, &buffer);
    try std.testing.expectEqualSlices(u8, "unmanaged", buffer[0.."unmanaged".len]);
}
