const std = @import("std");
const mem = std.mem;
const secureZero = std.crypto.secureZero;

/// Must call .deinit() on the returned struct when you are finished with it.
///
/// This struct stores an internal mem.Allocator to handle meory management.
/// To handle memory management yourself, use `SecretAnyUnmanaged`
pub fn SecretAny(comptime T: type) type {
    return struct {
        _secret_buffer: []T,
        allocator: mem.Allocator,

        const Secret = @This();

        pub fn init(allocator: mem.Allocator, secret: []const T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            const result: Secret = .{
                ._secret_buffer = secret_ptr,
                .allocator = allocator,
            };
            // std.debug.print("{any}\n", .{result});
            // const exposer = result.getExposer();
            // std.debug.print("{x}\n", .{exposer.exposeSecret()});
            return result;
        }

        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            const result: Secret = .{
                ._secret_buffer = secret_ptr,
                .allocator = allocator,
            };
            std.debug.print("{any}\n", .{result});
            return result;
        }

        pub fn deinit(self: *Secret) void {
            secureZero(T, self._secret_buffer);
            self.allocator.free(self._secret_buffer);
        }

        fn exposeSecret(self: *Secret) []T {
            return self._secret_buffer;
        }
    };
}

///
pub const SecretString = SecretAny(u8);

// pub fn SecretAnyUnmanaged(comptime T: type) type {
//     const SecretType = Secret(T);
//     return struct {
//         const Self = @This();
//
//         raw_secret: []T = undefined,
//         secret: SecretType,
//
//         pub fn init(allocator: mem.Allocator, secret: []const T) !Self {
//             const secret_ptr = try allocator.alloc(T, secret.len);
//             @memcpy(secret_ptr, secret);
//             return Self{
//                 .raw_secret = secret_ptr,
//                 .secret = SecretType{
//                     .get_raw_secret = Self.expose_secret,
//                 },
//             };
//         }
//
//         pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Self {
//             const secret_ptr = try allocator.alloc(T, secret().len);
//             secret_ptr.* = secret();
//             return Self{
//                 .raw_secret = secret_ptr,
//                 .secret = SecretType{
//                     .expose_secret = @This().expose_secret,
//                 },
//             };
//         }
//
//         pub fn deinit(self: *Self, allocator: mem.Allocator) void {
//             secureZero(T, self.raw_secret);
//             allocator.free(self.raw_secret);
//         }
//
//         fn expose_secret(s: *const SecretType) []T {
//             const this: *Self = @alignCast(@fieldParentPtr("secret", @constCast(s)));
//             return this.raw_secret;
//         }
//     };
// }
//
// pub const SecretStringUnmanaged = SecretAnyUnmanaged(u8);

test "secret string basic" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretString.init(allocator, "secret");
    defer secret_string.deinit();

    try std.testing.expectEqualSlices(u8, "secret", secret_string.exposeSecret());
}
// test "secret string unmanaged" {
//     const allocator = std.testing.allocator;
//
//     var secret_string = try SecretStringUnmanaged.init(allocator, "secret");
//     defer secret_string.deinit(allocator);
//     const hidden = secret_string.secret;
//
//     try std.testing.expectEqualSlices(u8, "secret", hidden.expose_secret());
// }
