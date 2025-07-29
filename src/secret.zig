const std = @import("std");
const mem = std.mem;
const secureZero = std.crypto.secureZero;

pub fn Exposer(comptime T: type) type {
    return struct {
        const ExposerType = @This();
        expose: *const fn (self: *const ExposerType) []T,

        pub fn exposeSecret(self: *const ExposerType) []T {
            return self.expose(self);
        }
    };
}

/// Must call .deinit() on the returned struct when you are finished with it.
///
/// This struct stores an internal mem.Allocator to handle meory management.
/// To handle memory management yourself, use `SecretAnyUnmanaged`
pub fn SecretAny(comptime T: type) type {
    return struct {
        secret: []T,
        allocator: mem.Allocator,
        _exposer_buffer: Exposer(T),

        const Secret = @This();

        pub fn init(allocator: mem.Allocator, secret: []const T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
                .allocator = allocator,
                ._exposer_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return .{
                .secret = secret_ptr,
                .allocator = allocator,
                ._exposer_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        pub fn deinit(self: *Secret) void {
            secureZero(T, self.secret);
            self.allocator.free(self.secret);
        }

        fn expose(e: *const Exposer(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposer_buffer", @constCast(e)));
            return s.secret;
        }

        pub fn getExposer(self: *const Secret) *const Exposer(T) {
            return &self._exposer_buffer;
        }
    };
}

///
pub const SecretString = SecretAny(u8);

pub fn SecretAnyUnmanaged(comptime T: type) type {
    return struct {
        secret: []T,
        _exposer_buffer: Exposer(T),

        const Secret = @This();

        pub fn init(allocator: mem.Allocator, secret: []const T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return .{
                .secret = secret_ptr,
                ._exposer_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Secret {
            const secret_ptr = try allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return .{
                .secret = secret_ptr,
                ._exposer_buffer = .{
                    .expose = Secret.expose,
                },
            };
        }

        pub fn deinit(self: *Secret, allocator: mem.Allocator) void {
            secureZero(T, self.secret);
            allocator.free(self.secret);
        }

        fn expose(e: *const Exposer(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposer_buffer", @constCast(e)));
            return s.secret;
        }

        pub fn getExposer(self: *const Secret) *const Exposer(T) {
            return &self._exposer_buffer;
        }
    };
}

pub const SecretStringUnmanaged = SecretAnyUnmanaged(u8);

test "secret string basic" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretString.init(allocator, "secret");
    defer secret_string.deinit();
    const exposer = secret_string.getExposer();

    try std.testing.expectEqualSlices(u8, "secret", exposer.exposeSecret());
}

test "secret string unmanaged" {
    const allocator = std.testing.allocator;

    var secret_string = try SecretStringUnmanaged.init(allocator, "secret");
    defer secret_string.deinit(allocator);
    const exposer = secret_string.getExposer();

    try std.testing.expectEqualSlices(u8, "secret", exposer.exposeSecret());
}
