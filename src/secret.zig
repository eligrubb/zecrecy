const std = @import("std");
const mem = std.mem;
const secureZero = std.crypto.secureZero;

///
pub fn Exposed(comptime T: type) type {
    return struct {
        expose: *const fn (self: *const ExposedType) []T,

        const ExposedType = @This();

        pub fn secret(self: *const ExposedType) []const T {
            return self.expose(self);
        }

        pub fn secretMutable(self: *const ExposedType) []T {
            return self.expose(self);
        }
    };
}

pub const ExposedString = Exposed(u8);

/// Must call .deinit() on the returned struct when you are finished with it.
///
/// This struct stores an internal mem.Allocator to handle meory management.
/// To handle memory management yourself, use `SecretAnyUnmanaged`
pub fn SecretAny(comptime T: type) type {
    return struct {
        secret: []T,
        allocator: mem.Allocator,
        _exposed_buffer: Exposed(T),

        const Secret = @This();

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

        pub fn deinit(self: *Secret) void {
            secureZero(T, self.secret);
            self.allocator.free(self.secret);
        }

        fn expose(e: *const Exposed(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposed_buffer", @constCast(e)));
            return s.secret;
        }

        pub fn exposeSecret(self: *const Secret) *const Exposed(T) {
            return &self._exposed_buffer;
        }
    };
}

///
pub const SecretString = SecretAny(u8);

pub fn SecretAnyUnmanaged(comptime T: type) type {
    return struct {
        secret: []T,
        _exposed_buffer: Exposed(T),

        const Secret = @This();

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

        pub fn deinit(self: *Secret, allocator: mem.Allocator) void {
            secureZero(T, self.secret);
            allocator.free(self.secret);
        }

        fn expose(e: *const Exposed(T)) []T {
            const s: *Secret = @alignCast(@fieldParentPtr("_exposed_buffer", @constCast(e)));
            return s.secret;
        }

        pub fn exposeSecret(self: *const Secret) *const Exposed(T) {
            return &self._exposed_buffer;
        }
    };
}

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
