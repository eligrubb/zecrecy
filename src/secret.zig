const std = @import("std");
const mem = std.mem;
const secureZero = std.crypto.secureZero;

pub fn Secret(comptime T: type) type {
    return struct {
        expose_secret: *const fn (self: *Secret) []T,
    };
}

/// Must call .deinit() on the returned struct when you are finished with it.
///
/// This struct stores an internal mem.Allocator to handle meory management.
/// To handle memory management yourself, use `SecretAnyUnmanaged`
pub fn SecretAny(comptime T: type) type {
    return struct {
        const Self = @This();

        raw_secret: [*]T = undefined,
        allocator: mem.Allocator = undefined,
        secret: Secret,

        pub fn init(allocator: mem.Allocator, secret: []T) !Self {
            const secret_ptr = allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return Self{
                .raw_secret = secret_ptr,
                .allocator = allocator,
                .secret = Secret{
                    .expose_secret = expose_secret,
                },
            };
        }

        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Self {
            const secret_ptr = allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return Self{
                .raw_secret = secret_ptr,
                .allocator = allocator,
                .secret = Secret{
                    .expose_secret = @This().expose_secret,
                },
            };
        }

        pub fn deinit(self: *Self) void {
            secureZero(T, self.secret[0..self.length]);
            self.allocator.free(self.secret);
        }

        fn expose_secret(s: *Secret) []T {
            const this: *Self = @alignCast(@fieldParentPtr("secret", s));
            return this.raw_secret[0..this.length];
        }
    };
}

///
pub const SecretString = SecretAny(u8);

pub fn SecretAnyUnmanaged(comptime T: type) type {
    return struct {
        const Self = @This();

        raw_secret: [*]T = undefined,
        secret: Secret,

        pub fn init(allocator: mem.Allocator, secret: []T) !Self {
            const secret_ptr = allocator.alloc(T, secret.len);
            @memcpy(secret_ptr, secret);
            return Self{
                .raw_secret = secret_ptr,
                .secret = Secret{
                    .expose_secret = expose_secret,
                },
            };
        }

        pub fn initFromFunction(allocator: mem.Allocator, secret: fn () []T) !Self {
            const secret_ptr = allocator.alloc(T, secret().len);
            secret_ptr.* = secret();
            return Self{
                .raw_secret = secret_ptr,
                .secret = Secret{
                    .expose_secret = @This().expose_secret,
                },
            };
        }

        pub fn deinit(self: *Self, allocator: mem.Allocator) void {
            secureZero(T, self.secret[0..self.length]);
            allocator.free(self.secret);
        }

        fn expose_secret(s: *Secret) []T {
            const this: *Self = @alignCast(@fieldParentPtr("secret", s));
            return this.raw_secret[0..this.length];
        }
    };
}

pub const SecretStringUnmanaged = SecretAnyUnmanaged(u8);
