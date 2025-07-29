//! By convention, root.zig is the root source file when making a library.
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
