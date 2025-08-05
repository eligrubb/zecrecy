//! ZerosOnlyAllocator is a custom mem.Allocator that panics if any memory is
//! not zeroed before being freed. ZerosOnlyAllocator does not handle any
//! memory operations itself, but instead wraps around a child allocator.
//! In most cases, this is `std.testing.allocator`.
//!
//! **CRITICAL**: This will not cause a panic as expected if the memory isfreed
//! using the standard `fn free(Allocator, anytype) void` function found in
//! `mem.Allocator`. This is because `mem.Allocator.free` calls `@memset(ptr,
//! undefined)` before it eventually calls the `free` function defined by our
//! custom allocator.
//!
//! To get around this, the `zecrecy` library calls `rawFree` directly instead
//! of using the multiple layers of indirection that `mem.Allocator.free`
//! provides.
const std = @import("std");
const mem = std.mem;

const ZerosOnlyAllocator = @This();

child_allocator: mem.Allocator,

pub fn init(child: mem.Allocator) ZerosOnlyAllocator {
    return .{
        .child_allocator = child,
    };
}

pub fn allocator(self: *ZerosOnlyAllocator) mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

fn alloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
    const self: *ZerosOnlyAllocator = @ptrCast(@alignCast(ctx));
    return self.child_allocator.rawAlloc(len, alignment, ret_addr);
}

fn resize(ctx: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
    const self: *ZerosOnlyAllocator = @ptrCast(@alignCast(ctx));
    return self.child_allocator.rawResize(memory, alignment, new_len, ret_addr);
}

fn remap(ctx: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
    const self: *ZerosOnlyAllocator = @ptrCast(@alignCast(ctx));
    return self.child_allocator.rawRemap(memory, alignment, new_len, ret_addr);
}

/// Panics if the memory is not zeroed before freeing.
fn free(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, ret_addr: usize) void {
    const self: *ZerosOnlyAllocator = @ptrCast(@alignCast(ctx));
    for (buf) |byte| {
        if (byte != 0) unreachable;
    }
    self.child_allocator.rawFree(buf, alignment, ret_addr);
}
