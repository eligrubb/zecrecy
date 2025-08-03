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

