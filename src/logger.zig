const builtin = @import("builtin");
const std = @import("std");

pub var debug_enabled = false;

pub fn Scoped(comptime scope: @TypeOf(.enum_literal)) type {
    const base = std.log.scoped(scope);

    return if (builtin.is_test)
        struct {
            pub const err = warn;
            pub const warn = base.warn;
            pub const info = base.info;
            pub const debug = base.debug;
        }
    else
        struct {
            fn debugWrapper(comptime fmt: []const u8, args: anytype) void {
                if (debug_enabled) {
                    base.debug(fmt, args);
                }
            }

            pub const err = base.err;
            pub const warn = base.warn;
            pub const info = base.info;
            pub const debug = debugWrapper;
        };
}
