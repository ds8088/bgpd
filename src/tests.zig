//! Tests: imports all application modules in a single comptime block,
//! ensuring the visibility of all test statements.

comptime {
    _ = @import("cidr.zig");
    _ = @import("Config.zig");
    _ = @import("Differ.zig");
    _ = @import("Fetcher.zig");
    _ = @import("main.zig");
    _ = @import("messages.zig");
    _ = @import("Semaphore.zig");
    _ = @import("Server.zig");
    _ = @import("Session.zig");
    _ = @import("shutdown.zig");
    _ = @import("trie.zig");
}
