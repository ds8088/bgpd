//! Server accepts incoming TCP connections and dispatches each one to a
//! ConnectionCallback on a thread-pool worker.

const std = @import("std");
const Config = @import("Config.zig");
const Semaphore = @import("Semaphore.zig");
const Differ = @import("Differ.zig");
const logger = @import("logger.zig").Scoped(.server);

/// ConnectionCallback is the function signature for handling an accepted connection.
pub const ConnectionCallback = *const fn (
    alloc: std.mem.Allocator,
    cfg: *const Config.ConfigBgpFields,
    conn: *std.net.Server.Connection,
    differ: *Differ,
    ready: *std.atomic.Value(bool),
) anyerror!void;

alloc: std.mem.Allocator = undefined,
cfg: *const Config.ConfigBgpFields,
sema: *Semaphore = undefined,
differ: *Differ = undefined,
ready: *std.atomic.Value(bool) = undefined,
callback: ConnectionCallback = undefined,
is_closed: std.atomic.Value(bool) = .init(false),
current_port: std.atomic.Value(u16) = .init(0),
connections_mu: std.Thread.Mutex = .{},
active_fds: std.ArrayList(std.net.Stream.Handle) = .empty,

const Self = @This();

/// init creates a new Server.
pub fn init(alloc: std.mem.Allocator, cfg: *const Config.ConfigBgpFields, sema: *Semaphore, differ: *Differ, ready: *std.atomic.Value(bool), callback: ConnectionCallback) Self {
    return .{ .alloc = alloc, .cfg = cfg, .sema = sema, .differ = differ, .ready = ready, .callback = callback };
}

/// run starts the server, accepting connections and dispatching them to the callback.
///
/// Blocks until the shutdown semaphore is signaled.
pub fn run(self: *Self) !void {
    logger.info("starting on {s}:{d}", .{ self.cfg.listen_addr, self.cfg.listen_port });
    defer logger.info("exiting", .{});

    const address = try std.net.Address.resolveIp(self.cfg.listen_addr, self.cfg.listen_port);
    var listener = try address.listen(.{ .reuse_address = true });
    defer {
        logger.debug("sending cancellation event", .{});
        self.close(&listener);
    }

    self.current_port.store(listener.listen_address.in.getPort(), .release);

    var pool: std.Thread.Pool = undefined;
    try std.Thread.Pool.init(&pool, .{ .allocator = self.alloc, .n_jobs = 64, .stack_size = 1024 * 1024 });
    defer pool.deinit();

    defer self.active_fds.deinit(self.alloc);

    const cancellation_thread = try std.Thread.spawn(.{}, cancellationThreadFunc, .{ self, &listener });
    defer cancellation_thread.join();

    const read_timeout = secondsToTimeval(self.cfg.hold_time_sec);
    const write_timeout = secondsToTimeval(self.cfg.write_timeout_sec);

    while (!self.sema.isSignaled()) {
        const conn = listener.accept() catch |err| switch (err) {
            error.WouldBlock, error.ConnectionResetByPeer, error.ConnectionAborted, error.Unexpected => {
                logger.debug("ignoring accept error: {any}", .{err});
                continue;
            },
            else => return err,
        };

        logger.debug("accepted connection from {f}", .{conn.address});

        try std.posix.setsockopt(conn.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &std.mem.toBytes(read_timeout));
        try std.posix.setsockopt(conn.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, &std.mem.toBytes(write_timeout));

        try pool.spawn(spawnConnection, .{ self, conn });
    }
}

fn close(self: *Self, listener: *std.net.Server) void {
    if (self.is_closed.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
        logger.debug("beginning cancellation", .{});

        // Shutdown the listener's socket before closing it;
        // otherwise, on Linux, the server will hang indefinitely.
        std.posix.shutdown(listener.stream.handle, .recv) catch {};
        listener.deinit();

        logger.debug("stopping all connections", .{});

        self.connections_mu.lock();
        for (self.active_fds.items) |fd| {
            std.posix.shutdown(fd, .both) catch {};
        }
        self.connections_mu.unlock();

        logger.debug("cancellation completed", .{});
    }
}

fn cancellationThreadFunc(self: *Self, listener: *std.net.Server) void {
    defer {
        logger.debug("sending async cancellation event", .{});
        self.close(listener);
    }

    while (!self.sema.timedWait(1 * std.time.ns_per_s)) {}
}

fn spawnConnection(self: *Self, conn: std.net.Server.Connection) void {
    if (self.sema.isSignaled()) {
        conn.stream.close();
        return;
    }

    var c = conn;

    self.connections_mu.lock();
    self.active_fds.append(self.alloc, c.stream.handle) catch {};
    self.connections_mu.unlock();

    defer {
        self.connections_mu.lock();
        for (self.active_fds.items, 0..) |fd, i| {
            if (fd == c.stream.handle) {
                _ = self.active_fds.swapRemove(i);
                break;
            }
        }
        self.connections_mu.unlock();
        c.stream.close();
    }

    self.callback(self.alloc, self.cfg, &c, self.differ, self.ready) catch |err| {
        logger.warn("error in connection from {f}: {any}", .{ conn.address, err });
    };
}

fn secondsToTimeval(secs: u64) std.posix.timeval {
    return std.posix.timeval{ .sec = @intCast(secs), .usec = 0 };
}

//
// Tests
//

test "secondsToTimeval" {
    for ([_]u64{ 0, 1, 5, 90 }) |secs| {
        const tv = secondsToTimeval(secs);
        try std.testing.expectEqual(@as(i64, @intCast(secs)), tv.sec);
        try std.testing.expectEqual(@as(i64, 0), tv.usec);
    }
}

test "smoke test" {
    const testCallback = struct {
        fn run(_: std.mem.Allocator, _: *const Config.ConfigBgpFields, conn: *std.net.Server.Connection, _: *Differ, _: *std.atomic.Value(bool)) !void {
            var write_buf: [64]u8 = undefined;
            var writer = conn.stream.writer(&write_buf);

            try writer.interface.writeAll("test");
            try writer.interface.flush();
        }
    }.run;

    var cfg = Config.ConfigBgpFields{
        .listen_addr = "127.0.0.1",
        .listen_port = 0,
    };

    var sema: Semaphore = .init;
    var differ: Differ = .init(std.testing.allocator);
    defer differ.deinit();

    var ready = std.atomic.Value(bool).init(true);
    var server = Self.init(std.testing.allocator, &cfg, &sema, &differ, &ready, testCallback);

    const server_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Self) void {
            s.run() catch |err| logger.err("{any}", .{err});
        }
    }.run, .{&server});

    defer {
        sema.broadcast();
        server_thread.join();
    }

    // Wait for the server to bind and start listening.
    var port: u16 = 0;
    while (port == 0) {
        std.Thread.sleep(1 * std.time.ns_per_ms);
        port = server.current_port.load(.acquire);
    }

    const addr = try std.net.Address.resolveIp("127.0.0.1", port);
    const stream = try std.net.tcpConnectToAddress(addr);
    defer stream.close();

    var read_buf: [64]u8 = undefined;
    var reader = stream.reader(&read_buf);

    const res = try reader.interface().allocRemaining(std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(res);

    try std.testing.expectEqualStrings("test", res);
}
