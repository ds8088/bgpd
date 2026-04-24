//! Session represents a BGP session and its lifecycle:
//! OPEN exchange, KEEPALIVE handshake, and established loop.

const std = @import("std");
const cidr = @import("cidr.zig");
const Config = @import("Config.zig");
const Differ = @import("Differ.zig");
const logger = @import("logger.zig").Scoped(.session);
const messages = @import("messages.zig");
const trie = @import("trie.zig");

/// IO_BUF_LEN is the size of the read and write buffers used for BGP I/O.
pub const IO_BUF_LEN = messages.MAX_MSG_LEN;

alloc: std.mem.Allocator = undefined,
cfg: *const Config.ConfigBgpFields = undefined,
address: std.net.Address = undefined,
reader: *std.Io.Reader = undefined,
writer: *std.Io.Writer = undefined,
differ: *Differ = undefined,
ready: *std.atomic.Value(bool) = undefined,

router_id: cidr.CIDRv4 = cidr.comptimeCIDRv4("0.0.0.0"),

const Self = @This();

/// init creates a new Session for the given connection.
///
/// reader and writer must remain valid for the lifetime of the session.
pub fn init(
    alloc: std.mem.Allocator,
    cfg: *const Config.ConfigBgpFields,
    address: std.net.Address,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    differ: *Differ,
    ready: *std.atomic.Value(bool),
) !Self {
    var self: Self = .{
        .alloc = alloc,
        .cfg = cfg,
        .address = address,
        .reader = reader,
        .writer = writer,
        .differ = differ,
        .ready = ready,
    };
    self.router_id = try cidr.CIDRv4.fromString(cfg.router_id);
    return self;
}

/// run performs the full BGP session lifecycle.
pub fn run(self: *Self) !void {
    logger.info("{f}: new session", .{self.address});

    if (!self.ready.load(.acquire)) {
        logger.info("{f}: rejecting connection: prefixes have not been fetched yet", .{self.address});
        try self.sendNotification(.CEASE, 5, "not ready");
        return;
    }

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(self.alloc);

    // Build BGP OPEN message
    logger.debug("{f}: sending OPEN", .{self.address});
    var msg = try messages.buildOpen(self.alloc, &buf, self.cfg.local_as, self.cfg.hold_time_sec, self.router_id.toArray());
    try self.writeAndFree(msg);

    logger.debug("{f}: waiting for OPEN (OpenConfirm)", .{self.address});
    const open_confirm_msg = try self.receiveBgpOpenConfirm();
    logger.debug("{f}: received OPEN (OpenConfirm)", .{self.address});

    if (!open_confirm_msg.supports_4byte_as and self.cfg.local_as > std.math.maxInt(u16)) {
        logger.warn("{f}: peer does not support 4-byte ASNs (our ASN is {d})", .{ self.address, self.cfg.local_as });
        try self.sendNotification(.OPEN_MESSAGE_ERROR, 2, "missing 4-byte ASN support");
        return error.Needs4ByteAsnSupport;
    }

    const timings = try self.negotiateTimings(&open_confirm_msg);

    logger.debug("{f}: sending KEEP_ALIVE", .{self.address});
    buf.clearRetainingCapacity();
    msg = try messages.buildKeepalive(self.alloc, &buf);
    try self.writeAndFree(msg);

    return try self.runEstablished(timings.hold_ms, timings.keepalive_ms);
}

fn runEstablished(self: *Self, hold_ms: i64, keepalive_ms: i64) !void {
    var last_recv_ms = std.time.milliTimestamp();
    var last_keepalive_ms = last_recv_ms;
    var last_gen: u64 = 0;

    while (true) {
        // Catch socket read timeouts.
        // std.Io.Reader wraps the underlying OS error, so if we get a ReadFailed error,
        // we can simply fall through to the hold timer check below.
        const opt_msg: ?messages.BgpMessage = self.readMessage() catch |err| switch (err) {
            error.ReadFailed => null,
            else => return err,
        };
        defer if (opt_msg) |m| self.alloc.free(m.body);

        if (opt_msg) |msg| {
            switch (msg.type) {
                .KEEP_ALIVE, .UPDATE => {
                    logger.debug("{f}: received {t}", .{ self.address, msg.type });
                    last_recv_ms = std.time.milliTimestamp();
                },
                .NOTIFICATION => {
                    const notification = messages.parseNotification(msg.body) catch |err| {
                        logger.info("{f}: received malformed NOTIFICATION: {any}", .{ self.address, err });
                        return;
                    };

                    logger.info("{f}: received NOTIFICATION: code={t}, subcode={d}, data={s}", .{
                        self.address, notification.error_code, notification.error_subcode, notification.data,
                    });

                    // Treat any notification as fatal
                    return;
                },
                .OPEN => {
                    logger.warn("{f}: unexpected OPEN", .{self.address});
                    try self.sendNotification(.FSM_ERROR, 2, "unexpected OPEN");
                    return error.UnexpectedOpen;
                },
                else => {},
            }
        }

        const now = std.time.milliTimestamp();

        if (hold_ms > 0 and now - last_recv_ms >= hold_ms) {
            logger.warn("{f}: hold timer expired", .{self.address});
            try self.sendNotification(.HOLD_TIMER_EXPIRED, 0, "hold timer expired");
            return error.HoldTimerExpired;
        }

        if (keepalive_ms > 0 and now - last_keepalive_ms >= keepalive_ms) {
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(self.alloc);

            logger.debug("{f}: sending KEEP_ALIVE", .{self.address});
            const keepalive_msg = try messages.buildKeepalive(self.alloc, &buf);
            try self.writeAndFree(keepalive_msg);
            last_keepalive_ms = now;
        }

        const new_gen = self.differ.getGeneration();
        if (new_gen == last_gen) {
            logger.debug("{f}: peer already has the latest generation, nothing to do", .{self.address});
        } else {
            if (last_gen == 0) { // First announce
                logger.info("{f}: session established", .{self.address});

                var latest_snapshot = try self.differ.getLatest(self.alloc);
                defer latest_snapshot.deinit();

                var v4 = trie.Trie(u32).init(self.alloc);
                defer v4.deinit();
                var v6 = trie.Trie(u128).init(self.alloc);
                defer v6.deinit();

                logger.debug("{f}: sending initial full update with gen {d}", .{ self.address, new_gen });
                try self.announce(&latest_snapshot.v4, &latest_snapshot.v6, &v4, &v6);
            } else if (new_gen - last_gen == 1) {
                var snapshot = try self.differ.getDiff(self.alloc);
                defer snapshot.deinit();

                logger.info("{f}: sending update from gen {d} to gen {d}", .{ self.address, last_gen, new_gen });
                try self.announce(&snapshot.v4_added, &snapshot.v6_added, &snapshot.v4_removed, &snapshot.v6_removed);
            } else {
                // The generations differ by more than one, and we don't have such a diff.
                // Reset the session so that the peer would try again.

                logger.warn("{f}: generation difference is too large, resetting", .{self.address});
                try self.sendNotification(.CEASE, 6, "generation difference is too large");
                return error.GenerationDifferenceTooLarge;
            }

            last_gen = new_gen;
        }

        // TODO: Route-Refresh capability
    }
}

fn announce(
    self: *Self,
    nlri_v4: *const trie.Trie(u32),
    nlri_v6: *const trie.Trie(u128),
    wd_ipv4: *const trie.Trie(u32),
    wd_ipv6: *const trie.Trie(u128),
) !void {
    var iter = try messages.buildUpdate(self.alloc, self.cfg, wd_ipv4, wd_ipv6, nlri_v4, nlri_v6);
    defer iter.deinit();

    while (try iter.next()) |msg| {
        try self.writeAndFree(msg);
    }
}

fn receiveBgpOpenConfirm(self: *Self) !messages.BgpMessageOpen {
    const bgp_msg = try self.readMessage();
    defer self.alloc.free(bgp_msg.body);

    if (bgp_msg.type != .OPEN) {
        logger.warn("{f}: FSM mismatch: expected OPEN_CONFIRM but got {t}", .{ self.address, bgp_msg.type });
        try self.sendNotification(.FSM_ERROR, 0, "expected OPEN_CONFIRM");
        return error.ExpectedOpen;
    }

    return try messages.parseOpen(bgp_msg.body);
}

fn writeAndFree(self: *Self, data: []const u8) !void {
    defer self.alloc.free(data);
    try self.writer.writeAll(data);
    try self.writer.flush();
}

fn readMessage(self: *Self) !messages.BgpMessage {
    return try messages.readMessage(self.alloc, self.reader);
}

fn sendNotification(self: *Self, code: messages.NotificationErrorCode, subcode: u8, data: []const u8) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(self.alloc);

    logger.debug("{f}: sending NOTIFICATION: {t}/{d}: {s}", .{ self.address, code, subcode, data });
    const msg = try messages.buildNotification(self.alloc, &buf, code, subcode, data);
    try self.writeAndFree(msg);
}

fn negotiateTimings(self: *Self, msg: *const messages.BgpMessageOpen) !struct { hold_ms: i64, keepalive_ms: i64 } {
    const min_hold_sec: u16 = @min(self.cfg.hold_time_sec, msg.hold_time);
    if (min_hold_sec != 0 and min_hold_sec < 3) {
        try self.sendNotification(.OPEN_MESSAGE_ERROR, 6, "hold time cannot be less than 3 seconds (RFC4271)");
        return error.UnacceptableHoldTime;
    }

    const min_hold_ms: i64 = @as(i64, min_hold_sec) * std.time.ms_per_s;
    const keepalive_ms: i64 = if (min_hold_sec == 0)
        0
    else
        @max(1, @divTrunc(min_hold_ms, 3));

    logger.debug("{f}: negotiated timings: hold = {D}, keepalive = {D}", .{
        self.address, min_hold_ms * std.time.ns_per_ms, keepalive_ms * std.time.ns_per_ms,
    });

    return .{ .hold_ms = min_hold_ms, .keepalive_ms = keepalive_ms };
}

//
// Tests
//

// runOneSession accepts one connection, creates a Session, and runs it.
fn runOneSession(
    listener: *std.net.Server,
    cfg: *const Config.ConfigBgpFields,
    differ: *Differ,
    ready: *std.atomic.Value(bool),
    result: *anyerror!void,
) void {
    result.* = (struct {
        fn run(l: *std.net.Server, c: *const Config.ConfigBgpFields, d: *Differ, r: *std.atomic.Value(bool)) !void {
            var conn = try l.accept();
            defer conn.stream.close();

            var read_buf: [IO_BUF_LEN]u8 = undefined;
            var buf_reader = conn.stream.reader(&read_buf);
            var write_buf: [IO_BUF_LEN]u8 = undefined;
            var buf_writer = conn.stream.writer(&write_buf);

            var session = try Self.init(
                std.testing.allocator,
                c,
                conn.address,
                buf_reader.interface(),
                &buf_writer.interface,
                d,
                r,
            );
            try session.run();
        }
    }.run)(listener, cfg, differ, ready);
}

test "smoke test" {
    const alloc = std.testing.allocator;

    var differ = Differ.init(alloc);
    defer differ.deinit();

    var ready = std.atomic.Value(bool).init(true);

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    // Send a single update to the Differ.
    _ = try differ.update(&v4, &v6);

    // hold_time_sec=0 disables hold and keepalive timers to avoid test timeouts.
    const cfg: Config.ConfigBgpFields = .{ .local_as = 65001, .hold_time_sec = 0 };

    // Create a TCP listener on an ephemeral port.
    const listen_addr = try std.net.Address.resolveIp("127.0.0.1", 0);
    var listener = try listen_addr.listen(.{});
    defer listener.deinit();
    const port = listener.listen_address.in.getPort();

    // Start the server thread.
    var session_result: anyerror!void = {};
    const session_thread = try std.Thread.spawn(.{}, runOneSession, .{ &listener, &cfg, &differ, &ready, &session_result });

    // Peer side: connect and perform the full BGP exchange.
    const peer_stream = try std.net.tcpConnectToAddress(
        try std.net.Address.resolveIp("127.0.0.1", port),
    );
    defer peer_stream.close();

    var p_read_buf: [IO_BUF_LEN]u8 = undefined;
    var peer_reader = peer_stream.reader(&p_read_buf);
    var p_write_buf: [IO_BUF_LEN]u8 = undefined;
    var peer_writer = peer_stream.writer(&p_write_buf);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // 1. Wait for an incoming OPEN message.
    {
        const msg = try messages.readMessage(alloc, peer_reader.interface());
        defer alloc.free(msg.body);
        try std.testing.expectEqual(messages.MessageType.OPEN, msg.type);
        const open = try messages.parseOpen(msg.body);
        try std.testing.expectEqual(@as(u32, 65001), open.my_as);
    }

    // 2. Send OPEN message.
    {
        const msg = try messages.buildOpen(alloc, &buf, 65002, 90, .{ 10, 0, 0, 1 });
        defer alloc.free(msg);
        try peer_writer.interface.writeAll(msg);
        try peer_writer.interface.flush();
    }

    // 3. Wait for a KEEPALIVE.
    {
        const msg = try messages.readMessage(alloc, peer_reader.interface());
        defer alloc.free(msg.body);
        try std.testing.expectEqual(messages.MessageType.KEEP_ALIVE, msg.type);
    }

    // 4. Send KEEPALIVE message.
    {
        const msg = try messages.buildKeepalive(alloc, &buf);
        defer alloc.free(msg);
        try peer_writer.interface.writeAll(msg);
        try peer_writer.interface.flush();
    }

    // 5. Read the initial UPDATE (10.0.0.0/8).
    {
        const msg = try messages.readMessage(alloc, peer_reader.interface());
        defer alloc.free(msg.body);
        try std.testing.expectEqual(messages.MessageType.UPDATE, msg.type);
        // We don't have a builtin method to parse and read UPDATE messages,
        // but if the message's structure is invalid,
        // the BGP message tests should have caught the issue.
    }

    // 6. Send NOTIFICATION.
    {
        const msg = try messages.buildNotification(alloc, &buf, .CEASE, 0, "");
        defer alloc.free(msg);
        try peer_writer.interface.writeAll(msg);
        try peer_writer.interface.flush();
    }

    // The session should exit cleanly.
    session_thread.join();
    try session_result;
}

test "session: sends CEASE/5 notification when not ready" {
    const alloc = std.testing.allocator;

    var differ = Differ.init(alloc);
    defer differ.deinit();

    // ready = false: no prefix data available yet.
    var ready = std.atomic.Value(bool).init(false);

    const cfg: Config.ConfigBgpFields = .{ .local_as = 65001, .hold_time_sec = 0 };

    const listen_addr = try std.net.Address.resolveIp("127.0.0.1", 0);
    var listener = try listen_addr.listen(.{});
    defer listener.deinit();
    const port = listener.listen_address.in.getPort();

    var session_result: anyerror!void = {};
    const session_thread = try std.Thread.spawn(.{}, runOneSession, .{ &listener, &cfg, &differ, &ready, &session_result });

    const peer_stream = try std.net.tcpConnectToAddress(try std.net.Address.resolveIp("127.0.0.1", port));
    defer peer_stream.close();

    var p_read_buf: [IO_BUF_LEN]u8 = undefined;
    var peer_reader = peer_stream.reader(&p_read_buf);

    // The session must immediately send a CEASE/5 (Connection Rejected) and close.
    const msg = try messages.readMessage(alloc, peer_reader.interface());
    defer alloc.free(msg.body);

    try std.testing.expectEqual(messages.MessageType.NOTIFICATION, msg.type);
    const notif = try messages.parseNotification(msg.body);
    try std.testing.expectEqual(messages.NotificationErrorCode.CEASE, notif.error_code);
    try std.testing.expectEqual(@as(u8, 5), notif.error_subcode);

    session_thread.join();
    try session_result;
}
