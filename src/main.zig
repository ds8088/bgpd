//! bgpd - BGP daemon that fetches AS prefix lists and advertises them over BGP.
//!
//! Usage: bgpd [-d|--debug] [-c|--config <config path>] [-h|--help]

const builtin = @import("builtin");
const std = @import("std");
const args_mod = @import("args.zig");
const Config = @import("Config.zig");
const logger_mod = @import("logger.zig");
const logger = logger_mod.Scoped(.main);
const Semaphore = @import("Semaphore.zig");
const shutdown = @import("shutdown.zig");
const Fetcher = @import("Fetcher.zig");
const Differ = @import("Differ.zig");
const Server = @import("Server.zig");
const Session = @import("Session.zig");

pub const std_options: std.Options = .{
    .log_level = .debug,
};

fn runFetcher(f: *Fetcher, cfg: *Config.ConfigFetchFields, sema: *Semaphore) void {
    logger.info("fetcher: starting", .{});
    defer logger.info("fetcher: exiting", .{});

    const interval_ns = cfg.interval_sec * std.time.ns_per_s;

    while (true) {
        f.fetch() catch |err| {
            logger.err("fetcher: failed to perform fetch: {any}", .{err});
        };

        logger.debug("fetcher: waiting until next fetch for {D}", .{interval_ns});

        if (sema.sleep(interval_ns)) {
            logger.debug("fetcher: shutting down due to signal", .{});
            return;
        }

        logger.debug("fetcher: waking up", .{});
    }
}

fn runServer(s: *Server, sema: *Semaphore) void {
    s.run() catch |err| {
        logger.err("failed to start bgp server: {any}", .{err});
        sema.broadcast();
    };
}

fn serverEntrypoint(alloc: std.mem.Allocator, cfg: *const Config.ConfigBgpFields, conn: *std.net.Server.Connection, differ: *Differ, ready: *std.atomic.Value(bool)) !void {
    var read_buf: [Session.IO_BUF_LEN]u8 = undefined;
    var buf_reader = conn.stream.reader(&read_buf);
    var write_buf: [Session.IO_BUF_LEN]u8 = undefined;
    var buf_writer = conn.stream.writer(&write_buf);

    var session = try Session.init(alloc, cfg, conn.address, buf_reader.interface(), &buf_writer.interface, differ, ready);
    try session.run();
}

pub fn main() !void {
    defer logger.debug("shutdown completed", .{});

    var debug_alloc: ?*std.heap.DebugAllocator(.{}) = null;
    var alloc: std.mem.Allocator = std.heap.smp_allocator;

    defer {
        // Deinitialize the debug allocator if it has been initialized.
        if (debug_alloc) |debug_alloc_inited| {
            const deinit_status = debug_alloc_inited.deinit();
            if (deinit_status == .leak) {
                logger.warn("memory leak after exiting", .{});
            }
        }
    }

    // For non-release modes, use the debug allocator.
    if (builtin.mode != .ReleaseFast and builtin.mode != .ReleaseSmall) {
        var inited: std.heap.DebugAllocator(.{}) = .init;
        alloc = inited.allocator();
        debug_alloc = &inited;
    }

    // Parse CLI args.
    var arg_iter = try std.process.argsWithAllocator(alloc);
    defer arg_iter.deinit();

    const cli_args = args_mod.parseArgs(&arg_iter) catch |err| {
        if (err == error.HelpRequested) {
            return;
        }

        return err;
    };

    var parsed_cfg = try Config.load(alloc, cli_args.config_path);
    defer parsed_cfg.deinit();

    const cfg = &parsed_cfg.value.fields;
    if (cli_args.debug) {
        cfg.debug = true;
    }

    logger_mod.debug_enabled = cfg.debug;

    logger.info("bgpd starting: listening on {s}:{d}, local AS = {d}, router ID = {s}", .{
        cfg.bgp.listen_addr,
        cfg.bgp.listen_port,
        cfg.bgp.local_as,
        cfg.bgp.router_id,
    });

    var sema: Semaphore = .init;
    try shutdown.init(&sema);

    var differ = Differ.init(alloc);
    defer differ.deinit();

    var prefixes_ready = std.atomic.Value(bool).init(false);

    var fetcher = Fetcher.init(alloc, cfg, &sema, &differ, &prefixes_ready);
    const fetcher_thread = try std.Thread.spawn(.{}, runFetcher, .{ &fetcher, &cfg.fetch, &sema });
    defer fetcher_thread.join();

    var server = Server.init(alloc, &cfg.bgp, &sema, &differ, &prefixes_ready, serverEntrypoint);
    const server_thread = try std.Thread.spawn(.{}, runServer, .{ &server, &sema });
    defer server_thread.join();

    // Wait until the semaphore gets raised
    while (!sema.timedWait(10 * std.time.ns_per_s)) {}

    logger.info("bgpd shutting down", .{});
}
