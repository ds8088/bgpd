//! Fetcher periodically grabs AS prefix lists from the ipverse GitHub repo,
//! summarizes them, and pushes the result into the differ.

const std = @import("std");
const cidr = @import("cidr.zig");
const Config = @import("Config.zig");
const Differ = @import("Differ.zig");
const Semaphore = @import("Semaphore.zig");
const trie = @import("trie.zig");
const logger = @import("logger.zig").Scoped(.fetcher);

alloc: std.mem.Allocator = undefined,
cfg: *Config.ConfigFields,
sema: *Semaphore = undefined,
differ: *Differ = undefined,
ready: *std.atomic.Value(bool) = undefined,
base_url: []const u8 = "https://raw.githubusercontent.com/ipverse/as-ip-blocks/refs/heads/master/as",

const Self = @This();

const AsFileJson = struct {
    prefixes: struct {
        ipv4: ?[][]const u8 = null,
        ipv6: ?[][]const u8 = null,
    },
};

/// init creates a new Fetcher.
pub fn init(alloc: std.mem.Allocator, cfg: *Config.ConfigFields, sema: *Semaphore, differ: *Differ, ready: *std.atomic.Value(bool)) Self {
    return .{ .alloc = alloc, .cfg = cfg, .sema = sema, .differ = differ, .ready = ready };
}

/// fetch fetches prefix lists for all configured AS numbers and pushes
/// the summarized result into the differ.
///
/// Returns if the shutdown semaphore is signaled.
pub fn fetch(self: *const Self) !void {
    var triev4 = trie.Trie(u32).init(self.alloc);
    defer triev4.deinit();

    var triev6 = trie.Trie(u128).init(self.alloc);
    defer triev6.deinit();

    for (self.cfg.fetch.as) |asn| {
        if (self.sema.isSignaled()) {
            return;
        }

        self.fetchAsn(asn, &triev4, &triev6) catch |err| {
            logger.err("failed to fetch data for AS{d}: {any}", .{ asn, err });
        };
    }

    logger.debug("finished fetching prefixes", .{});

    const gen_id = try self.differ.update(&triev4, &triev6);
    logger.debug("updated differ with generation {d}", .{gen_id});

    self.ready.store(true, .release);
}

fn fetchAsn(self: *const Self, asn: u32, triev4: *trie.Trie(u32), triev6: *trie.Trie(u128)) !void {
    const url = try std.fmt.allocPrint(self.alloc, "{s}/{d}/aggregated.json", .{ self.base_url, asn });
    defer self.alloc.free(url);

    const parsed = try self.fetchJsonFromRepo(url);
    defer parsed.deinit();

    const prefixes = parsed.value.prefixes;
    logger.debug("got fresh prefixes for AS {d}: {d} IPv4, {d} IPv6", .{
        asn,
        if (prefixes.ipv4) |p| p.len else 0,
        if (prefixes.ipv6) |p| p.len else 0,
    });

    for (prefixes.ipv4 orelse &.{}) |ipv4| {
        var prefix = cidr.CIDRv4.fromString(ipv4) catch |err| {
            logger.warn("invalid IPv4 prefix from AS {d}: {any}", .{ asn, err });
            continue;
        };

        if (self.cfg.summarization.ipv4_max_prefix_len > 0 and prefix.prefix_len > self.cfg.summarization.ipv4_max_prefix_len) {
            prefix.prefix_len = self.cfg.summarization.ipv4_max_prefix_len;
        }

        triev4.insert(prefix) catch |err| {
            logger.warn("failed to insert IPv4 prefix from AS {d}: {any}", .{ asn, err });
            continue;
        };
    }

    for (prefixes.ipv6 orelse &.{}) |ipv6| {
        var prefix = cidr.CIDRv6.fromString(ipv6) catch |err| {
            logger.warn("invalid IPv6 prefix from AS {d}: {any}", .{ asn, err });
            continue;
        };

        if (self.cfg.summarization.ipv6_max_prefix_len > 0 and prefix.prefix_len > self.cfg.summarization.ipv6_max_prefix_len) {
            prefix.prefix_len = self.cfg.summarization.ipv6_max_prefix_len;
        }

        triev6.insert(prefix) catch |err| {
            logger.warn("failed to insert IPv6 prefix from AS {d}: {any}", .{ asn, err });
            continue;
        };
    }
}

fn fetchJsonFromRepo(self: *const Self, url: []const u8) !std.json.Parsed(AsFileJson) {
    var client = std.http.Client{ .allocator = self.alloc };
    defer client.deinit();

    const headers = std.http.Header{ .name = "Accept", .value = "application/json" };

    var retries: u64 = 0;
    while (retries <= self.cfg.fetch.retry_max_count) {
        const delay_ms = calculateBackoffDelay(self, retries);

        var body = std.Io.Writer.Allocating.init(self.alloc);
        defer body.deinit();

        logger.debug("calling fetch for {s}, retries: {d}", .{ url, retries });

        const result = client.fetch(.{
            .method = .GET,
            .location = .{ .url = url },
            .extra_headers = &.{headers},
            .redirect_behavior = std.http.Client.Request.RedirectBehavior.init(5),
            .response_writer = &body.writer,
        }) catch |err| {
            logger.warn("error while fetching {s}: {any} (retry in {D}ms)", .{ url, err, delay_ms });
            if (self.sema.sleep(delay_ms * std.time.ns_per_ms)) {
                return error.SemaphoreTriggered;
            }

            retries += 1;
            continue;
        };

        if (result.status != .ok) {
            logger.warn("HTTP error {d} while fetching {s} (retry in {D}ms)", .{ @intFromEnum(result.status), url, delay_ms });
            if (self.sema.sleep(delay_ms * std.time.ns_per_ms)) {
                return error.SemaphoreTriggered;
            }

            retries += 1;
            continue;
        }

        const slice = try body.toOwnedSlice();
        defer self.alloc.free(slice);

        return try std.json.parseFromSlice(AsFileJson, self.alloc, slice, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
    }

    return error.MaxRetriesExceeded;
}

fn calculateBackoffDelay(self: *const Self, retry_num: u64) u64 {
    const min = self.cfg.fetch.retry_min_delay_ms;
    const max = self.cfg.fetch.retry_max_delay_ms;
    const pow = self.cfg.fetch.retry_multiplier;
    const mul = std.math.pow(f64, pow, @as(f64, @floatFromInt(retry_num))); // pow^retry_num

    // Check for overflow before multiplying
    if (min > 0 and mul > @as(f64, @floatFromInt(max)) / @as(f64, @floatFromInt(min))) {
        return max;
    }

    const delay = @as(f64, @floatFromInt(min)) * mul;
    return @intFromFloat(@min(delay, @as(f64, @floatFromInt(max))));
}

//
// Tests
//

test "calculateBackoffDelay" {
    const TestCase = struct {
        retry: u64,
        value: u64,
    };

    const tests = [_]struct {
        min: u64,
        max: u64,
        mul: f64,
        expect: []const TestCase,
    }{
        .{
            .min = 1,
            .max = 60,
            .mul = 2,
            .expect = &[_]TestCase{
                .{ .retry = 0, .value = 1 },
                .{ .retry = 1, .value = 2 },
                .{ .retry = 2, .value = 4 },
                .{ .retry = 3, .value = 8 },
                .{ .retry = 4, .value = 16 },
                .{ .retry = 5, .value = 32 },
                .{ .retry = 6, .value = 60 },
                .{ .retry = 7, .value = 60 },
            },
        },
        .{
            .min = 100,
            .max = 1000,
            .mul = 3,
            .expect = &[_]TestCase{
                .{ .retry = 0, .value = 100 },
                .{ .retry = 1, .value = 300 },
                .{ .retry = 2, .value = 900 },
                .{ .retry = 3, .value = 1000 },
            },
        },
        .{
            .min = 500,
            .max = 5000,
            .mul = 1,
            .expect = &[_]TestCase{
                .{ .retry = 0, .value = 500 },
                .{ .retry = 1, .value = 500 },
                .{ .retry = 5, .value = 500 },
                .{ .retry = 10, .value = 500 },
            },
        },
    };

    inline for (tests) |t| {
        var as_list = [_]u32{65001};
        var cfg = Config.ConfigFields{ .fetch = .{
            .as = &as_list,
            .retry_min_delay_ms = t.min,
            .retry_max_delay_ms = t.max,
            .retry_multiplier = t.mul,
        } };

        var sema = Semaphore{};
        var fetcher = Self{
            .alloc = std.testing.allocator,
            .cfg = &cfg,
            .sema = &sema,
        };

        inline for (t.expect) |e| {
            try std.testing.expectEqual(e.value, fetcher.calculateBackoffDelay(e.retry));
        }
    }
}

fn runTestServer(listener: *std.net.Server, init_sema: *std.Thread.Semaphore, deinit_sema: *std.atomic.Value(bool), response: []const u8) void {
    init_sema.post();

    defer listener.deinit();

    while (!deinit_sema.load(.acquire)) {
        const connection = listener.accept() catch |e| {
            if (e == error.Unexpected) {
                return;
            }

            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        defer connection.stream.close();

        var reader_buf: [32767]u8 = undefined;
        var writer_buf: [32767]u8 = undefined;

        var reader = connection.stream.reader(&reader_buf);
        var writer = connection.stream.writer(&writer_buf);
        var http_server = std.http.Server.init(reader.interface(), &writer.interface);

        var req = http_server.receiveHead() catch continue;

        if (req.head.method == .GET) {
            const headers = &.{std.http.Header{ .name = "Content-Type", .value = "application/json" }};
            req.respond(response, .{ .extra_headers = headers }) catch continue;
        } else {
            req.respond("", .{ .status = .method_not_allowed }) catch continue;
        }

        return;
    }
}

// Creates a mock HTTP server, mimicking the ipverse JSON format,
// fetches the prefixes once (with max_prefix_len summarization option)
// and checks if the prefixes has been received and summarized correctly.
test "smoke test" {
    const allocator = std.testing.allocator;

    const mock_response =
        \\{
        \\  "prefixes": {
        \\    "ipv4": [
        \\      "10.0.0.0/24",
        \\      "10.0.1.0/24",
        \\      "10.0.0.192/30",
        \\      "192.168.0.0/16",
        \\      "172.16.0.0/12",
        \\      "192.2.0.2/31"
        \\    ],
        \\    "ipv6": [
        \\      "2001:db8::/32",
        \\      "2001:db8:1::/48",
        \\      "2001:db8:2::/48",
        \\      "2a02::4/126"
        \\    ]
        \\  }
        \\}
    ;

    const address = try std.net.Address.resolveIp("127.0.0.1", 0);
    var listener = try address.listen(.{ .reuse_address = true });

    var init_sema = std.Thread.Semaphore{};
    var deinit_sema = std.atomic.Value(bool).init(false);
    const server_thread = try std.Thread.spawn(.{}, runTestServer, .{ &listener, &init_sema, &deinit_sema, mock_response });

    // Wait until the server is ready
    init_sema.wait();

    const base_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{listener.listen_address.in.getPort()});
    defer allocator.free(base_url);

    var as_list = [_]u32{65001};
    var cfg = Config.ConfigFields{
        .fetch = .{ .as = &as_list },
        .summarization = .{ .ipv4_max_prefix_len = 26, .ipv6_max_prefix_len = 120 },
    };
    var sema = Semaphore{};

    var differ = Differ.init(allocator);
    defer differ.deinit();

    var ready = std.atomic.Value(bool).init(false);
    var fetcher = Self.init(allocator, &cfg, &sema, &differ, &ready);
    fetcher.base_url = base_url;

    try fetcher.fetch();

    // Stop the server after a successful fetch
    deinit_sema.store(true, .release);
    server_thread.join();

    var latest = try differ.getLatest(allocator);
    defer latest.deinit();

    var iterv4 = latest.v4.collectIter();
    var iterv6 = latest.v6.collectIter();

    try std.testing.expectEqual(latest.gen, 1); // Latest gen should be set to 1
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/23"), iterv4.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("172.16.0.0/12"), iterv4.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.2.0.0/26"), iterv4.next()); // ipv4_max_prefix_len
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), iterv4.next());
    try std.testing.expect(iterv4.next() == null);

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iterv6.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2a02::/120"), iterv6.next()); // ipv6_max_prefix_len
    try std.testing.expect(iterv6.next() == null);
}
