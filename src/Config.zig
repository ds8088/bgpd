//! Config holds the parsed and validated bgpd configuration, loaded from a JSON file.

const std = @import("std");
const cidr = @import("cidr.zig");
const logger = @import("logger.zig").Scoped(.config);

/// ConfigFetchFields holds settings for the prefix-list fetcher.
pub const ConfigFetchFields = struct {
    as: []u32 = &[_]u32{},
    interval_sec: u64 = 14400,
    retry_min_delay_ms: u64 = 1000,
    retry_max_delay_ms: u64 = 60000,
    retry_multiplier: f64 = 2.0,
    retry_max_count: u64 = 10,

    /// validate checks that fetch fields are correct.
    pub fn validate(self: *const ConfigFetchFields) !void {
        if (self.as.len == 0) {
            logger.warn("fetcher: empty AS list", .{});
            return error.EmptyAsList;
        }

        if (self.interval_sec < 60) {
            logger.warn("fetcher: fetch interval is too small, should be at least 60 seconds", .{});
            return error.InvalidInterval;
        }

        if (self.retry_min_delay_ms > self.retry_max_delay_ms) {
            logger.warn("fetcher: min delay is greater than max delay", .{});
            return error.InvalidRetryDelay;
        }
    }
};

/// ConfigSummarizationFields controls how fetched prefixes are aggregated before
/// being announced over BGP.
pub const ConfigSummarizationFields = struct {
    // Prefixes longer than these are rounded up to this length.
    // Set to 0 to disable.
    ipv4_max_prefix_len: u8 = 0,
    ipv6_max_prefix_len: u8 = 0,

    /// validate checks that summarization fields are correct.
    pub fn validate(self: *const ConfigSummarizationFields) !void {
        if (self.ipv4_max_prefix_len > 32) {
            logger.warn("summarization: IPv4 max prefix length cannot be greater than 32", .{});
            return error.InvalidPrefixLength;
        }

        if (self.ipv6_max_prefix_len > 128) {
            logger.warn("summarization: IPv6 max prefix length cannot be greater than 128", .{});
            return error.InvalidPrefixLength;
        }
    }
};

/// ConfigBgpFields holds settings for the BGP server.
pub const ConfigBgpFields = struct {
    local_as: u32 = 0,
    router_id: []const u8 = "1.2.3.4",
    listen_addr: []const u8 = "0.0.0.0",
    listen_port: u16 = 179,
    hold_time_sec: u16 = 90,
    keepalive_sec: u16 = 30,
    write_timeout_sec: u16 = 5,

    announce_ipv4: bool = true,
    next_hop_ipv4: ?[]const u8 = null,
    announce_ipv6: bool = true,
    next_hop_ipv6: ?[]const u8 = null,

    /// validate checks that BGP fields are correct.
    pub fn validate(self: *const ConfigBgpFields) !void {
        if (@as(u32, self.hold_time_sec) < @as(u32, self.keepalive_sec) * 3) {
            logger.warn("bgp: hold time ({D}) cannot be lower than 3x keepalive ({D})", .{
                @as(u64, self.hold_time_sec) * std.time.ns_per_s,
                @as(u64, self.keepalive_sec) * std.time.ns_per_s,
            });
            return error.HoldTimeTooShort;
        }

        _ = cidr.CIDRv4.fromString(self.router_id) catch |err| {
            logger.warn("bgp: invalid router ID: {s}, error: {any}", .{ self.router_id, err });
            return error.InvalidRouterID;
        };

        if (self.next_hop_ipv4) |nh| {
            _ = cidr.CIDRv4.fromString(nh) catch |err| {
                logger.warn("bgp: invalid IPv4 next hop: {s}, error: {any}", .{ nh, err });
                return error.InvalidNexthopIPv4;
            };
        }

        if (self.next_hop_ipv6) |nh| {
            _ = cidr.CIDRv6.fromString(nh) catch |err| {
                logger.warn("bgp: invalid IPv6 next hop: {s}, error: {any}", .{ nh, err });
                return error.InvalidNexthopIPv6;
            };
        }
    }
};

/// ConfigFields is the top-level configuration structure that is deserialized
/// directly from JSON.
pub const ConfigFields = struct {
    debug: bool = false,

    bgp: ConfigBgpFields = .{},
    fetch: ConfigFetchFields = .{},
    summarization: ConfigSummarizationFields = .{},
};

fields: ConfigFields = .{},

const Self = @This();

/// load opens a JSON file and parses its contents to a Config structure.
///
/// Call deinit() when done.
pub fn load(alloc: std.mem.Allocator, path: []const u8) !std.json.Parsed(Self) {
    logger.info("loading from file: {s}", .{path});

    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();

    var read_buf: [4096]u8 = undefined;
    var reader = file.reader(&read_buf);

    var json_reader = std.json.Reader.init(alloc, &reader.interface);
    defer json_reader.deinit();

    const parsed_fields = try std.json.parseFromTokenSource(ConfigFields, alloc, &json_reader, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });

    errdefer parsed_fields.deinit();

    try parsed_fields.value.bgp.validate();
    try parsed_fields.value.fetch.validate();
    try parsed_fields.value.summarization.validate();

    // Manually construct the wrapper for our Config struct.
    return std.json.Parsed(Self){
        .arena = parsed_fields.arena,
        .value = Self{ .fields = parsed_fields.value },
    };
}

//
// Tests
//

// Helper function to create a temporary test file.
//
// Caller should free the resulting slice.
fn createTempConfigFile(alloc: std.mem.Allocator, dir: *std.testing.TmpDir, content: []const u8) ![]const u8 {
    const filename = "config_test.json";
    var file = try dir.dir.createFile(filename, .{ .exclusive = true });
    defer file.close();

    var write_buf: [4096]u8 = undefined;
    var writer = file.writer(&write_buf);

    try writer.interface.writeAll(content);
    try writer.interface.flush();

    return try dir.dir.realpathAlloc(alloc, filename);
}

test "smoke test" {
    const json_content =
        \\{
        \\  "fetch": {
        \\    "as": [65001, 65005]
        \\  },
        \\  "bgp": {
        \\    "local_as": 65002,
        \\    "router_id": "1.2.3.4",
        \\    "unknown_field": "ignore me"
        \\  }
        \\}
    ;

    var tmpdir = std.testing.tmpDir(.{});
    defer tmpdir.cleanup();

    const path = try createTempConfigFile(std.testing.allocator, &tmpdir, json_content);
    defer std.testing.allocator.free(path);

    const parsed = try load(std.testing.allocator, path);
    defer parsed.deinit();

    const fields = parsed.value.fields;

    try std.testing.expectEqual(@as(usize, 2), fields.fetch.as.len);
    try std.testing.expectEqual(@as(u32, 65001), fields.fetch.as[0]);
    try std.testing.expectEqual(@as(u32, 65005), fields.fetch.as[1]);
    try std.testing.expectEqual(@as(u32, 65002), fields.bgp.local_as);
    try std.testing.expectEqualStrings("1.2.3.4", fields.bgp.router_id);

    // Check that default values have been set too
    try std.testing.expectEqual(@as(u16, 179), fields.bgp.listen_port);
}

test "invalid config" {
    const tests = [_]struct {
        cfg: []const u8,
        expected_err: anyerror,
    }{
        .{
            // Empty AS
            .cfg =
            \\{
            \\  "fetch": {
            \\    "as": []
            \\  }
            \\}
            ,
            .expected_err = error.EmptyAsList,
        },
        .{
            // Invalid JSON
            .cfg =
            \\{
            \\  "summarization": {
            \\    "non-terminated key
            \\  }
            \\}
            ,
            .expected_err = error.SyntaxError,
        },
        .{
            // Invalid router ID
            .cfg =
            \\{
            \\  "fetch": {
            \\    "as": [10000]
            \\  },
            \\  "bgp": { "router_id": "1.2.3" }
            \\}
            ,
            .expected_err = error.InvalidRouterID,
        },
        .{
            // Bad hold time
            .cfg =
            \\{
            \\  "fetch": { "as": [65001] },
            \\  "bgp": { "hold_time_sec": 60, "keepalive_sec": 30 }
            \\}
            ,
            .expected_err = error.HoldTimeTooShort,
        },
        .{
            // fetch interval below the 60-second minimum
            .cfg =
            \\{
            \\  "fetch": { "as": [65001], "interval_sec": 10 }
            \\}
            ,
            .expected_err = error.InvalidInterval,
        },
        .{
            // retry_min_delay_ms > retry_max_delay_ms
            .cfg =
            \\{
            \\  "fetch": { "as": [65001], "retry_min_delay_ms": 5000, "retry_max_delay_ms": 1000 }
            \\}
            ,
            .expected_err = error.InvalidRetryDelay,
        },
        .{
            // IPv4 max prefix length out of range
            .cfg =
            \\{
            \\  "fetch": { "as": [65001] },
            \\  "summarization": { "ipv4_max_prefix_len": 33 }
            \\}
            ,
            .expected_err = error.InvalidPrefixLength,
        },
        .{
            // IPv6 max prefix length out of range
            .cfg =
            \\{
            \\  "fetch": { "as": [65001] },
            \\  "summarization": { "ipv6_max_prefix_len": 129 }
            \\}
            ,
            .expected_err = error.InvalidPrefixLength,
        },
        .{
            // Invalid IPv4 next hop
            .cfg =
            \\{
            \\  "fetch": { "as": [65001] },
            \\  "bgp": { "next_hop_ipv4": "214124" }
            \\}
            ,
            .expected_err = error.InvalidNexthopIPv4,
        },
        .{
            // Invalid IPv6 next hop
            .cfg =
            \\{
            \\  "fetch": { "as": [65001] },
            \\  "bgp": { "next_hop_ipv6": "a1" }
            \\}
            ,
            .expected_err = error.InvalidNexthopIPv6,
        },
    };

    inline for (tests) |t| {
        var tmpdir = std.testing.tmpDir(.{});
        defer tmpdir.cleanup();

        const path = try createTempConfigFile(std.testing.allocator, &tmpdir, t.cfg);
        defer std.testing.allocator.free(path);

        try std.testing.expectError(t.expected_err, load(std.testing.allocator, path));
    }
}
