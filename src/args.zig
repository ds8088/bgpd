const builtin = @import("builtin");
const std = @import("std");
const logger = @import("logger.zig").Scoped(.args);

pub const Args = struct {
    debug: bool = false,
    config_path: []const u8 = "config.json",
};

pub const ParseError = error{ HelpRequested, MissingArgument, UnknownFlag };

/// parseArgs collects known args from an iterator and builds the Args structure.
pub fn parseArgs(arg_iter: anytype) ParseError!Args {
    var args = Args{};

    _ = arg_iter.next(); // Skip argv[0].
    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--debug")) {
            args.debug = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            args.config_path = arg_iter.next() orelse {
                logger.err("{s}: missing config path", .{arg});
                printUsage();
                return error.MissingArgument;
            };
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return error.HelpRequested;
        } else {
            logger.err("{s}: unknown flag", .{arg});
            printUsage();
            return error.UnknownFlag;
        }
    }

    return args;
}

fn printUsage() void {
    if (!builtin.is_test) {
        std.debug.print("usage: bgpd [-d|--debug] [-c|--config <config path>] [-h|--help]\n", .{});
    }
}

test "parseArgs" {
    const tests = [_]struct {
        input: []const u8,
        expected: union(enum) { args: Args, err: ParseError },
    }{
        .{
            .input = "bgpd",
            .expected = .{ .args = .{} },
        },
        .{
            .input = "bgpd -d",
            .expected = .{ .args = .{ .debug = true } },
        },
        .{
            .input = "bgpd --debug",
            .expected = .{ .args = .{ .debug = true } },
        },
        .{
            .input = "bgpd -c file.json",
            .expected = .{ .args = .{ .config_path = "file.json" } },
        },
        .{
            .input = "bgpd --config /etc/bgpd/config.json",
            .expected = .{ .args = .{ .config_path = "/etc/bgpd/config.json" } },
        },
        .{
            .input = "bgpd -d -c custom.json",
            .expected = .{ .args = .{ .debug = true, .config_path = "custom.json" } },
        },
        .{
            .input = "bgpd -h",
            .expected = .{ .err = error.HelpRequested },
        },
        .{
            .input = "bgpd --help",
            .expected = .{ .err = error.HelpRequested },
        },
        .{
            .input = "bgpd -c",
            .expected = .{ .err = error.MissingArgument },
        },
        .{
            .input = "bgpd --flag",
            .expected = .{ .err = error.UnknownFlag },
        },
        .{
            .input = "bgpd -c config.json --flag2",
            .expected = .{ .err = error.UnknownFlag },
        },
    };

    for (tests) |t| {
        var iter = std.mem.splitScalar(u8, t.input, ' ');
        const result = parseArgs(&iter);
        switch (t.expected) {
            .args => |expected| {
                const args = try result;
                try std.testing.expectEqual(expected.debug, args.debug);
                try std.testing.expectEqualStrings(expected.config_path, args.config_path);
            },
            .err => |expected| {
                try std.testing.expectError(expected, result);
            },
        }
    }
}
