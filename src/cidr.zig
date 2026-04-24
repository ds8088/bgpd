//! cidr defines types and operations for handling IPv4/IPv6 prefixes.

const std = @import("std");

const err_invalid_address_family = "invalid IP family: must be either u32 (IPv4) or u128 (IPv6)";

/// CIDR represents an IP address combined with a network mask, as in CIDR notation.
///
/// Both IPv4 and IPv6 addresses are supported.
pub fn CIDR(comptime T: type) type {
    const highest_prefix_length: u8 = switch (T) {
        u32, u128 => @typeInfo(T).int.bits,
        else => @compileError(err_invalid_address_family),
    };

    return struct {
        addr: T,
        prefix_len: u8,

        const Self = @This();

        /// fromString builds a CIDR from its string representation.
        ///
        /// If the prefix length is missing, the highest prefix length is assumed (32 for IPv4, 128 for IPv6).
        pub fn fromString(s: []const u8) !Self {
            var result = Self{ .addr = 0, .prefix_len = highest_prefix_length };
            var ip_part = s;

            // Parse the prefix length, if it exists.
            if (std.mem.lastIndexOfScalar(u8, s, '/')) |pos| {
                result.prefix_len = std.fmt.parseUnsigned(u8, s[pos + 1 ..], 10) catch return error.InvalidPrefixLength;
                if (result.prefix_len > highest_prefix_length) {
                    return error.InvalidPrefixLength;
                }

                ip_part = s[0..pos];
            }

            switch (T) {
                u32 => {
                    const ip4 = std.net.Address.parseIp4(ip_part, 0) catch return error.InvalidAddress;
                    result.addr = std.mem.bigToNative(u32, ip4.in.sa.addr);
                },
                u128 => {
                    const ip6 = std.net.Address.parseIp6(ip_part, 0) catch return error.InvalidAddress;
                    result.addr = std.mem.readInt(u128, &ip6.in6.sa.addr, .big);
                },
                else => unreachable,
            }

            return result;
        }

        /// toArray returns the CIDR IP address as an array in a big-endian format.
        pub fn toArray(self: *const Self) [@sizeOf(T)]u8 {
            const val = std.mem.nativeToBig(T, self.addr);
            return std.mem.toBytes(val);
        }

        /// format writes the CIDR in its default format.
        pub fn format(self: *const Self, writer: *std.io.Writer) !void {
            const bytes = self.toArray();

            switch (T) {
                u32 => {
                    try writer.print("{}.{}.{}.{}/{}", .{
                        bytes[0], bytes[1], bytes[2], bytes[3], self.prefix_len,
                    });
                },
                u128 => {
                    var cur_len: usize = 0;
                    var cur_start: usize = 0;
                    var best_len: usize = 0;
                    var best_start: usize = 0;

                    // Determine the longest run of consecutive zero 16-bit groups.
                    for (0..8) |i| {
                        if (bytes[i * 2] == 0 and bytes[i * 2 + 1] == 0) {
                            if (cur_len == 0) {
                                cur_start = i;
                            }

                            cur_len += 1;
                        } else {
                            if (cur_len > best_len and cur_len >= 2) {
                                best_start = cur_start;
                                best_len = cur_len;
                            }

                            cur_len = 0;
                        }
                    }

                    if (cur_len > best_len and cur_len >= 2) {
                        best_start = cur_start;
                        best_len = cur_len;
                    }

                    // Write out the octets.
                    for (0..8) |i| {
                        // Is the current octet in the best zero group?
                        if (best_len > 0 and i >= best_start and i < best_start + best_len) {
                            if (i == best_start) {
                                // If it's the start of zero group, write out the two-colon marker.
                                try writer.writeAll("::");
                            }

                            continue;
                        }

                        if (i > 0 and i != best_start + best_len) {
                            try writer.writeByte(':');
                        }

                        try writer.print("{x}", .{(@as(u16, bytes[i * 2]) << 8) | bytes[i * 2 + 1]});
                    }

                    try writer.print("/{}", .{self.prefix_len});
                },
                else => unreachable,
            }
        }

        /// mask returns the CIDR's bitmask.
        pub fn mask(self: *const Self) T {
            if (self.prefix_len == 0) {
                return 0;
            }

            return (~@as(T, 0)) << @intCast(highest_prefix_length - self.prefix_len);
        }

        /// network returns the IP address with host bits zeroed.
        pub fn network(self: *const Self) T {
            return self.addr & self.mask();
        }

        /// asNetwork works the same as network, but returns a clone of this CIDR
        /// with IP address having its host bits zeroed.
        pub fn asNetwork(self: *const Self) Self {
            return Self{ .addr = self.network(), .prefix_len = self.prefix_len };
        }

        /// hostCount returns the number of addresses in the CIDR block.
        ///
        /// Note: for a /0 block the host count (2^32 or 2^128) overflows T,
        /// so std.math.maxInt(T) is returned instead.
        pub fn hostCount(self: *const Self) T {
            if (self.prefix_len == 0) {
                return std.math.maxInt(T);
            }

            return @as(T, 1) << @intCast(highest_prefix_length - self.prefix_len);
        }

        /// lessThan compares two CIDRs by their address.
        ///
        /// If the addresses are the same, the CIDRs are compared by their prefix lengths instead.
        pub fn lessThan(self: *const Self, other: *const Self) bool {
            if (self.addr != other.addr) {
                return self.addr < other.addr;
            }

            return self.prefix_len < other.prefix_len;
        }

        /// fullyContains checks if one CIDR (other) is fully encompassed by another one (self).
        pub fn fullyContains(self: *const Self, other: *const Self) bool {
            if (self.prefix_len > other.prefix_len) {
                return false;
            }

            return (other.addr & self.mask()) == self.network();
        }

        /// overlaps returns true if self and other share at least one address.
        pub fn overlaps(self: *const Self, other: *const Self) bool {
            return self.fullyContains(other) or other.fullyContains(self);
        }

        /// overlapsBogon checks if CIDR overlaps a known bogon address.
        pub fn overlapsBogon(self: *const Self) bool {
            const bogons = comptime blk: {
                const strs = blk2: {
                    switch (T) {
                        u32 => {
                            break :blk2 [_][]const u8{
                                "0.0.0.0/8", // "This" network (RFC 1122)
                                "10.0.0.0/8", // Private (RFC 1918)
                                "100.64.0.0/10", // Shared address space (RFC 6598)
                                "127.0.0.0/8", // Loopback (RFC 1122)
                                "169.254.0.0/16", // Link-local (RFC 3927)
                                "172.16.0.0/12", // Private (RFC 1918)
                                "192.0.0.0/24", // IETF Protocol Assignments (RFC 6890)
                                "192.0.2.0/24", // TEST-NET-1 (RFC 5737)
                                "192.88.99.0/24", // 6to4 relay anycast (RFC 7526)
                                "192.168.0.0/16", // Private (RFC 1918)
                                "198.18.0.0/15", // Benchmarking (RFC 2544)
                                "198.51.100.0/24", // TEST-NET-2 (RFC 5737)
                                "203.0.113.0/24", // TEST-NET-3 (RFC 5737)
                                "224.0.0.0/4", // Multicast (RFC 5771)
                                "240.0.0.0/4", // Reserved (RFC 1112)
                                "255.255.255.255/32", // Limited broadcast
                            };
                        },
                        u128 => {
                            break :blk2 [_][]const u8{
                                "::/128", // Unspecified (RFC 4291)
                                "::1/128", // Loopback (RFC 4291)
                                "::ffff:0:0/96", // IPv4-mapped (RFC 4291)
                                "64:ff9b::/96", // IPv4/IPv6 translation (RFC 6052)
                                "100::/64", // Discard (RFC 6666)
                                "2001::/23", // IETF protocol assignments (RFC 2928)
                                "2001:db8::/32", // Documentation (RFC 3849)
                                "2002::/16", // 6to4 (RFC 3056)
                                "3ffe::/16", // 6bone, deprecated (RFC 3701)
                                "fc00::/7", // Unique local (RFC 4193)
                                "fe80::/10", // Link-local (RFC 4291)
                                "ff00::/8", // Multicast (RFC 4291)
                            };
                        },
                        else => unreachable,
                    }
                };

                @setEvalBranchQuota(5000);
                var arr: [strs.len]Self = undefined;
                for (strs, 0..) |s, i| {
                    arr[i] = Self.fromString(s) catch unreachable;
                }

                break :blk arr;
            };

            for (&bogons) |*b| if (self.overlaps(b)) return true;
            return false;
        }
    };
}

/// CIDRv4 is a CIDR implementation for IPv4 addresses.
pub const CIDRv4 = CIDR(u32);

/// CIDRv6 is a CIDR implementation for IPv6 addresses.
pub const CIDRv6 = CIDR(u128);

/// comptimeCIDRv4 parses a CIDRv4 at compile time, emitting a compile error if
/// the string is not a valid IPv4 CIDR.
pub fn comptimeCIDRv4(comptime s: []const u8) CIDRv4 {
    return comptime CIDRv4.fromString(s) catch @compileError("invalid CIDRv4 string representation");
}

/// comptimeCIDRv6 parses a CIDRv6 at compile time, emitting a compile error if
/// the string is not a valid IPv6 CIDR.
pub fn comptimeCIDRv6(comptime s: []const u8) CIDRv6 {
    return comptime CIDRv6.fromString(s) catch @compileError("invalid CIDRv6 string representation");
}

//
// Tests
//

test "fromString" {
    const tests = [_]struct { t: type = u32, s: []const u8, expect: union(enum) {
        err: anyerror,
        addrv4: struct { prefix_len: u8, arr: [4]u8 },
        addrv6: struct { prefix_len: u8, arr: [16]u8 },
    } }{
        .{ .s = "127.0.0.1", .expect = .{ .addrv4 = .{ .prefix_len = 32, .arr = .{ 127, 0, 0, 1 } } } },
        .{ .s = "0.0.0.0", .expect = .{ .addrv4 = .{ .prefix_len = 32, .arr = .{ 0, 0, 0, 0 } } } },
        .{ .s = "255.255.255.255", .expect = .{ .addrv4 = .{ .prefix_len = 32, .arr = .{ 255, 255, 255, 255 } } } },
        .{ .s = "10.0.0.0/8", .expect = .{ .addrv4 = .{ .prefix_len = 8, .arr = .{ 10, 0, 0, 0 } } } },
        .{ .s = "192.168.1.0/24", .expect = .{ .addrv4 = .{ .prefix_len = 24, .arr = .{ 192, 168, 1, 0 } } } },
        .{ .s = "172.16.0.0/12", .expect = .{ .addrv4 = .{ .prefix_len = 12, .arr = .{ 172, 16, 0, 0 } } } },
        .{ .s = "1.2.3.4/32", .expect = .{ .addrv4 = .{ .prefix_len = 32, .arr = .{ 1, 2, 3, 4 } } } },
        .{ .s = "9.9.9.9/21", .expect = .{ .addrv4 = .{ .prefix_len = 21, .arr = .{ 9, 9, 9, 9 } } } },
        .{ .s = "0.0.0.0/0", .expect = .{ .addrv4 = .{ .prefix_len = 0, .arr = .{ 0, 0, 0, 0 } } } },
        .{ .t = u32, .s = "", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "test", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "1.2.3", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "1.2.3.4.5", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "256.0.0.1", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "192.168.x.1", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u32, .s = "10.0.0.0/abc", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u32, .s = "10.0.0.0/33", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u32, .s = "10.0.0.0/-1", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u32, .s = "10.0.0.0/", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u32, .s = "2001:123::/64", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u32, .s = "2001:124::", .expect = .{ .err = error.InvalidAddress } },

        .{ .s = "::1", .expect = .{ .addrv6 = .{ .prefix_len = 128, .arr = .{0} ** 15 ++ .{1} } } },
        .{ .s = "::1/128", .expect = .{ .addrv6 = .{ .prefix_len = 128, .arr = .{0} ** 15 ++ .{1} } } },
        .{ .s = "::/0", .expect = .{ .addrv6 = .{ .prefix_len = 0, .arr = .{0} ** 16 } } },
        .{ .s = "2001:db8::/32", .expect = .{ .addrv6 = .{ .prefix_len = 32, .arr = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 12 } } },
        .{ .s = "fe80::1/64", .expect = .{ .addrv6 = .{ .prefix_len = 64, .arr = .{ 0xfe, 0x80 } ++ .{0} ** 13 ++ .{1} } } },
        .{ .s = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", .expect = .{ .addrv6 = .{ .prefix_len = 128, .arr = .{0xff} ** 16 } } },
        .{ .t = u128, .s = "", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = ":", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = ":::", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = "test::", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = "::1/129", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u128, .s = "::1/test", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u128, .s = "1.1.1.1", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = "8.0.0.0/8", .expect = .{ .err = error.InvalidAddress } },
        .{ .t = u128, .s = "fe80::test/test", .expect = .{ .err = error.InvalidPrefixLength } },
        .{ .t = u128, .s = "::1/", .expect = .{ .err = error.InvalidPrefixLength } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .addrv4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                try std.testing.expectEqual(expected.prefix_len, addr.prefix_len);
                try std.testing.expectEqual(expected.arr, addr.toArray());
            },
            .addrv6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                try std.testing.expectEqual(expected.prefix_len, addr.prefix_len);
                try std.testing.expectEqual(expected.arr, addr.toArray());
            },
            .err => |expected_err| {
                try std.testing.expectError(expected_err, CIDR(t.t).fromString(t.s));
            },
        }
    }
}

test "mask" {
    const tests = [_]struct { s: []const u8, expect: union(enum) { maskv4: u32, maskv6: [16]u8 } }{
        .{ .s = "0.0.0.0/0", .expect = .{ .maskv4 = 0x00000000 } },
        .{ .s = "10.0.0.0/8", .expect = .{ .maskv4 = 0xFF000000 } },
        .{ .s = "172.16.0.0/12", .expect = .{ .maskv4 = 0xFFF00000 } },
        .{ .s = "192.168.0.0/16", .expect = .{ .maskv4 = 0xFFFF0000 } },
        .{ .s = "192.168.1.0/24", .expect = .{ .maskv4 = 0xFFFFFF00 } },
        .{ .s = "1.2.3.4/32", .expect = .{ .maskv4 = 0xFFFFFFFF } },
        .{ .s = "9.9.9.9", .expect = .{ .maskv4 = 0xFFFFFFFF } },

        .{ .s = "::/0", .expect = .{ .maskv6 = .{0} ** 16 } },
        .{ .s = "::1/128", .expect = .{ .maskv6 = .{0xff} ** 16 } },
        .{ .s = "2001:db8::/32", .expect = .{ .maskv6 = .{ 0xff, 0xff, 0xff, 0xff } ++ .{0} ** 12 } },
        .{ .s = "fe80::/10", .expect = .{ .maskv6 = .{ 0xff, 0xc0 } ++ .{0} ** 14 } },
        .{ .s = "ffff::/16", .expect = .{ .maskv6 = .{ 0xff, 0xff } ++ .{0} ** 14 } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .maskv4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                try std.testing.expectEqual(expected, addr.mask());
            },
            .maskv6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                const mask_bytes = std.mem.toBytes(std.mem.nativeToBig(u128, addr.mask()));
                try std.testing.expectEqual(expected, mask_bytes);
            },
        }
    }
}

test "network" {
    const tests = [_]struct { s: []const u8, expect: union(enum) { netv4: [4]u8, netv6: [16]u8 } }{
        .{ .s = "0.0.0.0/0", .expect = .{ .netv4 = .{ 0, 0, 0, 0 } } },
        .{ .s = "10.0.0.0/8", .expect = .{ .netv4 = .{ 10, 0, 0, 0 } } },
        .{ .s = "192.168.1.5/24", .expect = .{ .netv4 = .{ 192, 168, 1, 0 } } },
        .{ .s = "192.168.1.129/29", .expect = .{ .netv4 = .{ 192, 168, 1, 128 } } },
        .{ .s = "9.9.9.9/21", .expect = .{ .netv4 = .{ 9, 9, 8, 0 } } },
        .{ .s = "172.31.255.1/12", .expect = .{ .netv4 = .{ 172, 16, 0, 0 } } },
        .{ .s = "1.2.3.4/32", .expect = .{ .netv4 = .{ 1, 2, 3, 4 } } },

        .{ .s = "::/0", .expect = .{ .netv6 = .{0} ** 16 } },
        .{ .s = "fe80::1/10", .expect = .{ .netv6 = .{ 0xfe, 0x80 } ++ .{0} ** 14 } },
        .{ .s = "fe80::1/64", .expect = .{ .netv6 = .{ 0xfe, 0x80 } ++ .{0} ** 14 } },
        .{ .s = "2001:db8::1/32", .expect = .{ .netv6 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 12 } },
        .{ .s = "2001:db8::1:2:3/32", .expect = .{ .netv6 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 12 } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .netv4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                const net_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, addr.network()));
                try std.testing.expectEqual(expected, net_bytes);
            },
            .netv6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                const net_bytes = std.mem.toBytes(std.mem.nativeToBig(u128, addr.network()));
                try std.testing.expectEqual(expected, net_bytes);
            },
        }
    }
}

test "asNetwork" {
    const tests = [_]struct { s: []const u8, expect: union(enum) {
        netv4: struct { prefix_len: u8, arr: [4]u8 },
        netv6: struct { prefix_len: u8, arr: [16]u8 },
    } }{
        .{ .s = "10.0.0.0/8", .expect = .{ .netv4 = .{ .prefix_len = 8, .arr = .{ 10, 0, 0, 0 } } } },
        .{ .s = "1.2.3.4/32", .expect = .{ .netv4 = .{ .prefix_len = 32, .arr = .{ 1, 2, 3, 4 } } } },
        .{ .s = "0.0.0.0/0", .expect = .{ .netv4 = .{ .prefix_len = 0, .arr = .{ 0, 0, 0, 0 } } } },
        .{ .s = "192.168.1.5/24", .expect = .{ .netv4 = .{ .prefix_len = 24, .arr = .{ 192, 168, 1, 0 } } } },
        .{ .s = "9.9.9.9/21", .expect = .{ .netv4 = .{ .prefix_len = 21, .arr = .{ 9, 9, 8, 0 } } } },
        .{ .s = "172.31.255.1/12", .expect = .{ .netv4 = .{ .prefix_len = 12, .arr = .{ 172, 16, 0, 0 } } } },

        .{ .s = "::/0", .expect = .{ .netv6 = .{ .prefix_len = 0, .arr = .{0} ** 16 } } },
        .{ .s = "::1/128", .expect = .{ .netv6 = .{ .prefix_len = 128, .arr = .{0} ** 15 ++ .{1} } } },
        .{ .s = "2001:db8::/32", .expect = .{ .netv6 = .{ .prefix_len = 32, .arr = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 12 } } },
        .{ .s = "fe80::1/64", .expect = .{ .netv6 = .{ .prefix_len = 64, .arr = .{ 0xfe, 0x80 } ++ .{0} ** 14 } } },
        .{ .s = "2001:db8::1:2:3/32", .expect = .{ .netv6 = .{ .prefix_len = 32, .arr = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ .{0} ** 12 } } },
        .{ .s = "fe80::1/10", .expect = .{ .netv6 = .{ .prefix_len = 10, .arr = .{ 0xfe, 0x80 } ++ .{0} ** 14 } } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .netv4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                const net = addr.asNetwork();
                try std.testing.expectEqual(expected.prefix_len, net.prefix_len);
                try std.testing.expectEqual(expected.arr, net.toArray());
            },
            .netv6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                const net = addr.asNetwork();
                try std.testing.expectEqual(expected.prefix_len, net.prefix_len);
                try std.testing.expectEqual(expected.arr, net.toArray());
            },
        }
    }
}

test "fullyContains" {
    const tests = [_]struct { container: []const u8, inner: []const u8, expect: union(enum) { v4: bool, v6: bool } }{
        .{ .container = "10.0.0.0/8", .inner = "10.1.2.0/24", .expect = .{ .v4 = true } },
        .{ .container = "10.0.0.0/8", .inner = "10.0.0.0/8", .expect = .{ .v4 = true } },
        .{ .container = "192.168.0.0/16", .inner = "192.168.1.0/24", .expect = .{ .v4 = true } },
        .{ .container = "0.0.0.0/0", .inner = "1.2.3.4/32", .expect = .{ .v4 = true } },
        .{ .container = "10.0.0.0/24", .inner = "10.0.0.0/8", .expect = .{ .v4 = false } },
        .{ .container = "10.0.0.0/8", .inner = "11.0.0.0/24", .expect = .{ .v4 = false } },
        .{ .container = "192.168.1.0/24", .inner = "192.168.2.0/24", .expect = .{ .v4 = false } },
        .{ .container = "1.2.3.4/31", .inner = "1.2.3.4/32", .expect = .{ .v4 = true } },
        .{ .container = "1.2.3.4/31", .inner = "1.2.3.5/32", .expect = .{ .v4 = true } },
        .{ .container = "1.2.3.4/31", .inner = "1.2.3.6/32", .expect = .{ .v4 = false } },
        .{ .container = "1.2.3.4/32", .inner = "1.2.3.4/32", .expect = .{ .v4 = true } },
        .{ .container = "1.2.3.4/32", .inner = "1.2.3.5/32", .expect = .{ .v4 = false } },

        .{ .container = "fe80::/10", .inner = "fe80::1/128", .expect = .{ .v6 = true } },
        .{ .container = "fe80::/10", .inner = "fe80::1/64", .expect = .{ .v6 = true } },
        .{ .container = "2001:db8::/32", .inner = "2001:db8::1/128", .expect = .{ .v6 = true } },
        .{ .container = "::/0", .inner = "::1/128", .expect = .{ .v6 = true } },
        .{ .container = "::/0", .inner = "ffff::/16", .expect = .{ .v6 = true } },
        .{ .container = "::1/128", .inner = "::1/128", .expect = .{ .v6 = true } },
        .{ .container = "::1/128", .inner = "::2/128", .expect = .{ .v6 = false } },
        .{ .container = "2001:db8::/32", .inner = "2001:db9::/48", .expect = .{ .v6 = false } },
        .{ .container = "fe80::1/128", .inner = "fe80::/10", .expect = .{ .v6 = false } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .v4 => |expected| {
                const container = try CIDRv4.fromString(t.container);
                const inner = try CIDRv4.fromString(t.inner);
                try std.testing.expectEqual(expected, container.fullyContains(&inner));
            },
            .v6 => |expected| {
                const container = try CIDRv6.fromString(t.container);
                const inner = try CIDRv6.fromString(t.inner);
                try std.testing.expectEqual(expected, container.fullyContains(&inner));
            },
        }
    }
}

test "overlaps" {
    const tests = [_]struct { a: []const u8, b: []const u8, expect: union(enum) { v4: bool, v6: bool } }{
        .{ .a = "10.0.0.0/8", .b = "10.0.0.0/8", .expect = .{ .v4 = true } },
        .{ .a = "10.0.0.0/8", .b = "10.1.2.0/24", .expect = .{ .v4 = true } },
        .{ .a = "10.1.2.0/24", .b = "10.0.0.0/8", .expect = .{ .v4 = true } },
        .{ .a = "192.168.1.0/24", .b = "192.168.2.0/24", .expect = .{ .v4 = false } },
        .{ .a = "10.0.0.0/8", .b = "11.0.0.0/8", .expect = .{ .v4 = false } },
        .{ .a = "0.0.0.0/0", .b = "203.0.113.1/32", .expect = .{ .v4 = true } },
        .{ .a = "1.2.3.4/32", .b = "1.2.3.5/32", .expect = .{ .v4 = false } },
        .{ .a = "1.2.3.4/31", .b = "1.2.3.5/32", .expect = .{ .v4 = true } },

        .{ .a = "fe80::/10", .b = "fe80::1/128", .expect = .{ .v6 = true } },
        .{ .a = "fe80::1/128", .b = "fe80::/10", .expect = .{ .v6 = true } },
        .{ .a = "::/0", .b = "::1/128", .expect = .{ .v6 = true } },
        .{ .a = "2001:db8::/32", .b = "2001:db8::/48", .expect = .{ .v6 = true } },
        .{ .a = "::1/128", .b = "::1/128", .expect = .{ .v6 = true } },
        .{ .a = "::1/128", .b = "::2/128", .expect = .{ .v6 = false } },
        .{ .a = "fe80::/10", .b = "fc00::/7", .expect = .{ .v6 = false } },
        .{ .a = "2001:db8::/32", .b = "2001:db9::/32", .expect = .{ .v6 = false } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .v4 => |expected| {
                const a = try CIDRv4.fromString(t.a);
                const b = try CIDRv4.fromString(t.b);
                try std.testing.expectEqual(expected, a.overlaps(&b));
            },
            .v6 => |expected| {
                const a = try CIDRv6.fromString(t.a);
                const b = try CIDRv6.fromString(t.b);
                try std.testing.expectEqual(expected, a.overlaps(&b));
            },
        }
    }
}

test "overlapsBogon" {
    const tests = [_]struct { s: []const u8, expect: union(enum) { v4: bool, v6: bool } }{
        .{ .s = "0.0.0.1/32", .expect = .{ .v4 = true } },
        .{ .s = "192.0.2.1/32", .expect = .{ .v4 = true } },
        .{ .s = "1.1.1.1/32", .expect = .{ .v4 = false } },
        .{ .s = "8.8.8.8/32", .expect = .{ .v4 = false } },
        .{ .s = "9.9.9.9/32", .expect = .{ .v4 = false } },

        .{ .s = "::/128", .expect = .{ .v6 = true } },
        .{ .s = "::1/128", .expect = .{ .v6 = true } },
        .{ .s = "::2/128", .expect = .{ .v6 = false } },
        .{ .s = "100::1/128", .expect = .{ .v6 = true } },
        .{ .s = "2001:db8::1/128", .expect = .{ .v6 = true } },
        .{ .s = "2002:0102:0304::/48", .expect = .{ .v6 = true } },
        .{ .s = "2606::1/128", .expect = .{ .v6 = false } },
        .{ .s = "2a02::1/128", .expect = .{ .v6 = false } },
        .{ .s = "2001::ffff:ffff:1/128", .expect = .{ .v6 = true } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .v4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                try std.testing.expectEqual(expected, addr.overlapsBogon());
            },
            .v6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                try std.testing.expectEqual(expected, addr.overlapsBogon());
            },
        }
    }
}

test "lessThan" {
    const tests = [_]struct { a: []const u8, b: []const u8, expect: union(enum) { v4: bool, v6: bool } }{
        .{ .a = "10.0.0.0/8", .b = "11.0.0.0/8", .expect = .{ .v4 = true } },
        .{ .a = "10.0.0.0/8", .b = "10.0.0.0/16", .expect = .{ .v4 = true } },
        .{ .a = "10.0.0.0/16", .b = "10.0.0.0/8", .expect = .{ .v4 = false } },
        .{ .a = "10.0.0.0/8", .b = "10.0.0.0/8", .expect = .{ .v4 = false } },
        .{ .a = "11.0.0.0/8", .b = "10.0.0.0/8", .expect = .{ .v4 = false } },
        .{ .a = "1.2.3.4/32", .b = "1.2.3.5/32", .expect = .{ .v4 = true } },

        .{ .a = "::1", .b = "::2", .expect = .{ .v6 = true } },
        .{ .a = "::2", .b = "::1", .expect = .{ .v6 = false } },
        .{ .a = "::1", .b = "::1", .expect = .{ .v6 = false } },
        .{ .a = "::1/64", .b = "::1/128", .expect = .{ .v6 = true } },
        .{ .a = "::1/128", .b = "::1/64", .expect = .{ .v6 = false } },
        .{ .a = "2001:db8::/32", .b = "fe80::/10", .expect = .{ .v6 = true } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .v4 => |expected| {
                const a = try CIDRv4.fromString(t.a);
                const b = try CIDRv4.fromString(t.b);
                try std.testing.expectEqual(expected, a.lessThan(&b));
            },
            .v6 => |expected| {
                const a = try CIDRv6.fromString(t.a);
                const b = try CIDRv6.fromString(t.b);
                try std.testing.expectEqual(expected, a.lessThan(&b));
            },
        }
    }
}

test "format" {
    const tests = [_]struct { s: []const u8, ver: enum { v4, v6 } }{
        .{ .s = "0.0.0.0/0", .ver = .v4 },
        .{ .s = "10.0.0.0/8", .ver = .v4 },
        .{ .s = "192.168.1.0/24", .ver = .v4 },
        .{ .s = "1.2.3.4/32", .ver = .v4 },
        .{ .s = "255.255.255.255/32", .ver = .v4 },

        .{ .s = "::/0", .ver = .v6 },
        .{ .s = "::1/128", .ver = .v6 },
        .{ .s = "2001:db8::/32", .ver = .v6 },
        .{ .s = "fe80::1/64", .ver = .v6 },
        .{ .s = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", .ver = .v6 },
        .{ .s = "2001:db8::1:0:0:1/128", .ver = .v6 },
        .{ .s = "2001:db8::1:2:3:4/64", .ver = .v6 },
        .{ .s = "2001:db8:0:1:2:3:4:5/128", .ver = .v6 },
        .{ .s = "1:2:3:4:5:6:7:8/128", .ver = .v6 },
        .{ .s = "1::2:0:0:3:4/128", .ver = .v6 },
        .{ .s = "1:0:0:2::3/128", .ver = .v6 },
        .{ .s = "2001:db8:1:2:3:4::/128", .ver = .v6 },
        .{ .s = "::1:2:3:4:5:6/128", .ver = .v6 },
        .{ .s = "0:0:1::/128", .ver = .v6 },
    };

    inline for (tests) |t| {
        var buf: [64]u8 = undefined;
        switch (t.ver) {
            .v4 => {
                const addr = try CIDRv4.fromString(t.s);
                const actual = try std.fmt.bufPrint(&buf, "{f}", .{addr});
                try std.testing.expectEqualStrings(t.s, actual);
            },
            .v6 => {
                const addr = try CIDRv6.fromString(t.s);
                const actual = try std.fmt.bufPrint(&buf, "{f}", .{addr});
                try std.testing.expectEqualStrings(t.s, actual);
            },
        }
    }
}

test "hostCount" {
    const tests = [_]struct { s: []const u8, expect: union(enum) { v4: u32, v6: u128 } }{
        .{ .s = "0.0.0.0/0", .expect = .{ .v4 = std.math.maxInt(u32) } },
        .{ .s = "10.0.0.0/8", .expect = .{ .v4 = 1 << 24 } },
        .{ .s = "192.168.0.0/16", .expect = .{ .v4 = 1 << 16 } },
        .{ .s = "192.168.1.0/24", .expect = .{ .v4 = 256 } },
        .{ .s = "1.2.3.4/32", .expect = .{ .v4 = 1 } },
        .{ .s = "1.2.3.4/31", .expect = .{ .v4 = 2 } },

        .{ .s = "::/0", .expect = .{ .v6 = std.math.maxInt(u128) } },
        .{ .s = "::1/128", .expect = .{ .v6 = 1 } },
        .{ .s = "2001:db8::/32", .expect = .{ .v6 = @as(u128, 1) << 96 } },
        .{ .s = "fe80::/64", .expect = .{ .v6 = @as(u128, 1) << 64 } },
        .{ .s = "fe80::/10", .expect = .{ .v6 = @as(u128, 1) << 118 } },
    };

    inline for (tests) |t| {
        switch (t.expect) {
            .v4 => |expected| {
                const addr = try CIDRv4.fromString(t.s);
                try std.testing.expectEqual(expected, addr.hostCount());
            },
            .v6 => |expected| {
                const addr = try CIDRv6.fromString(t.s);
                try std.testing.expectEqual(expected, addr.hostCount());
            },
        }
    }
}
