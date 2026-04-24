//! BGP message encoding and decoding.

const std = @import("std");
const Config = @import("Config.zig");
const trie = @import("trie.zig");
const cidr = @import("cidr.zig");

pub const MARKER_LEN = 16;
pub const HEADER_LEN = 19;
pub const MAX_MSG_LEN = 4096;
pub const MAX_BODY_LEN = MAX_MSG_LEN - HEADER_LEN;

pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;
pub const SAFI_UNICAST: u8 = 1;

// Path attribute type codes
const PA_ORIGIN: u8 = 1;
const PA_AS_PATH: u8 = 2;
const PA_NEXT_HOP: u8 = 3;
const PA_LOCAL_PREF: u8 = 5;
const PA_MP_REACH_NLRI: u8 = 14;
const PA_MP_UNREACH_NLRI: u8 = 15;

// Path attribute flag bits
const PA_TRANSITIVE: u8 = 0x40;
const PA_OPTIONAL: u8 = 0x80;
const PA_EXT_LEN: u8 = 0x10;

// AS_PATH segment type
const AS_SEQUENCE: u8 = 2;

/// MessageType enumerates the BGP message types.
pub const MessageType = enum(u8) {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEP_ALIVE = 4,
    ROUTE_REFRESH = 5,
    _,
};

/// NotificationErrorCode enumerates the BGP NOTIFICATION error codes.
pub const NotificationErrorCode = enum(u8) {
    MESSAGE_HEADER_ERROR = 1,
    OPEN_MESSAGE_ERROR = 2,
    UPDATE_MESSAGE_ERROR = 3,
    HOLD_TIMER_EXPIRED = 4,
    FSM_ERROR = 5,
    CEASE = 6,
    _,
};

/// prefixSizeInBytes returns the number of bytes needed to encode a prefix with the variable encoding.
fn prefixSizeInBytes(prefix_len: u8) usize {
    return (@as(usize, prefix_len) + 7) / 8;
}

/// Begins a BGP message by writing a header with its length set to 0 (as a placeholder).
fn startMessage(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), msg_type: MessageType) !void {
    buf.clearRetainingCapacity();
    try buf.appendNTimes(alloc, 0xFF, MARKER_LEN);
    try buf.appendSlice(alloc, &[_]u8{ 0, 0 });
    try buf.append(alloc, @intFromEnum(msg_type));
}

/// finalizeMessage patches the length field in a BGP message and returns an owned slice.
///
/// The caller should free the slice.
fn finalizeMessage(alloc: std.mem.Allocator, buf: *std.ArrayList(u8)) ![]u8 {
    std.mem.writeInt(u16, buf.items[MARKER_LEN..][0..2], @intCast(buf.items.len), .big);
    return try buf.toOwnedSlice(alloc);
}

/// Builds a KEEP_ALIVE message.
pub fn buildKeepalive(alloc: std.mem.Allocator, buf: *std.ArrayList(u8)) ![]u8 {
    try startMessage(alloc, buf, .KEEP_ALIVE);
    return finalizeMessage(alloc, buf);
}

/// Builds a NOTIFICATION message.
pub fn buildNotification(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), code: NotificationErrorCode, subcode: u8, data: []const u8) ![]u8 {
    try startMessage(alloc, buf, .NOTIFICATION);
    try buf.append(alloc, @intFromEnum(code));
    try buf.append(alloc, subcode);
    try buf.appendSlice(alloc, data);
    return finalizeMessage(alloc, buf);
}

/// Builds an OPEN message.
pub fn buildOpen(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), local_as: u32, hold_time: u16, router_id: [4]u8) ![]u8 {
    try startMessage(alloc, buf, .OPEN);

    // BGP version: 4
    try buf.append(alloc, 4);

    // AS_TRANS is used if local AS number cannot fit into an u16.
    const local_as_u16: u16 = if (local_as > std.math.maxInt(u16)) 23456 else @intCast(local_as);
    try buf.appendSlice(alloc, &[_]u8{
        @intCast(local_as_u16 >> 8),
        @intCast(local_as_u16 & 0xFF),
    });

    try buf.appendSlice(alloc, &[_]u8{
        @intCast(hold_time >> 8),
        @intCast(hold_time & 0xFF),
    });

    try buf.appendSlice(alloc, &router_id);

    // Optional parameters.
    // Save the current position first, in order to patch the length later
    const opt_pos = buf.items.len;
    try buf.append(alloc, 0); // Use 0 as a length placeholder

    // Append 4-octet AS number capability
    try buf.appendSlice(alloc, &[_]u8{
        2,                                 6,
        65,                                4,
        @intCast((local_as >> 24) & 0xFF), @intCast((local_as >> 16) & 0xFF),
        @intCast((local_as >> 8) & 0xFF),  @intCast(local_as & 0xFF),
    });

    // Append multiprotocol extensions capabilities
    try buf.appendSlice(alloc, &[_]u8{
        2, 6,
        1, 4,
        0, AFI_IPV4,
        0, SAFI_UNICAST,
    });
    try buf.appendSlice(alloc, &[_]u8{
        2, 6,
        1, 4,
        0, AFI_IPV6,
        0, SAFI_UNICAST,
    });

    // Patch the length
    std.mem.writeInt(u8, buf.items[opt_pos..][0..1], 24, .big);

    return finalizeMessage(alloc, buf);
}

/// UpdateIterator yields serialized BGP UPDATE messages, sourced from four tries.
///
/// Prefixes are evaluated and messages are produced in this order:
///   1. Withdrawn IPv4: 1st BGP section (withdrawn routes);
///   2. Withdrawn IPv6: MP_UNREACH_NLRI path attributes;
///   3. IPv4 NLRIs: 3rd BGP section with system attributes;
///   4. IPv6 NLRIs: MP_REACH_NLRI path attribute with system attributes.
///
/// The iterator transparently handles chunking:
/// if a prefix set does not fit in a single 4096-byte BGP message,
/// it is split to multiple messages.
///
/// The caller owns each slice returned by next() and must free it with the same
/// allocator that was passed to buildUpdate().
///
/// Call deinit() when done.
pub const UpdateIterator = struct {
    alloc: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    config: *const Config.ConfigBgpFields,

    wd4_iter: trie.Trie(u32).Iterator,
    wd6_iter: trie.Trie(u128).Iterator,
    nlri4_iter: trie.Trie(u32).Iterator,
    nlri6_iter: trie.Trie(u128).Iterator,

    // A prefix that was fetched but did not fit in the previous message.
    // It becomes the first prefix in the next message of the same type.
    pending_wd4: ?cidr.CIDRv4 = null,
    pending_wd6: ?cidr.CIDRv6 = null,
    pending_nlri4: ?cidr.CIDRv4 = null,
    pending_nlri6: ?cidr.CIDRv6 = null,

    next_hop_v4: [4]u8 = cidr.comptimeCIDRv4("127.0.0.1").toArray(),
    next_hop_v6: [16]u8 = cidr.comptimeCIDRv6("::1").toArray(),

    phase: enum { wd4, wd6, nlri4, nlri6, done } = .wd4,

    const Self = @This();

    /// deinit frees resources held by the iterator.
    pub fn deinit(self: *Self) void {
        self.buf.deinit(self.alloc);
    }

    /// Returns the next UPDATE message, or null when all prefixes have been sent out.
    ///
    /// The caller is responsible for freeing the returned slice.
    pub fn next(self: *Self) !?[]u8 {
        while (self.phase != .done) {
            const result = switch (self.phase) {
                .wd4 => try self.nextWd4(),
                .wd6 => try self.nextWd6(),
                .nlri4 => try self.nextNlri4(),
                .nlri6 => try self.nextNlri6(),
                else => unreachable,
            };

            if (result) |msg| {
                return msg;
            }

            // Advance to the next phase.
            self.phase = switch (self.phase) {
                .wd4 => .wd6,
                .wd6 => .nlri4,
                .nlri4 => .nlri6,
                .nlri6 => .done,
                .done => unreachable,
            };
        }

        return null;
    }

    /// nextWd4 builds a single UPDATE message containing IPv4 withdrawn routes.
    fn nextWd4(self: *Self) !?[]u8 {
        var cur = self.pending_wd4 orelse self.wd4_iter.next() orelse return null;
        self.pending_wd4 = null;

        try startMessage(self.alloc, &self.buf, .UPDATE);

        // Save the current buffer position: it will be patched later.
        const saved_pos = self.buf.items.len;
        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Withdrawn length (2 bytes)

        var bytes_written: u16 = 0;
        while (true) {
            const addr_len = prefixSizeInBytes(cur.prefix_len);

            // Can we still fit that prefix to the buffer?
            // 1 byte for its length, addr_len for the prefix bytes,
            // and also 2 bytes for Total Path Attribute Length field.
            if (self.buf.items.len + 1 + addr_len + 2 > MAX_MSG_LEN) {
                self.pending_wd4 = cur; // If not - save the pending prefix and bail.
                break;
            }

            try self.buf.append(self.alloc, cur.prefix_len);
            try self.buf.appendSlice(self.alloc, cur.toArray()[0..addr_len]);

            bytes_written += @intCast(1 + addr_len);
            cur = self.wd4_iter.next() orelse break;
        }

        std.mem.writeInt(u16, self.buf.items[saved_pos..][0..2], bytes_written, .big);

        // Write the Total Path Attribute Length field.
        try self.buf.appendSlice(self.alloc, &.{ 0, 0 });

        return try finalizeMessage(self.alloc, &self.buf);
    }

    /// nextWd6 builds a single UPDATE message containing IPv6 withdrawn routes.
    ///
    /// Uses the MP_UNREACH_NLRI attribute.
    fn nextWd6(self: *Self) !?[]u8 {
        var cur = self.pending_wd6 orelse self.wd6_iter.next() orelse return null;
        self.pending_wd6 = null;

        try startMessage(self.alloc, &self.buf, .UPDATE);

        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // no IPv4 withdrawals

        const saved_pos = self.buf.items.len;
        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Total Path Attribute Length

        // MP_UNREACH_NLRI attribute header (optional, extended-length).
        try self.buf.appendSlice(self.alloc, &.{
            PA_OPTIONAL | PA_EXT_LEN, PA_MP_UNREACH_NLRI,
            0, 0, // extended attribute length, patched later
            0, AFI_IPV6, SAFI_UNICAST, // AFI=2, SAFI=1
        });

        while (true) {
            const addr_len = prefixSizeInBytes(cur.prefix_len);
            if (self.buf.items.len + 1 + addr_len > MAX_MSG_LEN) {
                self.pending_wd6 = cur;
                break;
            }

            try self.buf.append(self.alloc, cur.prefix_len);
            try self.buf.appendSlice(self.alloc, cur.toArray()[0..addr_len]);

            cur = self.wd6_iter.next() orelse break;
        }

        // Patch MP_UNREACH_NLRI extended length.
        const mp_len: u16 = @intCast(self.buf.items.len - saved_pos - 6);
        std.mem.writeInt(u16, self.buf.items[saved_pos + 4 ..][0..2], mp_len, .big);

        // Patch Total Path Attribute Length.
        const pa_len: u16 = @intCast(self.buf.items.len - saved_pos - 2);
        std.mem.writeInt(u16, self.buf.items[saved_pos..][0..2], pa_len, .big);

        return try finalizeMessage(self.alloc, &self.buf);
    }

    /// nextNlri4 builds a single UPDATE message containing IPv4 NLRI routes.
    fn nextNlri4(self: *Self) !?[]u8 {
        var cur = self.pending_nlri4 orelse self.nlri4_iter.next() orelse return null;
        self.pending_nlri4 = null;

        try startMessage(self.alloc, &self.buf, .UPDATE);

        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Withdrawn routes

        const pa_len_pos = self.buf.items.len;
        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Total Path Attribute Length

        // ORIGIN: IGP (0).
        try self.buf.appendSlice(self.alloc, &.{ PA_TRANSITIVE, PA_ORIGIN, 1, 0 });

        // AS_PATH: AS_SEQUENCE with the local 4-byte AS number.
        try self.writeAsPath();

        // NEXT_HOP: 4-byte IPv4 address.
        try self.buf.appendSlice(self.alloc, &.{ PA_TRANSITIVE, PA_NEXT_HOP, 4 });
        try self.buf.appendSlice(self.alloc, &self.next_hop_v4);

        // LOCAL_PREF: 100.
        try self.buf.appendSlice(self.alloc, &.{ PA_TRANSITIVE, PA_LOCAL_PREF, 4, 0, 0, 0, 100 });

        // Patch Total Path Attribute Length (NLRI follows as a separate section).
        const pa_len: u16 = @intCast(self.buf.items.len - pa_len_pos - 2);
        std.mem.writeInt(u16, self.buf.items[pa_len_pos..][0..2], pa_len, .big);

        // NLRI: fill until the message is full.
        while (true) {
            const addr_len = prefixSizeInBytes(cur.prefix_len);
            if (self.buf.items.len + 1 + addr_len > MAX_MSG_LEN) {
                self.pending_nlri4 = cur;
                break;
            }

            try self.buf.append(self.alloc, cur.prefix_len);
            try self.buf.appendSlice(self.alloc, cur.toArray()[0..addr_len]);

            cur = self.nlri4_iter.next() orelse break;
        }

        return try finalizeMessage(self.alloc, &self.buf);
    }

    /// nextNlri6 builds a single UPDATE message containing IPv6 NLRI routes.
    ///
    /// Uses the MP_REACH_NLRI attribute.
    fn nextNlri6(self: *Self) !?[]u8 {
        var cur = self.pending_nlri6 orelse self.nlri6_iter.next() orelse return null;
        self.pending_nlri6 = null;

        try startMessage(self.alloc, &self.buf, .UPDATE);

        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Withdrawn routes

        const pa_len_pos = self.buf.items.len;
        try self.buf.appendSlice(self.alloc, &.{ 0, 0 }); // Total Path Attribute Length

        // ORIGIN: IGP (0).
        try self.buf.appendSlice(self.alloc, &.{ PA_TRANSITIVE, PA_ORIGIN, 1, 0 });

        // AS_PATH: AS_SEQUENCE with the local 4-byte AS number.
        try self.writeAsPath();

        // LOCAL_PREF: 100.
        try self.buf.appendSlice(self.alloc, &.{ PA_TRANSITIVE, PA_LOCAL_PREF, 4, 0, 0, 0, 100 });

        // MP_REACH_NLRI attribute header (optional, extended-length).
        const attr_start = self.buf.items.len;
        try self.buf.appendSlice(self.alloc, &.{
            PA_OPTIONAL | PA_EXT_LEN, PA_MP_REACH_NLRI,
            0, 0, // extended attribute length, patched later
            0, AFI_IPV6, SAFI_UNICAST, // AFI=2, SAFI=1
            16, // next-hop length = 16 bytes (one global IPv6 address)
        });

        // IPv6 next-hop address (16 bytes, network byte order).
        try self.buf.appendSlice(self.alloc, &self.next_hop_v6);

        // SNPA count = 0 (no Subnetwork Points of Attachment).
        try self.buf.append(self.alloc, 0);

        // NLRIs
        while (true) {
            const addr_len = prefixSizeInBytes(cur.prefix_len);
            if (self.buf.items.len + 1 + addr_len > MAX_MSG_LEN) {
                self.pending_nlri6 = cur;
                break;
            }

            try self.buf.append(self.alloc, cur.prefix_len);
            try self.buf.appendSlice(self.alloc, cur.toArray()[0..addr_len]);
            cur = self.nlri6_iter.next() orelse break;
        }

        // Patch MP_REACH_NLRI extended length (value begins after the 4-byte attr header).
        const mp_len: u16 = @intCast(self.buf.items.len - attr_start - 4);
        std.mem.writeInt(u16, self.buf.items[attr_start + 2 ..][0..2], mp_len, .big);

        // Patch Total Path Attribute Length (covers everything after pa_len_pos+2).
        const pa_len: u16 = @intCast(self.buf.items.len - pa_len_pos - 2);
        std.mem.writeInt(u16, self.buf.items[pa_len_pos..][0..2], pa_len, .big);

        return try finalizeMessage(self.alloc, &self.buf);
    }

    /// writeAsPath appends an AS_PATH path attribute: AS_SEQUENCE with one 4-byte local AS.
    fn writeAsPath(self: *Self) !void {
        const as = self.config.local_as;
        try self.buf.appendSlice(self.alloc, &.{
            PA_TRANSITIVE, PA_AS_PATH,
            6, // attribute value length: 1 (seg_type) + 1 (seg_count) + 4 (AS)
            AS_SEQUENCE,                 1, // segment: type=AS_SEQUENCE, count=1
            @intCast((as >> 24) & 0xFF), @intCast((as >> 16) & 0xFF),
            @intCast((as >> 8) & 0xFF),  @intCast(as & 0xFF),
        });
    }
};

/// Returns an UpdateIterator that yields serialized BGP UPDATE messages.
///
/// Each slice returned by the iterator's next() is allocated with alloc,
/// the caller must free it.
///
/// Call deinit() on the iterator when done.
pub fn buildUpdate(
    alloc: std.mem.Allocator,
    config: *const Config.ConfigBgpFields,
    wd4: *const trie.Trie(u32),
    wd6: *const trie.Trie(u128),
    nlri4: *const trie.Trie(u32),
    nlri6: *const trie.Trie(u128),
) !UpdateIterator {
    var iter: UpdateIterator = .{
        .alloc = alloc,
        .config = config,
        .wd4_iter = wd4.collectIter(),
        .wd6_iter = wd6.collectIter(),
        .nlri4_iter = nlri4.collectIter(),
        .nlri6_iter = nlri6.collectIter(),
    };

    if (config.next_hop_ipv4) |nh| {
        const addr = try cidr.CIDRv4.fromString(nh);
        iter.next_hop_v4 = addr.toArray();
    }

    if (config.next_hop_ipv6) |nh| {
        const addr = try cidr.CIDRv6.fromString(nh);
        iter.next_hop_v6 = addr.toArray();
    }

    return iter;
}

/// BgpMessage holds a decoded BGP message: its type and raw body bytes.
///
/// The body is owned by the caller.
/// It should be freed with the same allocator passed to readMessage.
pub const BgpMessage = struct {
    type: MessageType,
    body: []const u8,
};

/// Reads a single complete BGP message from a stream to the memory.
///
/// The caller owns the body in the message object.
pub fn readMessage(alloc: std.mem.Allocator, reader: *std.Io.Reader) !BgpMessage {
    // Read the header first
    var header: [HEADER_LEN]u8 = undefined;
    try reader.readSliceAll(&header);

    // Check if the marker is valid
    if (!std.mem.eql(u8, header[0..MARKER_LEN], &([_]u8{0xFF} ** MARKER_LEN))) {
        return error.InvalidMarker;
    }

    const packet_len = std.mem.readInt(u16, header[MARKER_LEN..][0..2], .big);
    if (packet_len < HEADER_LEN or packet_len > MAX_MSG_LEN) {
        return error.InvalidMessageLength;
    }

    const body_len = packet_len - HEADER_LEN;
    const body = try alloc.alloc(u8, body_len);
    errdefer alloc.free(body);

    if (body_len > 0) {
        try reader.readSliceAll(body);
    }

    return BgpMessage{
        .type = @enumFromInt(header[MARKER_LEN + 2]),
        .body = body,
    };
}

/// BgpMessageOpen holds the decoded fields of a BGP OPEN message.
pub const BgpMessageOpen = struct {
    version: u8,
    my_as: u32,
    hold_time: u16,
    bgp_id: [4]u8,
    supports_4byte_as: bool,
    supports_ipv6: bool,
};

/// parseOpen decodes the body of a BGP OPEN message into a BgpMessageOpen.
pub fn parseOpen(body: []const u8) !BgpMessageOpen {
    const MIN_LENGTH = 10;
    const MIN_PARAM_LENGTH = 2;
    const MIN_CAPABILITY_LENGTH = 2;

    if (body.len < MIN_LENGTH) {
        return error.MessageTooShort;
    }

    const version = body[0];
    if (version != 4) {
        return error.UnsupportedVersion;
    }

    var my_as: u32 = std.mem.readInt(u16, body[1..3], .big);
    const hold_time = std.mem.readInt(u16, body[3..5], .big);
    const bgp_id: [4]u8 = body[5..9].*;
    const params_len = body[9];

    if (body.len < MIN_LENGTH + params_len) {
        return error.MessageTruncated;
    }

    // Parse the optional parameters
    var real_as: u32 = 0;
    var supports_ipv6 = false;

    var i: usize = MIN_LENGTH;
    const end = MIN_LENGTH + @as(usize, params_len);
    while (i < end) {
        if (i + MIN_PARAM_LENGTH > end) {
            return error.MalformedParameter;
        }

        const param_type = body[i];
        const param_len = body[i + 1];
        i += MIN_PARAM_LENGTH;

        if (i + param_len > end) {
            return error.MalformedParameter;
        }

        const param_data = body[i .. i + param_len];
        i += param_len;

        if (param_type != 2) {
            continue; // not a Capabilities parameter, skip it
        }

        // Walk through all capabilities within this parameter
        var j: usize = 0;
        while (j < param_data.len) {
            if (j + MIN_CAPABILITY_LENGTH > param_data.len) {
                return error.MalformedCapability;
            }

            const cap_code = param_data[j];
            const cap_len = param_data[j + 1];
            j += MIN_CAPABILITY_LENGTH;

            if (j + cap_len > param_data.len) {
                return error.MalformedCapability;
            }

            const cap_val = param_data[j .. j + cap_len];
            j += cap_len;

            switch (cap_code) {
                1 => {
                    if (cap_len < 4) {
                        return error.MalformedCapability;
                    }

                    const afi = std.mem.readInt(u16, cap_val[0..2], .big);
                    const safi = cap_val[3];
                    if (afi == AFI_IPV6 and safi == SAFI_UNICAST) {
                        supports_ipv6 = true;
                    }
                },
                65 => {
                    if (cap_len < 4) {
                        return error.MalformedCapability;
                    }

                    real_as = std.mem.readInt(u32, cap_val[0..4], .big);
                },
                else => {}, // unknown capability, skip
            }
        }
    }

    if (real_as != 0) {
        my_as = real_as;
    }

    return BgpMessageOpen{
        .version = version,
        .my_as = my_as,
        .hold_time = hold_time,
        .bgp_id = bgp_id,
        .supports_4byte_as = real_as != 0,
        .supports_ipv6 = supports_ipv6,
    };
}

//
// Tests
//

test "buildKeepalive" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    const msg = try buildKeepalive(std.testing.allocator, &buf);
    defer std.testing.allocator.free(msg);

    const expected = [_]u8{0xFF} ** 16 ++ [_]u8{
        0x00, 0x13, // length = 19
        0x04, // type = KEEP_ALIVE
    };
    try std.testing.expectEqualSlices(u8, &expected, msg);
}

test "buildNotification" {
    const tests = [_]struct {
        code: NotificationErrorCode,
        subcode: u8,
        data: []const u8,
        expected: []const u8,
    }{
        .{
            // CEASE with no data
            .code = .CEASE,
            .subcode = 0,
            .data = &.{},
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x15, // length = 21
                0x03, // type = NOTIFICATION
                0x06, // code = CEASE
                0x00, // subcode
            }),
        },
        .{
            // MESSAGE_HEADER_ERROR with two bytes of data
            .code = .MESSAGE_HEADER_ERROR,
            .subcode = 2,
            .data = &.{ 0x11, 0x22 },
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x17, // length = 23
                0x03, // type = NOTIFICATION
                0x01, // code = MESSAGE_HEADER_ERROR
                0x02, // subcode
                0x11, 0x22, // data
            }),
        },
        .{
            // UPDATE_MESSAGE_ERROR with non-zero subcode, no data
            .code = .UPDATE_MESSAGE_ERROR,
            .subcode = 1,
            .data = &.{},
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x15, // length = 21
                0x03, // type = NOTIFICATION
                0x03, // code = UPDATE_MESSAGE_ERROR
                0x01, // subcode
            }),
        },
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    for (tests) |t| {
        const msg = try buildNotification(std.testing.allocator, &buf, t.code, t.subcode, t.data);
        defer std.testing.allocator.free(msg);

        try std.testing.expectEqualSlices(u8, t.expected, msg);
    }
}

test "buildOpen" {
    // Multiprotocol IPv4+IPv6 unicast
    const mp_cap = [_]u8{
        0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01,
        0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01,
    };

    const tests = [_]struct {
        local_as: u32,
        hold_time: u16,
        router_id: [4]u8,
        expected: []const u8,
    }{
        .{
            // AS fits in u16
            .local_as = 65001,
            .hold_time = 90,
            .router_id = .{ 1, 2, 3, 4 },
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x35, // length = 53
                0x01, // type = OPEN
                0x04, // version = 4
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                0x01, 0x02, 0x03, 0x04, // router_id
                0x18, // opt_params_len = 24
                0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xFD, 0xE9, // 4-octet AS cap
            } ++ mp_cap),
        },
        .{
            // AS > 65535: AS_TRANS (23456) used in header, full AS in capability
            .local_as = 131072,
            .hold_time = 180,
            .router_id = .{ 10, 0, 0, 1 },
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x35, // length = 53
                0x01, // type = OPEN
                0x04, // version = 4
                0x5B, 0xA0, // AS_TRANS = 23456
                0x00, 0xB4, // hold_time = 180
                0x0A, 0x00, 0x00, 0x01, // router_id = 10.0.0.1
                0x18, // opt_params_len = 24
                0x02, 0x06, 0x41, 0x04, 0x00, 0x02, 0x00, 0x00, // 4-octet AS cap: 131072
            } ++ mp_cap),
        },
        .{
            // AS = 65535
            .local_as = 65535,
            .hold_time = 0,
            .router_id = .{ 0, 0, 0, 0 },
            .expected = &([_]u8{0xFF} ** 16 ++ [_]u8{
                0x00, 0x35, // length = 35
                0x01, // type = OPEN
                0x04, // version = 4
                0xFF, 0xFF, // AS = 65535
                0x00, 0x00, // hold_time = 0
                0x00, 0x00, 0x00, 0x00, // router_id
                0x18, // opt_params_len = 24
                0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0xFF, 0xFF, // 4-octet AS cap: 65535
            } ++ mp_cap),
        },
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    for (tests) |t| {
        const msg = try buildOpen(std.testing.allocator, &buf, t.local_as, t.hold_time, t.router_id);
        defer std.testing.allocator.free(msg);

        try std.testing.expectEqualSlices(u8, t.expected, msg);
    }
}

test "readMessage" {
    const M = [_]u8{0xFF} ** MARKER_LEN; // valid marker

    const tests = [_]struct {
        name: []const u8,
        input: []const u8,
        expected_err: ?anyerror = null,
        expected_type: ?MessageType = null,
        expected_body: ?[]const u8 = null,
    }{
        .{
            .name = "valid KEEP_ALIVE",
            .input = &(M ++ [_]u8{
                0x00, 0x13, // length = 19 (header only)
                0x04, // KEEP_ALIVE
            }),
            .expected_type = .KEEP_ALIVE,
            .expected_body = &.{},
        },
        .{
            .name = "valid NOTIFICATION with body",
            .input = &(M ++ [_]u8{
                0x00, 0x15, // length = 21
                0x03, // NOTIFICATION
                0x06, 0x00, // CEASE, subcode 0
            }),
            .expected_type = .NOTIFICATION,
            .expected_body = &.{ 0x06, 0x00 },
        },
        .{
            .name = "invalid marker",
            .input = &([_]u8{0x11} ** MARKER_LEN ++ [_]u8{ 0x00, 0x13, 0x04 }),
            .expected_err = error.InvalidMarker,
        },
        .{
            .name = "length too short",
            .input = &(M ++ [_]u8{
                0x00, 0x12, // length = 18 < HEADER_LEN
                0x04,
            }),
            .expected_err = error.InvalidMessageLength,
        },
        .{
            .name = "length too long",
            .input = &(M ++ [_]u8{
                0x10, 0x01, // length = 4097 > MAX_MSG_LEN
                0x04,
            }),
            .expected_err = error.InvalidMessageLength,
        },
        .{
            .name = "truncated packet (stream ends mid-header)",
            .input = &[_]u8{ 0xFF, 0xFF, 0xFF },
            .expected_err = error.EndOfStream,
        },
        .{
            .name = "truncated body (length says more than stream has)",
            .input = &(M ++ [_]u8{ 0x00, 0x15, 0x02 }),
            .expected_err = error.EndOfStream,
        },
    };

    for (tests) |t| {
        var reader = std.io.Reader.fixed(t.input);

        if (t.expected_err) |expected_err| {
            try std.testing.expectError(expected_err, readMessage(std.testing.allocator, &reader));
        } else {
            const msg = try readMessage(std.testing.allocator, &reader);
            defer std.testing.allocator.free(msg.body);

            try std.testing.expectEqual(t.expected_type.?, msg.type);
            try std.testing.expectEqualSlices(u8, t.expected_body.?, msg.body);
        }
    }
}

test "parseOpen" {
    const tests = [_]struct {
        name: []const u8,
        body: []const u8,
        expected_err: ?anyerror = null,
        expected: ?BgpMessageOpen = null,
    }{
        .{
            .name = "no optional parameters",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                0, // opt_params_len = 0
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = false,
                .supports_ipv6 = false,
            },
        },
        .{
            .name = "4-byte AS capability",
            .body = &[_]u8{
                4, // version
                0x5B, 0xA0, // AS_TRANS = 23456
                0x00, 0xB4, // hold_time = 180
                10, 0, 0, 1, // bgp_id = 10.0.0.1
                8, // opt_params_len = 8
                2, 6, 65, 4, 0x00, 0x02, 0x00, 0x00, // AS cap: 131072
            },
            .expected = .{
                .version = 4,
                .my_as = 131072,
                .hold_time = 180,
                .bgp_id = .{ 10, 0, 0, 1 },
                .supports_4byte_as = true,
                .supports_ipv6 = false,
            },
        },
        .{
            .name = "IPv6 multiprotocol capability",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                8, // opt_params_len = 8
                2, 6, 1, 4, 0, 2, 0, 1, // MP extensions: AFI=2, SAFI=1
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = false,
                .supports_ipv6 = true,
            },
        },
        .{
            .name = "IPv6 and AS capabilities",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                16, // opt_params_len = 16
                2, 6, 65, 4, 0x00, 0x00, 0xFD, 0xE9, // AS cap: 65001
                2, 6, 1, 4, 0, 2, 0, 1, // MP extensions: AFI=2, SAFI=1
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = true,
                .supports_ipv6 = true,
            },
        },
        .{
            .name = "IPv4 unicast does not set supports_ipv6",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                8, // opt_params_len = 8
                2, 6, 1, 4, 0, 1, 0, 1, // MP extensions: AFI=1 (IPv4), SAFI=1
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = false,
                .supports_ipv6 = false,
            },
        },
        .{
            .name = "non-capability parameter is skipped",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                4, // opt_params_len = 4
                1, 2, 0xAB, 0xCD, // param_type=1, param_len=2, data
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = false,
                .supports_ipv6 = false,
            },
        },
        .{
            .name = "unknown capability code is skipped",
            .body = &[_]u8{
                4, // version
                0xFD, 0xE9, // AS = 65001
                0x00, 0x5A, // hold_time = 90
                1, 2, 3, 4, // bgp_id
                5, // opt_params_len = 5
                2, 3, 0xFF, 1, 0x42, // cap_type=2, cap_len=3, cap_code=255, cap_len=1, cap_val
            },
            .expected = .{
                .version = 4,
                .my_as = 65001,
                .hold_time = 90,
                .bgp_id = .{ 1, 2, 3, 4 },
                .supports_4byte_as = false,
                .supports_ipv6 = false,
            },
        },
        .{
            .name = "body too short",
            .body = &[_]u8{ 4, 0xFD, 0xE9, 0x00, 0x5A, 1, 2, 3 },
            .expected_err = error.MessageTooShort,
        },
        .{
            .name = "unsupported version",
            .body = &[_]u8{ 3, 0xFD, 0xE9, 0x00, 0x5A, 1, 2, 3, 4, 0 },
            .expected_err = error.UnsupportedVersion,
        },
        .{
            .name = "message truncated",
            .body = &[_]u8{ 4, 0xFD, 0xE9, 0x00, 0x5A, 1, 2, 3, 4, 10 },
            .expected_err = error.MessageTruncated,
        },
        .{
            .name = "malformed parameter",
            .body = &[_]u8{
                4, 0xFD, 0xE9, 0x00, 0x5A, 1, 2, 3, 4,
                5, // opt_params_len = 5
                2, 10, 0, 0, 0, // param_type=2, param_len=10
            },
            .expected_err = error.MalformedParameter,
        },
        .{
            .name = "malformed capability",
            .body = &[_]u8{
                4, 0xFD, 0xE9, 0x00, 0x5A, 1, 2, 3, 4,
                4, // opt_params_len = 4
                2, 2, // param_type=2
                65, 10, // cap_code=65, cap_len=10
            },
            .expected_err = error.MalformedCapability,
        },
    };

    for (tests) |t| {
        if (t.expected_err) |expected_err| {
            try std.testing.expectError(expected_err, parseOpen(t.body));
        } else {
            const result = try parseOpen(t.body);
            try std.testing.expectEqual(t.expected.?, result);
        }
    }
}

/// BgpMessageNotification holds the decoded fields of a BGP NOTIFICATION message.
pub const BgpMessageNotification = struct {
    error_code: NotificationErrorCode,
    error_subcode: u8,

    /// data is a slice into the original body.
    data: []const u8,
};

/// parseNotification decodes the body of a BGP NOTIFICATION message into a BgpMessageNotification.
pub fn parseNotification(body: []const u8) !BgpMessageNotification {
    if (body.len < 2) {
        return error.MessageTooShort;
    }

    return BgpMessageNotification{
        .error_code = @enumFromInt(body[0]),
        .error_subcode = body[1],
        .data = body[2..],
    };
}

test "parseNotification" {
    const tests = [_]struct {
        name: []const u8,
        body: []const u8,
        expected_err: ?anyerror = null,
        expected: ?BgpMessageNotification = null,
    }{
        .{
            .name = "too short",
            .body = &[_]u8{4},
            .expected_err = error.MessageTooShort,
        },
        .{
            .name = "empty body",
            .body = &[_]u8{},
            .expected_err = error.MessageTooShort,
        },
        .{
            .name = "hold timer expired, no data",
            .body = &[_]u8{ 4, 0 },
            .expected = .{
                .error_code = .HOLD_TIMER_EXPIRED,
                .error_subcode = 0,
                .data = &[_]u8{},
            },
        },
        .{
            .name = "cease with data",
            .body = &[_]u8{ 6, 2, '1', '2', '3' },
            .expected = .{
                .error_code = .CEASE,
                .error_subcode = 2,
                .data = &[_]u8{ '1', '2', '3' },
            },
        },
        .{
            .name = "unknown error code",
            .body = &[_]u8{ 99, 1 },
            .expected = .{
                .error_code = @enumFromInt(99),
                .error_subcode = 1,
                .data = &[_]u8{},
            },
        },
    };

    for (tests) |t| {
        if (t.expected_err) |expected_err| {
            try std.testing.expectError(expected_err, parseNotification(t.body));
        } else {
            const result = try parseNotification(t.body);
            try std.testing.expectEqual(t.expected.?.error_code, result.error_code);
            try std.testing.expectEqual(t.expected.?.error_subcode, result.error_subcode);
            try std.testing.expectEqualSlices(u8, t.expected.?.data, result.data);
        }
    }
}

/// TriePack groups the four tries passed to buildUpdate into one struct, for convenience in tests.
pub const TriePack = struct {
    wd4: trie.Trie(u32),
    wd6: trie.Trie(u128),
    nlri4: trie.Trie(u32),
    nlri6: trie.Trie(u128),

    /// init creates a TriePack with four empty tries backed by alloc.
    pub fn init(alloc: std.mem.Allocator) @This() {
        return .{ .wd4 = .init(alloc), .wd6 = .init(alloc), .nlri4 = .init(alloc), .nlri6 = .init(alloc) };
    }

    /// deinit frees all four tries.
    pub fn deinit(self: *@This()) void {
        self.wd4.deinit();
        self.wd6.deinit();
        self.nlri4.deinit();
        self.nlri6.deinit();
    }
};

test "buildUpdate: empty tries produce no messages" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    const cfg = Config.ConfigBgpFields{ .local_as = 65001 };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    try std.testing.expect(try iter.next() == null);
}

test "buildUpdate: single IPv4 withdrawn prefix" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    try tp.wd4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));

    const cfg = Config.ConfigBgpFields{ .local_as = 65001 };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    const msg = (try iter.next()).?;
    defer alloc.free(msg);
    try std.testing.expect(try iter.next() == null);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 16 ++ [_]u8{
        0x00, 0x19, // length = 25
        0x02, // UPDATE
        0x00, 0x02, // WD_LEN = 2
        0x08, 0x0A, // 10.0.0.0/8
        0x00, 0x00, // PA_LEN = 0
    }, msg);
}

test "buildUpdate: single IPv4 NLRI prefix" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    try tp.nlri4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));

    const cfg = Config.ConfigBgpFields{ .local_as = 65001, .next_hop_ipv4 = "1.2.3.4" };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    const msg = (try iter.next()).?;
    defer alloc.free(msg);
    try std.testing.expect(try iter.next() == null);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 16 ++ [_]u8{
        0x00, 0x34, // length = 52
        0x02, // UPDATE
        0x00, 0x00, // WD_LEN = 0
        0x00, 0x1B, // PA_LEN = 27
        0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
        0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9, // AS_PATH = AS_SEQUENCE, 65001
        0x40, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, // NEXT_HOP = 1.2.3.4
        0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, // LOCAL_PREF = 100
        0x08, 0x0A, // NLRI: 10.0.0.0/8
    }, msg);
}

test "buildUpdate: single IPv6 withdrawn prefix" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    try tp.wd6.insert(cidr.comptimeCIDRv6("2001:db8::/32"));

    const cfg = Config.ConfigBgpFields{ .local_as = 65001 };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    const msg = (try iter.next()).?;
    defer alloc.free(msg);
    try std.testing.expect(try iter.next() == null);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 16 ++ [_]u8{
        0x00, 0x23, // length = 35
        0x02, // UPDATE
        0x00, 0x00, // WD_LEN = 0
        0x00, 0x0C, // PA_LEN = 12
        0x90, 0x0F, 0x00, 0x08, // MP_UNREACH_NLRI: opt|ext_len, type=15, ext_len=8
        0x00, 0x02, 0x01, // AFI=2, SAFI=1
        0x20, 0x20, 0x01, 0x0D, 0xB8, // 2001:db8::
    }, msg);
}

test "buildUpdate: single IPv6 NLRI prefix" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    try tp.nlri6.insert(cidr.comptimeCIDRv6("2001:db8::/32"));

    const cfg = Config.ConfigBgpFields{ .local_as = 65001, .next_hop_ipv6 = "2001:db8::1" };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    const msg = (try iter.next()).?;
    defer alloc.free(msg);
    try std.testing.expect(try iter.next() == null);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 16 ++ [_]u8{
        0x00, 0x49, // length = 73
        0x02, // UPDATE
        0x00, 0x00, // WD_LEN = 0
        0x00, 0x32, // PA_LEN = 50
        0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
        0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFD, 0xE9, // AS_PATH = AS_SEQUENCE, 65001
        0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, // LOCAL_PREF = 100
        0x90, 0x0E, 0x00, 0x1A, // MP_REACH_NLRI: opt|ext_len, type=14, ext_len=26
        0x00, 0x02, 0x01, // AFI=2, SAFI=1
        0x10, // NH_LEN = 16
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, // next-hop: 2001:db8::1 (1st half)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // next-hop: 2001:db8::1 (2nd half)
        0x00, // SNPA = 0
        0x20, 0x20, 0x01, 0x0D, 0xB8, // prefix: 2001:db8::/32
    }, msg);
}

test "buildUpdate: chunking of IPv4 withdrawn prefixes" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    // 1000 non-summarizable /32 addresses.
    for (0..1000) |i| {
        const x: u8 = @intCast(i >> 8);
        const y: u8 = @intCast(i & 0xFF);
        const addr: u32 = (@as(u32, 1) << 24) | (@as(u32, x) << 16) | (@as(u32, y) << 8) | 1;
        try tp.wd4.insert(cidr.CIDRv4{
            .addr = std.mem.bigToNative(u32, addr),
            .prefix_len = 32,
        });
    }

    const cfg = Config.ConfigBgpFields{ .local_as = 65001 };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    var msg_count: usize = 0;
    while (try iter.next()) |msg| {
        defer alloc.free(msg);
        msg_count += 1;

        try std.testing.expect(msg.len <= MAX_MSG_LEN);
        // We only check that the overall message frame is valid.
        // Other tests should handle checking the message's internals.
        try std.testing.expectEqualSlices(u8, &([_]u8{0xFF} ** 16), msg[0..16]);
        try std.testing.expectEqual(@as(u8, @intFromEnum(MessageType.UPDATE)), msg[18]);

        // Verify the embedded length field matches the actual slice length.
        const stated_len = std.mem.readInt(u16, msg[16..18], .big);
        try std.testing.expectEqual(@as(usize, stated_len), msg.len);
    }

    try std.testing.expectEqual(@as(usize, 2), msg_count);
}

test "buildUpdate: v4 and v6, WD and NLRI" {
    const alloc = std.testing.allocator;
    var tp = TriePack.init(alloc);
    defer tp.deinit();

    try tp.wd4.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try tp.wd6.insert(cidr.comptimeCIDRv6("fe80::/10"));
    try tp.nlri4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try tp.nlri6.insert(cidr.comptimeCIDRv6("2001:db8::/32"));

    const cfg = Config.ConfigBgpFields{ .local_as = 65001 };
    var iter = try buildUpdate(alloc, &cfg, &tp.wd4, &tp.wd6, &tp.nlri4, &tp.nlri6);
    defer iter.deinit();

    var msg_count: usize = 0;
    while (try iter.next()) |msg| {
        defer alloc.free(msg);
        msg_count += 1;

        try std.testing.expect(msg.len >= HEADER_LEN);
        try std.testing.expect(msg.len <= MAX_MSG_LEN);

        const stated_len = std.mem.readInt(u16, msg[16..18], .big);
        try std.testing.expectEqual(@as(usize, stated_len), msg.len);
    }

    try std.testing.expectEqual(@as(usize, 4), msg_count);
}
