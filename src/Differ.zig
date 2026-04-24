//! Differ tracks the latest Trie for each IP family and computes
//! the additions and removals that occurred since the last update.

const std = @import("std");
const cidr = @import("cidr.zig");
const trie = @import("trie.zig");

alloc: std.mem.Allocator = undefined,
mutex: std.Thread.Mutex = .{},
gen: u64 = 0,

latest_v4: ?trie.Trie(u32) = null,
diff_v4_added: ?trie.Trie(u32) = null,
diff_v4_removed: ?trie.Trie(u32) = null,

latest_v6: ?trie.Trie(u128) = null,
diff_v6_added: ?trie.Trie(u128) = null,
diff_v6_removed: ?trie.Trie(u128) = null,

const Self = @This();

/// init creates a new Differ backed by alloc.
pub fn init(alloc: std.mem.Allocator) Self {
    return .{ .alloc = alloc };
}

/// deinit frees all resources held by the Differ.
///
/// The Differ must not be used after this call.
pub fn deinit(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    self.clear();
}

fn clear(self: *Self) void {
    if (self.latest_v4) |*t| t.deinit();
    if (self.diff_v4_added) |*t| t.deinit();
    if (self.diff_v4_removed) |*t| t.deinit();

    if (self.latest_v6) |*t| t.deinit();
    if (self.diff_v6_added) |*t| t.deinit();
    if (self.diff_v6_removed) |*t| t.deinit();

    self.latest_v4 = null;
    self.latest_v6 = null;
    self.diff_v4_added = null;
    self.diff_v4_removed = null;
    self.diff_v6_added = null;
    self.diff_v6_removed = null;
}

/// difference returns a trie containing all prefixes in base that are not covered by
/// any prefix in subtract.
///
/// The caller owns the resulting trie.
fn difference(comptime T: type, alloc: std.mem.Allocator, base: ?*const trie.Trie(T), subtract: ?*const trie.Trie(T)) !trie.Trie(T) {
    var result = if (base) |b| try b.copy(alloc) else trie.Trie(T).init(alloc);
    errdefer result.deinit();

    if (subtract) |sub| {
        var iter = sub.collectIter();
        while (iter.next()) |prefix| {
            try result.delete(prefix);
        }
    }

    return result;
}

/// update saves a deep copy of v4 and v6 as the latest snapshot, and computes
/// the diff against the previous snapshot.
///
/// Returns the current generation ID. The generation is only incremented when
/// the new snapshot differs from the previous one; identical snapshots leave
/// the generation unchanged.
pub fn update(self: *Self, triev4: *const trie.Trie(u32), triev6: *const trie.Trie(u128)) !u64 {
    self.mutex.lock();
    defer self.mutex.unlock();

    const prev_v4: ?*const trie.Trie(u32) = if (self.latest_v4) |*t| t else null;
    const prev_v6: ?*const trie.Trie(u128) = if (self.latest_v6) |*t| t else null;

    // Compute the diffs first.
    var new_v4_added = try difference(u32, self.alloc, triev4, prev_v4);
    errdefer new_v4_added.deinit();

    var new_v4_removed = try difference(u32, self.alloc, prev_v4, triev4);
    errdefer new_v4_removed.deinit();

    var new_v6_added = try difference(u128, self.alloc, triev6, prev_v6);
    errdefer new_v6_added.deinit();

    var new_v6_removed = try difference(u128, self.alloc, prev_v6, triev6);
    errdefer new_v6_removed.deinit();

    var new_v4 = try triev4.copy(self.alloc);
    errdefer new_v4.deinit();

    var new_v6 = try triev6.copy(self.alloc);
    errdefer new_v6.deinit();

    // Only bump the generation when something actually changed.
    const has_changes = new_v4_added.root != null or new_v4_removed.root != null or
        new_v6_added.root != null or new_v6_removed.root != null;

    // All allocations succeeded: clear the old state and replace it with the current state.
    self.clear();
    self.latest_v4 = new_v4;
    self.latest_v6 = new_v6;
    self.diff_v4_added = new_v4_added;
    self.diff_v4_removed = new_v4_removed;
    self.diff_v6_added = new_v6_added;
    self.diff_v6_removed = new_v6_removed;
    if (has_changes) self.gen +%= 1;

    return self.gen;
}

/// Snapshot is a point-in-time copy of the latest IPv4 and IPv6 tries,
/// tagged with the generation ID.
pub const Snapshot = struct {
    v4: trie.Trie(u32),
    v6: trie.Trie(u128),
    gen: u64,

    /// init creates a deep copy of v4 and v6.
    ///
    /// Call deinit() when done.
    pub fn init(alloc: std.mem.Allocator, v4: *const trie.Trie(u32), v6: *const trie.Trie(u128), gen: u64) !@This() {
        var v4_copy = try v4.copy(alloc);
        errdefer v4_copy.deinit();
        const v6_copy = try v6.copy(alloc);

        return .{ .v4 = v4_copy, .v6 = v6_copy, .gen = gen };
    }

    /// deinit frees all resources held by the Snapshot.
    pub fn deinit(self: *@This()) void {
        self.v4.deinit();
        self.v6.deinit();
    }
};

/// DiffSnapshot holds the per-family added and removed tries from the latest
/// update, tagged with the generation ID.
pub const DiffSnapshot = struct {
    v4_added: trie.Trie(u32),
    v4_removed: trie.Trie(u32),
    v6_added: trie.Trie(u128),
    v6_removed: trie.Trie(u128),
    gen: u64,

    /// init creates deep copies of the four diff tries.
    ///
    /// Call deinit() when done.
    pub fn init(
        alloc: std.mem.Allocator,
        v4_added: *const trie.Trie(u32),
        v4_removed: *const trie.Trie(u32),
        v6_added: *const trie.Trie(u128),
        v6_removed: *const trie.Trie(u128),
        gen: u64,
    ) !@This() {
        var added4 = try v4_added.copy(alloc);
        errdefer added4.deinit();
        var removed4 = try v4_removed.copy(alloc);
        errdefer removed4.deinit();
        var added6 = try v6_added.copy(alloc);
        errdefer added6.deinit();
        const removed6 = try v6_removed.copy(alloc);

        return .{
            .v4_added = added4,
            .v4_removed = removed4,
            .v6_added = added6,
            .v6_removed = removed6,
            .gen = gen,
        };
    }

    /// deinit frees all resources held by the DiffSnapshot.
    pub fn deinit(self: *@This()) void {
        self.v4_added.deinit();
        self.v4_removed.deinit();
        self.v6_added.deinit();
        self.v6_removed.deinit();
    }
};

/// Returns the latest snapshot and the current generation ID.
///
/// Returns error.NoLatest if there is no latest snapshot.
///
/// Call deinit() when done.
pub fn getLatest(self: *Self, alloc: std.mem.Allocator) !Snapshot {
    self.mutex.lock();
    defer self.mutex.unlock();

    const v4 = if (self.latest_v4) |*t| t else return error.NoLatest;
    const v6 = if (self.latest_v6) |*t| t else return error.NoLatest;

    return Snapshot.init(alloc, v4, v6, self.gen);
}

/// Returns the latest diff as a pair of tries per each IP family and the current generation ID.
///
/// Returns error.NoDiff if there is no latest diff.
///
/// Call deinit() when done.
pub fn getDiff(self: *Self, alloc: std.mem.Allocator) !DiffSnapshot {
    self.mutex.lock();
    defer self.mutex.unlock();

    const v4_added = if (self.diff_v4_added) |*t| t else return error.NoDiff;
    const v4_removed = if (self.diff_v4_removed) |*t| t else return error.NoDiff;
    const v6_added = if (self.diff_v6_added) |*t| t else return error.NoDiff;
    const v6_removed = if (self.diff_v6_removed) |*t| t else return error.NoDiff;

    return DiffSnapshot.init(alloc, v4_added, v4_removed, v6_added, v6_removed, self.gen);
}

/// getGeneration returns the current differ generation.
///
/// Useful as a fast way to check if there is a new diff version,
/// without having to allocate the diff slices.
pub fn getGeneration(self: *Self) u64 {
    self.mutex.lock();
    defer self.mutex.unlock();

    return self.gen;
}

//
// Tests
//

test "empty struct" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    try std.testing.expectError(error.NoLatest, d.getLatest(alloc));
    try std.testing.expectError(error.NoDiff, d.getDiff(alloc));
}

test "update only increments generation when content changes" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    // Empty tries: no content, generation stays at 0.
    const g0 = try d.update(&v4, &v6);
    try std.testing.expectEqual(@as(u64, 0), g0);
    try std.testing.expectEqual(@as(u64, 0), d.getGeneration());

    // Adding a prefix: content changed, generation increments to 1.
    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    const g1 = try d.update(&v4, &v6);
    try std.testing.expectEqual(@as(u64, 1), g1);
    try std.testing.expectEqual(@as(u64, 1), d.getGeneration());

    // Same data again: no change, generation stays at 1.
    const g2 = try d.update(&v4, &v6);
    try std.testing.expectEqual(@as(u64, 1), g2);
    try std.testing.expectEqual(@as(u64, 1), d.getGeneration());
}

test "getLatest returns a copy of the trie passed to update" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try v6.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    const gen = try d.update(&v4, &v6);

    var latest = try d.getLatest(alloc);
    defer latest.deinit();

    try std.testing.expectEqual(gen, latest.gen);

    var iter4 = latest.v4.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter4.next());
    try std.testing.expect(iter4.next() == null);

    var iter6 = latest.v6.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter6.next());
    try std.testing.expect(iter6.next() == null);
}

test "mutating the original trie does not affect the differ" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    _ = try d.update(&v4, &v6);

    // Mutate the v4 trie after an update.
    try v4.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));

    var latest = try d.getLatest(alloc);
    defer latest.deinit();

    var iter = latest.v4.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "single update" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try v4.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try v6.insert(cidr.comptimeCIDRv6("2001:db8::/32"));

    _ = try d.update(&v4, &v6);
    var diff = try d.getDiff(alloc);
    defer diff.deinit();

    var added4 = diff.v4_added.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), added4.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), added4.next());
    try std.testing.expect(added4.next() == null);

    var removed4 = diff.v4_removed.collectIter();
    try std.testing.expect(removed4.next() == null);

    var added6 = diff.v6_added.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), added6.next());
    try std.testing.expect(added6.next() == null);

    var removed6 = diff.v6_removed.collectIter();
    try std.testing.expect(removed6.next() == null);
}

test "update and diff" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4a = trie.Trie(u32).init(alloc);
    defer v4a.deinit();
    var v6a = trie.Trie(u128).init(alloc);
    defer v6a.deinit();
    try v4a.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try v6a.insert(cidr.comptimeCIDRv6("2001:db8:1::/48"));
    try v6a.insert(cidr.comptimeCIDRv6("2001:db8:2::/48"));
    _ = try d.update(&v4a, &v6a);

    var v4b = trie.Trie(u32).init(alloc);
    defer v4b.deinit();
    var v6b = trie.Trie(u128).init(alloc);
    defer v6b.deinit();
    try v4b.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try v6b.insert(cidr.comptimeCIDRv6("2001:db8:1::/48"));
    try v6b.insert(cidr.comptimeCIDRv6("2001:db8:3::/48"));
    _ = try d.update(&v4b, &v6b);

    var diff = try d.getDiff(alloc);
    defer diff.deinit();

    var added4 = diff.v4_added.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), added4.next());
    try std.testing.expect(added4.next() == null);

    var removed4 = diff.v4_removed.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), removed4.next());
    try std.testing.expect(removed4.next() == null);

    var added6 = diff.v6_added.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8:3::/48"), added6.next());
    try std.testing.expect(added6.next() == null);

    var removed6 = diff.v6_removed.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8:2::/48"), removed6.next());
    try std.testing.expect(removed6.next() == null);
}

test "no change between updates" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4 = trie.Trie(u32).init(alloc);
    defer v4.deinit();
    var v6 = trie.Trie(u128).init(alloc);
    defer v6.deinit();

    try v4.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    const g1 = try d.update(&v4, &v6);
    const g2 = try d.update(&v4, &v6);
    try std.testing.expectEqual(g1, g2);

    var diff = try d.getDiff(alloc);
    defer diff.deinit();

    var added4 = diff.v4_added.collectIter();
    try std.testing.expect(added4.next() == null);

    var removed4 = diff.v4_removed.collectIter();
    try std.testing.expect(removed4.next() == null);
}

test "partial overlap" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4a = trie.Trie(u32).init(alloc);
    defer v4a.deinit();
    var v6a = trie.Trie(u128).init(alloc);
    defer v6a.deinit();
    try v4a.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    _ = try d.update(&v4a, &v6a);

    var v4b = trie.Trie(u32).init(alloc);
    defer v4b.deinit();
    var v6b = trie.Trie(u128).init(alloc);
    defer v6b.deinit();
    try v4b.insert(cidr.comptimeCIDRv4("10.0.0.0/9"));
    _ = try d.update(&v4b, &v6b);

    var diff = try d.getDiff(alloc);
    defer diff.deinit();

    var added4 = diff.v4_added.collectIter();
    try std.testing.expect(added4.next() == null);

    var removed4 = diff.v4_removed.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/9"), removed4.next());
    try std.testing.expect(removed4.next() == null);
}

test "partial overlap in reverse" {
    const alloc = std.testing.allocator;
    var d = Self.init(alloc);
    defer d.deinit();

    var v4a = trie.Trie(u32).init(alloc);
    defer v4a.deinit();
    var v6a = trie.Trie(u128).init(alloc);
    defer v6a.deinit();
    try v4a.insert(cidr.comptimeCIDRv4("10.0.0.0/9"));
    _ = try d.update(&v4a, &v6a);

    var v4b = trie.Trie(u32).init(alloc);
    defer v4b.deinit();
    var v6b = trie.Trie(u128).init(alloc);
    defer v6b.deinit();
    try v4b.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    _ = try d.update(&v4b, &v6b);

    var diff = try d.getDiff(alloc);
    defer diff.deinit();

    var added4 = diff.v4_added.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/9"), added4.next());
    try std.testing.expect(added4.next() == null);

    var removed4 = diff.v4_removed.collectIter();
    try std.testing.expect(removed4.next() == null);
}
