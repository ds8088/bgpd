//! trie is a binary prefix tree that stores and automatically summarizes CIDRs.

const std = @import("std");
const cidr = @import("cidr.zig");

/// Binary trie for IP prefix summarization.
///
/// Each node covers one bit of the address. A node marked as filled represents
/// a prefix in the summarized set; its subtree is implicitly covered and its
/// children (if any are present) are freed on insertion.
pub fn Trie(comptime T: type) type {
    const max_bits = @typeInfo(T).int.bits;

    return struct {
        const Node = struct {
            children: [2]?*Node = .{ null, null },
            filled: bool = false,
        };

        root: ?*Node = null,
        alloc: std.mem.Allocator,

        const Self = @This();

        /// Iterator performs a depth-first traversal of the trie, yielding each
        /// stored prefix in ascending address order.
        pub const Iterator = struct {
            stack: [max_bits + 1]StackFrame,
            stack_len: usize,

            const StackFrame = struct { node: *const Node, addr: T = 0, depth: u8 = 0, child_idx: ?u1 = 0 };

            /// Returns the next prefix in the trie, or null if no more prefixes exist.
            pub fn next(self: *@This()) ?cidr.CIDR(T) {
                while (self.stack_len > 0) {
                    var frame = &self.stack[self.stack_len - 1];

                    // If this is the first visit to this node and it has been already filled, return it
                    if (frame.child_idx == 0 and frame.node.filled) {
                        self.stack_len -= 1;
                        return cidr.CIDR(T){ .addr = frame.addr, .prefix_len = frame.depth };
                    }

                    const bit = frame.child_idx orelse {
                        // Go to the previous stack level if all children have been processed
                        self.stack_len -= 1;
                        continue;
                    };

                    if (bit == 0) {
                        frame.child_idx = 1;
                    } else if (bit == 1) {
                        frame.child_idx = null;
                    }

                    if (frame.node.children[bit]) |child| {
                        const child_addr = frame.addr | (@as(T, @intCast(bit)) << @intCast(max_bits - 1 - frame.depth));
                        self.stack[self.stack_len] = .{
                            .node = child,
                            .addr = child_addr,
                            .depth = frame.depth + 1,
                        };
                        self.stack_len += 1;
                    }
                }

                return null;
            }
        };

        /// init returns an empty trie backed by the given allocator.
        pub fn init(alloc: std.mem.Allocator) Self {
            return .{ .alloc = alloc };
        }

        /// deinit frees all nodes in the trie. The trie must not be used after this call.
        pub fn deinit(self: *Self) void {
            if (self.root) |r| {
                self.freeNode(r);
                self.root = null;
            }
        }

        /// insert adds prefix to the trie.
        ///
        /// If that prefix is already covered by an existing entry, it is a no-op.
        ///
        /// Host bits in prefix are zeroed.
        /// Sibling prefixes that together fill a parent are automatically collapsed.
        pub fn insert(self: *Self, prefix: cidr.CIDR(T)) !void {
            const p = prefix.asNetwork();
            if (self.root == null) {
                self.root = try self.alloc.create(Node);
                self.root.?.* = .{};
            }

            try self.insertNode(self.root.?, p.addr, p.prefix_len, 0);
        }

        /// delete removes all addresses covered by prefix from the trie.
        ///
        /// If the prefix has no overlap with the trie, this is a no-op.
        /// If the prefix partially overlaps a stored aggregate, only the overlapping
        /// portion is removed; the remainder is kept as one or more sub-prefixes.
        pub fn delete(self: *Self, prefix: cidr.CIDR(T)) !void {
            const p = prefix.asNetwork();
            const root = self.root orelse return; // If the tree is empty, deletion is a no-op.

            if (try self.deleteNode(root, p.addr, p.prefix_len, 0)) {
                self.alloc.destroy(root);
                self.root = null;
            }
        }

        /// collectIter returns an iterator over all prefixes currently in the trie.
        /// The trie must not be modified while the iterator is in use.
        pub fn collectIter(self: *const Self) Iterator {
            var iter = Iterator{
                .stack = undefined,
                .stack_len = 0,
            };
            if (self.root) |r| {
                iter.stack[0] = .{ .node = r };
                iter.stack_len = 1;
            }
            return iter;
        }

        /// collect walks the trie and append all stored prefixes to out, sorted by address.
        pub fn collect(self: *const Self, out: *std.ArrayList(cidr.CIDR(T)), out_alloc: std.mem.Allocator) !void {
            var iter = self.collectIter();
            while (iter.next()) |prefix| {
                try out.append(out_alloc, prefix);
            }
        }

        /// copy creates a deep copy of the trie, using the provided allocator for the new nodes.
        pub fn copy(self: *const Self, alloc: std.mem.Allocator) !Self {
            var new_trie = Self{ .alloc = alloc };
            if (self.root) |r| {
                new_trie.root = try copyNode(alloc, r);
            }

            return new_trie;
        }

        fn copyNode(alloc: std.mem.Allocator, node: *const Node) !*Node {
            const new_node = try alloc.create(Node);
            new_node.* = .{ .filled = node.filled };

            for (0..2) |i| {
                if (node.children[i]) |child| {
                    new_node.children[i] = try copyNode(alloc, child);
                }
            }

            return new_node;
        }

        fn freeNode(self: *const Self, node: *Node) void {
            for (node.children) |c| {
                if (c) |child| {
                    self.freeNode(child);
                }
            }

            self.alloc.destroy(node);
        }

        /// deleteNode recursively deletes prefix from the subtree rooted at node.
        ///
        /// Returns true when the node itself has become empty (not filled, no children)
        /// and should be freed by the caller.
        fn deleteNode(self: *const Self, node: *Node, addr: T, size: u8, depth: u8) !bool {
            // Handle filled nodes first.
            if (node.filled) {
                if (depth == size) {
                    // Exact match: this filled node is exactly the prefix being deleted.
                    node.filled = false;
                    return true;
                }

                // This node covers a superset of the prefix to delete.
                // Expand it into two filled children so we can descend further.
                {
                    const child0 = try self.alloc.create(Node);
                    child0.* = .{ .filled = true };
                    errdefer self.alloc.destroy(child0);

                    const child1 = try self.alloc.create(Node);
                    child1.* = .{ .filled = true };

                    node.filled = false;
                    node.children[0] = child0;
                    node.children[1] = child1;
                }
            }

            // Node is not filled (was already, or was just expanded above).
            if (depth == size) {
                // Reached the target prefix length: remove every sub-prefix inside it.
                for (&node.children) |*slot| {
                    if (slot.*) |child| {
                        self.freeNode(child);
                        slot.* = null;
                    }
                }
                return true;
            }

            // Descend one bit deeper toward the target prefix.
            const bit: u1 = @truncate(addr >> @intCast(max_bits - depth - 1));
            const child = node.children[bit] orelse return false; // prefix not in trie

            if (try self.deleteNode(child, addr, size, depth + 1)) {
                self.alloc.destroy(child);
                node.children[bit] = null;
            }

            // If this internal node has lost all children, it is now empty too.
            return node.children[0] == null and node.children[1] == null;
        }

        fn insertNode(self: *const Self, node: *Node, addr: T, size: u8, depth: u8) !void {
            // Exit if this node already covers the entire subtree.
            if (node.filled) {
                return;
            }

            if (depth == size) {
                // Mark this node as a complete prefix and free any children.
                node.filled = true;
                for (&node.children) |*slot| {
                    if (slot.*) |child| {
                        self.freeNode(child);
                        slot.* = null;
                    }
                }

                return;
            }

            // Descend one bit deeper.
            const bit: u1 = @truncate(addr >> @intCast(max_bits - depth - 1));
            if (node.children[bit] == null) {
                node.children[bit] = try self.alloc.create(Node);
                node.children[bit].?.* = .{};
            }

            try self.insertNode(node.children[bit].?, addr, size, depth + 1);

            // If both children exist and are filled, free them and mark this node as a complete prefix.
            const c0 = node.children[0] orelse return;
            const c1 = node.children[1] orelse return;
            if (c0.filled and c1.filled) {
                self.freeNode(c0);
                self.freeNode(c1);
                node.children = .{ null, null };
                node.filled = true;
            }
        }
    };
}

//
// Tests
//

test "init and deinit" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    var iter = trie.collectIter();

    try std.testing.expect(iter.next() == null);
}

test "insert single prefix" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null); // No more items should follow
}

test "insert and collect to ArrayList" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("11.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("12.0.0.0/8"));

    var list: std.ArrayList(cidr.CIDRv4) = .empty;
    defer list.deinit(std.testing.allocator);
    try trie.collect(&list, std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/7"), list.items[0]);
    try std.testing.expectEqual(cidr.comptimeCIDRv4("12.0.0.0/8"), list.items[1]);
}

test "insert multiple prefixes" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("172.16.0.0/12"));
    var iter = trie.collectIter();

    // Least-significant prefixes come first
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("172.16.0.0/12"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "insert overlapping prefixes, smaller first" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert two /16's
    try trie.insert(cidr.comptimeCIDRv4("10.2.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.1.0.0/16"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.1.0.0/16"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.2.0.0/16"), iter.next());
    try std.testing.expect(iter.next() == null);

    // Insert /8: should absorb both /16's
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    var iter2 = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter2.next());
    try std.testing.expect(iter2.next() == null);
}

test "insert overlapping prefixes, larger first" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert a lot of smaller prefixes in 10.0.0.0/8, with 10.0.0.0/8 being the largest
    try trie.insert(cidr.comptimeCIDRv4("10.1.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.2.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.127.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("10.64.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.255.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.252.0.0/14"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "summarization of adjacent prefixes" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert two halves of an /8
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/9"));
    try trie.insert(cidr.comptimeCIDRv4("10.128.0.0/9"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "summarization of multiple adjacent prefixes" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert all /10 blocks in 10.0.0.0/8
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.64.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.128.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.192.0.0/10"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "partial summarization" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert all four /10 blocks in 10.0.0.0/8, excluding 10.192.0.0/10
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.64.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.128.0.0/10"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/9"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/10"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "somewhat complex summarization" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("1.0.0.0/24"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.3.0/24"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.5.1/24"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.5.254/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.6.0/26"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.6.192/26"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.7.128/26"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.2.0/24"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.5.0/24"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.5.128/25"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.5.255/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.6.128/26"));
    try trie.insert(cidr.comptimeCIDRv4("1.0.7.0/26"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.0.0/24"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.2.0/23"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.5.0/24"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.6.0/26"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.6.128/25"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.7.0/26"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.0.7.128/26"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "another somewhat complex summarization" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("127.0.0.1/32"));
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.64.0.0/10"));
    try trie.insert(cidr.comptimeCIDRv4("10.128.0.0/11"));
    try trie.insert(cidr.comptimeCIDRv4("10.160.0.0/11"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/24"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.1.0/24"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/9"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/10"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("127.0.0.1/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/23"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "duplicate prefix" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "insert with non-network addresses" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    // Insert two prefixes with host bits set (should be normalized by the trie)
    try trie.insert(cidr.comptimeCIDRv4("10.13.37.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.123/16"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, insert with non-network addresses" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    // Host bits should be silently zeroed, just as for IPv4
    try trie.insert(cidr.comptimeCIDRv6("2001:db8::1234/32"));
    try trie.insert(cidr.comptimeCIDRv6("fe80::abcd/10"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv6("fe80::/10"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, insert single prefix" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter.next());
    try std.testing.expect(iter.next() == null); // No more items should follow
}

test "IPv6, automatic summarization" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    // Insert two /33 blocks that should combine to /32
    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/33"));
    try trie.insert(cidr.comptimeCIDRv6("2001:db8:8000::/33"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, multiple non-overlapping prefixes" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    try trie.insert(cidr.comptimeCIDRv6("fe80::/10"));
    try trie.insert(cidr.comptimeCIDRv6("fc00::/7"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv6("fc00::/7"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv6("fe80::/10"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, overlapping prefixes" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("2001:db8:1::/48"));
    try trie.insert(cidr.comptimeCIDRv6("2001:db8:2::/48"));
    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8::/32"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "multiple /32's" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("1.2.3.1/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.2/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.3/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.4/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.5/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.6/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.7/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.8/32"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.1/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.2/31"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.4/30"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.8/32"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "multiple separate /32's" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("1.2.3.1/32"));
    try trie.insert(cidr.comptimeCIDRv4("1.2.3.8/32"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.1/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("1.2.3.8/32"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "0.0.0.0/0 absorbs everything" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("0.0.0.0/0"));
    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/16"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv4("0.0.0.0/0"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, ::/0 absorbs everything" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("::/0"));
    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    var iter = trie.collectIter();

    try std.testing.expectEqual(cidr.comptimeCIDRv6("::/0"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deep copy produces independent trie" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("172.16.0.0/12"));

    var trie_copy = try trie.copy(std.testing.allocator);
    defer trie_copy.deinit();

    // The copy should contain the same prefixes
    var iter = trie_copy.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("172.16.0.0/12"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), iter.next());
    try std.testing.expect(iter.next() == null);

    // Mutating the copy should not affect the original
    try trie_copy.insert(cidr.comptimeCIDRv4("8.8.8.0/24"));
    var orig_iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), orig_iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("172.16.0.0/12"), orig_iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), orig_iter.next());
    try std.testing.expect(orig_iter.next() == null);
}

test "deep copy: deleting from copy does not affect original" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));

    var trie_copy = try trie.copy(std.testing.allocator);
    defer trie_copy.deinit();

    try trie_copy.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    // Original must be unchanged
    var orig_iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), orig_iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), orig_iter.next());
    try std.testing.expect(orig_iter.next() == null);

    // Copy reflects the deletion
    var copy_iter = trie_copy.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), copy_iter.next());
    try std.testing.expect(copy_iter.next() == null);
}

test "deep copy of empty trie" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    var trie_copy = try trie.copy(std.testing.allocator);
    defer trie_copy.deinit();

    var iter = trie_copy.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "deletion from empty trie" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));
    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "insert and delete for a single prefix" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "deletion of a nonexistent prefix" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("192.168.0.0/16"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deletion of a partially present prefix" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/9"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/9"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deletion of 0.0.0.0/0" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("172.16.0.0/12"));
    try trie.delete(cidr.comptimeCIDRv4("0.0.0.0/0"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "deletion of superset" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/16"));
    try trie.insert(cidr.comptimeCIDRv4("10.1.0.0/16"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "deletion of /16 leaves a ladder of prefixes" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/16"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.1.0.0/16"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.2.0.0/15"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.4.0.0/14"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.8.0.0/13"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.16.0.0/12"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.32.0.0/11"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.64.0.0/10"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/9"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deletion of /32 leaves a ladder of prefixes" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/16"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/32"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.1/32"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.2/31"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.4/30"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.8/29"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.16/28"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.32/27"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.64/26"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.128/25"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.1.0/24"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.2.0/23"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.4.0/22"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.8.0/21"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.16.0/20"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.32.0/19"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.64.0/18"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.128.0/17"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deletion of /8 from /0 leaves complement" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("0.0.0.0/0"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("0.0.0.0/5"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("8.0.0.0/7"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("11.0.0.0/8"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("12.0.0.0/6"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("16.0.0.0/4"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("32.0.0.0/3"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("64.0.0.0/2"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("128.0.0.0/1"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "deletion of an already deleted prefix is a no-op" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "delete then re-insert of a sub-prefix reforms the original aggregate" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/16"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.1.0.0/16"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.2.0.0/15"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.4.0.0/14"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.8.0.0/13"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.16.0.0/12"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.32.0.0/11"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.64.0.0/10"), iter.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.128.0.0/9"), iter.next());
    try std.testing.expect(iter.next() == null);

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/16"));

    var iter2 = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/8"), iter2.next());
    try std.testing.expect(iter2.next() == null);
}

test "combined inserts and deletes: interleaved operations" {
    var trie = Trie(u32).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/8"));
    try trie.insert(cidr.comptimeCIDRv4("192.168.0.0/16"));
    try trie.delete(cidr.comptimeCIDRv4("10.0.0.0/8"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.0.0/16"), iter.next());
    try std.testing.expect(iter.next() == null);

    try trie.insert(cidr.comptimeCIDRv4("10.0.0.0/24"));
    try trie.delete(cidr.comptimeCIDRv4("192.168.0.0/17"));

    var iter2 = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv4("10.0.0.0/24"), iter2.next());
    try std.testing.expectEqual(cidr.comptimeCIDRv4("192.168.128.0/17"), iter2.next());
    try std.testing.expect(iter2.next() == null);
}

test "IPv6, delete exact prefix" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    try trie.delete(cidr.comptimeCIDRv6("2001:db8::/32"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}

test "IPv6, delete half of aggregate" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("2001:db8::/32"));
    try trie.delete(cidr.comptimeCIDRv6("2001:db8::/33"));

    var iter = trie.collectIter();
    try std.testing.expectEqual(cidr.comptimeCIDRv6("2001:db8:8000::/33"), iter.next());
    try std.testing.expect(iter.next() == null);
}

test "IPv6, delete from ::/0" {
    var trie = Trie(u128).init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert(cidr.comptimeCIDRv6("::/0"));
    try trie.delete(cidr.comptimeCIDRv6("::/0"));

    var iter = trie.collectIter();
    try std.testing.expect(iter.next() == null);
}
