//! Semaphore provides a waitable semaphore implementation.
//!
//! The semaphore can only be raised once per its lifetime.

const builtin = @import("builtin");
const std = @import("std");

atomic: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
mutex: std.Thread.Mutex = .{},
cond: std.Thread.Condition = .{},

const Self = @This();

pub const init: Self = .{};

/// broadcast raises the semaphore and wakes all waiting threads.
pub fn broadcast(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    self.atomic.store(true, .release);
    self.cond.broadcast();
}

/// timedWait waits for the semaphore with a timeout.
///
/// Returns true if signaled, false if timeout expired.
pub fn timedWait(self: *Self, timeout_ns: u64) bool {
    // Fast path: check if already signaled without locking.
    if (self.isSignaled()) {
        return true;
    }

    // Otherwise, perform a timed wait with a locked mutex.
    self.mutex.lock();
    defer self.mutex.unlock();

    // Re-check under the lock: broadcast() may have fired between the
    // fast-path check above and the mutex acquisition.
    if (!self.isSignaled()) {
        self.cond.timedWait(&self.mutex, timeout_ns) catch {};
    }

    return self.isSignaled();
}

/// sleep works the same as timedWait, but avoids spurious wakeups.
pub fn sleep(self: *Self, sleep_ns: u64) bool {
    var last_time: i128 = std.time.nanoTimestamp();
    var current_time: i128 = 0;
    var remaining_ns: u64 = sleep_ns;
    const epsilon = 5 * std.time.ns_per_ms;

    while (true) {
        if (remaining_ns <= epsilon) {
            return self.isSignaled();
        }

        // Perform a timed wait.
        if (self.timedWait(remaining_ns)) {
            return true;
        }

        current_time = std.time.nanoTimestamp();
        const elapsed_ns = current_time - last_time;
        if (elapsed_ns < 0 or elapsed_ns > std.math.maxInt(@TypeOf(remaining_ns))) {
            // Time went backwards, or the difference is too big.
            remaining_ns = sleep_ns;
        } else if (elapsed_ns < @as(i128, sleep_ns)) {
            remaining_ns = sleep_ns - @as(u64, @intCast(elapsed_ns));
        } else {
            remaining_ns = 0;
        }

        last_time = current_time;
    }
}

/// Lock-free check if the signal has been raised.
///
/// Useful for fast-path checking without acquiring the mutex.
pub fn isSignaled(self: *const Self) bool {
    return self.atomic.load(.acquire);
}

test "signal is initially not raised" {
    var sig = Self.init;
    try std.testing.expect(!sig.isSignaled());
}

test "timedWait returns false on timeout" {
    var sig = Self.init;

    // Wait 1 ms
    const signaled = sig.timedWait(1 * std.time.ns_per_ms);

    // Should timeout since no broadcast was called
    try std.testing.expect(!signaled);
    try std.testing.expect(!sig.isSignaled());
}

test "consecutive isSignaled calls" {
    var sig = Self.init;
    try std.testing.expect(!sig.isSignaled());

    sig.broadcast();

    // All 3 of these should return TRUE
    try std.testing.expect(sig.isSignaled());
    try std.testing.expect(sig.isSignaled());
    try std.testing.expect(sig.isSignaled());
}

test "broadcast sets signal and wakes multiple waiters" {
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    var sig = Self.init;
    var sema = std.Thread.Semaphore{};
    var result = std.atomic.Value(u8).init(0);

    const waiterFn = struct {
        fn run(thread_sema: *std.Thread.Semaphore, thread_sig: *Self, thread_result: *std.atomic.Value(u8)) void {
            // Signal the semaphore
            thread_sema.post();

            // Wait for the signal and save the result
            const signaled = thread_sig.timedWait(1 * std.time.ns_per_s);
            _ = thread_result.fetchAdd(@intFromBool(signaled), .release);
        }
    }.run;

    const num_threads = 10;

    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, waiterFn, .{ &sema, &sig, &result });
    }

    // Wait until all threads starts working
    for (0..num_threads) |_| {
        sema.wait();
    }

    sig.broadcast(); // Broadcast the signal

    // Wait for all threads to finish
    for (0..num_threads) |i| {
        threads[i].join();
    }

    // Verify the waiter received the signal
    try std.testing.expectEqual(result.load(.acquire), num_threads);
    try std.testing.expect(sig.isSignaled());
}

test "sleep returns false on timeout" {
    var sig = Self.init;

    const sleep_ms: u64 = 50;
    const start = std.time.nanoTimestamp();
    const signaled = sig.sleep(sleep_ms * std.time.ns_per_ms);
    const elapsed = std.time.nanoTimestamp() - start;

    // Should timeout since no broadcast was called
    try std.testing.expect(!signaled);
    try std.testing.expect(!sig.isSignaled());

    // Verify the sleep duration is approximately correct.
    const elapsed_ms = @divTrunc(elapsed, std.time.ns_per_ms);
    try std.testing.expect(elapsed_ms >= sleep_ms - 10);
    try std.testing.expect(elapsed_ms <= sleep_ms + 30);
}

test "timedWait returns true when already signaled" {
    var sig = Self.init;
    sig.broadcast();

    try std.testing.expect(sig.timedWait(0));
}

test "sleep returns true when already signaled" {
    var sig = Self.init;
    sig.broadcast();

    try std.testing.expect(sig.sleep(1 * std.time.ns_per_s));
}

test "sleep returns true when signaled" {
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    var sig = Self.init;
    var sema = std.Thread.Semaphore{};

    const signalFn = struct {
        fn run(thread_sema: *std.Thread.Semaphore, thread_sig: *Self) void {
            thread_sema.wait(); // Wait for main thread to start sleeping
            std.Thread.sleep(20 * std.time.ns_per_ms); // Wait 20ms
            thread_sig.broadcast(); // Signal the semaphore
        }
    }.run;

    const thread = try std.Thread.spawn(.{}, signalFn, .{ &sema, &sig });

    // Start sleeping for 500ms
    sema.post(); // Signal thread to start
    const start = std.time.nanoTimestamp();
    const signaled = sig.sleep(500 * std.time.ns_per_ms);
    const elapsed = std.time.nanoTimestamp() - start;

    thread.join();

    // Should be signaled before timeout
    try std.testing.expect(signaled);
    try std.testing.expect(sig.isSignaled());

    // Should have woken up early (much less than 500ms)
    const elapsed_ms = @divTrunc(elapsed, std.time.ns_per_ms);
    try std.testing.expect(elapsed_ms < 100);
}
