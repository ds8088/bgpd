//! Shutdown handles OS signals in a cross-platform way and raises a Semaphore
//! once a termination signal has been received.

const std = @import("std");
const builtin = @import("builtin");
const logger = @import("logger.zig").Scoped(.shutdown);
const Semaphore = @import("Semaphore.zig");

var globalSema: *Semaphore = undefined;

/// init registers OS-level signal handlers that then raise a semaphore
/// on receiving a signal.
///
/// POSIX: handles SIGINT and SIGTERM.
/// Windows: handles CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, and
/// CTRL_SHUTDOWN_EVENT.
///
/// Must be called exactly once before any signals can arrive.
pub fn init(sema: *Semaphore) !void {
    globalSema = sema;

    switch (builtin.os.tag) {
        .windows => {
            logger.debug("setting up console control handler", .{});
            const ok = std.os.windows.kernel32.SetConsoleCtrlHandler(windowsHandler, std.os.windows.TRUE);
            if (ok == 0) {
                switch (std.os.windows.GetLastError()) {
                    std.os.windows.Win32Error.SUCCESS => {
                        logger.err("failed to set up console control handler: unknown error", .{});
                    },
                    else => |err| {
                        var buf_wstr: [2048:0]std.os.windows.WCHAR = undefined;
                        var buf_utf8: [2048]u8 = undefined;

                        const len = std.os.windows.kernel32.FormatMessageW(
                            std.os.windows.FORMAT_MESSAGE_FROM_SYSTEM | std.os.windows.FORMAT_MESSAGE_IGNORE_INSERTS,
                            null,
                            err,
                            (std.os.windows.SUBLANG.ENGLISH_US << 10) | std.os.windows.LANG.ENGLISH,
                            &buf_wstr,
                            buf_wstr.len,
                            null,
                        );

                        const sz = try std.unicode.utf16LeToUtf8(&buf_utf8, buf_wstr[0..len]);
                        logger.err("failed to set up console control handler: error {d}: {s}", .{ @intFromEnum(err), buf_utf8[0..sz] });
                    },
                }

                return error.SetConsoleCtrlHandlerFailed;
            }
        },
        else => {
            var sa = std.posix.Sigaction{
                .handler = .{ .handler = posixHandler },
                .mask = std.posix.sigemptyset(),
                .flags = std.posix.SA.RESTART,
            };

            logger.debug("setting up signal handlers", .{});
            std.posix.sigaction(std.posix.SIG.INT, &sa, null);
            std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
        },
    }
}

fn windowsHandler(ctrl_type: std.os.windows.DWORD) callconv(.winapi) std.os.windows.BOOL {
    if (ctrl_type == std.os.windows.CTRL_C_EVENT or
        ctrl_type == std.os.windows.CTRL_BREAK_EVENT or
        ctrl_type == std.os.windows.CTRL_CLOSE_EVENT or
        ctrl_type == std.os.windows.CTRL_SHUTDOWN_EVENT)
    {
        logger.debug("control event received, broadcasting shutdown", .{});
        globalSema.broadcast();
        return std.os.windows.TRUE;
    }

    return std.os.windows.FALSE;
}

fn posixHandler(_: c_int) callconv(.c) void {
    logger.debug("signal received, broadcasting shutdown", .{});
    globalSema.broadcast();
}
