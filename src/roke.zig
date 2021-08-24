const std = @import("std");
const Allocator = std.mem.Allocator;
const TailQueue = std.TailQueue;
const Thread = std.Thread;

const uri = @import("uri");

const c = @cImport(
    @cInclude("roke.h")
);

/// Thread-safe queue.
/// It's recommended to do not access specific fields.
///
/// Example:
/// ````
/// const std = @import("std");
/// const alloc = std.heap.GeneralPurposeAllocator(.{});
/// const queue = AtomicQueue(i64).init(&alloc.allocator);
/// queue.deinit();
/// ````
fn AtomicQueue(comptime T: type) type {
    return struct {
        zctx: *c_void,
        q0: *c_void, // zmq socket, in
        q1: *c_void, // zmq socket, out
        length: usize = 0,

        const Self = @This();

        pub fn init() Allocator.Error!Self {
            const zctx = c.zmq_ctx_new();
            if (zctx == null) return Allocator.Error.OutOfMemory;
            errdefer _ = c.zmq_ctx_term(zctx);
            _ = c.zmq_ctx_set(zctx, c.ZMQ_IO_THREADS, 0);
            _ = c.zmq_ctx_set(zctx, c.ZMQ_BLOCKY, 0);
            const q0 = c.zmq_socket(zctx, c.ZMQ_PAIR);
            if (q0 == null) return Allocator.Error.OutOfMemory;
            errdefer _ = c.zmq_close(q0);
            const q1 = c.zmq_socket(zctx, c.ZMQ_PAIR);
            if (q1 == null) return Allocator.Error.OutOfMemory;
            errdefer _ = c.zmq_close(q1);
            if (c.zmq_bind(q0, "inproc://queue") != 0){
                return Allocator.Error.OutOfMemory;
            }
            if(c.zmq_connect(q1, "inproc://queue") != 0){
                return Allocator.Error.OutOfMemory;
            }
            return Self {
                .zctx = zctx.?,
                .q0 = q0.?,
                .q1 = q1.?,
            };
        }

        pub fn deinit(self: *Self) void {
            self.clear();
            _ = c.zmq_close(self.q0);
            _ = c.zmq_close(self.q1);
            _ = c.zmq_ctx_term(self.zctx);
        }

        pub fn isEmpty(self: *Self) bool {
            return self.length == 0;
        }

        pub fn put(self: *Self, val: T) Allocator.Error!void {
            if (c.zmq_send(self.q0, &val, @sizeOf(T), 0) != -1){
                _ = @atomicRmw(usize, &self.length, .Add, 1, .Monotonic);
            } else {
                return Allocator.Error.OutOfMemory;
            }
        }

        fn _get(self: *Self, flags: c_int) ?T {
            var value: T = undefined;
            if (c.zmq_recv(self.q1, @ptrCast(*c_void, &value), @sizeOf(T), flags) != -1){
                _ = @atomicRmw(usize, &self.length, .Sub, 1, .Monotonic);
                return value;
            } else {
                return null;
            }
        }

        pub fn get(self: *Self) ?T {
            return self._get(0);
        }

        pub fn tryGet(self: *Self) ?T {
            return self._get(c.ZMQ_DONTWAIT);
        }

        pub fn clear(self: *Self) void {
            while (!self.isEmpty()){
                _ = self.get();
            }
        }
    };
}

test "AtomicQueue can put and get elements" {
    const testing = std.testing;
    const print = std.debug.print;
    var queue = try AtomicQueue(i64).init();
    defer queue.deinit();
    try queue.put(@intCast(i64, 1));
    try queue.put(@intCast(i64, 2));
    try queue.put(@intCast(i64, 3));
    try testing.expectEqual(@intCast(i64, 1), queue.get().?);
    try testing.expectEqual(@intCast(i64, 2), queue.get().?);
    try testing.expectEqual(@intCast(i64, 3), queue.get().?);
}

pub const Op = enum (i8){
    SEND,
    RECV,
    BIND,
    CONNECT,
    ACCEPT,
};

pub const Error = error {
    InvalidAddress,
} || Allocator.Error;

pub const IOError = error {};

pub const RokeCtx = struct {
    sq: AtomicQueue(*SQE),
    cq: AtomicQueue(*CQE),
    uvloop: c.uv_loop_t = undefined,
    alloc: *Allocator,

    const Self = @This();

    pub fn init(alloc: *Allocator) Error!Self {
        var result = Self {
            .sq = try AtomicQueue(*SQE).init(),
            .cq = try AtomicQueue(*CQE).init(),
            .alloc = alloc,
        };
        if(c.uv_loop_init(&result.uvloop) != 0){
            return Error.OutOfMemory;
        }
        return result;
    }

    pub fn deinit(self: *Self) void {
        _ = c.uv_loop_close(&self.uvloop);
        self.sq.deinit();
        self.cq.deinit();
    }

    fn _handleSingleSQE(self: *Self, sqe: *SQE) Error!void {
        var cqe = sqe.relatedCQE();
        switch (sqe.op){
            CONNECT => {
                // TODO: handle single SQE
            }
        }
    }

    pub fn enter(self: *Self, timeout: i32, wait_for_n: i32) Error!void {
        // TODO: handle SQE and I/O operation
    }
};

pub const Type = enum (i8){
    TCP, UDP,
}

pub const Roke = struct {
    roke_type: Type,
    handle: *c.uv_handle_t,

    const Self = @This();

    pub fn asTCP() *c.uv_tcp_t {
        // Check and return
    }

    pub fn asUDP() *c.uv_udp_t {
        // Check and return
    }
};

pub const SQE = struct {
    ctx: *RokeCtx,
    op: Op,
    buf: ?[]u8,
    flags: i32,

    const Self = @This();

    pub fn relatedCQE(self: *Self) *CQE {
        return @fieldParentPtr(RokeCQE, "sqe", self);
    }

    pub fn setupConnect(self: *Self, uri: []const u8) Error!void {
        // TODO: SQE setup connect
    }
};

pub const CQE = struct {
    sqe: SQE,
    status: IOError!i32,
    buf: ?[]u8,
    flags: i32,

    pub fn relatedSQE(self: *Self) *SQE {
        return &self.sqe;
    }

    pub fn consume(self: *Self) void {
        // TODO: release CQE resources
    }
};

export fn roke_ctx_init() ?*c_void {
    var ins = std.heap.c_allocator.create(RokeCtx) catch return null;
    errdefer std.heap.c_allocator.destroy(ins);
    ins.* = RokeCtx.init(std.heap.c_allocator) catch return null;
    return ins;
}

export fn roke_ctx_deinit(self: *RokeCtx) void {
    self.deinit();
    std.heap.c_allocator.destroy(self);
}
