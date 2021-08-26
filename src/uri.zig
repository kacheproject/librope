const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error {
    BadSyntax,
} || Allocator.Error;

const ParsingState = enum {
    EMPTY,
    SCHEME,
    SCHEME_SEP,
    HOST,
    HOST_SEP,
    PORT,
    COMPLETE,
};

pub const Uri = struct {
    schemeText: []const u8,
    hostText: []const u8,
    portText: ?[]const u8,
    alloc: ?*Allocator,
    selfInAllocator: bool = false,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.schemeText);
            alloc.free(self.hostText);
            if (self.portText) |portText|{
                alloc.free(portText);
            }
            if (self.selfInAllocator){
                alloc.destroy(self);
            }
        }
    }

    pub fn parseAdvanced(text: []const u8, alloc: ?*Allocator, copy: bool)  Error!Self {
        var result = Self {
            .schemeText = undefined,
            .hostText = undefined,
            .portText = null,
            .alloc = alloc,
        };
        var state = ParsingState.EMPTY;
        var start: usize = 0;
        var end: usize = 0;
        var errpos: usize = text.len-1;
        var inIPv6: bool = false;
        for (text) |c, i| {
            const lookForward: ?u8 = if (i<(text.len-1)) text[i+1] else null;
            switch (state){
                ParsingState.EMPTY => {
                    state = ParsingState.SCHEME;
                    end = i;
                },
                ParsingState.SCHEME => {
                    if (lookForward) |lookf| {
                        end = i;
                        if (c == ':' and lookf == '/'){
                            result.schemeText = text[start..end];
                            state = ParsingState.SCHEME_SEP;
                            start = i+1;
                            end = i+1;
                        }
                    } else {
                        errpos = i;
                        return Error.BadSyntax;
                    }
                },
                ParsingState.SCHEME_SEP => {
                    if (c == '/'){
                        end = i;
                    }
                    if (lookForward) |lookf| {
                        if ((end - start == 1) and (lookf != '/')){
                            state = ParsingState.HOST;
                            start = i+1;
                            end = i+1;
                        } else if (end - start < 1) {
                            continue;
                        } else {
                            errpos = i;
                            return Error.BadSyntax;
                        }
                    } else {
                        errpos = i;
                        return Error.BadSyntax;
                    }
                },
                ParsingState.HOST => {
                    end = i;
                    if (c == '[') {
                        start = i+1;
                        inIPv6 = true;
                    } else if (c == ']') {
                        state = .HOST_SEP;
                        result.hostText = text[start..end];
                    }
                    if (lookForward) |lf| {
                        if (!inIPv6 and lf == ':'){
                            state = ParsingState.HOST_SEP;
                            result.hostText = text[start..end+1];
                        }
                    } else {
                        state = .COMPLETE;
                        result.hostText = text[start..(if (inIPv6) end else end+1)];
                    }
                },
                ParsingState.HOST_SEP => {
                    if (c == ':' and lookForward != null){
                        state = ParsingState.PORT;
                        start = i+1;
                        end = i+1;
                    } else {
                        errpos = i;
                        return Error.BadSyntax;
                    }
                },
                ParsingState.PORT => {
                    end = i;
                    if (lookForward == null){
                        result.portText = text[start..end+1];
                        state = ParsingState.COMPLETE;
                    }
                },
                ParsingState.COMPLETE => {
                    break;
                }
            }
        }
        if (state != .COMPLETE){
            return Error.BadSyntax;
        }
        if (copy){
            if (alloc) |alloc_real| {
                result.schemeText = try alloc_real.dupe(u8, result.schemeText);
                result.hostText = try alloc_real.dupe(u8, result.hostText);
                if (result.portText) |portText| {
                    result.portText = try alloc_real.dupe(u8, portText);
                }
            } else unreachable;
        }
        std.debug.print("\n", .{});
        return result;
    }

    pub fn parse(text: []const u8, alloc: ?*Allocator) Error!Self {
        return Self.parseAdvanced(text, alloc, alloc != null);
    }

    pub fn port(self: *const Self) std.fmt.ParseIntError!?u16 {
        if (self.portText) |portText| {
            return try std.fmt.parseInt(u16, portText, 0);
        } else {
            return null;
        }
    }

    pub fn isIPv4(self: *const Self) bool {
        for (self.hostText) |c| {
            if (!(std.ascii.isDigit(c) or c == '.')){
                return false;
            }
        } else {
            return true;
        }
    }

    pub fn isIPv6(self: *const Self) bool {
        for (self.hostText) |c| {
            if (c == ':'){
                return true;
            }
        } else {
            return false;
        }
    }

    pub fn isDomain(self: *const Self) bool {
        return !(self.isIPv4() or self.isIPv6());
    }

    pub fn dupe(self: *const Self, new_alloc: ?*Allocator) Allocator.Error!Self {
        if (new_alloc) |alloc| {
            var schemeText = try alloc.dupe(u8, self.schemeText);
            errdefer alloc.free(schemeText);
            var hostText = try alloc.dupe(u8, self.hostText);
            errdefer alloc.free(hostText);
            var portText = if(self.portText) |oldPortText| try alloc.dupe(u8, oldPortText) else null;
            errdefer alloc.free(portText);
            return Self {
                .schemeText = schemeText,
                .hostText = hostText,
                .portText = portText,
                .alloc = alloc,
            };
        } else {
            return Self {
                .schemeText = self.schemeText,
                .hostText = self.hostText,
                .portText = self.portText,
                .alloc = self.alloc,
            };
        }
    }

    /// Copy the object and the strings refered into allocator's memory.
    pub fn copyInto(self: *const Self, alloc: *Allocator) Allocator.Error!*Self {
        var newObject = try self.dupe(alloc);
        var newSelf = try alloc.create(Self);
        newSelf.* = newObject;
        newSelf.selfInAllocator = true;
        return newSelf;
    }
};

test "Uri.parse can parse simple uri strings" {
    const testing = std.testing;
    const uri0 = try Uri.parse("tcp://127.0.0.1:1080", null);
    try testing.expectEqualStrings("tcp", uri0.schemeText);
    try testing.expectEqualStrings("127.0.0.1", uri0.hostText);
    try testing.expectEqualStrings("1080", uri0.portText.?);

    const uri1 = try Uri.parse("wg://localhost", null);
    try testing.expectEqualStrings("wg", uri1.schemeText);
    try testing.expectEqualStrings("localhost", uri1.hostText);
    try testing.expect(uri1.portText == null);
}

test "Uri.parse can make copy when alloc specified" {
    const testing = std.testing;
    var uriString: []u8 = try testing.allocator.dupe(u8, "tcp://127.0.0.1:1080");
    var uri0 = try Uri.parse(uriString, testing.allocator);
    testing.allocator.free(uriString);
    try testing.expectEqualStrings("tcp", uri0.schemeText);
    try testing.expectEqualStrings("127.0.0.1", uri0.hostText);
    try testing.expectEqualStrings("1080", uri0.portText.?);
    uri0.deinit();
}

test "Uri.port will return port digits when port exists" {
    const testing = std.testing;
    const uri0 = try Uri.parse("wg://localhost:1082", null);
    try testing.expectEqual(@intCast(u16, 1082), (try uri0.port()).?);

    const uri1 = try Uri.parse("udp://myhomeserver.local:!", null);
    try testing.expectError(std.fmt.ParseIntError.InvalidCharacter, uri1.port());

    const uri2 = try Uri.parse("webrtc://kache.myhomeserver.example.org", null);
    try testing.expect(null == try uri2.port());
}

test "Uri.parse can parse IPv6 address" {
    const testing = std.testing;
    const uri0 = try Uri.parse("tcp://[::1]:1080", null);
    try testing.expectEqualStrings("tcp", uri0.schemeText);
    try testing.expectEqualStrings("::1", uri0.hostText);
    try testing.expectEqualStrings("1080", uri0.portText.?);

    const uri1 = try Uri.parse("wg://[::1]", null);
    try testing.expectEqualStrings("wg", uri1.schemeText);
    try testing.expectEqualStrings("::1", uri1.hostText);
    try testing.expect(uri1.portText == null);

    const uri2 = try Uri.parse("udp://[2001:0db8:0000:0000:0000:8a2e:0370:7334]:64", null);
    try testing.expectEqualStrings("udp", uri2.schemeText);
    try testing.expectEqualStrings("2001:0db8:0000:0000:0000:8a2e:0370:7334", uri2.hostText);
    try testing.expectEqualStrings("64", uri2.portText.?);
}

test "Uri.isIPv4, .isIPv6, .isDomain can identify type of host text" {
    const testing = std.testing;
    const uri0 = try Uri.parse("wg://127.0.0.1:1082", null);
    try testing.expect(uri0.isIPv4());
    try testing.expect(!uri0.isIPv6());
    try testing.expect(!uri0.isDomain());

    const uri1 = try Uri.parse("tcp://[::1]", null);
    try testing.expect(!uri1.isIPv4());
    try testing.expect(uri1.isIPv6());
    try testing.expect(!uri1.isDomain());

    const uri2 = try Uri.parse("udp://myserver.org", null);
    try testing.expect(!uri2.isIPv4());
    try testing.expect(!uri2.isIPv6());
    try testing.expect(uri2.isDomain());
}

test "Uri.dupe can make copy on heap or on stack" {
    const testing = std.testing;
    const uri0 = try Uri.parse("wg://[unix:///dev/null]", null);
    
    var uri1 = uri0.dupe(null) catch return;
    try testing.expect(uri0.schemeText.ptr == uri1.schemeText.ptr);
    try testing.expect(uri0.hostText.ptr == uri1.hostText.ptr);

    var uri2 = try uri0.dupe(testing.allocator);
    try testing.expect(uri0.schemeText.ptr != uri2.schemeText.ptr);
    try testing.expectEqualStrings(uri0.schemeText, uri2.schemeText);
    try testing.expect(uri0.hostText.ptr != uri2.hostText.ptr);
    try testing.expectEqualStrings(uri0.hostText, uri2.hostText);
    uri2.deinit();
}

test "Uri.copyInto can copy whole object into allocator's memory" {
    const testing = std.testing;
    const uri0 = try Uri.parse("tcp://[unix:///dev/null]", null);
    var uri2 = try uri0.copyInto(testing.allocator);
    try testing.expect(uri0.schemeText.ptr != uri2.schemeText.ptr);
    try testing.expectEqualStrings(uri0.schemeText, uri2.schemeText);
    try testing.expect(uri0.hostText.ptr != uri2.hostText.ptr);
    try testing.expectEqualStrings(uri0.hostText, uri2.hostText);
    try testing.expect(uri2 != &uri0);
    uri2.deinit();
}
