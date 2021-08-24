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
    PORT,
    COMPLETE,
};

pub const Uri = struct {
    schemeText: []const u8,
    hostText: []const u8,
    portText: ?[]const u8,
    alloc: ?*Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.schemeText);
            alloc.free(self.hostText);
            if (self.portText) |portText|{
                alloc.free(portText);
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
                    if (c != ':'){
                        if (lookForward == null){
                            state = ParsingState.COMPLETE;
                            result.hostText = text[start..end+1];
                        }
                    } else {
                        result.hostText = text[start..end];
                        state = ParsingState.PORT;
                        start = i+1;
                        end = i+1;
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
        return result;
    }

    pub fn parse(text: []const u8, alloc: ?*Allocator) Error!Self {
        return Self.parseAdvanced(text, alloc, alloc != null);
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
