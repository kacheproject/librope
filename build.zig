const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const cflags= [_][]const u8{"-Wall", "-Werror", "-g", "-std=c11", if (mode==.Debug) "-DDebug" else "-DRelease"};

    const asprintf_object = b.addObject("asprintf.o", null);
    asprintf_object.addIncludeDir("include");
    asprintf_object.linkLibC();
    asprintf_object.addCSourceFile("src/asprintf.c", cflags[0..]);
    
    const rwtp_object = b.addObject("rwtp.o", null);
    rwtp_object.linkSystemLibrary("sodium");
    rwtp_object.linkSystemLibrary("msgpackc");
    rwtp_object.addIncludeDir("include");
    rwtp_object.addCSourceFile("src/rwtp.c", cflags[0..]);

    const rope_object = b.addObject("rope.o", null);
    rope_object.addIncludeDir("include");
    rope_object.linkSystemLibrary("sodium");
    rope_object.linkSystemLibrary("msgpackc");
    rope_object.linkSystemLibrary("czmq");
    rope_object.addObject(rwtp_object);
    rope_object.addCSourceFile("src/rope.c", cflags[0..]);
    rope_object.addCSourceFile("src/rwtp_ext.c", cflags[0..]);

    const libroke_static = b.addStaticLibrary("roke_static", "src/roke.zig");
    libroke_static.addIncludeDir("include");
    libroke_static.linkSystemLibrary("libuv");
    libroke_static.linkSystemLibrary("zmq");
    libroke_static.setBuildMode(mode);
    libroke_static.install();

    const librwtp_static = b.addStaticLibrary("rwtp_static", null);
    librwtp_static.addIncludeDir("include");
    librwtp_static.addObject(rwtp_object);
    librwtp_static.addObject(asprintf_object);
    librwtp_static.linkLibC();
    librwtp_static.linkSystemLibrary("sodium");
    librwtp_static.linkSystemLibrary("msgpackc");
    librwtp_static.setBuildMode(mode);
    librwtp_static.install();

    const librope_static = b.addStaticLibrary("rope_static", null);
    librope_static.addIncludeDir("include");
    librope_static.addObject(rope_object);
    librope_static.addObject(asprintf_object);
    librope_static.linkLibC();
    librope_static.linkLibrary(librwtp_static);
    librope_static.linkSystemLibrary("czmq");
    librope_static.setBuildMode(mode);
    librope_static.install();

    const librwtp = b.addSharedLibrary("rwtp", null, .unversioned);
    librwtp.addIncludeDir("include");
    librwtp.addCSourceFile("src/rwtp.c", cflags[0..]);
    librwtp.addObject(asprintf_object);
    librwtp.linkLibC();
    librwtp.linkSystemLibrary("sodium");
    librwtp.linkSystemLibrary("msgpackc");
    librwtp.setBuildMode(mode);
    librwtp.install();

    const librope = b.addSharedLibrary("rope", null, .unversioned);
    librope.addIncludeDir("include");
    librope.addCSourceFile("src/rwtp.c", cflags[0..]);
    librope.addCSourceFile("src/rope.c", cflags[0..]);
    librope.addCSourceFile("src/rwtp_ext.c", cflags[0..]);
    librope.addObject(asprintf_object);
    librope.linkLibC();
    librope.linkSystemLibrary("sodium");
    librope.linkSystemLibrary("msgpackc");
    librope.linkSystemLibrary("czmq");
    librope.setBuildMode(mode);
    librope.install();

    // TODO: use zig built-in test
    const rope_test = b.addExecutable("rope_test", null);
    rope_test.addIncludeDir("include");
    rope_test.addIncludeDir("tau");
    rope_test.linkLibC();
    rope_test.linkLibrary(librope_static);
    rope_test.addCSourceFile("tests/rope/main.c", cflags[0..]);
    rope_test.linkSystemLibrary("sodium");
    rope_test.setBuildMode(.Debug);
    rope_test.install();
    const rope_test_run_step = rope_test.run();

    const rope_test_step = b.step("rope_test", "run test for rope");
    rope_test_step.dependOn(&rope_test.step);
    rope_test_step.dependOn(&rope_test_run_step.step);

    const rwtp_test = b.addExecutable("rwtp_test", null);
    rwtp_test.addIncludeDir("include");
    rwtp_test.addIncludeDir("tau");
    rwtp_test.linkLibC();
    rwtp_test.linkLibrary(librwtp_static);
    rwtp_test.addCSourceFile("tests/rwtp/main.c", cflags[0..]);
    rwtp_test.setBuildMode(.Debug);
    rwtp_test.install();
    const rwtp_test_run_step = rwtp_test.run();

    const roke_test = b.addTest("src/roke.zig");
    roke_test.addIncludeDir("include");
    roke_test.linkSystemLibrary("libuv");
    roke_test.linkSystemLibrary("zmq");

    const uri_test = b.addTest("src/uri.zig");

    const rwtp_test_step = b.step("rwtp_test", "run test for rwtp");
    rwtp_test_step.dependOn(&rwtp_test.step);
    rwtp_test_step.dependOn(&rwtp_test_run_step.step);
    
    const step_test = b.step("test", "run all tests for rope and rwtp");
    step_test.dependOn(&uri_test.step);
    step_test.dependOn(&roke_test.step);
    step_test.dependOn(&rwtp_test.step);
    step_test.dependOn(&rope_test.step);
    step_test.dependOn(&rwtp_test_run_step.step);
    step_test.dependOn(&rope_test_run_step.step);
}
