const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    
    const rwtp_object = b.addObject("rwtp.o", null);
    rwtp_object.linkSystemLibrary("sodium");
    rwtp_object.linkSystemLibrary("msgpackc");
    rwtp_object.addIncludeDir("include");
    rwtp_object.addCSourceFile("src/rwtp.c", &.{"-Wall", "-g"});

    const rope_object = b.addObject("rope.o", null);
    rope_object.addIncludeDir("include");
    rope_object.linkSystemLibrary("sodium");
    rope_object.linkSystemLibrary("msgpackc");
    rope_object.linkSystemLibrary("czmq");
    rope_object.addObject(rwtp_object);
    rope_object.addCSourceFile("src/rope.c", &.{"-Wall", "-g"});

    const librwtp_static = b.addStaticLibrary("rwtp_static", null);
    librwtp_static.addIncludeDir("include");
    librwtp_static.addObject(rwtp_object);
    librwtp_static.linkLibC();
    librwtp_static.linkSystemLibrary("sodium");
    librwtp_static.linkSystemLibrary("msgpackc");
    librwtp_static.setBuildMode(mode);
    librwtp_static.install();

    const librope_static = b.addStaticLibrary("rope_static", null);
    librope_static.addIncludeDir("include");
    librope_static.addObject(rope_object);
    librope_static.linkLibC();
    librope_static.linkLibrary(librwtp_static);
    librope_static.linkSystemLibrary("czmq");
    librope_static.setBuildMode(mode);
    librope_static.install();

    const librwtp = b.addSharedLibrary("rwtp", null, .unversioned);
    librwtp.addIncludeDir("include");
    librwtp.addCSourceFile("src/rwtp.c", &.{"-Wall", "-g"});
    librwtp.linkLibC();
    librwtp.linkSystemLibrary("sodium");
    librwtp.linkSystemLibrary("msgpackc");
    librwtp.setBuildMode(mode);
    librwtp.install();

    const librope = b.addSharedLibrary("rope", null, .unversioned);
    librope.addIncludeDir("include");
    librope.addCSourceFile("src/rwtp.c", &.{"-Wall", "-g"});
    librope.addCSourceFile("src/rope.c", &.{"-Wall", "-g"});
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
    rope_test.addCSourceFile("tests/rope/main.c", &.{"-Wall", "-g"});
    rope_test.linkSystemLibrary("sodium");
    rope_test.setBuildMode(.Debug);
    const rope_test_run_step = rope_test.run();

    const rope_test_step = b.step("rope_test", "run test for rope");
    rope_test_step.dependOn(&rope_test.step);
    rope_test_step.dependOn(&rope_test_run_step.step);

    const rwtp_test = b.addExecutable("rwtp_test", null);
    rwtp_test.addIncludeDir("include");
    rwtp_test.addIncludeDir("tau");
    rwtp_test.linkLibC();
    rwtp_test.linkLibrary(librwtp_static);
    rwtp_test.addCSourceFile("tests/rwtp/main.c", &.{"-Wall", "-g"});
    rwtp_test.setBuildMode(.Debug);
    const rwtp_test_run_step = rwtp_test.run();

    const rwtp_test_step = b.step("rwtp_test", "run test for rwtp");
    rwtp_test_step.dependOn(&rwtp_test.step);
    rwtp_test_step.dependOn(&rwtp_test_run_step.step);
    
    const step_test = b.step("test", "run all tests for rope and rwtp");
    step_test.dependOn(&rwtp_test.step);
    step_test.dependOn(&rope_test.step);
    step_test.dependOn(&rwtp_test_run_step.step);
    step_test.dependOn(&rope_test_run_step.step);
}
