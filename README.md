# librope
Librope is a implementation for Rope.

This software is still in early stage.

Maintainer: `Rubicon <l1589002388 at gmail.com>`

## Build instruction

Currently librope only offically support *unix platform. Any contribution welcome!

librope have two parts: librope and librwtp: Librwtp is an abstract implementation for Rope Wire Transfer Protocol, Librope is an implementation uses ZeroMQ as transport.

To build librope, you need libraries following:

- msgpack-c (v2.0.0 or greater)
- libsodium
- czmq

and [a zig compiler, version 0.8.0](https://ziglang.org). The zig compiler ships with clang, so you don't need to mind the C compiler on computer.

````
zig build
````
To build libraries.

````
zig build --help
````
For help.

````
zig build test
````
To run tests.

## License
Licensed under GNU General Public License, version 3 or later.

    librope - the rope that fixes the world.
    Copyright (C) 2021 Rubicon <l1589002388@gmail.com>
    Copyright (c) 2021 The Librope Contributors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
