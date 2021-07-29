# librope
Librope is a implementation for Rope.

## Build instruction

Currently librope only offically support *unix platform. Any contribution welcome!

librope have two different parts: librope and librwtp: Librwtp is an abstract implementation for Rope Wire Transfer Protocol, Librope is an implementation uses ZeroMQ as transport.

To build librope, you need libraries following:

- msgpack-c (v2.0.0 or greater)
- libsodium
- czmq

and a C compiler supports C11 standard. Building librwtp just need the first two.

````
make rwtp
````
to make a shared library of librwtp. The production is "build/librwtp.so", You can copy the header file rwtp.h from "include".
