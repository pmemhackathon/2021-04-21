Low-Level Persistent Memory Hacking

This example is for programmers who want raw access to persistent memory.
Instead of the allocation, transactions, and other features of the
high-level PMDK APIs, this example focused on how the hardware works and
the low-level responsibilities of an application using persistent memory.
Unlike Example A, which just explained the concept or raw memory mapping,
this example is more complete, using libpmem2 to provide the correct
arguments to mmap() and optimized ways of copying to persistent memory.

If you are interested in raw access to pesistent memory and want to
handle everything else yourself, this example is for you. C programming
experience recommended.

This example consists of these files:

lowlevel.c -- example showing low-level pmem programming using libpmem2
Makefile   -- rules for building this example
run.sh     -- one way to run this example to illustrate what it does

To build this example run: make
To run it and see what it illustrates run: ./run.sh

Modifying the code and run steps is a great way to learn from this example.

This example shows pmem programming when you want to do eveything
yourself. There are no transactions or allocators here -- that's
all up to the programmer. We use libpmem2 to cover the low-level
boiler-plate code that sets required configuration and memory maps a file.
The correct mechanism for flushing data onto the underlaying storage is
automatically determined by libpmem2.

Have at it. But when you get tired of writing code to deal with
inconsistent data structures after a crash, you might take a look
at the libpmemobj examples.
