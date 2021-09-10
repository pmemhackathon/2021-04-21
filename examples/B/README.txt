The libpmemkv Key-Value Store

This example shows a high level API provided in multiple languages by
libpmemkv.  This example shows the concept of a persistent key-value
store that is built on top of lower-level libraries.  Reading through
this example is recommended for everyone since it provides an overview
of how the most common libraries are used together.

The pmemkv.cpp program uses the C++ language bindings for libpmemkv,
kv.py program uses the Python language bindings, and PmemkvExample is
a simple project using the Java bindings.  The programs are
very simple, so even people who are not that familiar with C++, Python,
and Java should be able to understand them.

This example consists of these files:

pmemkv.cpp        -- simple C++ program using libpmemkv
kvinit.cpp        -- convenient function for creating/opening the kv store
Makefile          -- rules for building this example
kv.py             -- simple Python program using libpmemkv
PmemkvExample/    -- simple Java project with its files:
	Makefile           -- rules for building the Java example
	pom.xml            -- project and dependencies configuration
	PmemkvExample.java -- source file (located in sub-dir src/main/java)
run_cpp.sh        -- script to run the C++ version
run_py.sh         -- script to run the Python version
run_java.sh       -- script to run the Java version
run_cross_lang.sh -- script executing all languages alternatively

To build this example run: make
To run it and see what it illustrates run:
./run_cpp.sh, ./run_py.sh or ./run_java.sh

The last script - run_cross_lang.sh - shows how data in the same
database can be accessed using various programs, even implemented
in different programming languages.  This will work in pmemkv
as long as they use the same engine.

Modifying the code and running steps is a great way to learn from this example.

This example shows a generic key-value store, called libpmemkv, which
handles all the details of persistent memory for you.  Each "put"
operation is immediately persistent, and transactional, maintaining
a consistent key-value store even if the program or machine crashes
unexpectedly.  This high-level API handles all the details like memory
mapping, allocation, flushing, etc. so the programmer doesn't have to
worry about them.

This example uses:
	- libpmemkv bindings and "cmap" engine, which uses:
	- the "cmap" persistent memory concurrent hashmap, which uses:
	- libpmemobj for allocation & transactions, which uses:
	- libpmem for low-level mapping and flushing, which uses:
	- a DAX-mounted file system to get direct access to pmem.

Although the above stack seems like lots of SW, it is all designed to
give applications direct access to their data where sits in pmem, rather
than copying data between buffers at each level.  So the operations you
see in the example, such as the "kvprint" function, are accessing the
persistent memory directly in persistent memory, not a copy fetched from
the key-value store each time.

Now that you've seen a simple, high-level API for using persistent memory,
continue on to the next example to see how you can build more complex
persistent memory programs using the libraries.
