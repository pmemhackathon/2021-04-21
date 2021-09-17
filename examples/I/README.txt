Allocation tiering based on memory-characteristics.

Starting from Linux Kernel version 5.5, the NUMA nodes concept was enhanced with
new memory attributes: latency, capacity and bandwidth. We could use them to
allocate data used in different scenarios on different types of memory. Note,
that we don't explicitly say which kind of medium (e.g. DRAM or PMEM) we want to
use here, because some characteristics (like latency or bandwidth) could be
relative to relationship between source and destination NUMA nodes. Instead of
that we use a concept of "lowest latency" or "highest bandwidth" nodes that
could be accessed from a CPU that runs our program. This concept was added to
Memkind 1.11. To use it, a hwloc library must be installed on the system with
kernel >= 5.5. For more information about memory attributes, see great 
https://pmem.io/2021/05/12/hmat_memkind.html article on PMEM.io blog.

In this example we use MEMKIND_LOWEST_LATENCY_LOCAL and MEMKIND_HIGHEST_CAPACITY
memory kinds to allocate simple array of data and access it through a hashmap.
Because all hashmap operations like searching or adding new data should be
efficient, keys that identifies user data entries are allocated in lowest
latency memory. On the other hand, because size of the data entires could be
huge, to allocate them we want a memory with highest capacity.

This example is intended for C programmers.

This example consists of the following files:

hashmap.c/h -- an example of hashmap that uses custom data allocator
hmat.c      -- main file that uses Memkind and hashmap
Makefile    -- rules for building this example
run.sh      -- one way to run this example to illustrate what it does

To build this example run: make
To run it and see what it illustrates run: ./run.sh

Modifying the code and run steps is a great way to learn from this example.

There is no persistent storage in this example, so topics such as:
 - flushing to persistent storage,
 - transactions and failure atomicity
 are not considered.
 