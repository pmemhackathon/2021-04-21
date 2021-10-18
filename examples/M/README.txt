RAS Persistent Memory Example

RAS (Reliability, Availability and Serviceability) features were designed
to support handling unique errors, which can be encountered in the
applications using persistent memory.

In this particular example, it is presented how we can use USC
(unsafe shutdown count) to detect unsafe shutdowns and act accordingly.
The occurance of the unsafe shutdown event indicates that flushing the data
to the persistent medium could have failed and the data might be corrupted.
The libpmem2 library is used to check the state of the persistent memory pool,
return the adequate message to the user and to repair the data if possible.

Another presented functionality is using libpmem2 for the purpose of
reading and clearing encountered bad blocks. Since uncorrectable errors
for persistent memory will survive power loss, they may require special
handling to clear corrupted data. Clearing uncorrectable errors is the
software's responsibility. With libpmem2, we unmap bad blocks and map new,
healthy blocks in their places. The new blocks are zeroed and the content
of bad blocks is lost.

C programming experience is recommended to get the most out of this example.

This example consists of these files:

RAS.c    -- example showing the usage of USC interfaces and additionally,
               a bad blocks handling
Makefile -- rules for building this example
run.sh   -- one way to run this example to illustrate what it does

To build this example run: make
To run it and see what it illustrates run: ./run.sh

Modifying the code and run steps is a great way to learn from this example.
