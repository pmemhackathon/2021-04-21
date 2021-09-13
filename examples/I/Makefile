#
# Makefile for hmat example
#
PROGS = hmat
CFLAGS = -g -Wall -Werror -std=gnu99
LIBS = -lmemkind

all: $(PROGS)

hmat: hashmap.o hmat.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

clean:
	$(RM) *.o core

clobber: clean
	$(RM) $(PROGS) hashmap hmat 

.PHONY: all clean clobber
