#
# Makefile for RAS example
#
PROGS = RAS
CFLAGS = -g -Wall -Werror -std=gnu99
LIBS = -lpmem2

all: $(PROGS)

RAS: RAS.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

clean:
	$(RM) *.o a.out core

clobber: clean
	$(RM) $(PROGS) RAS

.PHONY: all clean clobber
