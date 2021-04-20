#
# Makefile for simple pmemkv examples
#
OBJS = pmemkv.o kvinit.o
CXXFLAGS = -std=c++17
LIBS = -lpmemkv

all: pmemkv

pmemkv: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LIBS)

# for the Python script, the build step just checks for syntax errors
kv: kv.py
	python3 -m py_compile kv.py

clean:
	$(RM) *.o core a.out

clobber: clean
	$(RM) pmemkv

.PHONY: all clean clobber
