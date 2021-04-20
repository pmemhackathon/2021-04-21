#!/usr/bin/python3

import sys
import pmemkv

#
# kvprint is a callback function to process each key/value pair.
#
def kvprint(key, value):
    print(f"{memoryview(key).tobytes().decode()}=\"{memoryview(value).tobytes().decode()}\"")

#
# this is the main program, used this way:
#	kv pmemfile           -- print all the keys and values in the pmemfile
#	kv pmemfile key       -- lookup key and print the value
#	kv pmemfile key value -- add a key/value pair to the pmemfile
#
# the pmemfile is created automatically if it doesn't already exist.
#

if len(sys.argv) < 2 or len(sys.argv) > 4:
    print(f"Usage: {sys.argv[0]} kvfile [key [value]]", file=sys.stderr)
    sys.exit(1)

# configure the pmemkv engine to use the given kvfile
config = {}
config["path"] = sys.argv[1]
config["size"] = 10 * 1024 * 1024
config["create_if_missing"] = 1
db = pmemkv.Database("cmap", config)

if len(sys.argv) == 2:
    # iterate through the key-value store, printing them
    db.get_all(kvprint)
elif len(sys.argv) == 3:
    # lookup the given key and print the value
    db.get(sys.argv[2],
        lambda value:
        print(f"{sys.argv[2]}=\"{memoryview(value).tobytes().decode()}\""))
else:
    # add the given key-value pair
    db.put(sys.argv[2], sys.argv[3])

db.stop()
