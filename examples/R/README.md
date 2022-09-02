Example of performing an RPMA read, write and flush to persistence operations
===

This example implements both sides of an RDMA connection:
- The server prepares a local persistent memory and exposes the memory description
along with other parameters required to perform an RDMA read, write and flush operations.
After the connection is established, the server waits for the client to disconnect.
- The client allocates memory from DRAM and registers it as a reading destination
and writing source. After the connection is established the client receives
the server's memory regions registered as a reading source and a writing destination.
The client performs the RDMA read from the remote memory region to the local memory region,
then it writes new data to the local memory region and performs the RDMA write
from the local memory region to the remote memory region followed by the RPMA flush.

**Note**: The server requires a unique <user-id> argument in order to use
a different part of persistent memory which is shared by all the server instances
running on the same <pmem-path>. <user-id> is also used to pick a unique TCP port.

**Note**: For the sake of this example, the memory region being written to and
the server's peer configuration are transferred via the connection's private
data. In general, it can be transferred via an out-of-band or the in-band
channel.

## Usage

```bash
[user@server]$ ./server $server_address $port ${pmem-path} ${user-id}
```

```bash
[user@client]$ ./client $server_address $port
```
