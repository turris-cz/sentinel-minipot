# Sentinel-Minipots
`Minipots` component collects authentication data by emulating various
application layer services and sends them through Proxy to the Sentinel server.
It accommodates the implementation of minipots - minimal honeypots.


## Architecture
It consists of master process and a single child process for each emulated service.
```
                               +-----------------+
                       PIPE    |                 |    INTERNET
                +--------------+ Child           +^------------+
         +------v-------+      | (e.g., telnet)  |
   ZMQ   |              |      +-----------------+
<--------+   Master     |
         |              |
         +------+-------+      +-----------------+
                ^              |                 |   INTERNET
                +--------------+ Another child   +^------------+
                       PIPE    |                 |
                               +-----------------+
```
Master process creates child process, collects data from them and forwards
the data to Proxy. Each child process runs particular minipot. It sends data
to master process throught anonymous pipe. There can be more than one child
process running at the same time.

## Security considerations
The master process is not directly exposed to the Internet. It does not
process any input so it can run under a priviledged user. It can even run under
a lower priviledged user. It must be ensured it has enough priviledges to connect
to the ZMQ socket provided by Proxy. Child processes are started under low
priviledged user (`nobody` by default), chrooted to `/var/empty`, and dropped
the ability to get new priviledges before doing anything else. Thus, the process
is not able to read any files (outside of `/var/empty`, which shouldbe empty)
or do things reserved for high-privileged processes.

## Implementation

### Event-driven paradigm
The control flow in `Minipots` depends on events’ occurrences such as data
arrived from a pipe, data arrived from a socket, software interrupts,
sometime elapsed. The event handling is effectively solved using `libevent`
library. It provides a mechanism to execute a callback function when a specific
event occurs. First, event base and events must be declared. Events must be
added to the base, together with their callbacks and data attached to it.
Then theevent loop is run, and since that point, the program execution is
controlled by the loop. When an event occurs, its callback is executed.
The loop runs until it is broken. This approach is used in the master process
to handle incoming data from its child processes and in child processes
running minipots to manage communications on several connections.

### Resource management

### Application protocols

### Master child process communication
