# sentinel-minipot

## Introduction

This document describes the overall architecture of sentinel-minipot.

Sentinel-minipot serves the purpose of emulating simple honeypot services and
sending their recorded events to Sentinel server.

It consists of master process and a single process for each emulated service.

## Master process

Master process starts the other processes and forwards their messages to ZMQ
socket.

Master is supposed to run under root. It starts the minipot child processes
with low privileges, in chroot.

Since the child processes are chrooted, they cannot open files/sockets. Master
provides anonymous pipe to their child processes, where the child processes
report their events.

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

## Security considerations

Master is not directly exposed to the evil wild Internet, it does not process
any input, so it can run under root. It can even run under lower privileged
user, it must be just ensured it has enough privileges to connect to the ZMQ
socket provided by proxy.

Child processes are started under low privileged user (nobody by default),
chrooted to /var/empty and drops the ability to get new privileges before
doing anything else. The process is thus not able to read any files (outside of
/var/empty, which should be empty) or do things that are reserved for
high-privileged processes.

The fact that event messages are not sent from child processes directly to ZMQ
socket allows some filtering of messages. Child proceses do not send their
messages to master in the same form as is passed to the ZMQ then, they rather
use a special protocol. This should prevent child process from spoofing any
type of message.

## Master - child protocol

The protocol from child to parent is very simple. It uses raw socket, anonymous
pipe between master and child.

Every message consists of three parts - additional data, action, ip. Each part
is preceded by int of 4B size containing the length of the message. While
action and ip are strings, additional data might be any MSGPACK object.
Additional data might be empty (length 0 and no data after that).

The master process creates the actual ZMQ message from them.

Consider the following message:
`data={"user": "root", "pass":"root"}, ip="1.2.3.4", action="login"`
The message would look like this on the wire-level (in the anonymous pipe):
```
15 00 00 00 82 a4 75 73 65 72 a4 72 6f 6f 74 a4 70 61 73 73 a4 72 6f 6f 74
|---------| |------------------------------------------------------------|
 data size                  additional data (MSGPACK object)

05 00 00 00 6C 6F 67 69 6E 07 00 00 00 31 2E 32 2E 33 2E 34
|---------| |------------| |---------| |------------------|
action size  action (str)    ip size       ip (string)
            l  o  g  i  n              1  .  2  .  3  .  4
```
Master process will create the following ZMQ message from it (assuming it was
received from telnet minipot):
```
{"type": "telnet", "ts": #timestamp, "action": "login", "ip": "1.2.3.4",
"data": {"user": "root", "pass":"root"}}
```

Type is always added according to the child process from which the messages was
received. When no additional data have been sent, "data" entry is not emitted.

## Event handling
Each process uses libevent API for handling dedicated events throught events' callbacks. After start-up settings an event loop is run and from this point all the events (reads, writes from/to socket, pipe, signals etc.) are handled by their callbacks.

## Child process
Child processes implements functionality for particular service. The functionality is given to a service by executing protocol specific handler. Thus there can be more than one child process running same handler - protocol, but of course on different port.


## Child process - TCP
Until now all implemented protocols uses TCP as underlying protocol. So there is a common code base for handling TCP. Minipot can handle some predefined count of simultaneous connections. All the connections are handled by eventloop so only one connection is processed/served at the time. Connections are not handled in parallel manner.


## Child process - data structures
Each minipot can be represented as a set of data structures. All minipots have same main data structure. There is one data structure per opened TCP connection. At a service start, pool of connections' structure of predefined size is dynamically allocated.  When a new connection is established it gets assigned data from the pool. When connection is closed the data are put back to the pool. Every particular buffer has its predefined length. If data doesn't fit they are ignored. The pool memory is freed at a service process shutdown.


## Child process - server protocol
The particular protocol server functionality is implemented by one or two finite state machines. One FSM is used for processing received bytes. The second one is used in case of stateful protocol to implement state dependent functionality.