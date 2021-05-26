# Sentinel-minipot - minimal honeypot

It emulates Telnet, HTTP, FTP and SMTP network services. Main purpose of the Sentinel-minipot is to collect authentication information from login attempts. Not all functionalities of particular service - protocol are implemented, only functionality needed for authentication is.
Recorded events of peer connection and authentication are logged to Sentinel proxy.

## Dependencies
 - czmq
 - libevent
 - libmsgpack
 - [base64c](https://gitlab.nic.cz/turris/base64c)
 - [logc](https://gitlab.nic.cz/turris/logc)
 - [logc-libs](https://gitlab.nic.cz/turris/logc-libs)

for non glibc:
 - [argp-standalone](http://www.lysator.liu.se/~nisse/misc/)

compilation tools:
 - gperf - a perfect hash function generator

For bootstrap (not release tarballs):
- autotools
- autoconf-archive

For tests:
- [check](https://libcheck.github.io/check)
-  Optionally [valgrind](http://www.valgrind.org)


## Compilation and tests
GNU Autotools are used for building executable file from the source code.
C99 compliant compiler is needed.

In main project folder run:

```
./bootstrap
./configure
make
```

To enable tests run:
```./bootstrap --enable-tests```

To run tests:
```make ckeck```

To run tests with valgrind:
```make check-valgrind```

To run tests with just one specific Valgrind test such as memtest you can run:
``` make check-valgrind-memcheck ```

## Program arguments

optional - these arguments has a default values in case their value is not given by input arguments.

- `-u x` - user to drop privileges. Default is `nobody`.
- `-t x` - MQTT topic for later communication of Sentinel proxy with server. Default is `sentinel/collect/minipot`.
- `-s x` - local ZMQ socket for interprocess communication with Sentinel proxy. Default is `ipc:///tmp/sentinel_pull.sock`.

mandatory - At least one of them must be present. These arguments define which minipots are run on which ports, so at least one minipot must be set up for running.

- `-T x` - Telnet minipot on port x
- `-H x` - HTTP minipot on port x
- `-F x` - FTP minipot on port x
- `-S x` - SMTP minipot on port x

Several instances of same service minipot - child process can run together. Of course not at the same port.

E.g. for running HTTP minipot on port 9000, FTP minipot on port 9001 and SMTP minipot on port 9002 run:

```./sentinel_minipot -H 9000 -F 9001 -S 9002```
