# Sentinel-minipot - minimal honeypot

It emulates Telnet, HTTP, FTP and SMTP network services. Main purpose of the Sentinel-minipot is to collect authentication information from login attempts. Not all functionalities of particular service - protocol are implemented, only functionality needed for authentication is. 
Recorded events of peer connection and authentication are logged to Sentinel proxy.

## Dependencies
libraries
 - czmq
 - libevent
 - libmsgpack
 - libb64
 - argp

compilation tools
 - gperf - a perfect hash function generator

## Compilation
GNU Autotools are used for building executable file from the source code.
C99 compliant compiler is needed.

In main project folder run:

- `autoreconf`
- `./configure`
- `make`

### Program arguments

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

`./sentinel_minipot -H 9000 -F 9001 -S 9002`


### More info
For more information about Sentinel-minipot see `doc` folder. More information about tests see `README` and `doc` in `tests/integration` and `README` in `tests/manual`.