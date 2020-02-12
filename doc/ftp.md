# sentinel-minipot

## FTP
FTP is statefull, command-response protocol. There are two finite state machines used to implement the functionality.


## Authentication

Authentication mechanism of FTP is realized by USER and PASS command sequence. Where obviously username is argument of USER command and password is argument of PASS command.

## Recorded events

- client connection establishment

- login attempt - immediate sequence of USER and PASS commands
    Only username and password are recorded.
