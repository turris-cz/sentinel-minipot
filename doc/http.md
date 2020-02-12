# sentinel-minipot

## HTTP
An HTTP is a request-response stateless protocol. After each client request server sends response.
Only one finite state machine is used for implementing the protocol.

## Authentication
Only HTTP Basic authentication scheme is supported.

## Recorded events

- client connection establishment

- new HTTP message
    Following parts of request message are recorded:
    - Start/request line - method, url
    - headers - authorization, user agent

