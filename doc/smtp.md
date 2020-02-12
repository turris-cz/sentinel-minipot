# sentinel-minipot

## SMTP
SMTP is a stateful, command-response or data-response protocol. Server can receive command or base64 encoded authentication data. In both cases server sends back response.

## Authentication
SMTP does not have built in authentication mechanism. It uses SASL for authentication. PLAIN and LOGIN mechanisms are supported.

## Recorded events
- client connection establishment

- login attempt
Arguments of AUTH command and following base64 encoded authentication data are recorded.

