# sentinel-minipot
This document for now briefly describes generated Sentinel messages, their payload and conditions at which the messages are generated.

## FTP

### Connect
action: connect
data: no data

Generated at:
- New connection from a client/attacker was established.

### Login
action: login
data:
- username
- password

Generated at:
- login attempt = sending NON-EMPTY user, sending whatever password (CAN BE empty)  
*NOTE* empty username is protocol error

### Invalid
action: invalid
data: no data

Generated at:
- Login attempt with empty username


## HTTP

### Connect

action: connect
data: no data

Generated at:
- New connection from a client/attacker was established.

### Message
action: message
data:
- method
- url
- user-agent

Generated at:
- HTTP message not containing `Authorization` header was received.

### Login
action: login
data:
- method
- url
- user-agent
- username
- password

Generated at:
- HTTP message containing `Authorization` header with valid `Basic` authentication scheme data was received.

### Invalid
action: invalid
data: no data

Generated at:
- HTTP message containing `Authorization` header with invalid `Basic` authentication scheme data was received.
- HTTP message containing `Authorization` header with other authentication scheme than `Basic` was received.

## SMTP

### Connect
action: connect
data: no data

Generated at:
- New connection from a client/attacker was established.

### Login
action: login
data:
- username
- password
- mechanism - login/plain - SASL authentication mechanism used for the login

Generated at:
- valid authentication attempt using LOGIN SASL mechanism was made
- valid authentication attempt using PLAIN SASL mechanism was made

### Invalid
action: invalid
data: no data

Generated at:
- base64 decoded plain mechanism data are wrongly formatted -
 they doesn't contain at least two null bytes
 - invalid SASl mechanism is passed to AUTH command -
 only supported mechanisms are PLAIN and LOGIN
- received authentication data are not valid base64 strings
- empty line was received instead of authentication data
- authentication process was aborted by sending `*`

## Telnet

### Connect
action: connect
data: no data

Generated at:
- New connection from a client/attacker was established.

### Login
action: login
data:
- username
- password

Generated at:
- login attempt = sending password line
