# Sentinel-minipot

## Integration test

There are two key points for Sentinel-minipot correct functionality:
- client-server communication
- reporting event records to Sentinel-proxy 

Both of them are tested in different manner.

### Client-server communication
Each minipot is basicaly server, which seen from outside handles multiple simultaneous connection. Where of of course each connection is totaly independent of each other.

### Reporting recorded events
Each connection reports captured events independently. The records are sent through pipe to Master process which has its own mechanism for forwarding them to Sentinel-proxy - to local ZMQ IPC socket. 


## Architecture design
To test above mentioned minipots' correct functionality this testing mini framework was designed and developed.

### Test 
Main unit of the framework is Test.

Its tasks are:
- run given user defined handlers on given host and port
- retrieve handler generated proxy reports
- receive real proxy reports from Sentinel-proxy
- compare real and handler generated proxy reports
- log generated and received reports to files for debuging purposes

Concept of Test is implemented by `Test class`.

### Handler

Handler is interface between tested minipot and testing framework.

Its tasks are:
    - implement server-client communication - send and receive commands, messages etc.
    - validate correct server-client communication flow
    - generate proxy reports for each event, which supposed to be reported by Minipot
    - after succesfull c-s communication return list of generated reports.

A handler usually emulates some kind of different communication scenario e.g. bruteforce attack or sending single command message and receiving response from Minipot.

### Testing flow overview
1) All test handlers are run in parallel manner each in different process - correct client-server behaviour is checked. 
2) Records from Sentinel-minipot are retrived from local ZMQ socket.
3) Generated proxy reports are retrieved from all client handlers.
4) Generated records are matched against real proxy reports received from local ZMQ socket.
