# sentinel-minipot

## Integration test

Integration test serves for overall testing of Sentinel-minipot as a whole system. To test various protocols' server behaviour the client side is needed. This mini framork is dedicated to it.

## Dependencies
libraries
 - zmq
 - msgpack

external tools
- valgrind

## How to create test?

Each test is an instance of class `Test`. One must provide:
- test name
- path to local ZMQ ipc socket
- list of tuples (test_handler, host, port)

### Test handler
Test handler defines client-server communication. Its output is list of generated proxy reports.


## How to run?

After declaring `Test` instance just call `run` method.
One-line example for running simple SMTP test:

`Test("test", proxy_sock, [(handler, host, port)]).run()`

Before any test is run the Sentinel-minipot program must be also running! It is not done automatically.

For testing, validation and verification purposes the Sentinel-minipot is run in Valgring with the following flags:

`valgrind --leak-check=full --show-leak-kinds=definite,indirect,possible --track-fds=yes  --error-exitcode=1 --track-origins=yes  ./sentinel_minipot -H 9000 ....`