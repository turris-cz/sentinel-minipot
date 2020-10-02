# Manual tests
For manual testing of `Sentinel-Minipots` there is a small utility `manual_proxy`
(in `manual` folder) which purpose is just to print all captured communication
with local ZMQ socket to `stdout`. So one can observe the output generated
by `Minipots`. It is replacement for `Sentinel-Proxy` which forwards
the `Minipots` output to Turris servers.

## How to run `manual_proxy`?
Path to the ZMQ socket must be only argument to the `manual_proxy` e.g.:
`./manual_proxy.py ipc:///tmp/sentinel_pull.sock`

For the best setup see Test setup part of this document.


# Integration tests
Integration test framework (in folder `integration`) serves for overall automated
testing of `Minipots` as a whole system. It implements counterparts for
`Minipots` from both sides. It emulates attackers and captures data generated
by `Minipots` component. It compares captured output from real `Minipots`
component with intended outputs.

## How to run tests?
The integration tests are run by simply creating and running a script file
containing defined tests (see `integration/doc` for information how to
create a test). This allows ultimate modularity. Everyone can create their
own script files with any tests. Currently, there are 4 script files for each
type of Minipot:
- `run_ftp_tests.py`
- `run_http_tests.py`
- `run_smtp_tests.py`
- `run_telnet_tests.py`

For the best setup see Test setup part of this document.

## More information
For more information about integration testing framework see `integration\docs`
folder.

# Dependencies
Both `manual_proxy` and integration tests framework require following Python packages:
- PyZMQ
- msgpack


# Test setup
Each test requires running `Minipots` instance (see `../README.md`).
For the fastest testing it is possible to run multiple `Minipots` instances
at the same time. However, the instances must be run on mutually distinct
ports and ZMQ sockets.

**It is desirable to run `Minipot` component in `Valgrind` environment
especially in `Memcheck` for catching hidden memory flaws which could cause
security issues.**

For running `Minipots` in `Valgrind` prepend its command with:
```
valgrind \
--leak-check=full --trace-children=yes \
--show-leak-kinds=definite,indirect,possible --track-fds=yes \
--error-exitcode=1 --track-origins=yes \
```

# Example of test setup
There are two bash scripts for quick set up of the tests.

`../run_minipots_for_testing.sh` - It runs `Minipots` instance
on predefined port and predefined ZMQ socket based on minipot type and test type.
It has two mandatory arguments. The first argument is test type.
Its value is either `m` or `i` meaning manual or integration testing.
The second argument is minipot type. Its value is either `f`/`h`/`s`/`t`
representing `ftp`/`http`/`smtp`/`telnet` minipots.

`./manual/run_manual_proxy.sh` - It runs `manual_proxy.py` with predefined ZMQ
socket based on minipot type. It has only one mandatory argument - minipot type.
Its value and meaning is same as in `../run_minipots_for_testing.sh`.
