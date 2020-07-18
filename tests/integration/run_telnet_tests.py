#!/usr/bin/env python3

from test import Test
import telnet
import random

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull4.sock'
    host = '127.0.0.1'
    port = 9004
    # TODO run tests here
    Test("login test 1", proxy_sock, [(telnet.login_test1, host, port )]).run()
    Test("login test 2", proxy_sock, [(telnet.login_test2, host, port )]).run()
    Test("login test 3", proxy_sock, [(telnet.login_test3, host, port )]).run()
    Test("brute force test 1", proxy_sock, [(telnet.bruteforce_test, host, port )]).run()
    Test("multiple brute force test 1", proxy_sock, [(telnet.bruteforce_test, host, port ),
    (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port )]).run()
