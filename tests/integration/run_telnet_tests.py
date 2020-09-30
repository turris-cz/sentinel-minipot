#!/usr/bin/env python3

from framework.test import Test
import telnet
import random

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull8.sock'
    host = '127.0.0.1'
    port = 9008
    log_dir = "logs/telnet"
    # TODO run tests here

    Test("login_test_1", log_dir, proxy_sock, [(telnet.login_test1, host, port )]).run()
    Test("login_test_2", log_dir, proxy_sock, [(telnet.login_test2, host, port )]).run()
    Test("login_test_3", log_dir, proxy_sock, [(telnet.login_test3, host, port )]).run()
    Test("brute_force_test_1", log_dir, proxy_sock, [(telnet.bruteforce_test, host, port )]).run()
    Test("multiple_brute_force_test_1", log_dir, proxy_sock, [(telnet.bruteforce_test, host, port ),
    (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port ), (telnet.bruteforce_test, host, port )]).run()
