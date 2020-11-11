#!/usr/bin/env python3

import random


from framework.test import Test
import telnet as t


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull8.sock'
    host = '127.0.0.1'
    port = 9008
    log_dir = "logs/telnet"

    # TODO run tests here
    Test("login_test_1", log_dir, proxy_sock, [(t.login_test1, host, port)]).run()
    Test("login_test_2", log_dir, proxy_sock, [(t.login_test2, host, port)]).run()
    Test("login_test_3", log_dir, proxy_sock, [(t.login_test3, host, port)]).run()
    Test("login_test_4", log_dir, proxy_sock, [(t.login_test4, host, port)]).run()
    Test("login_test_5", log_dir, proxy_sock, [(t.login_test5, host, port)]).run()
    Test("brute_force_test_1", log_dir, proxy_sock, [(t.bruteforce_test, host, port)]).run()
    Test("multiple_brute_force_test_1", log_dir, proxy_sock, [(t.bruteforce_test, host, port),
         (t.bruteforce_test, host, port), (t.bruteforce_test, host, port),
         (t.bruteforce_test, host, port), (t.bruteforce_test, host, port)]).run()
