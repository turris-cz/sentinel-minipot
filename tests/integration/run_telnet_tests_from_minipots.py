#!/usr/bin/env python3

import random
from shutil import rmtree

from framework.test import Test
from framework.out_capture import minipot_out_capture
import telnet as t


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    handler = minipot_out_capture
    sock = 'ipc:///tmp/sentinel_pull8.sock'
    host = '127.0.0.1'
    port = 9008
    log_dir = "logs/telnet/minipots"
    rmtree(log_dir, ignore_errors=True)
    # TODO run tests here

    Test("login_test_1", log_dir, (handler, sock), [(t.login_test1, host, port)]).run()
    Test("login_test_2", log_dir, (handler, sock), [(t.login_test2, host, port)]).run()
    Test("login_test_3", log_dir, (handler, sock), [(t.login_test3, host, port)]).run()
    Test("login_test_4", log_dir, (handler, sock), [(t.login_test4, host, port)]).run()
    Test("login_test_5", log_dir, (handler, sock), [(t.login_test5, host, port)]).run()
    Test("login_test_6", log_dir, (handler, sock), [(t.login_test6, host, port)]).run()
    Test("login_test_7", log_dir, (handler, sock), [(t.login_test7, host, port)]).run()
    Test("login_test_8", log_dir, (handler, sock), [(t.login_test8, host, port)]).run()
    Test("brute_force_test_1", log_dir, (handler, sock), [(t.bruteforce_test, host, port)]).run()
    Test("multiple_brute_force_test_1", log_dir, (handler, sock), [(t.bruteforce_test, host, port),
         (t.bruteforce_test, host, port), (t.bruteforce_test, host, port),
         (t.bruteforce_test, host, port), (t.bruteforce_test, host, port)]).run()
