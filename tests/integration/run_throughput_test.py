#!/usr/bin/env python3

import random

from framework.test import HandlerRunner

import ftp as f
import http as h
import smtp as s
import telnet as t


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    host = '127.0.0.1'
    ftp_port = 9020
    http_port = 9021
    smtp_port = 9022
    telnet_port = 9023
    # TODO run tests here

    handlers = [(f.brute_force_handler, host, ftp_port),
                (f.brute_force_handler, host, ftp_port),
                (f.brute_force_handler, host, ftp_port),
                (f.brute_force_handler, host, ftp_port),
                (f.brute_force_handler, host, ftp_port),
                (h.brute_force_test1, host, http_port),
                (h.brute_force_test1, host, http_port),
                (h.brute_force_test1, host, http_port),
                (h.brute_force_test1, host, http_port),
                (h.brute_force_test1, host, http_port),
                (s.login_bruteforce, host, smtp_port),
                (s.login_init_bruteforce, host, smtp_port),
                (s.plain_brute_force, host, smtp_port),
                (s.plain_init_brute_force, host, smtp_port),
                (s.login_init_bruteforce, host, smtp_port),
                (t.bruteforce_test, host, telnet_port),
                (t.bruteforce_test, host, telnet_port),
                (t.bruteforce_test, host, telnet_port),
                (t.bruteforce_test, host, telnet_port),
                (t.bruteforce_test, host, telnet_port)]

    runner = HandlerRunner(handlers)
    for _ in range(10000):
        runner.run()
