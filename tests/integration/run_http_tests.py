#!/usr/bin/env python3

from framework.test import Test
import random
import http

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull6.sock'
    host = '127.0.0.1'
    port = 9006
    log_dir = "logs/http"
    # TODO run tests here

    Test("empty_mesg_test_1", log_dir, proxy_sock, [(http.empty_mesg_test1, host, port )]).run()
    Test("empty_mesg_test_2", log_dir, proxy_sock, [(http.empty_mesg_test2, host, port )]).run()

    Test("req_line_test_1", log_dir, proxy_sock, [(http.req_line_test1, host, port )]).run()
    Test("req_line_test_2", log_dir, proxy_sock, [(http.req_line_test2, host, port )]).run()
    Test("req_line_test_3", log_dir, proxy_sock, [(http.req_line_test3, host, port )]).run()
    Test("req_line_test_4", log_dir, proxy_sock, [(http.req_line_test4, host, port )]).run()
    Test("req_line_test_5", log_dir, proxy_sock, [(http.req_line_test5, host, port )]).run()
    Test("req_line_test_6", log_dir, proxy_sock, [(http.req_line_test6, host, port )]).run()
    Test("req_line_test_7", log_dir, proxy_sock, [(http.req_line_test7, host, port )]).run()
    Test("req_line_test_8", log_dir, proxy_sock, [(http.req_line_test8, host, port )]).run()

    Test("header_line_test_1", log_dir, proxy_sock, [(http.header_line_test1, host, port )]).run()
    Test("header_line_test_2", log_dir, proxy_sock, [(http.header_line_test2, host, port )]).run()
    Test("header_line_test_3", log_dir, proxy_sock, [(http.header_line_test3, host, port )]).run()
    Test("header_line_test_4", log_dir, proxy_sock, [(http.header_line_test4, host, port )]).run()
    Test("header_line_test_5", log_dir, proxy_sock, [(http.header_line_test5, host, port )]).run()
    Test("header_line_test_6", log_dir, proxy_sock, [(http.header_line_test6, host, port )]).run()
    Test("header_line_test_7", log_dir, proxy_sock, [(http.header_line_test7, host, port )]).run()
    Test("header_line_test_8", log_dir, proxy_sock, [(http.header_line_test8, host, port )]).run()
    Test("header_line_test_9", log_dir, proxy_sock, [(http.header_line_test9, host, port )]).run()
    Test("header_line_test_10", log_dir, proxy_sock, [(http.header_line_test10, host, port )]).run()
    Test("header_line_test_11", log_dir, proxy_sock, [(http.header_line_test11, host, port )]).run()
    Test("header_line_test_12", log_dir, proxy_sock, [(http.header_line_test12, host, port )]).run()
    Test("header_line_test_13", log_dir, proxy_sock, [(http.header_line_test13, host, port )]).run()
    Test("header_line_test_14", log_dir, proxy_sock, [(http.header_line_test14, host, port )]).run()
    Test("header_line_test_15", log_dir, proxy_sock, [(http.header_line_test15, host, port )]).run()
    Test("header_line_test_16", log_dir, proxy_sock, [(http.header_line_test16, host, port )]).run()
    Test("header_line_test_17", log_dir, proxy_sock, [(http.header_line_test17, host, port )]).run()
    Test("header_line_test_18", log_dir, proxy_sock, [(http.header_line_test18, host, port )]).run()
    Test("header_line_test_19", log_dir, proxy_sock, [(http.header_line_test19, host, port )]).run()

    Test("con_len_body_test_1", log_dir, proxy_sock, [(http.con_len_body_test1, host, port )]).run()
    Test("brute_force_test", log_dir, proxy_sock, [(http.brute_force, host, port )]).run()

    Test("chunked_body_test_1", log_dir, proxy_sock, [(http.chunk_body_test1, host, port )]).run()
    Test("chunked_body_test_2", log_dir, proxy_sock, [(http.chunk_body_test2, host, port )]).run()
    Test("chunked_body_test_3", log_dir, proxy_sock, [(http.chunk_body_test3, host, port )]).run()
    Test("chunked_body_test_4", log_dir, proxy_sock, [(http.chunk_body_test4, host, port )]).run()

    Test("chunked_body_test_5", log_dir, proxy_sock, [(http.chunk_body_test5, host, port )]).run()

    Test("chunked_body_test_6", log_dir, proxy_sock, [(http.chunk_body_test6, host, port )]).run()
    Test("chunked_body_test_7", log_dir, proxy_sock, [(http.chunk_body_test7, host, port )]).run()
    Test("chunked_body_test_8", log_dir, proxy_sock, [(http.chunk_body_test8, host, port )]).run()
    Test("chunked_body_test_9", log_dir, proxy_sock, [(http.chunk_body_test9, host, port )]).run()

    Test("chunked_body_test_10", log_dir, proxy_sock, [(http.chunk_body_test10, host, port )]).run()
    Test("chunked_body_test_11", log_dir, proxy_sock, [(http.chunk_body_test11, host, port )]).run()
    Test("chunked_body_test_12", log_dir, proxy_sock, [(http.chunk_body_test12, host, port )]).run()
    Test("chunked_body_test_13", log_dir, proxy_sock, [(http.chunk_body_test13, host, port )]).run()
    Test("chunked_body_test_14", log_dir, proxy_sock, [(http.chunk_body_test14, host, port )]).run()
