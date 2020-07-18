#!/usr/bin/env python3

from test import Test
import random
import httpv2

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull2.sock'
    host = '127.0.0.1'
    port = 9002
    # TODO run tests here

    Test("empty mesg test 1", proxy_sock, [(httpv2.empty_mesg_test1, host, port )]).run()
    Test("empty mesg test 2", proxy_sock, [(httpv2.empty_mesg_test2, host, port )]).run()

    Test("req line test 1", proxy_sock, [(httpv2.req_line_test1, host, port )]).run()
    Test("req line test 2", proxy_sock, [(httpv2.req_line_test2, host, port )]).run()
    Test("req line test 3", proxy_sock, [(httpv2.req_line_test3, host, port )]).run()
    Test("req line test 4", proxy_sock, [(httpv2.req_line_test4, host, port )]).run()
    Test("req line test 5", proxy_sock, [(httpv2.req_line_test5, host, port )]).run()
    Test("req line test 6", proxy_sock, [(httpv2.req_line_test6, host, port )]).run()
    Test("req line test 7", proxy_sock, [(httpv2.req_line_test7, host, port )]).run()
    Test("req line test 8", proxy_sock, [(httpv2.req_line_test8, host, port )]).run()

    Test("header line test 1", proxy_sock, [(httpv2.header_line_test1, host, port )]).run()
    Test("header line test 2", proxy_sock, [(httpv2.header_line_test2, host, port )]).run()
    Test("header line test 3", proxy_sock, [(httpv2.header_line_test3, host, port )]).run()
    Test("header line test 4", proxy_sock, [(httpv2.header_line_test4, host, port )]).run()
    Test("header line test 5", proxy_sock, [(httpv2.header_line_test5, host, port )]).run()
    Test("header line test 6", proxy_sock, [(httpv2.header_line_test6, host, port )]).run()
    Test("header line test 7", proxy_sock, [(httpv2.header_line_test7, host, port )]).run()
    Test("header line test 8", proxy_sock, [(httpv2.header_line_test8, host, port )]).run()
    Test("header line test 9", proxy_sock, [(httpv2.header_line_test9, host, port )]).run()
    Test("header line test 10", proxy_sock, [(httpv2.header_line_test10, host, port )]).run()
    Test("header line test 11", proxy_sock, [(httpv2.header_line_test11, host, port )]).run()
    Test("header line test 12", proxy_sock, [(httpv2.header_line_test12, host, port )]).run()
    Test("header line test 13", proxy_sock, [(httpv2.header_line_test13, host, port )]).run()
    Test("header line test 14", proxy_sock, [(httpv2.header_line_test14, host, port )]).run()
    Test("header line test 15", proxy_sock, [(httpv2.header_line_test15, host, port )]).run()
    Test("header line test 16", proxy_sock, [(httpv2.header_line_test16, host, port )]).run()
    Test("header line test 17", proxy_sock, [(httpv2.header_line_test17, host, port )]).run()
    Test("header line test 18", proxy_sock, [(httpv2.header_line_test18, host, port )]).run()
    Test("header line test 19", proxy_sock, [(httpv2.header_line_test19, host, port )]).run()

    Test("con len body test 1", proxy_sock, [(httpv2.con_len_body_test1, host, port )]).run()
    Test("brute force test", proxy_sock, [(httpv2.brute_force, host, port )]).run()

    Test("chunked body test 1", proxy_sock, [(httpv2.chunk_body_test1, host, port )]).run()
    Test("chunked body test 2", proxy_sock, [(httpv2.chunk_body_test2, host, port )]).run()
    Test("chunked body test 3", proxy_sock, [(httpv2.chunk_body_test3, host, port )]).run()
    Test("chunked body test 4", proxy_sock, [(httpv2.chunk_body_test4, host, port )]).run()

    Test("chunked body test 5", proxy_sock, [(httpv2.chunk_body_test5, host, port )]).run()

    Test("chunked body test 6", proxy_sock, [(httpv2.chunk_body_test6, host, port )]).run()
    Test("chunked body test 7", proxy_sock, [(httpv2.chunk_body_test7, host, port )]).run()
    Test("chunked body test 8", proxy_sock, [(httpv2.chunk_body_test8, host, port )]).run()
    Test("chunked body test 9", proxy_sock, [(httpv2.chunk_body_test9, host, port )]).run()

    Test("chunked body test 10", proxy_sock, [(httpv2.chunk_body_test10, host, port )]).run()
    Test("chunked body test 11", proxy_sock, [(httpv2.chunk_body_test11, host, port )]).run()
    Test("chunked body test 12", proxy_sock, [(httpv2.chunk_body_test12, host, port )]).run()
    Test("chunked body test 13", proxy_sock, [(httpv2.chunk_body_test13, host, port )]).run()
    Test("chunked body test 14", proxy_sock, [(httpv2.chunk_body_test14, host, port )]).run()
