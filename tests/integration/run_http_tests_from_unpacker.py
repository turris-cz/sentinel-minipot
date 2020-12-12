#!/usr/bin/env python3

import random
from shutil import rmtree

from framework.test import Test
from framework.out_capture import unpacker_out_capture
import http as h


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    handler = unpacker_out_capture
    sock = "tcp://127.0.0.1:9104"
    topic = "sentinel/collect/minipot/http"
    host = '127.0.0.1'
    port = 9016
    log_dir = "logs/http/unpacker"
    rmtree(log_dir, ignore_errors=True)
    # TODO run tests here

    Test("empty_mesg_test_1", log_dir, (handler, sock, topic), [(h.empty_mesg_test1, host, port)]).run()
    Test("empty_mesg_test_2", log_dir, (handler, sock, topic), [(h.empty_mesg_test2, host, port)]).run()

    Test("req_line_test_1", log_dir, (handler, sock, topic), [(h.req_line_test1, host, port)]).run()
    Test("req_line_test_2", log_dir, (handler, sock, topic), [(h.req_line_test2, host, port)]).run()
    Test("req_line_test_3", log_dir, (handler, sock, topic), [(h.req_line_test3, host, port)]).run()
    Test("req_line_test_4", log_dir, (handler, sock, topic), [(h.req_line_test4, host, port)]).run()
    Test("req_line_test_5", log_dir, (handler, sock, topic), [(h.req_line_test5, host, port)]).run()
    Test("req_line_test_6", log_dir, (handler, sock, topic), [(h.req_line_test6, host, port)]).run()
    Test("req_line_test_7", log_dir, (handler, sock, topic), [(h.req_line_test7, host, port)]).run()
    Test("req_line_test_8", log_dir, (handler, sock, topic), [(h.req_line_test8, host, port)]).run()
    Test("req_line_test_9", log_dir, (handler, sock, topic), [(h.req_line_test9, host, port)]).run()
    Test("req_line_test_10", log_dir, (handler, sock, topic), [(h.req_line_test10, host, port)]).run()
    Test("req_line_test_11", log_dir, (handler, sock, topic), [(h.req_line_test11, host, port)]).run()

    Test("header_line_test_1", log_dir, (handler, sock, topic), [(h.header_line_test1, host, port)]).run()
    Test("header_line_test_2", log_dir, (handler, sock, topic), [(h.header_line_test2, host, port)]).run()
    Test("header_line_test_3", log_dir, (handler, sock, topic), [(h.header_line_test3, host, port)]).run()
    Test("header_line_test_4", log_dir, (handler, sock, topic), [(h.header_line_test4, host, port)]).run()
    Test("header_line_test_5", log_dir, (handler, sock, topic), [(h.header_line_test5, host, port)]).run()
    Test("header_line_test_6", log_dir, (handler, sock, topic), [(h.header_line_test6, host, port)]).run()
    Test("header_line_test_7", log_dir, (handler, sock, topic), [(h.header_line_test7, host, port)]).run()
    Test("header_line_test_8", log_dir, (handler, sock, topic), [(h.header_line_test8, host, port)]).run()
    Test("header_line_test_9", log_dir, (handler, sock, topic), [(h.header_line_test9, host, port)]).run()
    Test("header_line_test_10", log_dir, (handler, sock, topic), [(h.header_line_test10, host, port)]).run()

    Test("user_agent_head_test1", log_dir, (handler, sock, topic), [(h.user_agent_head_test1, host, port)]).run()
    Test("user_agent_head_test2", log_dir, (handler, sock, topic), [(h.user_agent_head_test2, host, port)]).run()

    Test("auth_header_test1", log_dir, (handler, sock, topic), [(h.auth_header_test1, host, port)]).run()
    Test("auth_header_test2", log_dir, (handler, sock, topic), [(h.auth_header_test2, host, port)]).run()
    Test("auth_header_test3", log_dir, (handler, sock, topic), [(h.auth_header_test3, host, port)]).run()
    Test("auth_header_test4", log_dir, (handler, sock, topic), [(h.auth_header_test4, host, port)]).run()
    Test("auth_header_test5", log_dir, (handler, sock, topic), [(h.auth_header_test5, host, port)]).run()
    Test("auth_header_test6", log_dir, (handler, sock, topic), [(h.auth_header_test6, host, port)]).run()
    Test("auth_header_test7", log_dir, (handler, sock, topic), [(h.auth_header_test7, host, port)]).run()
    Test("auth_header_test8", log_dir, (handler, sock, topic), [(h.auth_header_test8, host, port)]).run()
    Test("auth_header_test9", log_dir, (handler, sock, topic), [(h.auth_header_test9, host, port)]).run()
    Test("auth_header_test10", log_dir, (handler, sock, topic), [(h.auth_header_test10, host, port)]).run()
    Test("auth_header_test11", log_dir, (handler, sock, topic), [(h.auth_header_test11, host, port)]).run()
    Test("auth_header_test12", log_dir, (handler, sock, topic), [(h.auth_header_test12, host, port)]).run()
    Test("brute_force_test1", log_dir, (handler, sock, topic), [(h.brute_force_test1, host, port)]).run()

    Test("con_len_head_test1", log_dir, (handler, sock, topic), [(h.con_len_head_test1, host, port)]).run()
    Test("con_len_head_test2", log_dir, (handler, sock, topic), [(h.con_len_head_test2, host, port)]).run()
    Test("con_len_head_test3", log_dir, (handler, sock, topic), [(h.con_len_head_test3, host, port)]).run()
    Test("con_len_head_test4", log_dir, (handler, sock, topic), [(h.con_len_head_test4, host, port)]).run()
    Test("con_len_head_test5", log_dir, (handler, sock, topic), [(h.con_len_head_test5, host, port)]).run()
    Test("con_len_head_test6", log_dir, (handler, sock, topic), [(h.con_len_head_test6, host, port)]).run()
    Test("con_len_head_test7", log_dir, (handler, sock, topic), [(h.con_len_head_test7, host, port)]).run()

    Test("con_len_body_test_1", log_dir, (handler, sock, topic), [(h.con_len_body_test1, host, port)]).run()

    Test("chunked_body_test_1", log_dir, (handler, sock, topic), [(h.chunk_body_test1, host, port)]).run()
    Test("chunked_body_test_2", log_dir, (handler, sock, topic), [(h.chunk_body_test2, host, port)]).run()
    Test("chunked_body_test_3", log_dir, (handler, sock, topic), [(h.chunk_body_test3, host, port)]).run()
    Test("chunked_body_test_4", log_dir, (handler, sock, topic), [(h.chunk_body_test4, host, port)]).run()

    Test("chunked_body_test_5", log_dir, (handler, sock, topic), [(h.chunk_body_test5, host, port)]).run()

    Test("chunked_body_test_6", log_dir, (handler, sock, topic), [(h.chunk_body_test6, host, port)]).run()
    Test("chunked_body_test_7", log_dir, (handler, sock, topic), [(h.chunk_body_test7, host, port)]).run()
    Test("chunked_body_test_8", log_dir, (handler, sock, topic), [(h.chunk_body_test8, host, port)]).run()
    Test("chunked_body_test_9", log_dir, (handler, sock, topic), [(h.chunk_body_test9, host, port)]).run()

    Test("chunked_body_test_10", log_dir, (handler, sock, topic), [(h.chunk_body_test10, host, port)]).run()
    Test("chunked_body_test_11", log_dir, (handler, sock, topic), [(h.chunk_body_test11, host, port)]).run()
    Test("chunked_body_test_12", log_dir, (handler, sock, topic), [(h.chunk_body_test12, host, port)]).run()
