#!/usr/bin/env python3

import random
from shutil import rmtree


from framework.test import Test
from framework.out_capture import minipot_out_capture
import http as h


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    handler = minipot_out_capture
    sock = 'ipc:///tmp/sentinel_pull6.sock'
    host = '127.0.0.1'
    port = 9006
    log_dir = "logs/http/minipots"
    rmtree(log_dir, ignore_errors=True)
    # TODO run tests here

    Test("empty_mesg_test_1", log_dir, (handler, sock), [(h.empty_mesg_test1, host, port)]).run()
    Test("empty_mesg_test_2", log_dir, (handler, sock), [(h.empty_mesg_test2, host, port)]).run()

    Test("req_line_test_1", log_dir, (handler, sock), [(h.req_line_test1, host, port)]).run()
    Test("req_line_test_2", log_dir, (handler, sock), [(h.req_line_test2, host, port)]).run()
    Test("req_line_test_3", log_dir, (handler, sock), [(h.req_line_test3, host, port)]).run()
    Test("req_line_test_4", log_dir, (handler, sock), [(h.req_line_test4, host, port)]).run()
    Test("req_line_test_5", log_dir, (handler, sock), [(h.req_line_test5, host, port)]).run()
    Test("req_line_test_6", log_dir, (handler, sock), [(h.req_line_test6, host, port)]).run()
    Test("req_line_test_7", log_dir, (handler, sock), [(h.req_line_test7, host, port)]).run()
    Test("req_line_test_8", log_dir, (handler, sock), [(h.req_line_test8, host, port)]).run()
    Test("req_line_test_9", log_dir, (handler, sock), [(h.req_line_test9, host, port)]).run()
    Test("req_line_test_10", log_dir, (handler, sock), [(h.req_line_test10, host, port)]).run()
    Test("req_line_test_11", log_dir, (handler, sock), [(h.req_line_test11, host, port)]).run()

    Test("header_line_test_1", log_dir, (handler, sock), [(h.header_line_test1, host, port)]).run()
    Test("header_line_test_2", log_dir, (handler, sock), [(h.header_line_test2, host, port)]).run()
    Test("header_line_test_3", log_dir, (handler, sock), [(h.header_line_test3, host, port)]).run()
    Test("header_line_test_4", log_dir, (handler, sock), [(h.header_line_test4, host, port)]).run()
    Test("header_line_test_5", log_dir, (handler, sock), [(h.header_line_test5, host, port)]).run()
    Test("header_line_test_6", log_dir, (handler, sock), [(h.header_line_test6, host, port)]).run()
    Test("header_line_test_7", log_dir, (handler, sock), [(h.header_line_test7, host, port)]).run()
    Test("header_line_test_8", log_dir, (handler, sock), [(h.header_line_test8, host, port)]).run()
    Test("header_line_test_9", log_dir, (handler, sock), [(h.header_line_test9, host, port)]).run()
    Test("header_line_test_10", log_dir, (handler, sock), [(h.header_line_test10, host, port)]).run()

    Test("user_agent_head_test1", log_dir, (handler, sock), [(h.user_agent_head_test1, host, port)]).run()
    Test("user_agent_head_test2", log_dir, (handler, sock), [(h.user_agent_head_test2, host, port)]).run()

    Test("auth_header_test1", log_dir, (handler, sock), [(h.auth_header_test1, host, port)]).run()
    Test("auth_header_test2", log_dir, (handler, sock), [(h.auth_header_test2, host, port)]).run()
    Test("auth_header_test3", log_dir, (handler, sock), [(h.auth_header_test3, host, port)]).run()
    Test("auth_header_test4", log_dir, (handler, sock), [(h.auth_header_test4, host, port)]).run()
    Test("auth_header_test5", log_dir, (handler, sock), [(h.auth_header_test5, host, port)]).run()
    Test("auth_header_test6", log_dir, (handler, sock), [(h.auth_header_test6, host, port)]).run()
    Test("auth_header_test7", log_dir, (handler, sock), [(h.auth_header_test7, host, port)]).run()
    Test("auth_header_test8", log_dir, (handler, sock), [(h.auth_header_test8, host, port)]).run()
    Test("auth_header_test9", log_dir, (handler, sock), [(h.auth_header_test9, host, port)]).run()
    Test("auth_header_test10", log_dir, (handler, sock), [(h.auth_header_test10, host, port)]).run()
    Test("auth_header_test11", log_dir, (handler, sock), [(h.auth_header_test11, host, port)]).run()
    Test("auth_header_test12", log_dir, (handler, sock), [(h.auth_header_test12, host, port)]).run()
    Test("brute_force_test1", log_dir, (handler, sock), [(h.brute_force_test1, host, port)]).run()

    Test("con_len_head_test1", log_dir, (handler, sock), [(h.con_len_head_test1, host, port)]).run()
    Test("con_len_head_test2", log_dir, (handler, sock), [(h.con_len_head_test2, host, port)]).run()
    Test("con_len_head_test3", log_dir, (handler, sock), [(h.con_len_head_test3, host, port)]).run()
    Test("con_len_head_test4", log_dir, (handler, sock), [(h.con_len_head_test4, host, port)]).run()
    Test("con_len_head_test5", log_dir, (handler, sock), [(h.con_len_head_test5, host, port)]).run()
    Test("con_len_head_test6", log_dir, (handler, sock), [(h.con_len_head_test6, host, port)]).run()
    Test("con_len_head_test7", log_dir, (handler, sock), [(h.con_len_head_test7, host, port)]).run()

    Test("con_len_body_test_1", log_dir, (handler, sock), [(h.con_len_body_test1, host, port)]).run()

    Test("chunked_body_test_1", log_dir, (handler, sock), [(h.chunk_body_test1, host, port)]).run()
    Test("chunked_body_test_2", log_dir, (handler, sock), [(h.chunk_body_test2, host, port)]).run()
    Test("chunked_body_test_3", log_dir, (handler, sock), [(h.chunk_body_test3, host, port)]).run()
    Test("chunked_body_test_4", log_dir, (handler, sock), [(h.chunk_body_test4, host, port)]).run()

    Test("chunked_body_test_5", log_dir, (handler, sock), [(h.chunk_body_test5, host, port)]).run()

    Test("chunked_body_test_6", log_dir, (handler, sock), [(h.chunk_body_test6, host, port)]).run()
    Test("chunked_body_test_7", log_dir, (handler, sock), [(h.chunk_body_test7, host, port)]).run()
    Test("chunked_body_test_8", log_dir, (handler, sock), [(h.chunk_body_test8, host, port)]).run()
    Test("chunked_body_test_9", log_dir, (handler, sock), [(h.chunk_body_test9, host, port)]).run()

    Test("chunked_body_test_10", log_dir, (handler, sock), [(h.chunk_body_test10, host, port)]).run()
    Test("chunked_body_test_11", log_dir, (handler, sock), [(h.chunk_body_test11, host, port)]).run()
    Test("chunked_body_test_12", log_dir, (handler, sock), [(h.chunk_body_test12, host, port)]).run()
