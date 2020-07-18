#!/usr/bin/env python3

from test import Test
import http
import random


if __name__ == "__main__":
    # TODO change here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull1.sock'
    host = '127.0.0.1'
    port = 9000
    # semantics
    Test('http get meth', proxy_sock, [(http.get_msg_handler, host, port)]).run()
    Test('http head meth', proxy_sock, [(http.head_msg_handler, host, port)]).run()
    Test('http post meth', proxy_sock, [(http.post_msg_handler, host, port)]).run()
    Test('http put meth', proxy_sock, [(http.put_msg_handler, host, port)]).run()
    Test('http del meth', proxy_sock, [(http.del_msg_handler, host, port)]).run()
    Test('http trac meth', proxy_sock, [(http.trac_msg_handler, host, port)]).run()
    Test('http conn meth', proxy_sock, [(http.conn_msg_handler, host, port)]).run()
    Test('http opt meth', proxy_sock, [(http.opt_msg_handler, host, port)]).run()
    Test('http patch meth', proxy_sock, [(http.patch_msg_handler, host, port)]).run()

    # scenarios
    Test('http brute force',  proxy_sock, [(http.brute_force_handler, host, port)]).run()
    Test('http too long connection1', proxy_sock, [(http.too_long_conn_handler1, host, port)]).run()
    Test('http too long connection2', proxy_sock, [(http.too_long_conn_handler2, host, port)]).run()
    Test('http interrupt connection', proxy_sock, [(http.interrupt_conn_handler, host, port)]).run()

    # syntax
    Test('incomplete mesg', proxy_sock, [(http.incomplete_mesg, host, port)]).run()
    Test('test1', proxy_sock, [(http.test1, host, port)]).run()
    Test('test2', proxy_sock, [(http.test2, host, port)]).run()
    Test('test3', proxy_sock, [(http.test3, host, port)]).run()
    Test('test4', proxy_sock, [(http.test4, host, port)]).run()
    Test('test5', proxy_sock, [(http.test5, host, port)]).run()
    Test('test6', proxy_sock, [(http.test6, host, port)]).run()
    Test('test7', proxy_sock, [(http.test7, host, port)]).run()
    Test('test8', proxy_sock, [(http.test8, host, port)]).run()
    Test('test9', proxy_sock, [(http.test9, host, port)]).run()

    Test('user-ag', proxy_sock, [(http.user_agent_header_limit, host, port)]).run()
    Test('cred encoding 1', proxy_sock, [(http.credentials_encoding_test1, host, port)]).run()
    Test('cred limit test3', proxy_sock, [(http.credentials_limit_test3, host, port)]).run()
    Test('cred limit test4', proxy_sock, [(http.credentials_limit_test4, host, port)]).run()
    Test('cred limit test5', proxy_sock, [(http.credentials_limit_test5, host, port)]).run()
    Test('transfer enc 1', proxy_sock, [(http.transfer_enc_test1, host, port)]).run()
    Test('transfer enc 2', proxy_sock, [(http.transfer_enc_test2, host, port)]).run()
    Test('transfer enc 3', proxy_sock, [(http.transfer_enc_test3, host, port)]).run()
    Test('transfer enc 4', proxy_sock, [(http.transfer_enc_test4, host, port)]).run()
    Test('transfer enc 5', proxy_sock, [(http.transfer_enc_test5, host, port)]).run()
    Test('transfer enc 6', proxy_sock, [(http.transfer_enc_test6, host, port)]).run()
    Test('transfer enc 7', proxy_sock, [(http.transfer_enc_test7, host, port)]).run()
    Test('content len 1', proxy_sock, [(http.content_len_test1, host, port)]).run()
    Test('content len 2', proxy_sock, [(http.content_len_test2, host, port)]).run()
    Test('content len 3', proxy_sock, [(http.content_len_test3, host, port)]).run()
    Test('content len 4', proxy_sock, [(http.content_len_test4, host, port)]).run()
    Test('content len 5', proxy_sock, [(http.content_len_test5, host, port)]).run()
    Test('content len 6', proxy_sock, [(http.content_len_test6, host, port)]).run()
    Test('content len 7', proxy_sock, [(http.content_len_test7, host, port)]).run()
    Test('content len 8', proxy_sock, [(http.content_len_test8, host, port)]).run()
    Test('content len 9', proxy_sock, [(http.content_len_test9, host, port)]).run()
    Test('content len 10', proxy_sock, [(http.content_len_test10, host, port)]).run()
    Test('body len 1', proxy_sock, [(http.body_len_test1, host, port)]).run()
    Test('body len 2', proxy_sock, [(http.body_len_test2, host, port)]).run()
    Test('body len 3', proxy_sock, [(http.body_len_test3, host, port)]).run()
    Test('body len 4', proxy_sock, [(http.body_len_test4, host, port)]).run()
    Test('body len 5', proxy_sock, [(http.body_len_test5, host, port)]).run()
    Test('mult user ag', proxy_sock, [(http.mult_user_ag_head_test, host, port)]).run()
    Test('mult auth', proxy_sock, [(http.mult_auth_head_test, host, port)]).run()
    Test('mult cont len', proxy_sock, [(http.mult_content_len_head_test, host, port)]).run()
    Test('mult trans enc', proxy_sock, [(http.mult_trans_enc_head_test, host, port)]).run()
    Test('chunked enc 1', proxy_sock, [(http.chunked_enc_test1, host, port)]).run()
    Test('chunked enc 2', proxy_sock, [(http.chunked_enc_test2, host, port)]).run()
    Test('chunked enc 3', proxy_sock, [(http.chunked_enc_test3, host, port)]).run()
    Test('chunked enc 4', proxy_sock, [(http.chunked_enc_test4, host, port)]).run()
    Test('chunked enc 5', proxy_sock, [(http.chunked_enc_test5, host, port)]).run()
    Test('chunked enc 6', proxy_sock, [(http.chunked_enc_test6, host, port)]).run()
    Test('chunked enc 7', proxy_sock, [(http.chunked_enc_test7, host, port)]).run()
    Test('chunked enc 8', proxy_sock, [(http.chunked_enc_test8, host, port)]).run()
    Test('chunked enc 9', proxy_sock, [(http.chunked_enc_test9, host, port)]).run()
    Test('chunked enc 10', proxy_sock, [(http.chunked_enc_test10, host, port)]).run()
    Test('chunked enc 11', proxy_sock, [(http.chunked_enc_test11, host, port)]).run()
    Test('chunked enc 12', proxy_sock, [(http.chunked_enc_test12, host, port)]).run()
    Test('chunked enc 13', proxy_sock, [(http.chunked_enc_test13, host, port)]).run()
    Test('chunked enc 14', proxy_sock, [(http.chunked_enc_test14, host, port)]).run()