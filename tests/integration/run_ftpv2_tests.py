#!/usr/bin/env python3

from test import Test
import ftpv2
import random

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull1.sock'
    host = '127.0.0.1'
    port = 9001
    # TODO run tests here

    Test("check cmd end test 1", proxy_sock, [(ftpv2.check_cmd_end_test1, host, port )]).run()
    Test("check cmd end test 2", proxy_sock, [(ftpv2.check_cmd_end_test2, host, port )]).run()
    Test("check cmd end test 3", proxy_sock, [(ftpv2.check_cmd_end_test3, host, port )]).run()

    Test("user cmd test 1", proxy_sock, [(ftpv2.user_cmd_test1, host, port )]).run()
    Test("user cmd test 2", proxy_sock, [(ftpv2.user_cmd_test2, host, port )]).run()
    Test("user cmd test 3", proxy_sock, [(ftpv2.user_cmd_test3, host, port )]).run()
    Test("user cmd test 4", proxy_sock, [(ftpv2.user_cmd_test4, host, port )]).run()

    Test("pass cmd test 1", proxy_sock, [(ftpv2.pass_cmd_test1, host, port )]).run()
    Test("pass cmd test 2", proxy_sock, [(ftpv2.pass_cmd_test2, host, port )]).run()
    Test("pass cmd test 3", proxy_sock, [(ftpv2.pass_cmd_test3, host, port )]).run()
    Test("pass cmd test 4", proxy_sock, [(ftpv2.pass_cmd_test4, host, port )]).run()

    Test("pass cmd test 5", proxy_sock, [(ftpv2.pass_cmd_test5, host, port )]).run()
    Test("pass cmd test 6", proxy_sock, [(ftpv2.pass_cmd_test6, host, port )]).run()
    Test("pass cmd test 7", proxy_sock, [(ftpv2.pass_cmd_test7, host, port )]).run()
    Test("pass cmd test 8", proxy_sock, [(ftpv2.pass_cmd_test8, host, port )]).run()

    Test("pass cmd test 9", proxy_sock, [(ftpv2.pass_cmd_test9, host, port )]).run()
    Test("pass cmd test 10", proxy_sock, [(ftpv2.pass_cmd_test10, host, port )]).run()
    Test("pass cmd test 11", proxy_sock, [(ftpv2.pass_cmd_test11, host, port )]).run()
    Test("pass cmd test 12", proxy_sock, [(ftpv2.pass_cmd_test12, host, port )]).run()

    Test("pass cmd test 13", proxy_sock, [(ftpv2.pass_cmd_test9, host, port )]).run()
    Test("pass cmd test 14", proxy_sock, [(ftpv2.pass_cmd_test10, host, port )]).run()
    Test("pass cmd test 15", proxy_sock, [(ftpv2.pass_cmd_test11, host, port )]).run()
    Test("pass cmd test 16", proxy_sock, [(ftpv2.pass_cmd_test16, host, port )]).run()

    Test("quit cmd test 1", proxy_sock, [(ftpv2.quit_cmd_test1, host, port )]).run()
    Test("quit cmd test 2", proxy_sock, [(ftpv2.quit_cmd_test2, host, port )]).run()
    Test("quit cmd test 3", proxy_sock, [(ftpv2.quit_cmd_test3, host, port )]).run()
    Test("quit cmd test 4", proxy_sock, [(ftpv2.quit_cmd_test4, host, port )]).run()

    Test("feat cmd test 1", proxy_sock, [(ftpv2.feat_cmd_test1, host, port )]).run()
    Test("feat cmd test 2", proxy_sock, [(ftpv2.feat_cmd_test2, host, port )]).run()
    Test("feat cmd test 3", proxy_sock, [(ftpv2.feat_cmd_test3, host, port )]).run()
    Test("feat cmd test 4", proxy_sock, [(ftpv2.feat_cmd_test4, host, port )]).run()


    Test("opts cmd test 1", proxy_sock, [(ftpv2.opts_cmd_test1, host, port )]).run()
    Test("opts cmd test 2", proxy_sock, [(ftpv2.opts_cmd_test2, host, port )]).run()
    Test("opts cmd test 3", proxy_sock, [(ftpv2.opts_cmd_test3, host, port )]).run()
    Test("opts cmd test 4", proxy_sock, [(ftpv2.opts_cmd_test4, host, port )]).run()
    Test("opts cmd test 5", proxy_sock, [(ftpv2.opts_cmd_test5, host, port )]).run()
    Test("opts cmd test 6", proxy_sock, [(ftpv2.opts_cmd_test6, host, port )]).run()
    Test("opts cmd test 7", proxy_sock, [(ftpv2.opts_cmd_test7, host, port )]).run()

    Test("other test 1", proxy_sock, [(ftpv2.other_test1, host, port )]).run()
    Test("other test 2", proxy_sock, [(ftpv2.other_test2, host, port )]).run()
    Test("other test 3", proxy_sock, [(ftpv2.other_test3, host, port )]).run()

    Test("brute force test", proxy_sock, [(ftpv2.brute_force_handler, host, port )]).run()

    Test("multiple brute force test", proxy_sock, [(ftpv2.brute_force_handler, host, port ),
        (ftpv2.brute_force_handler, host, port ), (ftpv2.brute_force_handler, host, port ),
        (ftpv2.brute_force_handler, host, port ), ]).run()
