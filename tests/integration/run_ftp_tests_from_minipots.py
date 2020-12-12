#!/usr/bin/env python3

import random
from shutil import rmtree


from framework.test import Test
from framework.out_capture import minipot_out_capture
import ftp as f


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    handler = minipot_out_capture
    sock = 'ipc:///tmp/sentinel_pull5.sock'
    host = '127.0.0.1'
    port = 9005
    log_dir = "logs/ftp/minipots"
    rmtree(log_dir, ignore_errors=True)
    # TODO run tests here

    Test("check_cmd_end_test_1", log_dir, (handler, sock), [(f.check_cmd_end_test1, host, port)]).run()
    Test("check_cmd_end_test_2", log_dir, (handler, sock), [(f.check_cmd_end_test2, host, port)]).run()
    Test("check_cmd_end_test_3", log_dir, (handler, sock), [(f.check_cmd_end_test3, host, port)]).run()

    Test("user_cmd_test_1", log_dir, (handler, sock), [(f.user_cmd_test1, host, port)]).run()
    Test("user_cmd_test_2", log_dir, (handler, sock), [(f.user_cmd_test2, host, port)]).run()
    Test("user_cmd_test_3", log_dir, (handler, sock), [(f.user_cmd_test3, host, port)]).run()
    Test("user_cmd_test_4", log_dir, (handler, sock), [(f.user_cmd_test4, host, port)]).run()

    Test("pass_cmd_test_1", log_dir, (handler, sock), [(f.pass_cmd_test1, host, port)]).run()
    Test("pass_cmd_test_2", log_dir, (handler, sock), [(f.pass_cmd_test2, host, port)]).run()
    Test("pass_cmd_test_3", log_dir, (handler, sock), [(f.pass_cmd_test3, host, port)]).run()
    Test("pass_cmd_test_4", log_dir, (handler, sock), [(f.pass_cmd_test4, host, port)]).run()

    Test("pass_cmd_test_5", log_dir, (handler, sock), [(f.pass_cmd_test5, host, port)]).run()
    Test("pass_cmd_test_6", log_dir, (handler, sock), [(f.pass_cmd_test6, host, port)]).run()
    Test("pass_cmd_test_7", log_dir, (handler, sock), [(f.pass_cmd_test7, host, port)]).run()
    Test("pass_cmd_test_8", log_dir, (handler, sock), [(f.pass_cmd_test8, host, port)]).run()

    Test("pass_cmd_test_9", log_dir, (handler, sock), [(f.pass_cmd_test9, host, port)]).run()
    Test("pass_cmd_test_10", log_dir, (handler, sock), [(f.pass_cmd_test10, host, port)]).run()
    Test("pass_cmd_test_11", log_dir, (handler, sock), [(f.pass_cmd_test11, host, port)]).run()
    Test("pass_cmd_test_12", log_dir, (handler, sock), [(f.pass_cmd_test12, host, port)]).run()

    Test("pass_cmd_test_13", log_dir, (handler, sock), [(f.pass_cmd_test9, host, port)]).run()
    Test("pass_cmd_test_14", log_dir, (handler, sock), [(f.pass_cmd_test10, host, port)]).run()
    Test("pass_cmd_test_15", log_dir, (handler, sock), [(f.pass_cmd_test11, host, port)]).run()
    Test("pass_cmd_test_16", log_dir, (handler, sock), [(f.pass_cmd_test16, host, port)]).run()

    Test("username_utf8_test1", log_dir, (handler, sock), [(f.username_utf8_test1, host, port)]).run()
    Test("password_utf8_test1", log_dir, (handler, sock), [(f.password_utf8_test1, host, port)]).run()

    Test("user_passw_utf8_test1", log_dir, (handler, sock), [(f.user_passw_utf8_test1, host, port)]).run()

    Test("quit_cmd_test_1", log_dir, (handler, sock), [(f.quit_cmd_test1, host, port)]).run()
    Test("quit_cmd_test_2", log_dir, (handler, sock), [(f.quit_cmd_test2, host, port)]).run()
    Test("quit_cmd_test_3", log_dir, (handler, sock), [(f.quit_cmd_test3, host, port)]).run()
    Test("quit_cmd_test_4", log_dir, (handler, sock), [(f.quit_cmd_test4, host, port)]).run()

    Test("feat_cmd_test_1", log_dir, (handler, sock), [(f.feat_cmd_test1, host, port)]).run()
    Test("feat_cmd_test_2", log_dir, (handler, sock), [(f.feat_cmd_test2, host, port)]).run()
    Test("feat_cmd_test_3", log_dir, (handler, sock), [(f.feat_cmd_test3, host, port)]).run()
    Test("feat_cmd_test_4", log_dir, (handler, sock), [(f.feat_cmd_test4, host, port)]).run()

    Test("opts_cmd_test_1", log_dir, (handler, sock), [(f.opts_cmd_test1, host, port)]).run()
    Test("opts_cmd_test_2", log_dir, (handler, sock), [(f.opts_cmd_test2, host, port)]).run()
    Test("opts_cmd_test_3", log_dir, (handler, sock), [(f.opts_cmd_test3, host, port)]).run()
    Test("opts_cmd_test_4", log_dir, (handler, sock), [(f.opts_cmd_test4, host, port)]).run()
    Test("opts_cmd_test_5", log_dir, (handler, sock), [(f.opts_cmd_test5, host, port)]).run()
    Test("opts_cmd_test_6", log_dir, (handler, sock), [(f.opts_cmd_test6, host, port)]).run()
    Test("opts_cmd_test_7", log_dir, (handler, sock), [(f.opts_cmd_test7, host, port)]).run()

    Test("other_test_1", log_dir, (handler, sock), [(f.other_test1, host, port)]).run()
    Test("other_test_2", log_dir, (handler, sock), [(f.other_test2, host, port)]).run()
    Test("other_test_3", log_dir, (handler, sock), [(f.other_test3, host, port)]).run()

    Test("brute_force_test", log_dir, (handler, sock), [(f.brute_force_handler, host, port)]).run()

    Test("multiple_brute_force_test", log_dir, (handler, sock),
         [(f.brute_force_handler, host, port), (f.brute_force_handler, host, port),
          (f.brute_force_handler, host, port), (f.brute_force_handler, host, port), ]).run()
