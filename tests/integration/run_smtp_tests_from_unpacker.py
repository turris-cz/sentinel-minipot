#!/usr/bin/env python3

import random
from shutil import rmtree

from framework.test import Test
from framework.out_capture import unpacker_out_capture
import smtp as s


if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    handler = unpacker_out_capture
    sock = "tcp://127.0.0.1:9104"
    topic = "sentinel/collect/minipot/smtp"
    host = '127.0.0.1'
    port = 9017
    log_dir = "logs/smtp/unpacker"
    rmtree(log_dir, ignore_errors=True)
    # TODO run tests here

    Test("empty_line_test_1", log_dir, (handler, sock, topic), [(s.empty_cmd_test1, host, port)]).run()
    Test("emptyline_test_2", log_dir, (handler, sock, topic), [(s.empty_cmd_test2, host, port)]).run()
    Test("empty_line_test_3", log_dir, (handler, sock, topic), [(s.empty_cmd_test3, host, port)]).run()

    Test("unrecognized_cmd_test_1", log_dir, (handler, sock, topic), [(s.unrec_cmd_test1, host, port)]).run()
    Test("unrecognized_cmd_test_2", log_dir, (handler, sock, topic), [(s.unrec_cmd_test2, host, port)]).run()

    Test("noop_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.noop_cmd_expect_helo_test1, host, port)]).run()
    Test("noop_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.noop_cmd_expect_helo_test2, host, port)]).run()
    Test("noop_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.noop_cmd_expect_helo_test3, host, port)]).run()
    Test("noop_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.noop_cmd_expect_helo_test4, host, port)]).run()

    Test("rset_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.rset_cmd_expect_helo_test1, host, port)]).run()
    Test("rset_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.rset_cmd_expect_helo_test2, host, port)]).run()
    Test("rset_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.rset_cmd_expect_helo_test3, host, port)]).run()
    Test("rset_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.rset_cmd_expect_helo_test4, host, port)]).run()

    Test("quit_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.quit_cmd_expect_helo_test1, host, port)]).run()
    Test("quit_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.quit_cmd_expect_helo_test2, host, port)]).run()
    Test("quit_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.quit_cmd_expect_helo_test3, host, port)]).run()
    Test("quit_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.quit_cmd_expect_helo_test4, host, port)]).run()

    Test("mail_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.mail_cmd_ecpect_helo_test1, host, port)]).run()
    Test("mail_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.mail_cmd_expect_helo_test2, host, port)]).run()
    Test("mail_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.mail_cmd_expect_helo_test3, host, port)]).run()
    Test("mail_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.mail_cmd_expect_helo_test4, host, port)]).run()

    Test("auth_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.auth_cmd_ecpect_helo_test1, host, port)]).run()
    Test("auth_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.auth_cmd_expect_helo_test2, host, port)]).run()
    Test("auth_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.auth_cmd_expect_helo_test3, host, port)]).run()
    Test("auth_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.auth_cmd_expect_helo_test4, host, port)]).run()

    Test("etrn_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.etrn_cmd_ecpect_helo_test1, host, port)]).run()
    Test("etrn_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.etrn_cmd_expect_helo_test2, host, port)]).run()
    Test("etrn_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.etrn_cmd_expect_helo_test3, host, port)]).run()
    Test("etrn_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.etrn_cmd_expect_helo_test4, host, port)]).run()

    Test("rcpt_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.rcpt_cmd_ecpect_helo_test1, host, port)]).run()
    Test("rcpt_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.rcpt_cmd_expect_helo_test2, host, port)]).run()
    Test("rcpt_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.rcpt_cmd_expect_helo_test3, host, port)]).run()
    Test("rcpt_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.rcpt_cmd_expect_helo_test4, host, port)]).run()

    Test("data_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.data_cmd_ecpect_helo_test1, host, port)]).run()
    Test("data_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.data_cmd_expect_helo_test2, host, port)]).run()
    Test("data_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.data_cmd_expect_helo_test3, host, port)]).run()
    Test("data_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.data_cmd_expect_helo_test4, host, port)]).run()

    Test("helo_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.helo_cmd_ecpect_helo_test1, host, port)]).run()
    Test("helo_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.helo_cmd_expect_helo_test2, host, port)]).run()
    Test("helo_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.helo_cmd_expect_helo_test3, host, port)]).run()
    Test("helo_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.helo_cmd_expect_helo_test4, host, port)]).run()

    Test("ehlo_cmd_expect_helo_test_1", log_dir, (handler, sock, topic), [(s.ehlo_cmd_ecpect_helo_test1, host, port)]).run()
    Test("ehlo_cmd_expect_helo_test_2", log_dir, (handler, sock, topic), [(s.ehlo_cmd_expect_helo_test2, host, port)]).run()
    Test("ehlo_cmd_expect_helo_test_3", log_dir, (handler, sock, topic), [(s.ehlo_cmd_expect_helo_test3, host, port)]).run()
    Test("ehlo_cmd_expect_helo_test_4", log_dir, (handler, sock, topic), [(s.ehlo_cmd_expect_helo_test4, host, port)]).run()

    Test("etrn_cmd_helo_sent_test_1", log_dir, (handler, sock, topic), [(s.etrn_cmd_helo_sent_test1, host, port)]).run()
    Test("etrn_cmd_helo_sent_test_2", log_dir, (handler, sock, topic), [(s.etrn_cmd_helo_sent_test2, host, port)]).run()
    Test("etrn_cmd_helo_sent_test_3", log_dir, (handler, sock, topic), [(s.etrn_cmd_helo_sent_test3, host, port)]).run()

    Test("mail_cmd_helo_sent_test_1", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test1, host, port)]).run()
    Test("mail_cmd_helo_sent_test_2", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test2, host, port)]).run()
    Test("mail_cmd_helo_sent_test_3", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test3, host, port)]).run()
    Test("mail_cmd_helo_sent_test_4", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test4, host, port)]).run()
    Test("mail_cmd_helo_sent_test_5", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test5, host, port)]).run()
    Test("mail_cmd_helo_sent_test_6", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test6, host, port)]).run()
    Test("mail_cmd_helo_sent_test_7", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_sent_test7, host, port)]).run()

    Test("noop_cmd_helo_sent_test_1", log_dir, (handler, sock, topic), [(s.noop_cmd_helo_sent_test1, host, port)]).run()
    Test("noop_cmd_helo_sent_test_2", log_dir, (handler, sock, topic), [(s.noop_cmd_helo_sent_test2, host, port)]).run()

    Test("vrfy_cmd_helo_sent_test_1", log_dir, (handler, sock, topic), [(s.vrfy_cmd_helo_sent_test1, host, port)]).run()
    Test("vrfy_cmd_helo_sent_test_2", log_dir, (handler, sock, topic), [(s.vrfy_cmd_helo_sent_test2, host, port)]).run()

    Test("auth_cmd_helo_sent_no_sasl_test_1", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_no_sasl_test1, host, port)]).run()
    Test("auth_cmd_helo_sent_no_sasl_test_2", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_no_sasl_test2, host, port)]).run()

    Test("auth_cmd_helo_sent_sasl_test_1", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test1, host, port)]).run()
    Test("auth_cmd_helo_sent_sasl_test_2", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test2, host, port)]).run()
    Test("auth_cmd_helo_sent_sasl_test_3", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test3, host, port)]).run()
    Test("auth_cmd_helo_sent_sasl_test_4", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test4, host, port)]).run()
    Test("auth_cmd_helo_sent_sasl_test_5", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test5, host, port)]).run()
    Test("auth_cmd_helo_sent_sasl_test_6", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_sent_sasl_test6, host, port)]).run()

    Test("auth_cmd_helo_sent_init_resp_test_1", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test1, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_2", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test2, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_3", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test3, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_4", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test4, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_5", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test5, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_6", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test6, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_7", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test7, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_8", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test8, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_9", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test9, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_10", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test10, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_11", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test11, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_12", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test12, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_13", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test13, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_14", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test14, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_15", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test15, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_16", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test16, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_17", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test17, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_18", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test17, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_19", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test17, host, port)]).run()
    Test("auth_cmd_helo_sent_init_resp_test_20", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_init_resp_test17, host, port)]).run()

    Test("auth_cmd_helo_sent_too_much_param_test_1", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_too_much_param_test1, host, port)]).run()
    Test("auth_cmd_helo_sent_too_much_param_test_2", log_dir, (handler, sock, topic),
         [(s.auth_cmd_helo_sent_too_much_param_test2, host, port)]).run()

    Test("expect_plain_data_test_1", log_dir, (handler, sock, topic), [(s.expect_plain_data_test1, host, port)]).run()
    Test("expect_plain_data_test_2", log_dir, (handler, sock, topic), [(s.expect_plain_data_test2, host, port)]).run()
    Test("expect_plain_data_test_3", log_dir, (handler, sock, topic), [(s.expect_plain_data_test3, host, port)]).run()
    Test("expect_plain_data_test_4", log_dir, (handler, sock, topic), [(s.expect_plain_data_test4, host, port)]).run()
    Test("expect_plain_data_test_5", log_dir, (handler, sock, topic), [(s.expect_plain_data_test5, host, port)]).run()
    Test("expect_plain_data_test_6", log_dir, (handler, sock, topic), [(s.expect_plain_data_test6, host, port)]).run()
    Test("expect_plain_data_test_7", log_dir, (handler, sock, topic), [(s.expect_plain_data_test7, host, port)]).run()
    Test("expect_plain_data_test_8", log_dir, (handler, sock, topic), [(s.expect_plain_data_test8, host, port)]).run()
    Test("expect_plain_data_test_9", log_dir, (handler, sock, topic), [(s.expect_plain_data_test9, host, port)]).run()
    Test("expect_plain_data_test_10", log_dir, (handler, sock, topic), [(s.expect_plain_data_test10, host, port)]).run()
    Test("expect_plain_data_test_11", log_dir, (handler, sock, topic), [(s.expect_plain_data_test11, host, port)]).run()
    Test("expect_plain_data_test_12", log_dir, (handler, sock, topic), [(s.expect_plain_data_test12, host, port)]).run()
    Test("expect_plain_data_test_13", log_dir, (handler, sock, topic), [(s.expect_plain_data_test13, host, port)]).run()
    Test("expect_plain_data_test_14", log_dir, (handler, sock, topic), [(s.expect_plain_data_test14, host, port)]).run()
    Test("expect_plain_data_test_15", log_dir, (handler, sock, topic), [(s.expect_plain_data_test15, host, port)]).run()
    Test("expect_plain_data_test_16", log_dir, (handler, sock, topic), [(s.expect_plain_data_test16, host, port)]).run()

    Test("expect_login_user_test_1", log_dir, (handler, sock, topic), [(s.expect_login_user_test1, host, port)]).run()
    Test("expect_login_user_test_2", log_dir, (handler, sock, topic), [(s.expect_login_user_test2, host, port)]).run()
    Test("expect_login_user_test_3", log_dir, (handler, sock, topic), [(s.expect_login_user_test3, host, port)]).run()
    Test("expect_login_user_test_4", log_dir, (handler, sock, topic), [(s.expect_login_user_test4, host, port)]).run()

    Test("expect_login_passw_test_1", log_dir, (handler, sock, topic), [(s.expect_login_passw_test1, host, port)]).run()
    Test("expect_login_passw_test_2", log_dir, (handler, sock, topic), [(s.expect_login_passw_test2, host, port)]).run()
    Test("expect_login_passw_test_3", log_dir, (handler, sock, topic), [(s.expect_login_passw_test3, host, port)]).run()
    Test("expect_login_passw_test_4", log_dir, (handler, sock, topic), [(s.expect_login_passw_test4, host, port)]).run()
    Test("expect_login_passw_test_5", log_dir, (handler, sock, topic), [(s.expect_login_passw_test5, host, port)]).run()
    Test("expect_login_passw_test_6", log_dir, (handler, sock, topic), [(s.expect_login_passw_test6, host, port)]).run()
    Test("expect_login_passw_test_7", log_dir, (handler, sock, topic), [(s.expect_login_passw_test7, host, port)]).run()

    Test("plain_init_brute_force", log_dir, (handler, sock, topic), [(s.plain_init_brute_force, host, port)]).run()
    Test("plain_brute_force", log_dir, (handler, sock, topic), [(s.plain_brute_force, host, port)]).run()
    Test("login_init_brute_force", log_dir, (handler, sock, topic), [(s.login_init_bruteforce, host, port)]).run()
    Test("login_brute_force", log_dir, (handler, sock, topic), [(s.login_bruteforce, host, port)]).run()

    Test("etrn_cmd_helo_mail_sent_test_1", log_dir, (handler, sock, topic), [(s.etrn_cmd_helo_mail_sent_test1, host, port)]).run()
    Test("etrn_cmd_helo_mail_sent_test_2", log_dir, (handler, sock, topic), [(s.etrn_cmd_helo_mail_sent_test2, host, port)]).run()

    Test("mail_cmd_helo_mail_sent_test_1", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_mail_sent_test1, host, port)]).run()
    Test("mail_cmd_helo_mail_sent_test_2", log_dir, (handler, sock, topic), [(s.mail_cmd_helo_mail_sent_test2, host, port)]).run()

    Test("data_cmd_helo_mail_sent_test_1", log_dir, (handler, sock, topic), [(s.data_cmd_helo_mail_sent_test1, host, port)]).run()
    Test("data_cmd_helo_mail_sent_test_2", log_dir, (handler, sock, topic), [(s.data_cmd_helo_mail_sent_test2, host, port)]).run()

    Test("auth_cmd_helo_mail_sent_test_1", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_mail_sent_test1, host, port)]).run()
    Test("auth_cmd_helo_mail_sent_test_2", log_dir, (handler, sock, topic), [(s.auth_cmd_helo_mail_sent_test2, host, port)]).run()

    Test("rcpt_cmd_helo_mail_sent_test_1", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test1, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_2", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test2, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_3", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test3, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_4", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test4, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_5", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test5, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_6", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test6, host, port)]).run()
    Test("rcpt_cmd_helo_mail_sent_test_7", log_dir, (handler, sock, topic), [(s.rcpt_cmd_helo_mail_sent_test7, host, port)]).run()

    Test("multiple_bruteforce_test_1", log_dir, (handler, sock, topic), [(s.login_bruteforce, host, port),
                                                              (s.login_init_bruteforce, host, port),
                                                              (s.plain_brute_force, host, port),
                                                              (s.plain_init_brute_force, host, port),
                                                              (s.login_bruteforce, host, port)]).run()
