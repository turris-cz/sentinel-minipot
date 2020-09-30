#!/usr/bin/env python3

from framework.test import Test
import smtp
import random

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull7.sock'
    host = '127.0.0.1'
    port = 9007
    log_dir = "logs/smtp"
    # TODO run tests here

    Test("empty_line_test_1", log_dir,  proxy_sock, [(smtp.empty_cmd_test1, host, port )]).run()
    Test("emptyline_test_2", log_dir,  proxy_sock, [(smtp.empty_cmd_test2, host, port )]).run()
    Test("empty_line_test_3", log_dir,  proxy_sock, [(smtp.empty_cmd_test3, host, port )]).run()
    Test("unrecognized_cmd_test_1", log_dir,  proxy_sock, [(smtp.unrec_cmd_test1, host, port )]).run()
    Test("unrecognized_cmd_test_2", log_dir,  proxy_sock, [(smtp.unrec_cmd_test2, host, port )]).run()

    Test("noop_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.noop_cmd_expect_helo_test1, host, port )]).run()
    Test("noop_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.noop_cmd_expect_helo_test2, host, port )]).run()
    Test("noop_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.noop_cmd_expect_helo_test3, host, port )]).run()
    Test("noop_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.noop_cmd_expect_helo_test4, host, port )]).run()

    Test("rset_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.rset_cmd_expect_helo_test1, host, port )]).run()
    Test("rset_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.rset_cmd_expect_helo_test2, host, port )]).run()
    Test("rset_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.rset_cmd_expect_helo_test3, host, port )]).run()
    Test("rset_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.rset_cmd_expect_helo_test4, host, port )]).run()

    Test("quit_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.quit_cmd_expect_helo_test1, host, port )]).run()
    Test("quit_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.quit_cmd_expect_helo_test2, host, port )]).run()
    Test("quit_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.quit_cmd_expect_helo_test3, host, port )]).run()
    Test("quit_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.quit_cmd_expect_helo_test4, host, port )]).run()

    Test("mail_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.mail_cmd_ecpect_helo_test1, host, port )]).run()
    Test("mail_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.mail_cmd_expect_helo_test2, host, port )]).run()
    Test("mail_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.mail_cmd_expect_helo_test3, host, port )]).run()
    Test("mail_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.mail_cmd_expect_helo_test4, host, port )]).run()

    Test("auth_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_ecpect_helo_test1, host, port )]).run()
    Test("auth_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_expect_helo_test2, host, port )]).run()
    Test("auth_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.auth_cmd_expect_helo_test3, host, port )]).run()
    Test("auth_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.auth_cmd_expect_helo_test4, host, port )]).run()

    Test("etrn_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.etrn_cmd_ecpect_helo_test1, host, port )]).run()
    Test("etrn_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.etrn_cmd_expect_helo_test2, host, port )]).run()
    Test("etrn_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.etrn_cmd_expect_helo_test3, host, port )]).run()
    Test("etrn_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.etrn_cmd_expect_helo_test4, host, port )]).run()

    Test("rcpt_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.rcpt_cmd_ecpect_helo_test1, host, port )]).run()
    Test("rcpt_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.rcpt_cmd_expect_helo_test2, host, port )]).run()
    Test("rcpt_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.rcpt_cmd_expect_helo_test3, host, port )]).run()
    Test("rcpt_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.rcpt_cmd_expect_helo_test4, host, port )]).run()

    Test("data_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.data_cmd_ecpect_helo_test1, host, port )]).run()
    Test("data_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.data_cmd_expect_helo_test2, host, port )]).run()
    Test("data_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.data_cmd_expect_helo_test3, host, port )]).run()
    Test("data_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.data_cmd_expect_helo_test4, host, port )]).run()

    Test("helo_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.helo_cmd_ecpect_helo_test1, host, port )]).run()
    Test("helo_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.helo_cmd_expect_helo_test2, host, port )]).run()
    Test("helo_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.helo_cmd_expect_helo_test3, host, port )]).run()
    Test("helo_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.helo_cmd_expect_helo_test4, host, port )]).run()

    Test("ehlo_cmd_expect_helo_test_1", log_dir,  proxy_sock, [(smtp.ehlo_cmd_ecpect_helo_test1, host, port )]).run()
    Test("ehlo_cmd_expect_helo_test_2", log_dir,  proxy_sock, [(smtp.ehlo_cmd_expect_helo_test2, host, port )]).run()
    Test("ehlo_cmd_expect_helo_test_3", log_dir,  proxy_sock, [(smtp.ehlo_cmd_expect_helo_test3, host, port )]).run()
    Test("ehlo_cmd_expect_helo_test_4", log_dir,  proxy_sock, [(smtp.ehlo_cmd_expect_helo_test4, host, port )]).run()


    Test("auth_cmd_helo_sent_no_sasl_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_no_sasl_test1, host, port )]).run()
    Test("auth_cmd_helo_sent_no_sasl_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_no_sasl_test2, host, port )]).run()

    Test("auth_cmd_helo_sent_sasl_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test1, host, port )]).run()
    Test("auth_cmd_helo_sent_sasl_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test2, host, port )]).run()
    Test("auth_cmd_helo_sent_sasl_test_3", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test3, host, port )]).run()
    Test("auth_cmd_helo_sent_sasl_test_4", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test4, host, port )]).run()
    Test("auth_cmd_helo_sent_sasl_test_5", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test5, host, port )]).run()
    Test("auth_cmd_helo_sent_sasl_test_6", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_sasl_test6, host, port )]).run()

    Test("auth_cmd_helo_sent_init_resp_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test1, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test2, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_3", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test3, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_4", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test4, host, port )]).run()

    Test("auth_cmd_helo_sent_init_resp_test_5", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test5, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_6", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test6, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_7", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test7, host, port )]).run()
    Test("auth_cmd_helo_sent_init_resp_test_8", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_init_resp_test8, host, port )]).run()


    Test("auth_cmd_helo_sent_too_much_param_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_too_much_param_test1, host, port )]).run()
    Test("auth_cmd_helo_sent_too_much_param_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_too_much_param_test2, host, port )]).run()
    Test("auth_cmd_helo_sent_too_much_param_test_3", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_too_much_param_test3, host, port )]).run()
    Test("auth_cmd_helo_sent_too_much_param_test_4", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_sent_too_much_param_test4, host, port )]).run()


    Test("expect_plain_data_test_1", log_dir,  proxy_sock, [(smtp.expect_plain_data_test1, host, port )]).run()
    Test("expect_plain_data_test_2", log_dir,  proxy_sock, [(smtp.expect_plain_data_test2, host, port )]).run()
    Test("expect_plain_data_test_3", log_dir,  proxy_sock, [(smtp.expect_plain_data_test3, host, port )]).run()
    Test("expect_plain_data_test_4", log_dir,  proxy_sock, [(smtp.expect_plain_data_test4, host, port )]).run()

    Test("expect_login_user_test_1", log_dir,  proxy_sock, [(smtp.expect_login_user_test1, host, port )]).run()
    Test("expect_login_user_test_2", log_dir,  proxy_sock, [(smtp.expect_login_user_test2, host, port )]).run()
    Test("expect_login_user_test_3", log_dir,  proxy_sock, [(smtp.expect_login_user_test3, host, port )]).run()
    Test("expect_login_user_test_4", log_dir,  proxy_sock, [(smtp.expect_login_user_test4, host, port )]).run()

    Test("expect_login_passw_test_1", log_dir,  proxy_sock, [(smtp.expect_login_passw_test1, host, port )]).run()
    Test("expect_login_passw_test_2", log_dir,  proxy_sock, [(smtp.expect_login_passw_test2, host, port )]).run()
    Test("expect_login_passw_test_3", log_dir,  proxy_sock, [(smtp.expect_login_passw_test3, host, port )]).run()
    Test("expect_login_passw_test_4", log_dir,  proxy_sock, [(smtp.expect_login_passw_test4, host, port )]).run()

    Test("plain_init_brute_force", log_dir,  proxy_sock, [(smtp.plain_init_brute_force, host, port )]).run()
    Test("plain_brute_force", log_dir,  proxy_sock, [(smtp.plain_brute_force, host, port )]).run()

    Test("login_init_brute_force", log_dir,  proxy_sock, [(smtp.login_init_bruteforce, host, port )]).run()
    Test("login_brute_force", log_dir,  proxy_sock, [(smtp.login_bruteforce, host, port )]).run()

    Test("etrn_cmd_helo_sent_test_1", log_dir,  proxy_sock, [(smtp.etrn_cmd_helo_sent_test1, host, port )]).run()
    Test("etrn_cmd_helo_sent_test_2", log_dir,  proxy_sock, [(smtp.etrn_cmd_helo_sent_test2, host, port )]).run()
    Test("etrn_cmd_helo_sent_test_3", log_dir,  proxy_sock, [(smtp.etrn_cmd_helo_sent_test3, host, port )]).run()

    Test("mail_cmd_helo_sent_test_1", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test1, host, port )]).run()
    Test("mail_cmd_helo_sent_test_2", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test2, host, port )]).run()
    Test("mail_cmd_helo_sent_test_3", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test3, host, port )]).run()
    Test("mail_cmd_helo_sent_test_4", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test4, host, port )]).run()
    Test("mail_cmd_helo_sent_test_5", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test5, host, port )]).run()
    Test("mail_cmd_helo_sent_test_6", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test6, host, port )]).run()
    Test("mail_cmd_helo_sent_test_7", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_sent_test7, host, port )]).run()


    Test("noop_cmd_helo_sent_test_1", log_dir,  proxy_sock, [(smtp.noop_cmd_helo_sent_test1, host, port )]).run()
    Test("noop_cmd_helo_sent_test_2", log_dir,  proxy_sock, [(smtp.noop_cmd_helo_sent_test2, host, port )]).run()

    Test("vrfy_cmd_helo_sent_test_1", log_dir,  proxy_sock, [(smtp.vrfy_cmd_helo_sent_test1, host, port )]).run()
    Test("vrfy_cmd_helo_sent_test_2", log_dir,  proxy_sock, [(smtp.vrfy_cmd_helo_sent_test2, host, port )]).run()


    Test("etrn_cmd_helo_mail_sent_test_1", log_dir,  proxy_sock, [(smtp.etrn_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("etrn_cmd_helo_mail_sent_test_2", log_dir,  proxy_sock, [(smtp.etrn_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("mail_cmd_helo_mail_sent_test_1", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("mail_cmd_helo_mail_sent_test_2", log_dir,  proxy_sock, [(smtp.mail_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("data_cmd_helo_mail_sent_test_1", log_dir,  proxy_sock, [(smtp.data_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("data_cmd_helo_mail_sent_test_2", log_dir,  proxy_sock, [(smtp.data_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("auth_cmd_helo_mail_sent_test_1", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("auth_cmd_helo_mail_sent_test_2", log_dir,  proxy_sock, [(smtp.auth_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("rcpt_cmd_helo_mail_sent_test_1", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_2", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test2, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_3", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test3, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_4", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test4, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_5", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test5, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_6", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test6, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_7", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test7, host, port )]).run()
    Test("rcpt_cmd_helo_mail_sent_test_8", log_dir,  proxy_sock, [(smtp.rcpt_cmd_helo_mail_sent_test8, host, port )]).run()


    Test("multiple_bruteforce_test_1", log_dir,  proxy_sock, [(smtp.login_bruteforce, host, port ),
        (smtp.login_init_bruteforce, host, port ),
        (smtp.plain_brute_force, host, port ),
        (smtp.plain_init_brute_force, host, port ),
        (smtp.login_bruteforce, host, port )]).run()
