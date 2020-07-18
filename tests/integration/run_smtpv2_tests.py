#!/usr/bin/env python3

from test import Test
import smtpv2
import random

if __name__ == "__main__":
    # TODO setup here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull3.sock'
    host = '127.0.0.1'
    port = 9003
    # TODO run tests here

    Test("empty line test 1", proxy_sock, [(smtpv2.empty_cmd_test1, host, port )]).run()
    Test("empty line test 2", proxy_sock, [(smtpv2.empty_cmd_test2, host, port )]).run()
    Test("empty line test 3", proxy_sock, [(smtpv2.empty_cmd_test3, host, port )]).run()
    Test("unrecognized cmd test 1", proxy_sock, [(smtpv2.unrec_cmd_test1, host, port )]).run()
    Test("unrecognized cmd test 2", proxy_sock, [(smtpv2.unrec_cmd_test2, host, port )]).run()

    Test("noop cmd expect helo test 1", proxy_sock, [(smtpv2.noop_cmd_expect_helo_test1, host, port )]).run()
    Test("noop cmd expect helo test 2", proxy_sock, [(smtpv2.noop_cmd_expect_helo_test2, host, port )]).run()
    Test("noop cmd expect helo test 3", proxy_sock, [(smtpv2.noop_cmd_expect_helo_test3, host, port )]).run()
    Test("noop cmd expect helo test 4", proxy_sock, [(smtpv2.noop_cmd_expect_helo_test4, host, port )]).run()

    Test("rset cmd expect helo test 1", proxy_sock, [(smtpv2.rset_cmd_expect_helo_test1, host, port )]).run()
    Test("rset cmd expect helo test 2", proxy_sock, [(smtpv2.rset_cmd_expect_helo_test2, host, port )]).run()
    Test("rset cmd expect helo test 3", proxy_sock, [(smtpv2.rset_cmd_expect_helo_test3, host, port )]).run()
    Test("rset cmd expect helo test 4", proxy_sock, [(smtpv2.rset_cmd_expect_helo_test4, host, port )]).run()

    Test("quit cmd expect helo test 1", proxy_sock, [(smtpv2.quit_cmd_expect_helo_test1, host, port )]).run()
    Test("quit cmd expect helo test 2", proxy_sock, [(smtpv2.quit_cmd_expect_helo_test2, host, port )]).run()
    Test("quit cmd expect helo test 3", proxy_sock, [(smtpv2.quit_cmd_expect_helo_test3, host, port )]).run()
    Test("quit cmd expect helo test 4", proxy_sock, [(smtpv2.quit_cmd_expect_helo_test4, host, port )]).run()

    Test("mail cmd expect helo test 1", proxy_sock, [(smtpv2.mail_cmd_ecpect_helo_test1, host, port )]).run()
    Test("mail cmd expect helo test 2", proxy_sock, [(smtpv2.mail_cmd_expect_helo_test2, host, port )]).run()
    Test("mail cmd expect helo test 3", proxy_sock, [(smtpv2.mail_cmd_expect_helo_test3, host, port )]).run()
    Test("mail cmd expect helo test 4", proxy_sock, [(smtpv2.mail_cmd_expect_helo_test4, host, port )]).run()

    Test("auth cmd expect helo test 1", proxy_sock, [(smtpv2.auth_cmd_ecpect_helo_test1, host, port )]).run()
    Test("auth cmd expect helo test 2", proxy_sock, [(smtpv2.auth_cmd_expect_helo_test2, host, port )]).run()
    Test("auth cmd expect helo test 3", proxy_sock, [(smtpv2.auth_cmd_expect_helo_test3, host, port )]).run()
    Test("auth cmd expect helo test 4", proxy_sock, [(smtpv2.auth_cmd_expect_helo_test4, host, port )]).run()

    Test("etrn cmd expect helo test 1", proxy_sock, [(smtpv2.etrn_cmd_ecpect_helo_test1, host, port )]).run()
    Test("etrn cmd expect helo test 2", proxy_sock, [(smtpv2.etrn_cmd_expect_helo_test2, host, port )]).run()
    Test("etrn cmd expect helo test 3", proxy_sock, [(smtpv2.etrn_cmd_expect_helo_test3, host, port )]).run()
    Test("etrn cmd expect helo test 4", proxy_sock, [(smtpv2.etrn_cmd_expect_helo_test4, host, port )]).run()

    Test("rcpt cmd expect helo test 1", proxy_sock, [(smtpv2.rcpt_cmd_ecpect_helo_test1, host, port )]).run()
    Test("rcpt cmd expect helo test 2", proxy_sock, [(smtpv2.rcpt_cmd_expect_helo_test2, host, port )]).run()
    Test("rcpt cmd expect helo test 3", proxy_sock, [(smtpv2.rcpt_cmd_expect_helo_test3, host, port )]).run()
    Test("rcpt cmd expect helo test 4", proxy_sock, [(smtpv2.rcpt_cmd_expect_helo_test4, host, port )]).run()

    Test("data cmd expect helo test 1", proxy_sock, [(smtpv2.data_cmd_ecpect_helo_test1, host, port )]).run()
    Test("data cmd expect helo test 2", proxy_sock, [(smtpv2.data_cmd_expect_helo_test2, host, port )]).run()
    Test("data cmd expect helo test 3", proxy_sock, [(smtpv2.data_cmd_expect_helo_test3, host, port )]).run()
    Test("data cmd expect helo test 4", proxy_sock, [(smtpv2.data_cmd_expect_helo_test4, host, port )]).run()

    Test("helo cmd expect helo test 1", proxy_sock, [(smtpv2.helo_cmd_ecpect_helo_test1, host, port )]).run()
    Test("helo cmd expect helo test 2", proxy_sock, [(smtpv2.helo_cmd_expect_helo_test2, host, port )]).run()
    Test("helo cmd expect helo test 3", proxy_sock, [(smtpv2.helo_cmd_expect_helo_test3, host, port )]).run()
    Test("helo cmd expect helo test 4", proxy_sock, [(smtpv2.helo_cmd_expect_helo_test4, host, port )]).run()

    Test("ehlo cmd expect helo test 1", proxy_sock, [(smtpv2.ehlo_cmd_ecpect_helo_test1, host, port )]).run()
    Test("ehlo cmd expect helo test 2", proxy_sock, [(smtpv2.ehlo_cmd_expect_helo_test2, host, port )]).run()
    Test("ehlo cmd expect helo test 3", proxy_sock, [(smtpv2.ehlo_cmd_expect_helo_test3, host, port )]).run()
    Test("ehlo cmd expect helo test 4", proxy_sock, [(smtpv2.ehlo_cmd_expect_helo_test4, host, port )]).run()


    Test("auth cmd helo sent no sasl test 1", proxy_sock, [(smtpv2.auth_cmd_helo_sent_no_sasl_test1, host, port )]).run()
    Test("auth cmd helo sent no sasl test 2", proxy_sock, [(smtpv2.auth_cmd_helo_sent_no_sasl_test2, host, port )]).run()

    Test("auth cmd helo sent sasl test 1", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test1, host, port )]).run()
    Test("auth cmd helo sent sasl test 2", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test2, host, port )]).run()
    Test("auth cmd helo sent sasl test 3", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test3, host, port )]).run()
    Test("auth cmd helo sent sasl test 4", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test4, host, port )]).run()
    Test("auth cmd helo sent sasl test 5", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test5, host, port )]).run()
    Test("auth cmd helo sent sasl test 6", proxy_sock, [(smtpv2.auth_cmd_helo_sent_sasl_test6, host, port )]).run()

    Test("auth cmd helo sent init resp test 1", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test1, host, port )]).run()
    Test("auth cmd helo sent init resp test 2", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test2, host, port )]).run()
    Test("auth cmd helo sent init resp test 3", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test3, host, port )]).run()
    Test("auth cmd helo sent init resp test 4", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test4, host, port )]).run()

    Test("auth cmd helo sent init resp test 5", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test5, host, port )]).run()
    Test("auth cmd helo sent init resp test 6", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test6, host, port )]).run()
    Test("auth cmd helo sent init resp test 7", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test7, host, port )]).run()
    Test("auth cmd helo sent init resp test 8", proxy_sock, [(smtpv2.auth_cmd_helo_sent_init_resp_test8, host, port )]).run()


    Test("auth cmd helo sent too much param test 1", proxy_sock, [(smtpv2.auth_cmd_helo_sent_too_much_param_test1, host, port )]).run()
    Test("auth cmd helo sent too much param test 2", proxy_sock, [(smtpv2.auth_cmd_helo_sent_too_much_param_test2, host, port )]).run()
    Test("auth cmd helo sent too much param test 3", proxy_sock, [(smtpv2.auth_cmd_helo_sent_too_much_param_test3, host, port )]).run()
    Test("auth cmd helo sent too much param test 4", proxy_sock, [(smtpv2.auth_cmd_helo_sent_too_much_param_test4, host, port )]).run()


    Test("expect plain data test 1", proxy_sock, [(smtpv2.expect_plain_data_test1, host, port )]).run()
    Test("expect plain data test 2", proxy_sock, [(smtpv2.expect_plain_data_test2, host, port )]).run()
    Test("expect plain data test 3", proxy_sock, [(smtpv2.expect_plain_data_test3, host, port )]).run()
    Test("expect plain data test 4", proxy_sock, [(smtpv2.expect_plain_data_test4, host, port )]).run()

    Test("expect login user test 1", proxy_sock, [(smtpv2.expect_login_user_test1, host, port )]).run()
    Test("expect login user test 2", proxy_sock, [(smtpv2.expect_login_user_test2, host, port )]).run()
    Test("expect login user test 3", proxy_sock, [(smtpv2.expect_login_user_test3, host, port )]).run()
    Test("expect login user test 4", proxy_sock, [(smtpv2.expect_login_user_test4, host, port )]).run()

    Test("expect login passw test 1", proxy_sock, [(smtpv2.expect_login_passw_test1, host, port )]).run()
    Test("expect login passw test 2", proxy_sock, [(smtpv2.expect_login_passw_test2, host, port )]).run()
    Test("expect login passw test 3", proxy_sock, [(smtpv2.expect_login_passw_test3, host, port )]).run()
    Test("expect login passw test 4", proxy_sock, [(smtpv2.expect_login_passw_test4, host, port )]).run()

    Test("plain init brute force", proxy_sock, [(smtpv2.plain_init_brute_force, host, port )]).run()
    Test("plain brute force", proxy_sock, [(smtpv2.plain_brute_force, host, port )]).run()

    Test("login init brute force", proxy_sock, [(smtpv2.login_init_bruteforce, host, port )]).run()
    Test("login brute force", proxy_sock, [(smtpv2.login_bruteforce, host, port )]).run()

    Test("etrn cmd helo sent test 1", proxy_sock, [(smtpv2.etrn_cmd_helo_sent_test1, host, port )]).run()
    Test("etrn cmd helo sent test 2", proxy_sock, [(smtpv2.etrn_cmd_helo_sent_test2, host, port )]).run()
    Test("etrn cmd helo sent test 3", proxy_sock, [(smtpv2.etrn_cmd_helo_sent_test3, host, port )]).run()

    Test("mail cmd helo sent test 1", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test1, host, port )]).run()
    Test("mail cmd helo sent test 2", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test2, host, port )]).run()
    Test("mail cmd helo sent test 3", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test3, host, port )]).run()
    Test("mail cmd helo sent test 4", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test4, host, port )]).run()
    Test("mail cmd helo sent test 5", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test5, host, port )]).run()
    Test("mail cmd helo sent test 6", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test6, host, port )]).run()
    Test("mail cmd helo sent test 7", proxy_sock, [(smtpv2.mail_cmd_helo_sent_test7, host, port )]).run()


    Test("noop cmd helo sent test 1", proxy_sock, [(smtpv2.noop_cmd_helo_sent_test1, host, port )]).run()
    Test("noop cmd helo sent test 2", proxy_sock, [(smtpv2.noop_cmd_helo_sent_test2, host, port )]).run()

    Test("vrfy cmd helo sent test 1", proxy_sock, [(smtpv2.vrfy_cmd_helo_sent_test1, host, port )]).run()
    Test("vrfy cmd helo sent test 2", proxy_sock, [(smtpv2.vrfy_cmd_helo_sent_test2, host, port )]).run()

    Test("vrfy cmd helo sent test 2", proxy_sock, [(smtpv2.vrfy_cmd_helo_sent_test2, host, port )]).run()
    Test("vrfy cmd helo sent test 2", proxy_sock, [(smtpv2.vrfy_cmd_helo_sent_test2, host, port )]).run()


    Test("etrn cmd helo mail sent test 1", proxy_sock, [(smtpv2.etrn_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("etrn cmd helo mail sent test 2", proxy_sock, [(smtpv2.etrn_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("mail cmd helo mail sent test 1", proxy_sock, [(smtpv2.mail_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("mail cmd helo mail sent test 2", proxy_sock, [(smtpv2.mail_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("data cmd helo mail sent test 1", proxy_sock, [(smtpv2.data_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("data cmd helo mail sent test 2", proxy_sock, [(smtpv2.data_cmd_helo_mail_sent_test2, host, port )]).run()


    Test("auth cmd helo mail sent test 1", proxy_sock, [(smtpv2.auth_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("auth cmd helo mail sent test 2", proxy_sock, [(smtpv2.auth_cmd_helo_mail_sent_test2, host, port )]).run()

    Test("rcpt cmd helo mail sent test 1", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test1, host, port )]).run()
    Test("rcpt cmd helo mail sent test 2", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test2, host, port )]).run()
    Test("rcpt cmd helo mail sent test 3", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test3, host, port )]).run()
    Test("rcpt cmd helo mail sent test 4", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test4, host, port )]).run()
    Test("rcpt cmd helo mail sent test 5", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test5, host, port )]).run()
    Test("rcpt cmd helo mail sent test 6", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test6, host, port )]).run()
    Test("rcpt cmd helo mail sent test 7", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test7, host, port )]).run()
    Test("rcpt cmd helo mail sent test 8", proxy_sock, [(smtpv2.rcpt_cmd_helo_mail_sent_test8, host, port )]).run()


    Test("multiple bruteforce test 1", proxy_sock, [(smtpv2.login_bruteforce, host, port ),
        (smtpv2.login_init_bruteforce, host, port ),
        (smtpv2.plain_brute_force, host, port ),
        (smtpv2.plain_init_brute_force, host, port ),
        (smtpv2.login_bruteforce, host, port )]).run()
