#!/usr/bin/env python3

from test import Test
import random
import smtp

if __name__ == "__main__":
    # TODO change here
    random.seed(9878798798798)
    proxy_sock = 'ipc:///tmp/sentinel_pull3.sock'
    host = '127.0.0.1'
    port = 9003
    
    Test("smtp help cmd test 1", proxy_sock, [(smtp.help_cmd_handler1, host, port)]).run()
    Test("smtp help cmd test 2", proxy_sock, [(smtp.help_cmd_handler2, host, port)]).run()
    Test("smtp mail cmd test 1", proxy_sock, [(smtp.mail_cmd_handler1, host, port)]).run()
    Test("smtp mail cmd test 2", proxy_sock, [(smtp.mail_cmd_handler2, host, port)]).run()
    Test("smtp rcpt cmd test 1", proxy_sock, [(smtp.rcpt_cmd_handler1, host, port)]).run()
    Test("smtp rcpt cmd test 2", proxy_sock, [(smtp.rcpt_cmd_handler2, host, port)]).run()
    Test("smtp data cmd test 1", proxy_sock, [(smtp.data_cmd_handler1, host, port)]).run()
    Test("smtp data cmd test 2", proxy_sock, [(smtp.data_cmd_handler2, host, port)]).run()
    Test("smtp vrfy cmd test 1", proxy_sock, [(smtp.vrfy_cmd_handler1, host, port)]).run()
    Test("smtp vrfy cmd test 2", proxy_sock, [(smtp.vrfy_cmd_handler2, host, port)]).run()
    Test("smtp expn cmd test 1", proxy_sock, [(smtp.expn_cmd_handler1, host, port)]).run()
    Test("smtp expn cmd test 2", proxy_sock, [(smtp.expn_cmd_handler2, host, port)]).run()
    Test("smtp burl cmd test 1", proxy_sock, [(smtp.burl_cmd_handler1, host, port)]).run()
    Test("smtp burl cmd test 2", proxy_sock, [(smtp.burl_cmd_handler2, host, port)]).run()
    Test("smtp noop cmd test 1", proxy_sock, [(smtp.noop_cmd_handler1, host, port)]).run()
    Test("smtp noop cmd test 2", proxy_sock, [(smtp.noop_cmd_handler2, host, port)]).run()
    Test("smtp rset cmd test 1", proxy_sock, [(smtp.rset_cmd_handler1, host, port)]).run()
    Test("smtp rset cmd test 2", proxy_sock, [(smtp.rset_cmd_handler2, host, port)]).run()
    Test("smtp ehlo cmd test 1", proxy_sock, [(smtp.ehlo_cmd_handler1, host, port)]).run()
    Test("smtp ehlo cmd test 2", proxy_sock, [(smtp.ehlo_cmd_handler2, host, port)]).run()
    Test("smtp helo cmd test 1", proxy_sock, [(smtp.helo_cmd_handler1, host, port)]).run()
    Test("smtp helo cmd test 2", proxy_sock, [(smtp.helo_cmd_handler2, host, port)]).run()
    Test("smtp quit cmd test 1", proxy_sock, [(smtp.quit_cmd_handler1, host, port)]).run()
    Test("smtp quit cmd test 2", proxy_sock, [(smtp.quit_cmd_handler2, host, port)]).run()

    # authentication

    Test("smtp auth cmd test 1", proxy_sock, [(smtp.auth_cmd_handler1, host, port)]).run()
    Test("smtp auth cmd test 2", proxy_sock, [(smtp.auth_cmd_handler2, host, port)]).run()
    Test("smtp auth login test 1", proxy_sock, [(smtp.auth_login_handler1, host, port)]).run()
    Test("smtp auth login test 2", proxy_sock, [(smtp.auth_login_handler2, host, port)]).run()
    Test("smtp auth login test 3", proxy_sock, [(smtp.auth_login_handler3, host, port)]).run()
    Test("smtp auth login test 4", proxy_sock, [(smtp.auth_login_handler4, host, port)]).run()
    Test("smtp auth login test 5", proxy_sock, [(smtp.auth_login_handler5, host, port)]).run()
    Test("smtp auth login test 6", proxy_sock, [(smtp.auth_login_handler6, host, port)]).run()
    Test("smtp auth login test 7", proxy_sock, [(smtp.auth_login_handler7, host, port)]).run()

    Test("smtp auth plain test 1", proxy_sock, [(smtp.auth_plain_handler1, host, port)]).run()
    Test("smtp auth plain test 2", proxy_sock, [(smtp.auth_plain_handler2, host, port)]).run()
    
    Test("smtp auth plain test 3", proxy_sock, [(smtp.auth_plain_handler3, host, port)]).run()
    Test("smtp auth plain test 4", proxy_sock, [(smtp.auth_plain_handler4, host, port)]).run()
    Test("smtp auth plain test 5", proxy_sock, [(smtp.auth_plain_handler5, host, port)]).run()

    Test("plain initial brute force test ", proxy_sock, [(smtp.plain_ir_brute_force_handler, host, port)]).run()
    Test("plain brute force test ", proxy_sock, [(smtp.plain_brute_force_handler, host, port)]).run()
    Test("smtp auth login init resp bruteforce test ", proxy_sock, [(smtp.login_ir_bruteforce_handler, host, port)]).run()
    Test("smtp auth login bruteforce test ", proxy_sock, [(smtp.login_bruteforce_handler, host, port)]).run()