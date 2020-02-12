#!/usr/bin/env python3
import base64
from utils import *
import proxy

# replies

SMTP_220_WELCOME_REP = b"220 <service> service reday\r\n"
SMTP_221_200_REP = b"221 2.0.0 <service> closing connection\r\n"
SMTP_250_EHLO_REP = b"250-<service> Hello\r\n250-SIZE 100000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
SMTP_250_HELO_REP = b"250-<service> Hello\r\n"
SMTP_250_200_NOOP_REP = b"250 2.0.0 OK\r\n"
SMTP_250_200_RSET_REP = b"250 2.0.0 Flushed\r\n"
SMTP_334_LOG_USER_REP = b"334 VXNlcm5hbWU6\r\n"
SMTP_334_LOG_PASS_REP = b"334 UGFzc3dvcmQ6\r\n"
SMTP_334_PL_REP = b"334 \r\n"
SMTP_421_REP = b"421 <service not available. Closing connection\r\n>"
SMTP_500_REP = b"500 Unrecognized command\r\n"
SMTP_501_HELO_REP = b"501  Invalid domain name\r\n"
SMTP_501_554_REP = b"501 5.5.4 Malformed authentication data\r\n"
SMTP_504_576_REP = b"504 5.7.6 Authentication mechanism not supported\r\n"
SMTP_530_570_REP = b"530 5.7.0 Authentication required\r\n"
SMTP_535_578_REP = b"535 5.7.8 Authentication credentials invalid\r\n"



def gen_plain_auth_data(authzid="", authcid="", passw=""):
    """ Generates and base 64 encode sasl plain authentication data.
    authzid -  string
    authcid - string
    passw - string
    returns string """
    data = authzid.encode() + b"\x00" + authcid.encode() + b"\x00" + passw.encode()
    return base64.standard_b64encode(data).decode()


# command generators

def gen_cmd(cmd, param=""):
    """ Generates byte string from given comand and parameters 
        cmd - string 
        param -  string 
        return bytes """
    if not cmd or not cmd.strip():
        raise Exception("gen_cmd - cmd must NOT be empty")
    if param:
        return cmd.encode() + b" " + param.encode() + b"\r\n"
    else:
        return cmd.encode() + b"\r\n"


def gen_help_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("help", param)


def gen_mail_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("mail", param)


def gen_rcpt_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("rcpt", param)


def gen_data_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("data", param)


def gen_vrfy_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("vrfy", param)


def gen_expn_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("expn", param)


def gen_burl_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("burl", param)


def gen_noop_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("noop", param)


def gen_rset_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("rset", param)


def gen_ehlo_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("ehlo", param)


def gen_helo_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("helo", param)


def gen_auth_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("auth", param)


def gen_quit_cmd(param=""):
    """ 
    param - string
    returns bytes """
    return gen_cmd("quit", param)

# proxy reports

def gen_connect_report(ip):
    """ Generates proxy report connect message.
        ip - string 
        returns dictionary """
    return proxy.gen_connect_report(ip, "smtp")


def gen_login_auth_report(ip, user="", passw=""):
    """ Generates proxy report login authentication message.
    ip - string
    user - string
    passw - string
    returns dictionary """
    data = {}
    if user:
        data["user"] = user
    if passw:
        data["passw"] = passw
    return proxy.gen_proxy_report("smtp", "logauth", ip, data)


def gen_plain_auth_report(ip, authzid="", authcid="", passw=""):
    """ Generates proxy report plain authentication message.
    ip - string
    authzid - string
    authcid - string
    passw - string
    returns dictionary
    """
    data = {}
    if authzid:
        data["authzid"] = authzid
    if authcid:
        data["authcid"] = authcid
    if passw:
        data["passw"] = passw
    return proxy.gen_proxy_report("smtp", "plauth", ip, data)

# handlers

def help_cmd_handler1(server_sock):
    """ sends help coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_help_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def help_cmd_handler2(server_sock):
    """ sends help coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_help_cmd(gen_rand_printable_str(70))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def mail_cmd_handler1(server_sock):
    """ sends mail coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_mail_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def mail_cmd_handler2(server_sock):
    """ sends mail coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_mail_cmd(gen_rand_printable_str(65))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def rcpt_cmd_handler1(server_sock):
    """ sends rcpt coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_rcpt_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def rcpt_cmd_handler2(server_sock):
    """ sends rcpt coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_rcpt_cmd(gen_rand_printable_str(49))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def data_cmd_handler1(server_sock):
    """ sends data coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_data_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def data_cmd_handler2(server_sock):
    """ sends data coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_data_cmd(gen_rand_printable_str(39))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def vrfy_cmd_handler1(server_sock):
    """ sends vrfy coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_vrfy_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def vrfy_cmd_handler2(server_sock):
    """ sends vrfy coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_vrfy_cmd(gen_rand_printable_str(54))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports

def expn_cmd_handler1(server_sock):
    """ sends expn coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_expn_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def expn_cmd_handler2(server_sock):
    """ sends expn coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_expn_cmd(gen_rand_printable_str(78))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def burl_cmd_handler1(server_sock):
    """ sends burl coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_burl_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports


def burl_cmd_handler2(server_sock):
    """ sends burl coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_burl_cmd(gen_rand_printable_str(53))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_530_570_REP)
    return reports

def noop_cmd_handler1(server_sock):
    """ sends noop coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_noop_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_250_200_NOOP_REP)
    return reports


def noop_cmd_handler2(server_sock):
    """ sends noop coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_noop_cmd(gen_rand_printable_str(42))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_250_200_NOOP_REP)
    return reports


def rset_cmd_handler1(server_sock):
    """ sends rset coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_rset_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_250_200_RSET_REP)
    return reports


def rset_cmd_handler2(server_sock):
    """ sends rset coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_rset_cmd(gen_rand_printable_str(35))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_250_200_RSET_REP)
    return reports


def helo_cmd_handler1(server_sock):
    """ sends ehlo coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_helo_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_501_HELO_REP)
    return reports


def helo_cmd_handler2(server_sock):
    """ sends helo coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_helo_cmd(gen_rand_printable_str(67))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    # TODO check for domain name
    str_cmp(response, SMTP_250_HELO_REP)
    return reports


def ehlo_cmd_handler1(server_sock):
    """ sends ehlo coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_ehlo_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    print(response)
    str_cmp(response, SMTP_501_HELO_REP)
    return reports


def ehlo_cmd_handler2(server_sock):
    """ sends ehlo coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_ehlo_cmd(gen_rand_printable_str(32))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    # TODO check for domain name
    str_cmp(response, SMTP_250_EHLO_REP)
    return reports


def quit_cmd_handler1(server_sock):
    """ sends quit coomand with no params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_quit_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_221_200_REP)
    return reports


def quit_cmd_handler2(server_sock):
    """ sends quit coomand with some random params
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_quit_cmd(gen_rand_printable_str(27))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_221_200_REP)
    return reports

# authentication commands

def auth_cmd_handler1(server_sock):
    """ sends auth coomand with no other parameters
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_504_576_REP)
    return reports


def auth_cmd_handler2(server_sock):
    """ sends auth coomand with random garbage as parameter
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd(gen_rand_printable_str(23))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_504_576_REP)
    return reports


def auth_plain_handler1(server_sock):
    """ sends auth plain
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("plain")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_PL_REP)
    return reports


def auth_plain_handler2(server_sock):
    """ sends auth plain appended with SPs
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("plain          ")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_PL_REP)
    return reports


def auth_plain_handler3(server_sock):
    """ sends auth plain with valid base 64 data and valid authentication data after decoding
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    authzid = gen_rand_printable_str(15)
    authcid = gen_rand_printable_str(15)
    passw = gen_rand_printable_str(15)
    reports = [gen_connect_report(ip_addr),
                gen_plain_auth_report(ip_addr, authzid, authcid, passw),]
    param = "plain " + gen_plain_auth_data(authzid, authcid, passw)
    cmd = gen_auth_cmd(param)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_535_578_REP)
    return reports


def auth_plain_handler4(server_sock):
    """ sends auth plain with valid base 64 data appended with whitespaces. Data after decoding are valid.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    authzid = gen_rand_printable_str(15)
    authcid = gen_rand_printable_str(15)
    passw = gen_rand_printable_str(15)
    reports = [gen_connect_report(ip_addr),
                gen_plain_auth_report(ip_addr, authzid, authcid, passw),]
    param = "plain " + gen_plain_auth_data(authzid, authcid, passw) + "       "
    cmd = gen_auth_cmd(param)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_535_578_REP)
    return reports


def auth_plain_handler5(server_sock):
    """ sends auth plain with invalid base 64 data
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("plain ----------")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_501_554_REP)
    return reports


def auth_login_handler1(server_sock):
    """ sends auth login with invalid base 64 data
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("login ----------")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_501_554_REP)
    return reports


def auth_login_handler2(server_sock):
    """ sends auth login
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("login")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_USER_REP)
    return reports


def auth_login_handler3(server_sock):
    """ sends auth login with whitespaces
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("login           ")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_USER_REP)
    return reports


def auth_login_handler4(server_sock):
    """ sends auth login with valid base 64 data appended with whitespaces. Since data is just username. It is always avlid after successfull decoding.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    username = gen_rand_printable_str(random.randint(15, 1000))
    username_encoded = base64.standard_b64encode(username.encode()).decode() 
    cmd = gen_auth_cmd("login " + username_encoded + "           ")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_PASS_REP)
    return reports


def auth_login_handler5(server_sock):
    """ sends auth login with valid base 64 data Since data is just username. It is always avlid after successfull decoding.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    username = gen_rand_printable_str(random.randint(15, 1000))
    username_encoded = base64.standard_b64encode(username.encode()).decode() 
    cmd = gen_auth_cmd("login " + username_encoded)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_PASS_REP)
    return reports



def auth_login_handler6(server_sock):
    """ sends auth login with valid base 64 data and password
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    username = gen_rand_printable_str(random.randint(15, 1000))
    username_encoded = base64.standard_b64encode(username.encode()).decode() 
    cmd = gen_auth_cmd("login " + username_encoded)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_PASS_REP)
    password = gen_rand_printable_str(random.randint(5, 2000))
    password_encoded = base64.standard_b64encode(password.encode()) + b"\r\n"
    send_to_sock(server_sock, password_encoded)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_535_578_REP)
    reports.append(gen_login_auth_report(ip_addr, username, password))
    return reports


def auth_login_handler7(server_sock):
    """ sends auth login command, encoded username and password
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    cmd = gen_auth_cmd("login")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_USER_REP)
    username = gen_rand_printable_str(random.randint(15, 1000))
    username_encoded = base64.standard_b64encode(username.encode()) + b"\r\n" 
    send_to_sock(server_sock, username_encoded)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_334_LOG_PASS_REP)
    password = gen_rand_printable_str(random.randint(5, 2000))
    password_encoded = base64.standard_b64encode(password.encode()) + b"\r\n"
    send_to_sock(server_sock, password_encoded)
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_535_578_REP)
    reports.append(gen_login_auth_report(ip_addr, username, password))
    return reports


def plain_ir_brute_force_handler(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    while True:
        authzid = gen_rand_printable_str(15)
        authcid = gen_rand_printable_str(15)
        passw = gen_rand_printable_str(15)
        param = "plain " + gen_plain_auth_data(authzid, authcid, passw)
        cmd = gen_auth_cmd(param) 
        reports.append(gen_plain_auth_report(ip_addr, authzid, authcid, passw))
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        if (response == SMTP_535_578_REP):
            continue
        elif (response == SMTP_421_REP):
            break
        else:
            raise Exception("wrong flow")
    return reports



def plain_brute_force_handler(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    while True:       
        cmd = gen_auth_cmd("plain")
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        str_cmp(response, SMTP_334_PL_REP)
        authzid = gen_rand_printable_str(15)
        authcid = gen_rand_printable_str(15)
        passw = gen_rand_printable_str(15)
        cmd =  gen_plain_auth_data(authzid, authcid, passw).encode() + b"\r\n"
        send_to_sock(server_sock, cmd)
        reports.append(gen_plain_auth_report(ip_addr, authzid, authcid, passw))
        response = recv_from_sock(server_sock)
        if (response == SMTP_535_578_REP):
            continue
        elif (response == SMTP_421_REP):
            break
        else:
            raise Exception("wrong flow")
    return reports


def login_ir_bruteforce_handler(server_sock):
    """ auth login with initial response brute force attack
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    while True:
        username = gen_rand_printable_str(random.randint(15, 1000))
        username_encoded = base64.standard_b64encode(username.encode()).decode() 
        cmd = gen_auth_cmd("login " + username_encoded)
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        str_cmp(response, SMTP_334_LOG_PASS_REP)
        password = gen_rand_printable_str(random.randint(5, 2000))
        password_encoded = base64.standard_b64encode(password.encode()) + b"\r\n"
        reports.append(gen_login_auth_report(ip_addr, username, password))
        send_to_sock(server_sock, password_encoded)
        response = recv_from_sock(server_sock)
        if (response == SMTP_535_578_REP):
            continue
        elif (response == SMTP_421_REP):
            break
        else:
            raise Exception("wrong flow")
    return reports


def login_bruteforce_handler(server_sock):
    """ sends auth login command, encoded username and password
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr),]
    response = recv_from_sock(server_sock)
    str_cmp(response, SMTP_220_WELCOME_REP)
    while True:
        cmd = gen_auth_cmd("login")
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        str_cmp(response, SMTP_334_LOG_USER_REP)
        username = gen_rand_printable_str(random.randint(15, 1000))
        username_encoded = base64.standard_b64encode(username.encode()) + b"\r\n" 
        send_to_sock(server_sock, username_encoded)
        response = recv_from_sock(server_sock)
        str_cmp(response, SMTP_334_LOG_PASS_REP)
        password = gen_rand_printable_str(random.randint(5, 2000))
        password_encoded = base64.standard_b64encode(password.encode()) + b"\r\n"
        send_to_sock(server_sock, password_encoded)
        reports.append(gen_login_auth_report(ip_addr, username, password))
        response = recv_from_sock(server_sock)
        if (response == SMTP_535_578_REP):
            continue
        elif (response == SMTP_421_REP):
            break
        else:
            raise Exception("wrong flow")
    return reports
