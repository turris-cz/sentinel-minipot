#!/usr/bin/env python3

from framework.utils import *
from framework.proxy import gen_proxy_report


FTP_CMD_BUFF_LEN = 4096
FTP_USER_BUFF_LEN = 4096
FTP_PASS_BUFF_LEN = 4096

FTP_CMD_SEP = 10
FTP_PARAM_SEP = 32

FTP_LOG_ATMPS_CNT = 100

# NOTE
# all must be BYTE strings

FTP_CONNECT_EV = b"connect"
FTP_LOGIN_EV = b"login"
FTP_LOGIN_USER = b"username"
FTP_LOGIN_PASS = b"password"

FTP_WELOME_RESP = b"220 (vsFTPd 3.0.3)\r\n"
FTP_TIMEOUT_RESP = b"421 Timeout.\r\n"
FTP_OTHER_RESP = b"530 Please login with USER and PASS.\r\n"
FTP_TOO_LONG_CMD_RESP = b"500 Input line too long.\r\n"
FTP_USER_RESP = b"331 Please specify the password.\r\n"
FTP_FEAT_RESP = b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n"
FTP_OPTS_501_RESP = b"501 Option not understood.\r\n"
FTP_OPTS_200_RESP = b"200 Always in UTF8 mode.\r\n"
FTP_PASS_530_RESP = b"530 Login incorrect.\r\n"
FTP_PASS_503_RESP = b"503 Login with USER first.\r\n"
FTP_QUIT_RESP = b"221 Goodbye.\r\n"

FTP_UTF8_ON_OPT = b"utf8 on"


def gen_connect_report(ip):
    """ Generates proxy report connect message.
        ip - string
        returns dictionary """
    return gen_proxy_report(b"ftp", FTP_CONNECT_EV, ip, None)


def gen_login_report(ip, user=b"", password=b""):
    """ Generates proxy report login message.
        user -  bytes
        password - bytes
        returns dictionary"""
    # strip \r in the end of parameter
    if user and user[-1] == 13:
        user = user[:-1]

    if password and password[-1] == 13:
        password = password[:-1]
    data = {
        FTP_LOGIN_USER: user,
        FTP_LOGIN_PASS: password,
    }

    return gen_proxy_report(b"ftp", FTP_LOGIN_EV, ip, data)


def check_cmd_end_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    cmd = gen_rand_bytes(bytelist, 1)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_TIMEOUT_RESP
    return reports


def check_cmd_end_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    cmd = gen_rand_bytes(bytelist, FTP_CMD_BUFF_LEN - 1)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_TIMEOUT_RESP
    return reports


def check_cmd_end_test3(server_sock):
    """  """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    cmd = gen_rand_bytes(bytelist, FTP_CMD_BUFF_LEN)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == FTP_TIMEOUT_RESP
    return reports


def user_cmd_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    cmd = b"user\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    # print(response)
    # print(FTP_USER_RESP)
    assert response == FTP_USER_RESP
    return reports


def user_cmd_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    cmd = b"user \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    return reports


def user_cmd_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"user ", user, b"\n"])
    # cmd = b"user " + bytes(user) + b"\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    return reports


def user_cmd_test4(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"user " + bytes(user) + b"\n"
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    return reports


def pass_cmd_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports

def pass_cmd_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw =   gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test4(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test5(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports

def pass_cmd_test6(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test7(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test8(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"user \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_503_RESP
    # reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test9(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"user ", user, b"\n"])
    # print(cmd)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user))
    return reports


def pass_cmd_test10(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user))
    return reports


def pass_cmd_test11(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"pass ", passw, b"\n"])
    # cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user,passw))
    return reports


def pass_cmd_test12(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"pass ", passw, b"\n"])
    # cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user,passw))
    return reports


def pass_cmd_test13(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test14(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    # passw = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"pass ", passw, b"\n"])
    cmd = b"pass \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test15(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def pass_cmd_test16(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    user = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"user ", user, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_USER_RESP
    passw = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"pass ", passw, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_PASS_530_RESP
    reports.append(gen_login_report(ip_addr,user, passw))
    return reports


def quit_cmd_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"quit\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_QUIT_RESP
    return reports


def quit_cmd_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"quit \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_QUIT_RESP
    return reports


def quit_cmd_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"quit ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_QUIT_RESP
    return reports


def quit_cmd_test4(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"quit ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_QUIT_RESP
    return reports


def feat_cmd_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"feat\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_FEAT_RESP
    return reports


def feat_cmd_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"user ", user, b"\n"])
    cmd = b"feat \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_FEAT_RESP
    return reports


def feat_cmd_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"feat ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_FEAT_RESP
    return reports


def feat_cmd_test4(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"feat ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_FEAT_RESP
    return reports


def opts_cmd_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # param = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"feat ", param, b"\n"])
    cmd = b"opts\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # param = gen_rand_bytes(bytelist, 1)
    # cmd = b"".join([b"feat ", param, b"\n"])
    cmd = b"opts \n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 1)
    cmd = b"".join([b"opts ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test4(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 6)
    cmd = b"".join([b"opts ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test5(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 8)
    cmd = b"".join([b"opts ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test6(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    param = gen_rand_bytes(bytelist, 4090)
    cmd = b"".join([b"opts ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_501_RESP
    return reports


def opts_cmd_test7(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    param = FTP_UTF8_ON_OPT
    cmd = b"".join([b"opts ", param, b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OPTS_200_RESP
    return reports


def other_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # cmd = gen_rand_bytes(bytelist, 1)
    cmd = b"\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_TIMEOUT_RESP
    return reports


def other_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == FTP_WELOME_RESP
    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    cmd = b"".join([gen_rand_bytes(bytelist, 1), b"\n"])
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_OTHER_RESP
    return reports


def other_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == FTP_WELOME_RESP
    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # cmd = gen_rand_bytes(bytelist, 1)
    cmd = b"\r\n"
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == FTP_TIMEOUT_RESP
    return reports


def brute_force_handler(server_sock):

    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    assert response == FTP_WELOME_RESP

    bytelist = list(range(256))
    bytelist.remove(FTP_CMD_SEP)
    # print(bytelist)

    for _ in range(FTP_LOG_ATMPS_CNT):

        # print(_)

        user = gen_rand_bytes(bytelist, random.randint(1,4090))
        cmd = b"".join([b"user ", user, b"\n"])
        server_sock.sendall(cmd)
        response = recv_from_sock(server_sock)
        # print(response)
        assert response == FTP_USER_RESP

        passw = gen_rand_bytes(bytelist, random.randint(0,4090))

        cmd = b"".join([b"pass ", passw, b"\n"])
        server_sock.sendall(cmd)
        response = recv_from_sock(server_sock)
        # print(response)
        if user:
            reports.append(gen_login_report(ip_addr,user,passw))
            assert response == FTP_PASS_530_RESP
        else:
            assert response == FTP_PASS_503_RESP


    response = recv_from_sock(server_sock)
    if response:
        raise Exception("wrong flow")

    return reports
