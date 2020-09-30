#!/usr/bin/env python3

from framework.utils import *
from framework.proxy import gen_proxy_report


MAX_CONN_COUNT = 5

MAX_LINE_LEN = 1024
MAX_ATTEMPTS = 20

CONNECT_EV = b"connect"
LOGIN_EV = b"login"
TYPE = b"telnet"

LOGIN_USER = b"username"
LOGIN_PASS = b"password"

ASK_FOR_USER = b"Username: \xff\xf9"
ASK_FOR_PASSW = b"Password: \xff\xf9"
PROTOCOL_ERR = b"Protocol error\r\n\xff\xf9"
INCORR_LOGIN = b"Login incorrect\r\n\xff\xf9"


def gen_connect_report(ip):
    """ Generates proxy report connect message.
        ip - string
        returns dictionary """
    return gen_proxy_report(TYPE, CONNECT_EV, ip, None)


def gen_login_report(ip, user=b"", password=b""):
    """ Generates proxy report login message.
        ip - string
        user -  bytes
        password - bytes
        returns dictionary"""
    data = {
        LOGIN_USER: user,
        LOGIN_PASS: password,
    }
    return gen_proxy_report(TYPE, LOGIN_EV, ip, data)


def login_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_USER

    bytelist = list(range(33,126))

    user = gen_rand_bytes(bytelist, 4090)

    cmd = b"".join([user, b"\r\n"])
    server_sock.sendall(cmd)

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_PASSW

    passw = gen_rand_bytes(bytelist, 4090)

    cmd = b"".join([passw, b"\r\n"])
    server_sock.sendall(cmd)

    reports.append(gen_login_report(ip_addr, user[:MAX_LINE_LEN], passw[:MAX_LINE_LEN]))

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == INCORR_LOGIN

    return reports


def login_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_USER


    cmd = b"\r\n"
    server_sock.sendall(cmd)

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_PASSW

    cmd = b"\r\n"
    server_sock.sendall(cmd)

    reports.append(gen_login_report(ip_addr))

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == INCORR_LOGIN

    return reports



def login_test3(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_USER

    bytelist = list(range(33,126))

    user = gen_rand_bytes(bytelist, 1)

    cmd = b"".join([user, b"\r\n"])
    server_sock.sendall(cmd)

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == ASK_FOR_PASSW

    passw = gen_rand_bytes(bytelist, 1)

    cmd = b"".join([passw, b"\r\n"])
    server_sock.sendall(cmd)

    reports.append(gen_login_report(ip_addr, user, passw))

    response = recv_from_sock(server_sock)
    # print(response)
    assert response == INCORR_LOGIN

    return reports




def bruteforce_test(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    for i in range(MAX_ATTEMPTS):
        response = recv_from_sock(server_sock)
        # print(response)
        assert response == ASK_FOR_USER
        bytelist = list(range(33,126))

        user = gen_rand_bytes(bytelist, 4090)

        cmd = b"".join([user, b"\r\n"])
        server_sock.sendall(cmd)

        response = recv_from_sock(server_sock)
        # print(response)
        assert response == ASK_FOR_PASSW

        passw = gen_rand_bytes(bytelist, 4090)

        cmd = b"".join([passw, b"\r\n"])
        server_sock.sendall(cmd)

        reports.append(gen_login_report(ip_addr, user[:1024], passw[:1024]))

        response = recv_from_sock(server_sock)
        print(response)
        # print(INCORR_LOGIN)
        # print("------")
        assert response == INCORR_LOGIN

    return reports
