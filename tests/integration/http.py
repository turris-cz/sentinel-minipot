#!/usr/bin/env python3
import base64
from framework.utils import *
from framework.proxy import gen_proxy_report


TOKEN_BUFF_LEN = 8192
HEADER_LIMIT = 100
MESSAGES_LIMIT = 100
TRANS_ENC_LEN = 8

CONNECT_EV = b"connect"
MSG_EV = b"message"
TYPE = b"http"

METHOD = b"method"
URL = b"url"
USER_AG = b"user_agent"
AUTH = b"authorization"

URI_TOO_LONG_PART1 = b"HTTP/1.1 414 Request-URI Too Long\r\n"
BAD_REQ_PART1 = b"HTTP/1.1 400 Bad Request\r\n"
UNAUTH_REQ_PART1 = b"HTTP/1.1 401 Unauthorized\r\n"


def gen_connect_report(ip):
    """ Generates proxy report connect message.
        ip - string
        returns dictionary """
    return gen_proxy_report(TYPE, CONNECT_EV, ip, None)


def gen_mesg_report(ip, meth=b"", url=b"", auth=b"", user_ag=b""):
    """ Generates proxy report login message.
        ip - string
        meth -  bytes
        url - bytes
        auth - bytes
        user_ag - bytes
        returns dictionary"""
    data = {
        METHOD: meth,
        URL: url,
        AUTH: auth,
        USER_AG: user_ag,
    }
    return gen_proxy_report(TYPE, MSG_EV, ip, data)


def empty_mesg_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    msg = b"\n"
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1
    return reports


def empty_mesg_test2(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    msg = b"\r\n"
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1
    return reports


def req_line_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)

    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1
    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def req_line_test2(server_sock):
    """ missing first SP """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method,url, b" ", version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def req_line_test3(server_sock):
    """ missing last SP """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method, b" ", url, version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def req_line_test4(server_sock):
    """ wrong method """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"\x00aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method, b" ", url, b" ", version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def req_line_test5(server_sock):
    """ wrong url """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aadsdadsad"
    url = b"\t\x02adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method, b" ", url, b" ", version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def req_line_test6(server_sock):
    """ wrong version """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aadsdadsad"
    url = b"adasdasdasdasd"
    version = b"jTTP/1.1"

    msg = b"".join([method, b" ", url, b" ", version, b"\r\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def req_line_test7(server_sock):
    """ too long """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(256))
    bytelist.remove(10)
    msg = gen_rand_bytes(bytelist, TOKEN_BUFF_LEN) + b"\n"

    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(URI_TOO_LONG_PART1)] == URI_TOO_LONG_PART1

    return reports


def req_line_test8(server_sock):
    """ missing CR """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    msg = b"".join([method, b" ", url, b" ", version, b"\n\r\n"])
    server_sock.sendall(msg)

    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports



def header_line_test1(server_sock):
    """ missing double dot """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"aaaaaaaaa\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])

    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test2(server_sock):
    """ invalid value in header name """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"\x00aaa: ff \r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])

    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test3(server_sock):
    """ invalid value in header value """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"aaa: \x00ff \r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test4(server_sock):
    """ empty header name """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b":ff \r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def header_line_test5(server_sock):
    """ empty header value """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"aa:\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1
    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def header_line_test6(server_sock):
    """ empty header name and value """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b":\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def header_line_test7(server_sock):
    """ missing CR """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"a:v\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports



def header_line_test8(server_sock):
    """ unknown - ignored header """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"a:v\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))
    return reports



def header_line_test9(server_sock):
    """ too long header """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"


    bytelist = list(range(256))
    bytelist.remove(10)
    header = gen_rand_bytes(bytelist, TOKEN_BUFF_LEN) + b"\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports




def header_line_test10(server_sock):
    """ header limit count """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    # bytelist = list(range(256))
    # bytelist.remove(FTP_CMD_SEP)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"a:v\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header * HEADER_LIMIT, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test11(server_sock):
    """ user agent """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    user_ag =  gen_rand_bytes(bytelist, random.randint(0,8000))
    header = b"user-agent:  \t" + user_ag + b"\t  \r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, meth=method, url=url, user_ag=user_ag))
    return reports


def header_line_test12(server_sock):
    """ authentication """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    auth =  gen_rand_bytes(bytelist, random.randint(0,8000))
    header = b"authorization:  \t" + auth + b"\t  \r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, meth=method, url=url, auth=auth))
    return reports


def header_line_test13(server_sock):
    """ content len missing value """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t   \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test14(server_sock):
    """ content len not number """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t sdsdsd  \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test15(server_sock):
    """ content len negative number """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t -1  \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test16(server_sock):
    """ content len - number out of range - positive """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t 9223372036854775808  \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test17(server_sock):
    """ content len - number out of range - negative """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t -9223372036854775809  \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test18(server_sock):
    """ content len - multiple values """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t 20  20 \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def header_line_test19(server_sock):
    """ content len - zero """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"content-length: \t 0 \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports



def brute_force(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,127))
    version = b"HTTP/1.1"

    for i in range(MESSAGES_LIMIT):

        method = gen_rand_bytes(bytelist, 100)
        url = gen_rand_bytes(bytelist, 7000)

        auth =  gen_rand_bytes(bytelist, random.randint(0,8000))
        auth_header = b"authorization:  \t" + auth + b"\t  \r\n"

        user_ag = gen_rand_bytes(bytelist, random.randint(0,8000))
        user_ag_header = b"user-agent:  \t" + user_ag + b"\t  \r\n"

        msg = b"".join([method, b" ",url, b" ", version, b"\r\n", auth_header, user_ag_header,b"\r\n"])
        server_sock.sendall(msg)
        response = recv_from_sock(server_sock)

        assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1
        reports.append(gen_mesg_report(ip_addr, method, url, auth, user_ag))

    return reports


def con_len_body_test1(server_sock):
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    body_len = random.randint(0, 1000000)

    header = b"content-length: \t " + str(body_len).encode() + b"  \t\r\n"

    body = gen_rand_bytes(list(range(256)), body_len)

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n", body])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def chunk_body_test1(server_sock):
    """ chunked not last - only value"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"transfer-encoding: \t aaaaaa \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1


    return reports


def chunk_body_test2(server_sock):
    """ chunked not last - two values"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header = b"transfer-encoding: \t chunked , bbbbbb \t\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header, b"\r\n"])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports



def chunk_body_test3(server_sock):
    """ only chunked, one chunk """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = hex(chunk_size).encode() + b"\r\n"
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def chunk_body_test4(server_sock):
    """ more encodings - chunked last """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t aaaaa, bbbb, vvvvv, chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = hex(chunk_size).encode() + b"\r\n"
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def chunk_body_test5(server_sock):
    """ more encodings - more headers - chunked last """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t aaaaa, bbbb, vvvvv \t\r\n"
    header2 = b"transfer-encoding: \t hhhh, , dddd, chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = hex(chunk_size).encode() + b"\r\n"
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, header2,b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] == UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def chunk_body_test6(server_sock):
    """  invalid size char"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"hhh\r\n"
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test7(server_sock):
    """ size out of range """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"8000000000000000\r\n"
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test8(server_sock):
    """ size extension """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    # print(response)
    assert response[0:len(UNAUTH_REQ_PART1)] ==UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))

    return reports


def chunk_body_test9(server_sock):
    """ size extension - invalid char"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\x00", b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test10(server_sock):
    """ trailer - missing :"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\x00", b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    trailer = b"dsddsddd\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test11(server_sock):
    """ trailer ok"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    trailer = b"dsddsddd: hjkjhkjhkhkhjkhhkjjkkhkjhkjkjhkhjjk\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] ==UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))
    return reports


def chunk_body_test12(server_sock):
    """ trailer - wrong header name"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\x00", b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    trailer = b"dsddsddd\x02: hjkjhkjhkhkhjkhhkjjkkhkjhkjkjhkhjjk\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test13(server_sock):
    """ trailer - bad header value"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(1, 20)

    chunk_size_line = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\x00", b"\r\n"])
    chunk_body = bytearray(chunk_size)
    chunk_body.append(13)
    chunk_body.append(10)
    last_chunk_size = b"0\r\n"
    trailer = b"dsddsddd: hjkjhkjhkhkhjkhhkj\x03jkkhkjhkjkjhkhjjk\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line, chunk_body, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(BAD_REQ_PART1)] == BAD_REQ_PART1

    return reports


def chunk_body_test14(server_sock):
    """ more chunks"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]

    bytelist = list(range(33,256))
    bytelist.remove(127)
    # user = gen_rand_bytes(bytelist, 4090)
    # cmd = b"".join([b"user ", user, b"\n"])
    method = b"aaadsdadsad"
    url = b"adasdasdasdasd"
    version = b"HTTP/1.1"

    header1 = b"transfer-encoding: \t chunked \t\r\n"

    chunk_size = random.randint(100, 100000)
    chunk_size_line1 = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\r\n"])
    chunk_body1 = bytearray(chunk_size)
    chunk_body1.append(13)
    chunk_body1.append(10)

    chunk_size = random.randint(100, 10000)
    chunk_size_line2 = b"".join([hex(chunk_size).encode(), b" ; ", gen_rand_bytes(list(range(32, 127)), 2000), b"\r\n"])
    chunk_body2 = bytearray(chunk_size)
    chunk_body2.append(13)
    chunk_body2.append(10)

    last_chunk_size = b"0\r\n"
    last_chunk = b"\r\n"

    msg = b"".join([method, b" ",url, b" ", version, b"\r\n", header1, b"\r\n", chunk_size_line1, chunk_body1, chunk_size_line2, chunk_body2, last_chunk_size, last_chunk])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[0:len(UNAUTH_REQ_PART1)] ==UNAUTH_REQ_PART1

    reports.append(gen_mesg_report(ip_addr, method, url))
    return reports
