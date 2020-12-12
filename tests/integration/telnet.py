from random import randint

from framework.utils import get_ip_addr, recv_from_sock, gen_rand_utf8_string, gen_proxy_report

MINIPOT_MAX_LINE_LEN = 1024  # in bytes

MINIPOT_MAX_ATTEMPTS = 20

MINIPOT_CONNECT_EV = b"connect"
MINIPOT_LOGIN_EV = b"login"
MINIPOT_INV_EV = b"invalid"
MINIPOT_TYPE = b"telnet"

MINIPOT_LOGIN_USER = b"username"
MINIPOT_LOGIN_PASS = b"password"

MINIPOT_ASK_FOR_USER = b"Username: \xff\xf9"
MINIPOT_ASK_FOR_PASSW = b"Password: \xff\xf9"
MINIPOT_PROTOCOL_ERR = b"Protocol error\r\n\xff\xf9"
MINIPOT_INCORR_LOGIN = b"Login incorrect\r\n\xff\xf9"


CRLF = b"\r\n"


def gen_connect_report(sock):
    """ Generates proxy report connect message and returns it as dictionary.

    Parameters:
        sock: socket """
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_CONNECT_EV, get_ip_addr(sock))


def gen_login_report(sock, user=b"", password=b""):
    """ Generates proxy report login message and returns it as dictionary.

    Parameters:
        sock: socket
        user: bytes
        password: bytes """
    data = {
        MINIPOT_LOGIN_USER: user,
        MINIPOT_LOGIN_PASS: password,
    }
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_LOGIN_EV, get_ip_addr(sock), data)


def gen_invalid_report(sock):
    """ Generates proxy report invalid message and returns it as dictionary.

    Parameters:
        sock: socket """
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_INV_EV, get_ip_addr(sock))


def gen_username(len):
    """ Returns UTF-8 byte string generated randomly without byte values 0 and 13.

    Parameters:
        len: int """
    ret = gen_rand_utf8_string(len)
    ret = ret.replace(b"\x0d", bytes([randint(14, 127)]))
    ret = ret.replace(b"\x00", bytes([randint(14, 127)]))
    return ret


def gen_password(len):
    """ Returns UTF-8 byte string generated randomly without bte values 0 and 13.

    Parameters:
        len: int """
    ret = gen_rand_utf8_string(len)
    ret = ret.replace(b"\x0d", bytes([randint(14, 127)]))
    ret = ret.replace(b"\x00", bytes([randint(14, 127)]))
    return ret


################################################################################
# tests


def login_test1(server_sock):
    """ Sends to Minipots:
        username longer than MINIPOT_MAX_LINE_LEN
        password longer than MINIPOT_MAX_LINE_LEN
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(255)
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(255)
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user[:MINIPOT_MAX_LINE_LEN],
            password=passw[:MINIPOT_MAX_LINE_LEN])]


def login_test2(server_sock):
    """ Sends to Minipots:
        empty username - CRLF
        empty password - CRLF
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    server_sock.sendall(CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    server_sock.sendall(CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_login_report(server_sock)]


def login_test3(server_sock):
    """ Sends to Minipots:
        one byte username
        one byte password
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(1)
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(1)
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user, password=passw)]


def login_test4(server_sock):
    """ Sends to Minipots:
        random username
        empty password
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(randint(1, 255))
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    server_sock.sendall(CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_login_report(server_sock, user=user)]


def login_test5(server_sock):
    """ Sends to Minipots:
        empty username
        random password
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    server_sock.sendall(CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(randint(1, 255))
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_login_report(server_sock, password=passw)]


def login_test6(server_sock):
    """ Sends to Minipots:
        username containing invalid utf-8 character
        password
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(250) + b"\xf8"
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(250)
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def login_test7(server_sock):
    """ Sends to Minipots:
        username
        password containing invalid utf-8 character
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(250)
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(250) + b"\xf9"
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def login_test8(server_sock):
    """ Sends to Minipots:
        username containing invalid utf-8 character
        password containing invalid utf-8 character
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_USER
    user = gen_username(250) + b"\xf7"
    server_sock.sendall(user + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_ASK_FOR_PASSW
    passw = gen_password(250) + b"\xf9"
    server_sock.sendall(passw + CRLF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_INCORR_LOGIN
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def bruteforce_test(server_sock):
    """ Sends to Minipots:
        MINIPOT_MAX_ATTEMPTS times usernames, passwords with random length
    Required response from Minipots':
        MINIPOT_ASK_FOR_USER
        MINIPOT_ASK_FOR_PASSW
        MINIPOT_INCORR_LOGIN
    Required Minipots generated Sentinel message:
        connect
        login for each login attempt
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    reports = [gen_connect_report(server_sock)]
    for i in range(MINIPOT_MAX_ATTEMPTS):
        response = recv_from_sock(server_sock)
        assert response == MINIPOT_ASK_FOR_USER
        user = gen_username(randint(0, 255))
        server_sock.sendall(user + CRLF)
        response = recv_from_sock(server_sock)
        assert response == MINIPOT_ASK_FOR_PASSW
        passw = gen_password(randint(0, 255))
        server_sock.sendall(passw + CRLF)
        response = recv_from_sock(server_sock)
        assert response == MINIPOT_INCORR_LOGIN
        reports.append(gen_login_report(server_sock, user=user, password=passw))
    return reports
