from random import randint

from framework.utils import get_ip_addr, recv_from_sock, gen_rand_bytes_w10
from framework.proxy import gen_proxy_report


MINIPOT_CMD_BUFF_LEN = 4096
MINIPOT_USER_BUFF_LEN = 4096
MINIPOT_PASS_BUFF_LEN = 4096

MINIPOT_CMD_SEP = 10
MINIPOT_PARAM_SEP = 32

MINIPOT_LOG_ATMPS_CNT = 100

MINIPOT_TYPE = b"ftp"
MINIPOT_CONNECT_EV = b"connect"
MINIPOT_LOGIN_EV = b"login"
MINIPOT_INV_EV = b"invalid"
MINIPOT_LOGIN_USER = b"username"
MINIPOT_LOGIN_PASS = b"password"

MINIPOT_WELOME_RESP = b"220 (vsFTPd 3.0.3)\r\n"
MINIPOT_TIMEOUT_RESP = b"421 Timeout.\r\n"
MINIPOT_OTHER_RESP = b"530 Please login with USER and PASS.\r\n"
MINIPOT_TOO_LONG_CMD_RESP = b"500 Input line too long.\r\n"
MINIPOT_USER_RESP = b"331 Please specify the password.\r\n"
MINIPOT_FEAT_RESP = b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n"
MINIPOT_OPTS_501_RESP = b"501 Option not understood.\r\n"
MINIPOT_OPTS_200_RESP = b"200 Always in UTF8 mode.\r\n"
MINIPOT_PASS_530_RESP = b"530 Login incorrect.\r\n"
MINIPOT_PASS_503_RESP = b"503 Login with USER first.\r\n"
MINIPOT_QUIT_RESP = b"221 Goodbye.\r\n"


UTF8_ON_OPT = b"utf8 on"
USER = b"user"
PASS = b"pass"
QUIT = b"quit"
FEAT = b"feat"
OPTS = b"opts"
LF = b"\n"

USER_EMPTY_CMD = b"user\n"
PASS_EMPTY_CMD = b"pass\n"


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
    # strip \r in the end of parameter
    if user and user[-1] == 13:
        user = user[:-1]
    if password and password[-1] == 13:
        password = password[:-1]
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


def gen_cmd(keyword, param=b""):
    """ Generates and returns command byte string.

    Parameters:
        keyword: bytes
        param: bytes """
    return keyword + b" " + param + LF


################################################################################
# tests


def check_cmd_end_test1(server_sock):
    """ Sends to Minipots:
        one random byte NOT LF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_TIMEOUT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    cmd = gen_rand_bytes_w10(1)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_TIMEOUT_RESP
    return [gen_connect_report(server_sock)]


def check_cmd_end_test2(server_sock):
    """ Sends to Minipots:
        MINIPOT_CMD_BUFF_LEN - 1 times random bytes without LF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_TIMEOUT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    cmd = gen_rand_bytes_w10(MINIPOT_CMD_BUFF_LEN - 1)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_TIMEOUT_RESP
    return [gen_connect_report(server_sock)]


def check_cmd_end_test3(server_sock):
    """ Sends to Minipots:
        MINIPOT_CMD_BUFF_LEN times random bytes without LF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_TIMEOUT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    cmd = gen_rand_bytes_w10(MINIPOT_CMD_BUFF_LEN)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_TIMEOUT_RESP
    return [gen_connect_report(server_sock)]


def user_cmd_test1(server_sock):
    """ Sends to Minipots:
        user command without parameters
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(USER_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    return [gen_connect_report(server_sock)]


def user_cmd_test2(server_sock):
    """ Sends to Minipots:
        user SP command
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(USER))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    return [gen_connect_report(server_sock)]


def user_cmd_test3(server_sock):
    """ Sends to Minipots:
        user SP command with one byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(1)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    return [gen_connect_report(server_sock)]


def user_cmd_test4(server_sock):
    """ Sends to Minipots:
        user SP command with maximal length parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    return [gen_connect_report(server_sock)]


def pass_cmd_test1(server_sock):
    """ Sends to Minipots:
        user command with no parameter
        pass command with no parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(USER_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(PASS_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test2(server_sock):
    """ Sends to Minipots:
        user command with no parameter
        pass SP command
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(USER_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(gen_cmd(PASS))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test3(server_sock):
    """ Sends to Minipots:
        user command with no parameter
        pass command with one byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(USER_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(1)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test4(server_sock):
    """ Sends to Minipots:
        user command with no parameter
        pass SP command with maximal length parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(USER_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test5(server_sock):
    """ Sends to Minipots:
        user SP command without parameter
        pass command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(USER))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(PASS_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test6(server_sock):
    """ Sends to Minipots:
        user SP command without parameter
        pass SP command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(USER))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(gen_cmd(PASS))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test7(server_sock):
    """ Sends to Minipots:
        user SP command without parameter
        pass command with one byte parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(USER))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(1)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test8(server_sock):
    """ Sends to Minipots:
        user SP command without parameter
        pass command with maximal length parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_503_RESP
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(USER))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_503_RESP
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def pass_cmd_test9(server_sock):
    """ Sends to Minipots:
        user command with one byte parameter
        pass command with no parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(1)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(PASS_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock), gen_login_report(server_sock, user=user)]


def pass_cmd_test10(server_sock):
    """ Sends to Minipots:
        user command with one byte parameter
        pass SP command with no parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(1)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    cmd = gen_cmd(PASS)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock), gen_login_report(server_sock, user=user)]


def pass_cmd_test11(server_sock):
    """ Sends to Minipots:
        user command with one byte parameter
        pass command with one byte parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(1)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(1)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user, password=passw)]


def pass_cmd_test12(server_sock):
    """ Sends to Minipots:
        user command with one byte parameter
        pass command with maximal length parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(1)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user, password=passw)]


def pass_cmd_test13(server_sock):
    """ Sends to Minipots:
        user command with maximal length parameter
        pass command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    server_sock.sendall(PASS_EMPTY_CMD)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock), gen_login_report(server_sock, user=user)]


def pass_cmd_test14(server_sock):
    """ Sends to Minipots:
        user command with maximal length parameter
        pass SP command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    cmd = gen_cmd(PASS)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock), gen_login_report(server_sock, user=user)]


def pass_cmd_test15(server_sock):
    """ Sends to Minipots:
        user command with maximal length parameter
        pass command with one byte parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(1)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user, password=passw)]


def pass_cmd_test16(server_sock):
    """ Sends to Minipots:
        user command with maximal length parameter
        pass command with maximal length parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    user = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(USER, user)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_USER_RESP
    passw = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(PASS, passw)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_PASS_530_RESP
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, user=user, password=passw)]


def quit_cmd_test1(server_sock):
    """ Sends to Minipots:
        quit command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_QUIT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(QUIT + LF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_QUIT_RESP
    return [gen_connect_report(server_sock)]


def quit_cmd_test2(server_sock):
    """ Sends to Minipots:
        quit SP command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_QUIT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(QUIT))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_QUIT_RESP
    return [gen_connect_report(server_sock)]


def quit_cmd_test3(server_sock):
    """ Sends to Minipots:
        quit command with one byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_QUIT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(1)
    cmd = gen_cmd(QUIT, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_QUIT_RESP
    return [gen_connect_report(server_sock)]


def quit_cmd_test4(server_sock):
    """ Sends to Minipots:
        quit command with maximal length random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_QUIT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(QUIT, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_QUIT_RESP
    return [gen_connect_report(server_sock)]


def feat_cmd_test1(server_sock):
    """ Sends to Minipots:
        feat command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_FEAT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(FEAT + LF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_FEAT_RESP
    return [gen_connect_report(server_sock)]


def feat_cmd_test2(server_sock):
    """ Sends to Minipots:
        feat SP command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_FEAT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(FEAT))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_FEAT_RESP
    return [gen_connect_report(server_sock)]


def feat_cmd_test3(server_sock):
    """ Sends to Minipots:
        feat command with one byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_FEAT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(1)
    cmd = gen_cmd(FEAT, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_FEAT_RESP
    return [gen_connect_report(server_sock)]


def feat_cmd_test4(server_sock):
    """ Sends to Minipots:
        feat command with maximal length random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_FEAT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(FEAT, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_FEAT_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test1(server_sock):
    """ Sends to Minipots:
        opts command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(OPTS + LF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test2(server_sock):
    """ Sends to Minipots:
        opts SP command without parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(OPTS))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test3(server_sock):
    """ Sends to Minipots:
        opts command with one byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(1)
    cmd = gen_cmd(OPTS, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test4(server_sock):
    """ Sends to Minipots:
        opts command with 6 byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(6)
    cmd = gen_cmd(OPTS, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test5(server_sock):
    """ Sends to Minipots:
        opts command with 8 byte random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(8)
    cmd = gen_cmd(OPTS, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test6(server_sock):
    """ Sends to Minipots:
        opts command with maximal length random parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_501_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    param = gen_rand_bytes_w10(4090)
    cmd = gen_cmd(OPTS, param)
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_501_RESP
    return [gen_connect_report(server_sock)]


def opts_cmd_test7(server_sock):
    """ Sends to Minipots:
        opts command with UTF8_ON_OPT parameter
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OPTS_200_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(gen_cmd(OPTS, UTF8_ON_OPT))
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OPTS_200_RESP
    return [gen_connect_report(server_sock)]


def other_test1(server_sock):
    """ Sends to Minipots:
        empty line - LF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_TIMEOUT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(LF)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_TIMEOUT_RESP
    return [gen_connect_report(server_sock)]


def other_test2(server_sock):
    """ Sends to Minipots:
        one random byte + LF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_OTHER_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    cmd = gen_rand_bytes_w10(1) + LF
    server_sock.sendall(cmd)
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_OTHER_RESP
    return [gen_connect_report(server_sock)]


def other_test3(server_sock):
    """ Sends to Minipots:
        empty line - CRLF
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_TIMEOUT_RESP
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    server_sock.sendall(b"\r\n")
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_TIMEOUT_RESP
    return [gen_connect_report(server_sock)]


def brute_force_handler(server_sock):
    """ Sends to Minipots:
        MINIPOT_LOG_ATMPS_CNT times user, pass commands with random parameters
    Required response from Minipots':
        MINIPOT_WELCOME_RESP
        MINIPOT_USER_RESP
        MINIPOT_PASS_530_RESP / MINIPOT_PASS_503_RESP depends on if username
        is empty or no
    Required Minipots generated Sentinel message:
        connect
        MINIPOT_LOG_ATMPS_CNT times login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    reports = [gen_connect_report(server_sock)]
    response = recv_from_sock(server_sock)
    assert response == MINIPOT_WELOME_RESP
    for _ in range(MINIPOT_LOG_ATMPS_CNT):
        user = gen_rand_bytes_w10(randint(1, 4090))
        cmd = gen_cmd(USER, user)
        server_sock.sendall(cmd)
        response = recv_from_sock(server_sock)
        assert response == MINIPOT_USER_RESP
        passw = gen_rand_bytes_w10(randint(0, 4090))
        cmd = gen_cmd(PASS, passw)
        server_sock.sendall(cmd)
        response = recv_from_sock(server_sock)
        if user:
            reports.append(gen_login_report(server_sock, user=user, password=passw))
            assert response == MINIPOT_PASS_530_RESP
        else:
            assert response == MINIPOT_PASS_503_RESP
    response = recv_from_sock(server_sock)
    if response:
        raise Exception("wrong flow")
    return reports
