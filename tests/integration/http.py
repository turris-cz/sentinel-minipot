from random import randint, choice
from base64 import standard_b64encode

from framework.utils import gen_rand_bytes_w10, recv_from_sock, get_ip_addr
from framework.proxy import gen_proxy_report

MINIPOT_TOKEN_BUFF_LEN = 8192
MINIPOT_HEADER_LIMIT = 100
MINIPOT_MESSAGES_LIMIT = 100

MINIPOT_CONNECT_EV = b"connect"
MINIPOT_MSG_EV = b"message"
MINIPOT_LOGIN_EV = b"login"
MINIPOT_INVALID_EV = b"invalid"
MINIPOT_TYPE = b"http"

MINIPOT_METHOD = b"method"
MINIPOT_URL = b"url"
MINIPOT_USER_AG = b"user_agent"
MINIPOT_USERNAME = b"username"
MINIPOT_PASSWORD = b"password"

MINIPOT_URI_TOO_LONG_PART1 = b"HTTP/1.1 414 Request-URI Too Long\r\n"
MINIPOT_BAD_REQ_PART1 = b"HTTP/1.1 400 Bad Request\r\n"
MINIPOT_UNAUTH_REQ_PART1 = b"HTTP/1.1 401 Unauthorized\r\n"

SP = b" "
LF = b"\n"
CRLF = b"\r\n"
CRLF_x_2 = b"\r\n\r\n"
LAST_CHUNK_SIZE = b"0\r\n"
VERSION = b"HTTP/1.1"
USER_AG = b"user-agent:"
AUTH = b"authorization:"
BASIC = b"\t\t \t Basic  \t\t "
WS = b"  \t \t\t  "
CON_LEN = b"content-length:"
TR_ENC = b"transfer-encoding:"
CHNKD = b"\t  \t chunked \t\t  "


REQ_LINE = b"asasasas okjljlkjlkjlk " + VERSION + CRLF
TR_ENC_HEAD = TR_ENC + CHNKD + CRLF


def gen_connect_report(sock):
    """ Generates proxy report connect message and returns it as dictionary.

    Parameters:
        sock: socket """
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_CONNECT_EV, get_ip_addr(sock))


def gen_mesg_report(sock, meth=b"", url=b"", user_ag=b""):
    """ Generates proxy report message message and returns it as dictionary.

    Parameters:
        sock: socket
        meth:  bytes
        url: bytes
        user_ag: bytes """
    data = {
        MINIPOT_METHOD: meth,
        MINIPOT_URL: url,
        MINIPOT_USER_AG: user_ag,
    }
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_MSG_EV, get_ip_addr(sock), data)


def gen_login_report(sock, meth=b"", url=b"", user_ag=b"", user=b"", passw=b""):
    """ Generates proxy report login message and returns it as a dictionary.

    Parameters:
        sock: socket
        meth: bytes
        url: bytes
        user_ag: bytes
        user: bytes
        passw: bytes """
    data = {
        MINIPOT_METHOD: meth,
        MINIPOT_URL: url,
        MINIPOT_USER_AG: user_ag,
        MINIPOT_USERNAME: user,
        MINIPOT_PASSWORD: passw,
    }
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_LOGIN_EV, get_ip_addr(sock), data)


def gen_invalid_report(sock):
    """ Generates proxy report invalid message and returns it as dictionary.

    Parameters:
        sock: socket """
    return gen_proxy_report(MINIPOT_TYPE, MINIPOT_INVALID_EV, get_ip_addr(sock))


def gen_req_line(method, url):
    """ Generates request line with given method and url and returns it as bytes.

    Parameters:
        method: bytes
        url: bytes """
    return method + SP + url + SP + VERSION + CRLF


def gen_header(name=b"", value=b""):
    """ Generates header line with given name and value and returns it as bytes.

    Parameters:
        name: bytes
        value: bytes """
    return name + b":" + WS + value + WS + CRLF


def gen_user_ag_header(user_ag=b""):
    """ Generates user-agent header with given value and returns it as bytes.

    Parameters:
        user_ag: bytes """
    return USER_AG + WS + user_ag + WS + CRLF


def gen_auth_header(user=b"", passw=b""):
    """ Generates authorization header from username and password and returns it as bytes.

    Parameters:
        user: bytes
        passw: bytes """
    return AUTH + BASIC + standard_b64encode(user + b":" + passw) + WS + CRLF


def gen_con_len_header(value=b""):
    """ Generates content length header with given value and returns it as bytes.

    Parameter:
        value: bytes """
    return CON_LEN + WS + value + WS + CRLF


def gen_tr_enc_header(value=b""):
    """ Generates transfer-encoding header with given value and returns it as bytes.

    Parameters:
        value: bytes """
    return TR_ENC + WS + value + WS + CRLF


def gen_chunk_size_line(size, ext=b""):
    """ Generates chunk size line with given size and extension and returns it as bytes.

    Parameters:
        size: int
        ext: bytes """
    if ext:
        return hex(size).encode() + b" ; " + ext + CRLF
    return hex(size).encode() + CRLF


def gen_con_len_body(len):
    """ Returns randomly generated content length body with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(256))) for _ in range(len)])


def gen_chunk_body(size):
    """ Returns randomly generated chunk body with given length as bytearray.

    Parameters:
        size: int """
    chunk_body = bytearray([choice(list(range(256))) for _ in range(size)])
    chunk_body.append(13)
    chunk_body.append(10)
    return chunk_body


def gen_meth(len):
    """ Returns randomly generated method with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(33, 127))) for _ in range(len)])


def gen_url(len):
    """ Returns randomly generated url with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(33, 127))) for _ in range(len)])


def gen_head_name(len):
    """ Returns randomly generated header name with given length as bytes.

    Parameters:
        len: int """
    discard = [34, 40, 41, 44, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 123, 125]
    bytevals = [_ for _ in list(range(33, 127)) if _ not in discard]
    return bytes([choice(bytevals) for _ in range(len)])


def gen_head_val(len):
    """ Returns randomly generated header value with given length as bytes.

    Parameters:
        len: int """
    bytevals = list(range(32, 127))
    bytevals.append(9)  # tab
    return bytes([choice(bytevals) for _ in range(len)])


def gen_user_ag(len):
    """ Returns randomly generated user agent with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(33, 127))) for _ in range(len)])


def gen_chunk_ext(len):
    """ Returns randomly generated chunk size line extension with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(32, 127))) for _ in range(len)])


def gen_username(len):
    """ Returns randomly generated username with given length as bytes.

    Parameters:
        len: int """
    bytevals = list(range(256))
    bytevals.remove(58)  # : - it is delimeter of username and password
    # if username contains : then username and password are incorrectly parsed
    return bytes([choice(bytevals) for _ in range(len)])


def gen_password(len):
    """ Returns randomly generated password with given length as bytes.

    Parameters:
        len: int """
    return bytes([choice(list(range(256))) for _ in range(len)])


################################################################################
# Empty line tests


def empty_mesg_test1(server_sock):
    """ Sends to Minipots:
        Empty line - LF only
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = LF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def empty_mesg_test2(server_sock):
    """ Sends to Minipots:
        empty line - CRLF
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


################################################################################
# request line tests


def req_line_test1(server_sock):
    """ Sends to Minipots:
        valid request line with some data
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, meth=method, url=url)]


def req_line_test2(server_sock):
    """ Sends to Minipots:
        request line with missing first SP
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_meth(30) + SP + VERSION + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test3(server_sock):
    """ Sends to Minipots:
        request line with missing second SP
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_meth(30) + SP + gen_url(40) + VERSION + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test4(server_sock):
    """ Sends to Minipots:
        request line with method with invalid character
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_req_line(b"\x00adsd", gen_url(40)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test5(server_sock):
    """ Sends to Minipots:
        request line with url with invalid character
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_req_line(gen_meth(30), b"\x01dsdsd") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test6(server_sock):
    """ Sends to Minipots:
        request line with wrong version string
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_meth(30) + SP + gen_url(40) + SP + b"jTTP/1.1" + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test7(server_sock):
    """ Sends to Minipots:
        random bytes with size of buffer + LF
    Required response from Minipots':
        MINIPOT_URI_TOO_LONG_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_rand_bytes_w10(MINIPOT_TOKEN_BUFF_LEN) + LF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_URI_TOO_LONG_PART1)] == MINIPOT_URI_TOO_LONG_PART1
    return [gen_connect_report(server_sock)]


def req_line_test8(server_sock):
    """ Sends to Minipots:
        request line with missing CR
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_meth(30) + SP + gen_url(40) + SP + VERSION + LF + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test9(server_sock):
    """ Sends to Minipots:
        valid request line with no method
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    url = gen_url(500)
    msg = gen_req_line(b"", url) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, url=url)]


def req_line_test10(server_sock):
    """ Sends to Minipots:
        valid request line with no url
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    msg = gen_req_line(method, b"") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def req_line_test11(server_sock):
    """ Sends to Minipots:
        valid request line with no url
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = gen_req_line(b"", b"") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


################################################################################
# general header line tests


def header_line_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with missing double dot
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        double dot is separator of header name and value
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + b"aaaaaaaaa" + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def header_line_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with invalid character in header name
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_header(name=b"\x00sssas", value=gen_head_val(200)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def header_line_test3(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with invalid character in header value
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_header(name=gen_head_name(200), value=b"\x00sasa") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def header_line_test4(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with empty header name
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        header with empty name is valid
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_header(value=gen_head_val(200)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, meth=method, url=url)]


def header_line_test5(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with empty value
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        header with empty value is valid
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_header(name=gen_head_name(200)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, meth=method, url=url)]


def header_line_test6(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with empty name and value
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        header with empty name and value is valid
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_header() + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, meth=method, url=url)]


def header_line_test7(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with missing CR
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_head_name(200) + b":" + gen_head_val(200) + LF + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def header_line_test8(server_sock):
    """ Sends to Minipots:
        valid request line
        valid header line with unknown name
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        the unknown header is ignored
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_header(name=gen_head_name(200),
                                                 value=gen_head_val(200)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_mesg_report(server_sock, meth=method, url=url)]


def header_line_test9(server_sock):
    """ Sends to Minipots:
        valid request line
        header line with size of buffer with LF
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        header line doesn't fit into buffer
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    bytelist = list(range(256))
    bytelist.remove(10)
    msg = REQ_LINE + gen_rand_bytes_w10(MINIPOT_TOKEN_BUFF_LEN) + LF + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def header_line_test10(server_sock):
    """ Sends to Minipots:
        valid request line
        maximal number of header lines
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        header lines has limit on count
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + MINIPOT_HEADER_LIMIT * gen_header(name=gen_head_name(200),
                                                       value=gen_head_val(200)) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


################################################################################
# user agent header tests


def user_agent_head_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        valid user agent header
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    user_ag = gen_user_ag(randint(1, 8000))
    msg = gen_req_line(method, url) + gen_user_ag_header(user_ag) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url, user_ag=user_ag)]


def user_agent_head_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        valid user agent header with empty user agent
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_user_ag_header() + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


################################################################################
# authorization header tests


def auth_header_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with random data in value
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + AUTH + WS + b"kjyrsdsdsdscvbnj" + WS + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def auth_header_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with two random data tokens
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = b"".join([REQ_LINE, AUTH, WS, b"kjyrsdsdsdscvbnj", WS,
                    b"uuywretwoteds", WS, CRLF_x_2])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def auth_header_test3(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with valid scheme and invalid base64 data
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + AUTH + BASIC + b"hjhjj)" + CRLF_x_2
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def auth_header_test4(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with valid scheme and valid base64 data
        but missing double dot after decoding
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        invalid
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = b"".join([REQ_LINE, AUTH, BASIC, standard_b64encode(b"hfjfjffjhfjhjdh"),
                    WS, CRLF_x_2])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock), gen_invalid_report(server_sock)]


def auth_header_test5(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with valid scheme and valid base64 data
        empty username
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    password = gen_password(4000)
    msg = gen_req_line(method, url) + gen_auth_header(passw=password) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, meth=method, url=url, passw=password)]


def auth_header_test6(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with valid scheme and valid base64 data
        empty password
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    username = gen_username(4000)
    msg = gen_req_line(method, url) + gen_auth_header(user=username) + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, meth=method, url=url, user=username)]


def auth_header_test7(server_sock):
    """ Sends to Minipots:
        valid request line
        authorization header with valid scheme and valid base64 data
        non empty username and password
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    username = gen_username(2000)
    password = gen_password(2000)
    msg = b"".join([gen_req_line(method, url),
                    gen_auth_header(user=username, passw=password), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, meth=method, url=url, user=username,
            passw=password)]


def auth_header_test8(server_sock):
    """ Sends to Minipots:
        valid request line
        2x authorization header with valid data
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:
        only data from the last auth header should be sent to server
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    username1 = gen_username(randint(0, 2000))
    password1 = gen_password(randint(0, 2000))
    username2 = gen_username(randint(0, 2000))
    password2 = gen_password(randint(0, 2000))
    msg = b"".join([gen_req_line(method, url),
                    gen_auth_header(user=username1, passw=password1),
                    gen_auth_header(user=username2, passw=password2), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, meth=method, url=url, user=username2,
            passw=password2)]


def auth_header_test9(server_sock):
    """ Sends to Minipots:
        valid request line
        valid authorization header
        valid user agent header
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    username = gen_username(2000)
    password = gen_password(2000)
    user_ag = gen_user_ag(randint(0, 8000))
    msg = b"".join([gen_req_line(method, url),
                    gen_auth_header(user=username, passw=password),
                    gen_user_ag_header(user_ag), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_login_report(server_sock, meth=method, url=url, user=username,
            passw=password, user_ag=user_ag)]


def brute_force_test1(server_sock):
    """ Sends to Minipots:
        performs bruteforce attack by sending
        multiple valid messages wiith authorization and user agent headers
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        login
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    reports = [gen_connect_report(server_sock)]
    for i in range(MINIPOT_MESSAGES_LIMIT):
        method = gen_meth(randint(0, 3000))
        url = gen_url(randint(1, 4000))
        username = gen_username(randint(0, 2500))
        password = gen_password(randint(0, 2500))
        user_ag = gen_user_ag(randint(0, 8000))
        msg = b"".join([gen_req_line(method, url),
                        gen_auth_header(user=username, passw=password),
                        gen_user_ag_header(user_ag), CRLF])
        server_sock.sendall(msg)
        response = recv_from_sock(server_sock)
        assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
        reports.append(gen_login_report(server_sock, meth=method, url=url,
                       user=username, passw=password, user_ag=user_ag))
    return reports


################################################################################
# content length header test


def con_len_head_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        content lngth header with no value
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header() + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        content length header where value is not a number
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header(b"asdsadsd") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test3(server_sock):
    """ Sends to Minipots:
        valid request line
        content length header with negative value
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header(b"-1") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test4(server_sock):
    """ Sends to Minipots:
        valid request line
        content header with value out of range
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header(b"9223372036854775808") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test5(server_sock):
    """ Sends to Minipots:
        valid request line
        content length header with negative value out of range
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header(b"-9223372036854775809") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test6(server_sock):
    """ Sends to Minipots:
        valid request line
        content length header with multiple valid values
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_con_len_header(b"20 , 34") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def con_len_head_test7(server_sock):
    """ Sends to Minipots:
        valid request line
        content length header with value zero
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    msg = gen_req_line(method, url) + gen_con_len_header(b"0") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


################################################################################
# static length body tests


def con_len_body_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        valid content length header
        body with random bytes
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    body_len = randint(100, 1000000)
    msg = b"".join([gen_req_line(method, url),
                    gen_con_len_header(str(body_len).encode()), CRLF,
                    gen_con_len_body(body_len)])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


################################################################################
# transfer encoding header tests


def trans_enc_header_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with random value
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        chunked coding must be last coding if transfer encoding header is present
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_tr_enc_header(b"aaaaaaaaa") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def trans_enc_header_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with two values - first is chunked,
        second is random garbage
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        chunked coding must be last coding if transfer encoding header is present
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = REQ_LINE + gen_tr_enc_header(CHNKD + b"  ,  \t\tbbbb") + CRLF
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


################################################################################
# chunked body tests

def chunk_body_test1(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked as value
        one chunk as body
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size = randint(100, 2000)
    msg = b"".join([gen_req_line(method, url), TR_ENC_HEAD, CRLF,
                    gen_chunk_size_line(chunk_size), gen_chunk_body(chunk_size),
                    LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


def chunk_body_test2(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with 4 values -
        first 3 are not valid codings names
        last is chunked
        one chunk as body
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        chunked coding must be last coding if transfer encoding header is present
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size = randint(100, 2000)
    msg = b"".join([gen_req_line(method, url),
                    gen_tr_enc_header(b"aaaaa\t, \tbbbb, \tvvvvv," + CHNKD), CRLF,
                    gen_chunk_size_line(chunk_size), gen_chunk_body(chunk_size),
                    LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


def chunk_body_test3(server_sock):
    """ Sends to Minipots:
        valid request line
        two transfer encoding headers with multiple values
        chunked is last value
        one chunk as body
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        chunked coding must be last coding if transfer encoding header is present
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size = randint(100, 2000)
    msg = b"".join([gen_req_line(method, url),
                    gen_tr_enc_header(b"\t aaaaa\t, \tbbbb, \tvvvvv"),
                    gen_tr_enc_header(b"hhhh\t,\t , \tdddd\t," + CHNKD), CRLF,
                    gen_chunk_size_line(chunk_size), gen_chunk_body(chunk_size),
                    LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


def chunk_body_test4(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
            chunk size value is not number
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF, b"hhh", CRLF,
                    gen_chunk_body(randint(100, 2000)), LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test5(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
            chunk size out of range
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF, gen_chunk_size_line(9223372036854775808),
                    gen_chunk_body(randint(100, 2000)), LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test6(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chnk as body
            with chunk extension
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size = randint(100, 2000)
    msg = b"".join([gen_req_line(method, url), TR_ENC_HEAD, CRLF,
                    gen_chunk_size_line(chunk_size,
                                        gen_chunk_ext(randint(10, 3000))),
                    gen_chunk_body(chunk_size), LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


def chunk_body_test7(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
            with invalid character in chunk extension
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    chunk_size = randint(100, 2000)
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF,
                    gen_chunk_size_line(chunk_size,
                                        b"sdsfdsfdfdsfdsffdsfds\x00"),
                    gen_chunk_body(chunk_size), LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test8(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
        chunked body trailer with missing double dot
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        trailer is "header" in chunked body
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    chunk_size = randint(100, 2000)
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF, hex(chunk_size).encode(), CRLF,
                    gen_chunk_body(chunk_size), LAST_CHUNK_SIZE, b"dsddsddd", CRLF_x_2])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test9(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
        valid chunked body trailer
    Required response from Minipots':
        MINIPOT_UNAUTH_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
        message
    More description:
        trailer is "header" in chunked body
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size = randint(100, 2000)
    msg = b"".join([gen_req_line(method, url), TR_ENC_HEAD, CRLF,
                    gen_chunk_size_line(chunk_size), gen_chunk_body(chunk_size),
                    LAST_CHUNK_SIZE, gen_header(name=b"aa", value=b"aa"), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]


def chunk_body_test10(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
            trailer has invalid character in name
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        trailer is "header" in chunked body
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    chunk_size = randint(100, 2000)
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF, gen_chunk_size_line(chunk_size),
                    gen_chunk_body(chunk_size), LAST_CHUNK_SIZE,
                    gen_header(name=b"\x00asas", value=b"asas"), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test11(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        one chunk as body
            trailer has invalid charater in value
    Required response from Minipots':
        MINIPOT_BAD_REQ_PART1
    Required Minipots generated Sentinel message:
        connect
    More description:
        trailer is "header" in chunked body
    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    chunk_size = randint(100, 2000)
    msg = b"".join([REQ_LINE, TR_ENC_HEAD, CRLF, gen_chunk_size_line(chunk_size),
                    gen_chunk_body(chunk_size), LAST_CHUNK_SIZE,
                    gen_header(name=b"asa", value=b"\x00asas"), CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_BAD_REQ_PART1)] == MINIPOT_BAD_REQ_PART1
    return [gen_connect_report(server_sock)]


def chunk_body_test12(server_sock):
    """ Sends to Minipots:
        valid request line
        transfer encoding header with chunked coding
        body with two chunks
    Required response from Minipots':
        aunauthorized
    Required Minipots generated Sentinel message:
        connect
        message
    More description:

    Parameters:
        server_sock: socket
    Returns list of dictionaries - generated proxy reports or assert
    exception if communication with minipot went wrong. """
    method = gen_meth(500)
    url = gen_url(500)
    chunk_size1 = randint(100, 100000)
    chunk_size2 = randint(100, 10000)
    msg = b"".join([gen_req_line(method, url), TR_ENC_HEAD, CRLF,
                    gen_chunk_size_line(chunk_size1, gen_chunk_ext(randint(1, 7000))),
                    gen_chunk_body(chunk_size1),
                    gen_chunk_size_line(chunk_size2, gen_chunk_ext(randint(1, 7000))),
                    gen_chunk_body(chunk_size2), LAST_CHUNK_SIZE, CRLF])
    server_sock.sendall(msg)
    response = recv_from_sock(server_sock)
    assert response[:len(MINIPOT_UNAUTH_REQ_PART1)] == MINIPOT_UNAUTH_REQ_PART1
    return [gen_connect_report(server_sock),
            gen_mesg_report(server_sock, meth=method, url=url)]
