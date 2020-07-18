#!/usr/bin/env python3

import random
import base64
import time
from proxy import gen_proxy_report
from utils import *



BAD_REQ_RESPONSE = b"HTTP/1.1 400 Bad Request\r\n\r\n"
UNAUTHORIZED_RESPONSE = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"simple\"\r\n\r\n"
FORBIDDEN_RESPONSE = b"HTTP/1.1 403 Forbidden\r\n\r\n"
METH_NOT_ALLOW_RESP = b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\n\r\n"

MAX_MESG_SIZE = 65536

# minimum number of guesses for minipot
HTTP_CRED_MIN_RANGE = 100
# maximum number of guesses for minipot
HTTP_CRED_MAX_RANGE = 1000

GET_METH = b"GET"
HEAD_METH = b"HEAD"
POST_METH = b"POST"
PUT_METH = b"PUT"
DEL_METH = b"DELETE"
CONN_METH = b"CONNECT"
OPT_METH = b"OPTIONS"
TRAC_METH = b"TRACE"
PATCH_METH = b"PATCH"

VERSION_1_1 = b"HTTP/1.1"


def gen_user_id(len):
    """ Returns random user-id binary string with given length. """
    # allowed chars: ASCII 32-57, 59-126
    chars = list(range(32, 127))
    # remove 58-: - it is delimeter of user-id and password
    chars.remove(58)
    return bytearray(random.choice(chars) for n in range(len))


def gen_password(len):
    """ Returns random password binary string with given length. """
    # allowed chars: ASCII 32-126
    return gen_rand_ascii_print_byte_str(len)


def gen_url(len):
    """ Generates random url byte string of given length. """
    # allowed chars: ASCII 33-126
    return bytearray(random.choice(list(range(33, 127))) for n in range(len))


def gen_user_agent(len):
    """ Generates random user agent byte string of given length. """
    # allowed chars: ASCII 32-126
    return gen_rand_ascii_print_byte_str(len)


def encode_cred(credentials):
    """ Encodes credentials using Base64 coding.
    Credentials is bytes string. Returns bytes string. """
    return base64.standard_b64encode(credentials)


def gen_authorization_header(user_id, password):
    """ Generates authorization header field.
    user_id, password are byte strings.  Returns byte string. """
    return b"Authorization: Basic " + encode_cred(user_id + b':' + password) + b"\r\n"


def gen_user_agent_header(user_ag):
    """ Generates user agent header field from user agent value.
    user_ag is byte string. Returns byte string. """
    return b"User-Agent: " + user_ag + b"\r\n"


def gen_content_len_header(content_len):
    """ Generates content length header field.
    content_len is byte string. Returns byte string. """
    return b"Content-Length: " + content_len + b"\r\n"


def gen_transfer_enc_header(transfer_enc):
    """ Generates transfer encoding header field.
    transfer_enc is byte string. Returns byte string. """
    return b"Transfer-Encoding: " + transfer_enc + b"\r\n"


def gen_body(len):
    """ Generates random body of given length.
    Returns byte string. """
    return gen_rand_ascii_print_byte_str(len)


def gen_chunks(sizes=[]):
    """ generates list of chunk objects according to sizes in input list.
    Bodies contains random chars. """
    chunks = []
    for size in sizes:
        # extensions
        chunks.append(gen_chunk(size, gen_rand_ascii_print_byte_str(size)))
    return chunks


def gen_chunk(size, body, ext=b""):
    """ Generates chunk byte string from given input data.
    size is int.
    body is  byte string.
    ext is byte string. """
    return hex(size).encode() + ext + b"\r\n" + body + b"\r\n"


def gen_chunked_body(chunks=[], trailers=[]):
    """ generates chunked body from list of chunks and trailers.
    chunks is list of chunk objects. Last chunk of size 0 is generated automaticaly
    trailers is list of byte strings
    Returns bytes string. """
    return b"".join(chunks) + b"0\r\n" + b"".join(trailers) + b"\r\n"


def compose_message(method=b"", url=b"", version=b"", headers=(), body=b""):
    """ Generates HTTP messages from given input data.
    method,url,version,body are binary strings.
    Headers is tuple of binary srings.
    Returns binary strings. """
    # start line
    mesg = method + b" " + url + b" " + version + b"\r\n"
    # headers
    if headers:
        mesg += b"".join(headers)
    # headers, body
    mesg = mesg + b"\r\n" + body
    return mesg


def proxy_report_connect(ip):
    """ Generates proxy connect report.
    ip is string.
    Returns string. """
    return gen_proxy_report('http', 'connect', ip, None)


# def proxy_report_disconnect(ip):
#     """ Generates proxy disconnet report.
#     ip is string.
#     Returns string. """
#     return gen_proxy_report('http', 'disconnect', ip, None)


# def proxy_report_syntax_error(ip):
#     """ Generates proxy syntax error reposrt.
#     ip is string.
#     Returns string. """
#     return gen_proxy_report('http', 'syntax error', ip, None)


def proxy_report_message(ip="", method=b"", url=b"", user_id=b"", passw=b"", user_ag=b""):
    """ Generates proxy message report.
    ip is string.
    method,url,user_id,passw,user_ag are byte strings.
    Returns string. """
    data = {}
    if method:
        data['method'] = method.decode('utf-8')
    if url:
        data['url'] = url.decode('utf-8')
    if user_id:
        data['user-id'] = user_id.decode('utf-8')
    if passw:
        data['password'] = passw.decode('utf-8')
    if user_ag:
        data['user-agent'] = user_ag.decode('utf-8')
    return gen_proxy_report('http', 'message', ip, data)


# semantics
def get_msg_handler(server_sock):
    # payload has no defined semantics
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, UNAUTHORIZED_RESPONSE)
    return sent_messages


def head_msg_handler(server_sock):
    # payload has no defined semantics
    ip_addr = get_ip_addr(server_sock)
    method = HEAD_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, UNAUTHORIZED_RESPONSE)
    return sent_messages


def post_msg_handler(server_sock):
    ip_addr = get_ip_addr(server_sock)
    method = POST_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages



def put_msg_handler(server_sock):
    ip_addr = get_ip_addr(server_sock)
    method = PUT_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages



def del_msg_handler(server_sock):
    # payload has no defined semantics
    ip_addr = get_ip_addr(server_sock)
    method = DEL_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages



def trac_msg_handler(server_sock):
    # client must not send payload
    ip_addr = get_ip_addr(server_sock)
    method = TRAC_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages



def conn_msg_handler(server_sock):
    # payload has no defined semantics
    ip_addr = get_ip_addr(server_sock)
    method = CONN_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages


def opt_msg_handler(server_sock):
    # payload has no defined semantics
    ip_addr = get_ip_addr(server_sock)
    method = OPT_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages



def patch_msg_handler(server_sock):
    ip_addr = get_ip_addr(server_sock)
    method = PATCH_METH
    url = gen_url(10)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    mesg = compose_message(method, url, VERSION_1_1)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, METH_NOT_ALLOW_RESP)
    return sent_messages


# scenarios
def brute_force_handler(server_sock):
    """ Do standart brute force attack. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_ag = gen_user_agent(random.randint(200, 300))
    user_ag_header = gen_user_agent_header(user_ag)
    sent_messages = [proxy_report_connect(ip_addr)]
    while True:
        # gen data
        user_id = gen_user_id(random.randint(10, 100))
        passw = gen_password(random.randint(10, 200))
        # for proxy
        sent_messages.append(proxy_report_message(ip_addr, method, url, user_id, passw, user_ag))
        # for server
        auth_header = gen_authorization_header(user_id, passw)
        message = compose_message(method, url, VERSION_1_1, (user_ag_header, auth_header))
        send_to_sock(server_sock, message)
        response = recv_from_sock(server_sock)
        if response == UNAUTHORIZED_RESPONSE:
            continue
        if response == FORBIDDEN_RESPONSE:
            if not recv_from_sock(server_sock):
                # closed connection by server
                break
        raise Exception("wrong response: ", response)
    return sent_messages


def too_long_conn_handler1(server_sock):
    """ No communication. Just hanging connection. """
    ip_addr = get_ip_addr(server_sock)
    sent_messages = [proxy_report_connect(ip_addr)]
    time.sleep(5)
    if recv_from_sock(server_sock):
        raise Exception('wrong flow')
    return sent_messages


def too_long_conn_handler2(server_sock):
    """ Send and receive 1x . Wait 5s. Check if connection was closed. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(200)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]

    mesg = compose_message(method, url)
    send_to_sock(server_sock, mesg)
    resp = recv_from_sock(server_sock)
    str_cmp(resp, UNAUTHORIZED_RESPONSE)
    time.sleep(5)
    if recv_from_sock(server_sock):
        raise Exception('wrong flow')
    return sent_messages


def interrupt_conn_handler(server_sock):
    """ Send and receive random number times. Close connection. Check of it was closed.
    Guess less times than minimum number guesses set up on minipot to ensure the connection is closed by client
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(100)
    user_ag = gen_user_agent(200)
    user_ag_header = gen_user_agent_header(user_ag)
    sent_messages = [proxy_report_connect(ip_addr)]
    for i in range(random.randint(0, HTTP_CRED_MIN_RANGE-1)):
        # gen data
        user_id = gen_user_id(random.randint(10, 100))
        passw = gen_password(random.randint(10, 200))
        # for proxy
        sent_messages.append(proxy_report_message(ip_addr, method, url, user_id, passw, user_ag))
        # for server
        auth_header = gen_authorization_header(user_id, passw)
        mesg = compose_message(method, url, VERSION_1_1, [user_ag_header, auth_header])
        send_to_sock(server_sock, mesg)
        response = recv_from_sock(server_sock)
        if response == UNAUTHORIZED_RESPONSE:
            continue
        raise Exception("wrong response: ", response)
    server_sock.close()
    return sent_messages

#syntax

def incomplete_mesg(server_sock):
    """ Sends an incomplete message.
    Maximum message size is used.
    The connection is terminated in 5 seconds. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(32763)
    # we just want random string
    version = gen_password(32764)
    mesg = compose_message(method, url, version)
    # take random incomplete part
    mesg = mesg[0:random.randint(1, 65534)]
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    time.sleep(5)
    if recv_from_sock(server_sock):
        raise Exception('wrong flow')
    return sent_messages


# syntax
def test1(server_sock):
    """ Send random garbage of maximum message size.
    Connection should be closed in 5 seconds. """
    ip_addr = get_ip_addr(server_sock)
    # remove space to not fail on method token parsing
    mesg = gen_rand_byte_str(65536).replace(b" ", bytes([random.randint(33, 128)]))
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    time.sleep(5)
    if recv_from_sock(server_sock):
        raise Exception('wrong flow')
    return sent_messages


def test2(server_sock):
    """ Send random garbage of more than maximum message size.
    It should close immediately, because message size limit. """
    ip_addr = get_ip_addr(server_sock)
    # remove space to not fail on method token parsing
    mesg = gen_rand_byte_str(65537).replace(b" ", bytes([random.randint(33, 128)]))
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def test3(server_sock):
    """ Send random garbage as url and version.
    Maximum message size is used.
    It will pass since these tokens are not checked.
    Url is only saved up to 8192 bytes and version is ignored. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(32763)
    version = gen_rand_ascii_print_byte_str(32764)
    mesg = method + b" " + url + b" " + version + b"\r\n\r\n"
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url[:8191])]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def test4(server_sock):
    """
    Send random garbage as url and version.
    Maximum message size is used.
    Wrong character at the end of start line end 0B instead of 0A
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(32763)
    version = gen_rand_ascii_print_byte_str(32764)
    mesg = method + b" " + url + b" " + version + b"\x0D\x0B\x0D\x0A"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def test5(server_sock):
    """
    Send random garbage as url and version.
    Maximum message size is used.
    Wrong character at the end of message end 0B instead of 0A
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(32763)
    version = gen_rand_ascii_print_byte_str(32764)
    mesg = method + b" " + url + b" " + version + b"\x0D\x0A\x0D\x0B"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def test6(server_sock):
    """
    Send random garbage as url,http version and header.
    Wrong character at the end of header field 0B instead of 0A
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10000)
    version = gen_rand_ascii_print_byte_str(10000)
    header = gen_rand_ascii_print_byte_str(10000)
    mesg = method + b" " + url + b" " + version + b"\x0D\x0A" + header + b"\x0D\x0B"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def test7(server_sock):
    """
    Send random garbage as url and version.
    In header field there is missing delimeter
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10000)
    version = gen_rand_ascii_print_byte_str(10000)
    # no user_id -> we just want rand string without :
    header = gen_user_id(10000)
    mesg = method + b" " + url + b" " + version + b"\x0D\x0A" + header + b"\x0D\x0A"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def test8(server_sock):
    """
    Send random garbage as url and version.
    The header name is 4094 chars of garbage with 1 char delimeter.
    The token buffer of the minipot, which is used to process headers is 4096 chars but last char
    is string terminator to avoid problems during processing the information.
    The header value is garbage but it doesn't fit into token buffer.
    The garbage heder name is ignored because it is unknown.
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10000)
    version = gen_rand_ascii_print_byte_str(10000)
    # no user_id -> we just want string without :
    header = gen_user_id(4094)
    mesg = method + b" " + url + b" " + version + b"\x0D\x0A" + header + b":\x0D\x0A\x0D\x0A"
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url[:8191])]
    send_to_sock(server_sock, mesg)
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def test9(server_sock):
    """ White space between the start line end and headers part end - message.
    The connectio should be closed after 5s timeout.
    Minipot will consider space as start of a heder. """
    ip_addr = get_ip_addr(server_sock)
    sent_messages = [proxy_report_connect(ip_addr)]
    mesg = GET_METH + b" " + gen_url(10) + b" " + VERSION_1_1 + b"\r\n   \r\n"
    send_to_sock(server_sock, mesg)
    if recv_from_sock(server_sock):
        raise Exception('wrong flow')
    return sent_messages

#

def user_agent_header_limit(server_sock):
    """
    Send random garbage as url and version.
    Check user agent header field limit
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10000)
    user_ag = gen_user_agent(10000)
    user_ag_head = gen_user_agent_header(user_ag)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip=ip_addr, method=method, url=url[:8191], user_ag=user_ag[:4083])]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [user_ag_head]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_encoding_test1(server_sock):
    """
    Generates correct credentials and encodes it.
    Encoded credentials fully fit in token buffer of 4095 chars.
    Inject error to encoded credentials.
    It has to fail due to check of encoded characters.
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = gen_user_id(100)
    passwd = gen_password(200)
    auth_header = b"Authorization: Basic " + encode_cred(user_id + b":" + passwd) + b"*\r\n"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def credentials_encoding_test2(server_sock):
    """
    Base 64 encoding takes 3 chars and encodes it as 4 chars.
    Token buffer is 4075.
    3054 bytes are encoded into 4072 bytes
    3055 + 2 bytes padding -> 4076 bytes
    3056 + 1 bytes padding -> 4076 bytes
    3057 bytes are encoded into 4076 bytes

    Maximal encoded credentials len which are processed is 4075 (4095-20)
    4095 - length of token buffer
    20 - length of authorization header and name of the authentication scheme.

    If we encode more than 3055 bytes. The decoded data in minipot are incomplete
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(20)
    user_id = gen_user_id(1500)
    passwd = gen_password(1554)
    auth_header = b"Authorization: Basic " + encode_cred(user_id + b":" + passwd) + b"*\r\n"

    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url, user_id, passwd)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_encoding_test3(server_sock):
    """ Generates valid encoded credentials token with length greater than 4075.
    Char 4076 is not processed. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    # maximal length user-id
    user_id = gen_user_id(3054)
    # password will be skipped
    passwd = gen_password(3000)
    auth_header = gen_authorization_header(user_id, passwd)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url, user_id, passwd)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_limit_test1(server_sock):
    """
    Generated correct credetials with length bigger than token buffer length.

    Minipot decodes only 3055 bytes. The rest is ignored.
    the double dot is byte 3056. It is not recognized after decoding.
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = gen_user_id(3055)
    password = gen_password(4000)
    auth_header = gen_authorization_header(user_id, password)
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def credentials_limit_test2(server_sock):
    """
    Generated correct credetials with length bigger than token buffer length.

    Byte 3056 in credentials string is last char that is fully decoded in minipot
    If userid is 3055 bytes long following delimeter is decoded and credentials are valid with missing password.
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = gen_user_id(3054)
    password = gen_password(4000)
    auth_header = gen_authorization_header(user_id, password)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url, user_id)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_limit_test3(server_sock):
    """
    generates credentials with maximal length user ID
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = gen_user_id(3054)
    password = b""
    auth_header = gen_authorization_header(user_id, password)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url, user_id)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_limit_test4(server_sock):
    """
    Send empty user-id and empty password
    it fits into 4075 char long token buffer
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = b""
    password = b""
    auth_header = gen_authorization_header(user_id, password)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def credentials_limit_test5(server_sock):
    """
    Send empty user-id with some password
    it fits into 4075 char long token buffer
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id = b""
    password = gen_password(3054)
    auth_header = gen_authorization_header(user_id, password)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method=method, url=url, passw=password)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def transfer_enc_test1(server_sock):
    """
    send invalid value
    -> syntax error
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(15)
    transfer_enc_header = gen_transfer_enc_header(b"kjkjhkjhdkjsah")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def transfer_enc_test2(server_sock):
    """
    send valid values  + last valid value different than chunked
    -> syntax error
    last chunked encoding must be chunked
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"compress,deflate,gzip")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def transfer_enc_test3(server_sock):
    """
    send valid values including chunked + last chunked
    No body - timeout
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    transfer_enc_header = gen_transfer_enc_header(b"compress,deflate,gzip,chunked")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def transfer_enc_test4(server_sock):
    """
    send valid values including chunked + last chunked

    white spaces between values and commas
    No body - timeout
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    transfer_enc_header = gen_transfer_enc_header(b"compress   ,   deflate   ,  gzip     ,   chunked")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def transfer_enc_test5(server_sock):
    """
    Two chunked encodings
    invalid
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    transfer_enc_header = gen_transfer_enc_header(b"compress, deflate, gzip, chunked, chunked")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def transfer_enc_test6(server_sock):
    """
    Chunked encoding only once and last with some added garbage
    The garbage is 9th value which is not stored and further processed
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    transfer_enc_header = gen_transfer_enc_header(b"compress, deflate, gzip, compress, gzip, gzip, deflate, chunked, 55555555555555555454545dsfsfddsfsdfsdfsdfsdfsfsdfsdffds")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    if (recv_from_sock(server_sock)):
        raise Exception("wrong flow")
    return sent_messages


def transfer_enc_test7(server_sock):
    """
    send empty value
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    transfer_enc_header = gen_transfer_enc_header(b"")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [transfer_enc_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test1(server_sock):
    """
    Send different values
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"1,1,2,1,1,1,1,1")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test2(server_sock):
    """
    Send no value
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test3(server_sock):
    """
    send same values
    connection timeout - minipot waits for body
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"1,1,1,1,1,1,1,1")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    if recv_from_sock(server_sock):
        raise Exception("Wrong flow")
    return sent_messages


def content_len_test4(server_sock):
    """
    send  text instead of number
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"fdsfsdfsdfd")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test5(server_sock):
    """
    send negative value
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"-5")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test6(server_sock):
    """
    send value out of range long_max + 1
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"9223372036854775808")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test7(server_sock):
    """
    send value out of range long_min - 1
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"-9223372036854775899")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def content_len_test8(server_sock):
    """
    send one value
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"15")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def content_len_test9(server_sock):
    """
    send more than 8 values
    values more than 8 are ignored
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"13,13,13,13,13,13,13,13,hgjgjgkjgkjhgkjgkjgkjgkjgkjgkjgkjgkj")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def content_len_test10(server_sock):
    """
    send 8 values with various whitespaces
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    con_len_header = gen_content_len_header(b"13   ,   13\t,\t13   ,    13\t,   13\t, \t13,    13,\t13,   ")
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_header]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def mult_user_ag_head_test(server_sock):
    """ Send multiple user agent headers.
    It should report last processed value. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10000)
    user_ag1 = gen_user_agent(10000)
    user_ag_head1 = gen_user_agent_header(user_ag1)
    user_ag2 = gen_user_agent(10000)
    user_ag_head2 = gen_user_agent_header(user_ag2)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip=ip_addr, method=method, url=url[:8191], user_ag=user_ag2[:4083])]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [user_ag_head1, user_ag_head2]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def mult_auth_head_test(server_sock):
    """ Send multiple credentials headers.
    It should report last processed value. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    user_id1 = gen_user_id(200)
    passwd1 = gen_password(300)
    auth_header1 = gen_authorization_header(user_id1, passwd1)
    user_id2 = gen_user_id(150)
    passwd2 = gen_password(250)
    auth_header2 = gen_authorization_header(user_id2, passwd2)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url, user_id2, passwd2)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [auth_header1, auth_header2]))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def mult_content_len_head_test(server_sock):
    """ Send multiple content length headers.
    It should merge all values from different headers to a list of values. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 10
    con_len_header1 = gen_content_len_header(str(body_len).encode())
    con_len_header2 = gen_content_len_header(str(body_len).encode())
    con_len_header3 = gen_content_len_header(str(body_len).encode())
    body = gen_body(body_len)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url,
              VERSION_1_1, [con_len_header1, con_len_header2, con_len_header3], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def mult_trans_enc_head_test(server_sock):
    """ Send multiple transfer encoding headers.
    It should merge all values from different headers to a list of values. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head1 = gen_transfer_enc_header(b"gzip")
    trans_enc_head2 = gen_transfer_enc_header(b"compress")
    trans_enc_head3 = gen_transfer_enc_header(b"chunked")
    chunks = gen_chunks([100]*10)
    chunked_body = gen_chunked_body(chunks)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1,
              [trans_enc_head1, trans_enc_head2, trans_enc_head3], chunked_body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def body_len_test1(server_sock):
    """ send body of length 20"""
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 20
    cont_len_head = gen_content_len_header(str(body_len).encode())
    body = gen_body(body_len)

    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [cont_len_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def body_len_test2(server_sock):
    """ send that body is length of 20 but send no body"""
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 20
    cont_len_head = gen_content_len_header(str(body_len).encode())
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [cont_len_head]))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


def body_len_test3(server_sock):
    """
    send that body is length of 20 but send bigger body
    the rest of the body is considered as a new message
    if the rest of the body doesn't have space the connection is going to timeout
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 20
    cont_len_head = gen_content_len_header(str(body_len).encode())
    body = gen_url(body_len+1)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [cont_len_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def body_len_test4(server_sock):
    """
    send maximum memssage size with body
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 65486
    con_len_head = gen_content_len_header(str(body_len).encode())
    body = gen_body(body_len)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def body_len_test5(server_sock):
    """ Send more than maximum message size
    the connection is cloesd after
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    body_len = 65487
    con_len_head = gen_content_len_header(str(body_len).encode())
    body = gen_body(body_len)
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [con_len_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# chunked body
# state:  PROC_CHUNK_SIZE
def chunked_enc_test1(server_sock):
    """ NO CR at the end of chunk size.
    it is buffering till CR is found
    """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"A"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


# state: PROC_CHUNK_SIZE_END
def chunked_enc_test2(server_sock):
    """ NO LF at the end of chunk size """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"A\rf"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# state: PARSE_CHUNK_SIZE
def chunked_enc_test3(server_sock):
    """ NO chunk size value.
    response: syntax error. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"\r\n"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def chunked_enc_test4(server_sock):
    """ Chunk size as total garbage.
    response: syntax error. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"kljlkjljkj\r\n"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


def chunked_enc_test5(server_sock):
    """ chunk size out of range"""
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    ulong_max = 9223372036854775807*2 + 1
    ulong_max += 1
    body = hex(ulong_max).encode() + b"\r\n"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# state: PROCESS_CHUNK + HAS_TRAILER
def chunked_enc_test6(server_sock):
    """ only last-zero chunk  """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = gen_chunked_body()
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def chunked_enc_test7(server_sock):
    "one chunnk of size 15"
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunk_size = 15
    chunk = gen_chunk(chunk_size, gen_rand_ascii_print_byte_str(chunk_size))
    body = gen_chunked_body([chunk])
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def chunked_enc_test8(server_sock):
    """ Chunked body of 40000 bytes with chunk size 2000"""
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunks = gen_chunks([2000]*20)
    body = gen_chunked_body(chunks)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


def chunked_enc_test9(server_sock):
    """ Chunked body of 40000 bytes with chunk size 200"""
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunks = gen_chunks([200]*200)
    body = gen_chunked_body(chunks)
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages


# state: PROC_CHUNK_SIZE_END1
def chunked_enc_test10(server_sock):
    """ No CR at the end of chunk.
    response: syntax error. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"A\r\naaaaaaaaaax"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# state: PROC_CHUNK_SIZE_END2
def chunked_enc_test11(server_sock):
    """ missing LF at the end of chunk.
    response: syntax error. """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    body = b"A\r\naaaaaaaaaa\rx"
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# state: PROCESS_TRAILER
def chunked_enc_test12(server_sock):
    """ missing CR in trailer.
    it is buffering till the CR is found.
    Connection timeou """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunk_size = 15
    chunk = gen_chunk(chunk_size, gen_rand_ascii_print_byte_str(chunk_size))
    trailer = b"dffdfd"
    body = gen_chunked_body([chunk], [trailer])
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    if recv_from_sock(server_sock):
        raise Exception("wrong flow")
    return sent_messages


# state: PROCESS_TRAILER_END
def chunked_enc_test13(server_sock):
    """ missing LF in trailer """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunk_size = 15
    chunk = gen_chunk(chunk_size, gen_rand_ascii_print_byte_str(chunk_size))
    trailer = b"dffdfd\rg"
    body = gen_chunked_body([chunk], [trailer])
    sent_messages = [proxy_report_connect(ip_addr)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), BAD_REQ_RESPONSE)
    return sent_messages


# state: PARSE_TRAILER
def chunked_enc_test14(server_sock):
    """ trailer is ignored """
    ip_addr = get_ip_addr(server_sock)
    method = GET_METH
    url = gen_url(10)
    trans_enc_head = gen_transfer_enc_header(b"chunked")
    chunk_size = 15
    chunk = gen_chunk(chunk_size, gen_rand_ascii_print_byte_str(chunk_size))
    trailer = b"dffdfd\r\n"
    body = gen_chunked_body([chunk], [trailer])
    sent_messages = [proxy_report_connect(ip_addr),
                     proxy_report_message(ip_addr, method, url)]
    send_to_sock(server_sock, compose_message(method, url, VERSION_1_1, [trans_enc_head], body))
    str_cmp(recv_from_sock(server_sock), UNAUTHORIZED_RESPONSE)
    return sent_messages
