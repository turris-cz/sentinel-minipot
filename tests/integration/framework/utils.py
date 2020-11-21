import random as r
import sys


def recv_from_sock(sock):
    """ Receives and returns 4096 bytes from socket in BLOCKING mode.

    Parameters:
        sock: socket """
    return sock.recv(4096)


def get_ip_addr(sock):
    """ Get peer IP address from a socket sock and returns it as bytes.

    Parameters:
        sock: socket """
    return bytes(sock.getpeername()[0], encoding=sys.getdefaultencoding())


def gen_rand_bytes_w10(len):
    """ Returns randomly generated byte string from values 0-255 without 10.

    Parameters:
        len: int """
    bytevals = list(range(256))
    bytevals.remove(10)  # LF
    return bytes([r.choice(bytevals) for _ in range(len)])


def gen_rand_utf8_char(len):
    """ Returns randomly generated utf-8 char NOT containing NULL byte with
    given length as bytes.

    Parameters:
        len: int
            number of bytes for the char
            Must be 1,2,3 or 4 otherwise Exception is returned. """
    if len == 1:
        ret = bytes([r.randint(0, 127)])
    elif len == 2:
        ret = bytes([r.randint(194, 223), r.randint(128, 191)])
    elif len == 3:
        ret = r.choice([bytes([224, r.randint(160, 191), r.randint(128, 191)]),
                        bytes([r.randint(225, 236), r.randint(128, 191), r.randint(128, 191)]),
                        bytes([237, r.randint(128, 159), r.randint(128, 191)]),
                        bytes([r.randint(238, 239), r.randint(128, 191), r.randint(128, 191)])])
    elif len == 4:
        ret = r.choice([bytes([240, r.randint(144, 191),
                               r.randint(128, 191), r.randint(128, 191)]),
                        bytes([r.randint(241, 243), r.randint(128, 191),
                               r.randint(128, 191), r.randint(128, 191)]),
                        bytes([244, r.randint(128, 143),
                               r.randint(128, 191), r.randint(128, 191)])])
    else:
        return Exception("gen_rand_utf8_char: len is NOT valid")
    ret.decode(encoding="utf-8", errors="strict")  # check whether it is really UTF-8 string
    return ret


def gen_rand_utf8_string(len):
    """ Returns randomly generated utf-8 string with given length as bytes.

    Parameters:
        len: int
            number of utf-8 characters NOT bytes """
    ret = b"".join(gen_rand_utf8_char(r.randint(1, 4)) for _ in range(len))
    ret.decode(encoding="utf-8", errors="strict")  # check whether it is really UTF-8 string
    return ret
