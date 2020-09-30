import random
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


def gen_rand_bytes(bytelist, len):
    """ Generates and returns bytes of given len with values randomly chosen from bytelist.

    Parameters:
        bytelist: list of ints with values 0 - 255
        len: int """
    return bytes([random.choice(bytelist) for _ in range(len)])
