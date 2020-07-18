#!/usr/bin/env python3

import random
import string


def gen_rand_byte_str(len):
    """ Generates random byte string of given length from 0-255 values.
        returns bytearray """
    return bytearray(random.choice(list(range(0, 256))) for n in range(len))


def gen_rand_ascii_print_byte_str(len):
    """ Generates random string from printable characters only (32-126) of given len.
        returns bytearray """
    return bytearray(random.choice(list(range(32, 127))) for n in range(len))


def gen_rand_str(len):
    """ Generates random string of given length from all 0-127 ASCII char set.
        returns string """
    return ''.join([chr(_) for _ in range(128)])


def gen_rand_printable_str(len):
    """ Generates random string from only ASCII printable chars 32-126 of given length.
        returns string """
    s = ''.join(random.choices(string.printable, k=len))
    # replace is here because a sequence of \r was generated and it caused error while parsing command in a minipot
    s = s.replace("\r", "/")
    # for sake of safety replace other escape sequences as well
    s = s.replace("\n", "/")
    s = s.replace("\a", "/")
    s = s.replace("\b", "/")
    s = s.replace("\f", "/")
    return s 


def send_to_sock(sock, data):
    """ Sends given data to given socket.
        sock - socket
        data - bytes
         """
    return sock.sendall(data)


def recv_from_sock(sock):
    """ Receives 16384 bytes from socket 128 bytes.
        If no data are available rerurn empty string.
        returns bytes"""
    # try:
    #     # TODO change receive buffer size here
    #     data = sock.recv(128)
    # except ConnectionError:
    #     return None
    # else:
    #     return data
    return sock.recv(16384)

def str_cmp(str1, str2):
    """ Checks if str1 is equal to str2. If not exception is raised. """
    if str1 != str2:
        raise Exception('str_cmp - strings does not match: ')


def get_ip_addr(sock):
    """ Get peer IP address from a socket.
        returns string """
    ip_addr, port = sock.getpeername()
    return ip_addr


def get_ip_addr2(sock):
    """ Get peer IP address from a socket.
        returns bytes """
    ip_addr, port = sock.getpeername()
    return bytes(ip_addr, "utf-8")
