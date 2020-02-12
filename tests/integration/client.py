#!/usr/bin/env python3
import socket


def client_runner(handler, host, port):
    server_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_soc.connect((host, port))
    data = handler(server_soc)
    server_soc.close()
    return data
