#!/usr/bin/env python3

import zmq
import msgpack


def gen_proxy_report(protocol, action, ip, data):
    """ Generates proxy report from given input data.
        protocol - string
        action - string
        ip - string
        data - dictionary, keys, values are strings
        returns dictionary """
    report = {}
    report['type'] = protocol
    report['action'] = action
    report['ip'] = ip
    if data:
        report['data'] = {}
        for k, v in data.items():
            if v:
                report['data'][k] = v
    return report


def gen_connect_report(ip, protocol):
    """ Generates proxy connect report.
        ip - string
        protocol - string
        returns dictionary """
    return gen_proxy_report(protocol, 'connect', ip, None)


def gen_disconnect_report(ip, protocol):
    """ Generates proxy disconnet report.
        ip - string
        protocol - string
        returns dictionary """
    return gen_proxy_report(protocol, 'disconnect', ip, None)


def gen_syntax_error_report(ip, protocol):
    """ Generates proxy syntax error report.
        ip - string
        protocol - string
        returns dictionary """
    return gen_proxy_report(protocol, 'syntax error', ip, None)


def proxy_handler(zmq_sock_path):
    """ Receives messages from sentinel proxy.
        zmq_sock_path - path to local ipc zmq socket - string
        returns list of dictionaries """
    received = []
    context = zmq.Context()
    proxy_sock = context.socket(zmq.PULL)
    proxy_sock.bind(zmq_sock_path)
    while True:
        # poll timeout 10,5 seconds
        # reports are sent by main minipots' process every 10 seconds in a batch
        if proxy_sock.poll(timeout=10500, flags=zmq.POLLIN):
            zmq_mesg = proxy_sock.recv_multipart()
            topic = str(zmq_mesg[0], encoding="UTF-8")
            if topic != 'sentinel/collect/minipot':
                raise Exception('wrong topic: ', topic)
            for mesg in msgpack.unpackb(zmq_mesg[1], raw=False):
                # remove timestamp, because of later matching received reports with generated reports
                del mesg['ts']
                received.append(mesg)
        else:
            break
    context.destroy()
    return received
