import zmq
import msgpack
import re

TS = b"ts"
ID = b"id"
DEV_TOKEN = b"device_token"

DOMAIN_RE = re.compile("^mx[0-9]\.[0-9a-zA-Z]{5,15}\.((com)|(org)|(net)|(cz))$")


def minipot_out_capture(zmq_sock_path):
    """ Receives messages from Sentinel-Minipots and returns them in list of dictionaries.
        It connects and PULL from given ZMQ socket.

    Parameters:
        zmq_sock_path: string
            path to zmq socket """
    ret = []
    context = zmq.Context()
    s = context.socket(zmq.PULL)
    s.bind(zmq_sock_path)
    while True:
        # poll timeout 10,5 seconds
        # reports are sent by main minipots' process every 10 seconds in a batch
        if s.poll(timeout=10500, flags=zmq.POLLIN):
            zmq_mesg = s.recv_multipart()
            topic = str(zmq_mesg[0], encoding="UTF-8")
            if topic != "sentinel/collect/minipot":
                raise Exception("wrong topic: ", topic)
            received = msgpack.unpackb(zmq_mesg[1], raw=True)
            for mesg in received:
                if mesg[TS] <= 0:
                    raise Exception("Time stamp has invalid value.")
                # Remove timestamp, because of later matching received reports
                # with generated reports
                del mesg[TS]
                if mesg[b"type"] == b"smtp" and mesg[b"action"] == b"login":
                    if not DOMAIN_RE.match(mesg[b"data"][b"our_domain"].decode()):
                        raise Exception("smtp: our_domain match failed")
                    # Remove our_domain because we cannot match it with any counterpart
                    # It is randomly generated by minipots
                    del mesg[b"data"][b"our_domain"]
                ret.append(mesg)
        else:
            break
    context.destroy()
    return ret


def unpacker_out_capture(zmq_sock_path, topic):
    """ Receives messages published by unpacker under topic
    sentinel/collect/minipot/telnet and returns them in list of dictionaries.
    It connects and SUBscribes to given socket.

    Parameters:
        zmq_sock_path: string
            path to zmq socket
        topic: string
            topic to subscribe on given zmq socket"""
    ret = []
    context = zmq.Context()
    s = context.socket(zmq.SUB)
    s.setsockopt_string(zmq.SUBSCRIBE, topic)
    s.connect(zmq_sock_path)
    while True:
        # poll timeout 10,5 seconds
        # reports are sent by main minipots' process every 10 seconds in a batch
        if s.poll(timeout=10500, flags=zmq.POLLIN):
            zmq_mesg = s.recv_multipart()
            msg_topic = str(zmq_mesg[0], encoding="UTF-8")
            if msg_topic != topic:
                raise Exception("wrong topic: ", topic)
            received = msgpack.unpackb(zmq_mesg[1], raw=True)
            # remove timestamp, because of later matching received reports with generated reports
            del received[TS]
            # remove id and device_token as this is added by proxy
            del received[ID]
            del received[DEV_TOKEN]
            ret.append(received)
        else:
            break
    context.destroy()
    return ret
