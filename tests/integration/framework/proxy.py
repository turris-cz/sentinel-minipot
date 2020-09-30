import zmq
import msgpack


def gen_proxy_report(protocol, action, ip, data=None):
    """ Generates proxy report from given input data and returns it as bytes.

    Parameters:
        protocol: bytes
        action: bytes
        ip: bytes
        data: dictionary: keys and values are bytes  """
    report = {
        b"type": protocol,
        b"action": action,
        b"ip": ip,
    }
    if data:
        report[b"data"] = data
    return report


def proxy_handler(zmq_sock_path):
    """ Receives messages from sentinel proxy and returns them in list of dictionaries.

    Parameters:
        zmq_sock_path: string
            path to local ipc zmq socket """
    ret = []
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
            received = msgpack.unpackb(zmq_mesg[1], raw=True)
            for mesg in received:
                # remove timestamp, because of later matching received reports with generated reports
                del mesg[b'ts']
                ret.append(mesg)
        else:
            break
    context.destroy()
    return ret
