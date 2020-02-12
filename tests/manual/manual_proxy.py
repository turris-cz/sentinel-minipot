#!/usr/bin/env python3
import zmq
import msgpack
import sys

def parse_msg(msg):
	type = str(msg[0], encoding="UTF-8")
	payload = msgpack.unpackb(msg[1], raw=True)
	return type, payload


if __name__ == "__main__":
	socket_path = str(sys.argv[1])
	print("sentinel test proxy running on socket: ", socket_path)
	with zmq.Context() as context, context.socket(zmq.PULL) as zmq_sock:
		zmq_sock.bind(socket_path)
		while True:
			zmq_msg = zmq_sock.recv_multipart()
			msg_type, msg_payload = parse_msg(zmq_msg)
			print("{}: {}".format(msg_type, msg_payload))
