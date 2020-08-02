#!/usr/bin/env python3

from utils import *
import proxy
import time


MAX_CONN_COUNT = 5

MAX_LINE_LEN = 1024
MAX_ATTEMPTS = 20

CONNECT_EV = b"connect"
LOGIN_EV = b"login"
TYPE = b"telnet"

LOGIN_USER = b"username"
LOGIN_PASS = b"password"

ASK_FOR_USER = b"Username: \xff\xf9"
ASK_FOR_PASSW = b"Password: \xff\xf9"
PROTOCOL_ERR = b"Protocol error\r\n\xff\xf9"
INCORR_LOGIN = b"Login incorrect\r\n\xff\xf9"


def gen_connect_report(ip):
	""" Generates proxy report connect message.
		ip - string
		returns dictionary """
	return proxy.gen_proxy_report2(TYPE, CONNECT_EV, ip, None)


def gen_login_report(ip, user=b"", password=b""):
	""" Generates proxy report login message.
		ip - string
		user -  bytes
		password - bytes
		returns dictionary"""
	data = {}
	if user:
		data[LOGIN_USER] = user
	if password:
		data[LOGIN_PASS] = password

	return proxy.gen_proxy_report2(TYPE, LOGIN_EV, ip, data)



def gen_rand_bytes(bytelist, len):
	""" generates bytes of given len with values randomly chosen from bytelist """
	b = bytearray(len)
	i = 0
	while i < len:
		b[i] = random.choice(bytelist)
		i = i +1
	return bytes(b)


def login_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_USER)

	bytelist = list(range(33,126))

	user = gen_rand_bytes(bytelist, 4090)

	cmd = b"".join([user, b"\r\n"])
	send_to_sock(server_sock, cmd)

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_PASSW)

	passw = gen_rand_bytes(bytelist, 4090)

	cmd = b"".join([passw, b"\r\n"])
	send_to_sock(server_sock, cmd)

	reports.append(gen_login_report(ip_addr, user[:MAX_LINE_LEN], passw[:MAX_LINE_LEN]))

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, INCORR_LOGIN)

	return reports


def login_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_USER)


	cmd = b"\r\n"
	send_to_sock(server_sock, cmd)

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_PASSW)

	cmd = b"\r\n"
	send_to_sock(server_sock, cmd)

	reports.append(gen_login_report(ip_addr))

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, INCORR_LOGIN)

	return reports



def login_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_USER)

	bytelist = list(range(33,126))

	user = gen_rand_bytes(bytelist, 1)

	cmd = b"".join([user, b"\r\n"])
	send_to_sock(server_sock, cmd)

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, ASK_FOR_PASSW)

	passw = gen_rand_bytes(bytelist, 1)

	cmd = b"".join([passw, b"\r\n"])
	send_to_sock(server_sock, cmd)

	reports.append(gen_login_report(ip_addr, user, passw))

	response = recv_from_sock(server_sock)
	# print(response)
	str_cmp(response, INCORR_LOGIN)

	return reports




def bruteforce_test(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]

	for i in range(MAX_ATTEMPTS):
		response = recv_from_sock(server_sock)
		# print(response)
		str_cmp(response, ASK_FOR_USER)
		bytelist = list(range(33,126))

		user = gen_rand_bytes(bytelist, 4090)

		cmd = b"".join([user, b"\r\n"])
		send_to_sock(server_sock, cmd)

		response = recv_from_sock(server_sock)
		# print(response)
		str_cmp(response, ASK_FOR_PASSW)

		passw = gen_rand_bytes(bytelist, 4090)

		cmd = b"".join([passw, b"\r\n"])
		send_to_sock(server_sock, cmd)

		reports.append(gen_login_report(ip_addr, user[:1024], passw[:1024]))

		response = recv_from_sock(server_sock)
		print(response)
		# print(INCORR_LOGIN)
		# print("------")
		str_cmp(response, INCORR_LOGIN)

	return reports
