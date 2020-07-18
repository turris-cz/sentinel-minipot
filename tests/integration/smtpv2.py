#!/usr/bin/env python3

from utils import *
import proxy
import time
import base64

ERROR_LIMIT = 20
TOKEN_BUFF_LEN = 16384

TOKEN_SEPARATORS = [9,11,12,13,32]

TYPE = b"smtp"
CONNECT_EV = b"connect"
LOGIN_EV = b"login"
PLAIN_EV = b"plain"
LOGIN_USER = b"username"
LOGIN_PASS = b"password"
PLAIN_DATA = b"data"

TOUT_RESP = b"421 4.4.2 <> Error: timeout exceeded\r\n"
WELCOME_RESP = b"220"
# WELCOME_RESP = b"220 <> ESMTP Postfix (Debian/GNU)\r\n"
TOO_LONG_DATA_RESP = b"500 5.5.0 Error: line too long\r\n"
TOO_MUCH_ERR_RESP = b"421 4.7.0 <> Error: too many errors\r\n"
EMPTY_LINE_RESP = b"500 5.5.2 Error: bad syntax\r\n"
UNKNOWN_CMD_RESP = b"502 5.5.2 Error: command not recognized\r\n"

# EHLO_250_RESP = b"250-<>\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n"
EHLO_250_RESP = b"250"

EHLO_501_RESP = b"501 Syntax: EHLO hostname\r\n"

# HELO_250_RESP = b"250 <>\r\n"
HELO_250_RESP = b"250"

HELO_501_RESP = b"501 Syntax: HELO hostname\r\n"

ETRN_EXPECT_HELO_RESP = b"503 Error: send HELO/EHLO first\r\n"
ETRN_HELO_554_RESP_PART1 = b"554 5.7.1 <unknown["
ETRN_HELO_554_RESP_PART2 = b"]>: Client host rejected: Access denied\r\n"
ETRN_HELO_500_RESP = b"500 Syntax: ETRN domain\r\n"
ETRN_HELO_MAIL_RESP = b"503 Error: MAIL transaction in progress\r\n"

OK_RESP = b"250 2.0.0 Ok\r\n"

QUIT_RESP = b"221 2.0.0 Bye\r\n"

RSET_501_RESP = b"501 5.5.4 Syntax: RSET\r\n"

VRFY_RESP = b"502 5.5.1 VRFY command is disabled\r\n"

DATA_503_RESP = b"503 5.5.1 Error: need RCPT command\r\n"
DATA_554_RESP = b"554 5.5.1 Error: no valid recipients\r\n"

RCPT_503_RESP = b"503 5.5.1 Error: need MAIL command\r\n"
RCPT_554_RESP_PART1 = b"554 5.7.1 <unknown["
RCPT_554_RESP_PART2 = b"]>: Client host rejected: Access denied\r\n"
RCPT_501_RESP = b"501 5.5.4 Syntax: RCPT TO:<address>\r\n"
RCPT_TO_STR = b"to:"

MAIL_EXPECT_HELO_RESP = b"503 5.5.1 Error: send HELO/EHLO first\r\n"
MAIL_HELO_MAIL_RESP = b"503 5.5.1 Error: nested MAIL command\r\n"
MAIL_501_RESP = b"501 5.5.4 Syntax: MAIL FROM:<address>\r\n"
MAIL_FROM_STR = b"from:"

AUTH_HELO_MAIL_RESP = b"503 5.5.1 Error: MAIL transaction in progress\r\n"
AUTH_EXPECT_HELO_RESP = b"503 5.5.1 Error: send HELO/EHLO first\r\n"
AUTH_501_RESP = b"501 5.5.4 Syntax: AUTH mechanism\r\n"
AUTH_INVLD_SASL_MECH = b"535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n"
AUTH_PLAIN_ASK_DATA_RESP = b"334 \r\n"
AUTH_LOG_ASK_USER_RESP = b"334 VXNlcm5hbWU6\r\n"
AUTH_INIT_RESP_ERROR = b"535 5.7.8 Error: authentication failed: Invalid base64 data in initial response\r\n"
AUTH_PLAIN_INIT_RESP_RESP = b"535 5.7.8 Error: authentication failed:\r\n"
AUTH_LOG_ASK_FOR_PASSW = b"334 UGFzc3dvcmQ6\r\n"

PROC_DATA_EXPCT_LOG_USER_EMPTY_LINE = b"535 5.7.8 Error: authentication failed: VXNlcm5hbWU6\r\n"
PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE = b"535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n"
PROC_DATA_AUTH_ABOR = b"501 5.7.0 Authentication aborted\r\n"

PROC_DATA_INVALID_B64 = b"535 5.7.8 Error: authentication failed: Invalid base64 data in continued response\r\n"

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


def gen_plain_report(ip, pl_data=b""):
	""" Generates proxy report login message.
		ip - string
		pl_data - bytes
		returns dictionary"""
	data = {}
	if pl_data:
		data[PLAIN_DATA] = pl_data

	return proxy.gen_proxy_report2(TYPE, PLAIN_EV, ip, data)


def gen_rand_bytes(bytelist, len):
	""" generates bytes of given len with values randomly chosen from bytelist """
	b = bytearray(len)
	i = 0
	while i < len:
		b[i] = random.choice(bytelist)
		i = i +1
	return bytes(b)



def empty_cmd_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	# cmd = b"".join([b"user ", user, b"\n"])
	cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, EMPTY_LINE_RESP)
	return reports


def empty_cmd_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = TOKEN_SEPARATORS
	# bytelist.remove(FTP_CMD_SEP)
	rnd_bts = gen_rand_bytes(bytelist, TOKEN_BUFF_LEN - 1)
	cmd = b"".join([rnd_bts, b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, EMPTY_LINE_RESP)
	return reports


def empty_cmd_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = TOKEN_SEPARATORS
	# bytelist.remove(FTP_CMD_SEP)
	rnd_bts = gen_rand_bytes(bytelist, 1)
	cmd = b"".join([rnd_bts, b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, EMPTY_LINE_RESP)
	return reports


def unrec_cmd_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	# bytelist.remove(TOKEN_SEPARATORS)
	bytelist.remove(10)
	rnd_bts = gen_rand_bytes(bytelist, 1)
	cmd = b"".join([rnd_bts, b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, UNKNOWN_CMD_RESP)
	return reports


def unrec_cmd_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	# bytelist.remove(TOKEN_SEPARATORS)
	bytelist.remove(10)
	rnd_bts = gen_rand_bytes(bytelist, TOKEN_BUFF_LEN - 1)
	cmd = b"".join([rnd_bts, b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, UNKNOWN_CMD_RESP)
	return reports




def noop_cmd_expect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"noop", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, OK_RESP)
	return reports


def noop_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"noop",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, OK_RESP)
	return reports


def noop_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"noop",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, OK_RESP)
	return reports

def noop_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"noop",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, OK_RESP)
	return reports


def rset_cmd_expect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"rset", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, OK_RESP)
	return reports


def rset_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, OK_RESP)
	return reports


def rset_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	# cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 1),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 1), b"A",b"\n"])
	# cmd = b"\n"

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, RSET_501_RESP)
	return reports


def rset_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, RSET_501_RESP)
	return reports


def quit_cmd_expect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"quit", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, QUIT_RESP)
	return reports


def quit_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"quit",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, QUIT_RESP)
	return reports


def quit_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	# cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 1),b"quit",gen_rand_bytes(TOKEN_SEPARATORS, 1), b"A",b"\n"])
	# cmd = b"\n"

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, QUIT_RESP)
	return reports


def quit_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"quit",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, QUIT_RESP)
	return reports



def mail_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"mail", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, MAIL_EXPECT_HELO_RESP)
	return reports


def mail_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"mail",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, MAIL_EXPECT_HELO_RESP)
	return reports


def mail_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"mail",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, MAIL_EXPECT_HELO_RESP)
	return reports


def mail_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"mail",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, MAIL_EXPECT_HELO_RESP)
	return reports



def auth_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"auth", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, AUTH_EXPECT_HELO_RESP)
	return reports


def auth_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, AUTH_EXPECT_HELO_RESP)
	return reports


def auth_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, AUTH_EXPECT_HELO_RESP)
	return reports


def auth_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, AUTH_EXPECT_HELO_RESP)
	return reports



def etrn_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"etrn", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, ETRN_EXPECT_HELO_RESP)
	return reports


def etrn_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"etrn",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, ETRN_EXPECT_HELO_RESP)
	return reports


def etrn_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# # bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"etrn",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, ETRN_EXPECT_HELO_RESP)
	return reports


def etrn_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"etrn",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, ETRN_EXPECT_HELO_RESP)
	return reports


def rcpt_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"rcpt", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, RCPT_503_RESP)
	return reports


def rcpt_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, RCPT_503_RESP)
	return reports


def rcpt_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, RCPT_503_RESP)
	return reports


def rcpt_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	# for _ in TOKEN_SEPARATORS:
	#     bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, RCPT_503_RESP)
	return reports


def data_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"data", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, DATA_503_RESP)
	return reports


def data_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"data",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, DATA_503_RESP)
	return reports


def data_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	# cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"rset",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 1),b"data",gen_rand_bytes(TOKEN_SEPARATORS, 1), b"A",b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, DATA_503_RESP)
	return reports


def data_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"data",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, DATA_503_RESP)
	return reports


def helo_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"helo", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, HELO_501_RESP)
	return reports


def helo_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"helo",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, HELO_501_RESP)
	return reports


def helo_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"helo",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response[0:3],HELO_250_RESP)
	return reports


def helo_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"helo",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response[0:3],HELO_250_RESP)
	return reports

def ehlo_cmd_ecpect_helo_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([b"ehlo", b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, EHLO_501_RESP)
	return reports


def ehlo_cmd_expect_helo_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	# bytelist = list(range(256))
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"ehlo",gen_rand_bytes(TOKEN_SEPARATORS, 5), b"\n"])
	# cmd = b"\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, EHLO_501_RESP)
	return reports


def ehlo_cmd_expect_helo_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"ehlo",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 1),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response[0:3],EHLO_250_RESP)
	return reports


def ehlo_cmd_expect_helo_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)
	bytelist = list(range(256))
	for _ in TOKEN_SEPARATORS:
		bytelist.remove(_)
	bytelist.remove(10)
	# bytelist.remove(FTP_CMD_SEP)
	# user = gen_rand_bytes(bytelist, 4090)
	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"ehlo",gen_rand_bytes(TOKEN_SEPARATORS, 5), gen_rand_bytes(bytelist, 5000),b"\n"])
	# cmd = b"\n"
	#
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response[0:3],EHLO_250_RESP)
	return reports


#######################################################################################################################################
#######################################################################################################################################


def auth_cmd_helo_sent_no_sasl_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, AUTH_501_RESP)
	return reports


def auth_cmd_helo_sent_no_sasl_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_501_RESP)
	return reports


def auth_cmd_helo_sent_sasl_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"plain",b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)
	return reports

def auth_cmd_helo_sent_sasl_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)
	return reports


def auth_cmd_helo_sent_sasl_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"login",b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)
	return reports

def auth_cmd_helo_sent_sasl_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)
	return reports



def auth_cmd_helo_sent_sasl_test5(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"dfdfdf",b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_INVLD_SASL_MECH)
	return reports


def auth_cmd_helo_sent_sasl_test6(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"klljkj",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_INVLD_SASL_MECH)
	return reports

########################################################################################################################################################################


def auth_cmd_helo_sent_init_resp_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	passwd = b"aaaaaasassasdfgdfgdfg"

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),base64.standard_b64encode(passwd),b"\n"])

	reports.append(gen_plain_report(ip_addr,passwd))

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)
	return reports


def auth_cmd_helo_sent_init_resp_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	passwd = b"aaaaaasassasdfgdfgdfg"

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),base64.standard_b64encode(passwd),gen_rand_bytes(TOKEN_SEPARATORS, 5),b"\n"])

	reports.append(gen_plain_report(ip_addr,passwd))

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)
	return reports



def auth_cmd_helo_sent_init_resp_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@@",b"\n"])


	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	# print(response)
	# TODO
	str_cmp(response, AUTH_INIT_RESP_ERROR)
	return reports



def auth_cmd_helo_sent_init_resp_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"\n"])


	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_INIT_RESP_ERROR)
	return reports



def auth_cmd_helo_sent_init_resp_test5(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	user = b"asdasdas"

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),base64.standard_b64encode(user),b"\n"])


	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)
	return reports


def auth_cmd_helo_sent_init_resp_test6(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	user = b"asdsadsad"

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),base64.standard_b64encode(user),gen_rand_bytes(TOKEN_SEPARATORS, 5),b"\n"])


	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)
	return reports



def auth_cmd_helo_sent_init_resp_test7(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@@",b"\n"])


	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_INIT_RESP_ERROR)
	return reports



def auth_cmd_helo_sent_init_resp_test8(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"\n"])

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_INIT_RESP_ERROR)
	return reports


def auth_cmd_helo_sent_too_much_param_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"s",b"\n"])

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)

	str_cmp(response, AUTH_501_RESP)
	return reports


def auth_cmd_helo_sent_too_much_param_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),b"s",b"\n"])

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_501_RESP)
	return reports


def auth_cmd_helo_sent_too_much_param_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"login",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"s",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_501_RESP)
	return reports


def auth_cmd_helo_sent_too_much_param_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS, 5),b"auth",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"plain",gen_rand_bytes(TOKEN_SEPARATORS,6),b"@@@@@",gen_rand_bytes(TOKEN_SEPARATORS, 5),
		b"s",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])

	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_501_RESP)
	return reports



############################################################################################

def expect_plain_data_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth plain\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)

	data = b"*\n"

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, PROC_DATA_AUTH_ABOR)
	return reports


def expect_plain_data_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth plain\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)

	data = b"\n"

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)


	str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)
	return reports


def expect_plain_data_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth plain\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)

	pl_data = b"dsdsdsds"
	data = b"".join([base64.standard_b64encode(pl_data),b"\n"])

	reports.append(gen_plain_report(ip_addr,pl_data))

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)
	return reports


def expect_plain_data_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth plain\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)

	data = b"".join([b")))))",b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)

	str_cmp(response, PROC_DATA_INVALID_B64)
	return reports



############################################################################################

def expect_login_user_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	data = b"*\n"

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, PROC_DATA_AUTH_ABOR)
	return reports


def expect_login_user_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	data = b"\n"

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)


	str_cmp(response, PROC_DATA_EXPCT_LOG_USER_EMPTY_LINE)
	return reports


def expect_login_user_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	pl_data = b"dsdsdsds"
	data = b"".join([base64.standard_b64encode(pl_data),b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)
	return reports


def expect_login_user_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	data = b"".join([b")))))",b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)

	str_cmp(response, PROC_DATA_INVALID_B64)
	return reports



############################################################################################

def expect_login_passw_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	user = b"jokookokok"
	data = b"".join([base64.standard_b64encode(user),b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

	data = b"".join([b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE)

	return reports


def expect_login_passw_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	user = b"jokookokok"
	data = b"".join([base64.standard_b64encode(user),b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

	data = b"".join([b"*\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, PROC_DATA_AUTH_ABOR)

	return reports


def expect_login_passw_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	user = b"jokookokok"
	data = b"".join([base64.standard_b64encode(user),b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

	passw = b"ooooooookkkkkkkkkkkkkkkkkkkkk"
	data = b"".join([base64.standard_b64encode(passw),b"\n"])

	reports.append(gen_login_report(ip_addr,user, passw))

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE)

	return reports


def expect_login_passw_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"auth login\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_USER_RESP)

	user = b"jokookokok"
	data = b"".join([base64.standard_b64encode(user),b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

	data = b"".join([b")))))",b"\n"])

	send_to_sock(server_sock, data)
	response = recv_from_sock(server_sock)
	#
	str_cmp(response, PROC_DATA_INVALID_B64)
	return reports

##################################################################################################

def plain_init_brute_force(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	for i in range(ERROR_LIMIT):

		data = gen_rand_bytes(list(range(256)), 12000)
		cmd = b"".join([b"auth plain ", base64.standard_b64encode(data), b"\n"])

		reports.append(gen_plain_report(ip_addr, data))

		send_to_sock(server_sock, cmd)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)

	return reports


def plain_brute_force(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	for i in range(ERROR_LIMIT):

		cmd = b"auth plain\n"
		send_to_sock(server_sock, cmd)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, AUTH_PLAIN_ASK_DATA_RESP)

		pl_data = gen_rand_bytes(list(range(256)), 12000)
		data = b"".join([base64.standard_b64encode(pl_data), b"\n"])

		reports.append(gen_plain_report(ip_addr, pl_data))

		send_to_sock(server_sock, data)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, AUTH_PLAIN_INIT_RESP_RESP)

	return reports


def login_init_bruteforce(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	for i in range(ERROR_LIMIT):

		user = gen_rand_bytes(list(range(256)),12000)

		cmd = b"".join([b"auth login ",base64.standard_b64encode(user),b"\n"])

		send_to_sock(server_sock, cmd)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

		passw = gen_rand_bytes(list(range(256)), 12000)
		data = b"".join([base64.standard_b64encode(passw), b"\n"])

		reports.append(gen_login_report(ip_addr,user,passw))

		send_to_sock(server_sock, data)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE)

	return reports


def login_bruteforce(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)


	for i in range(int(ERROR_LIMIT)):


		cmd = b"auth login\n"
		send_to_sock(server_sock, cmd)
		response = recv_from_sock(server_sock)

		str_cmp(response, AUTH_LOG_ASK_USER_RESP)

		user = gen_rand_bytes(list(range(256)),12000)
		data = b"".join([base64.standard_b64encode(user), b"\n"])

		send_to_sock(server_sock, data)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, AUTH_LOG_ASK_FOR_PASSW)

		passw = gen_rand_bytes(list(range(256)), 12000)
		data = b"".join([base64.standard_b64encode(passw), b"\n"])

		reports.append(gen_login_report(ip_addr,user,passw))

		send_to_sock(server_sock, data)
		response = recv_from_sock(server_sock)
		#
		str_cmp(response, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE)

	return reports


########################################################################################################################


def etrn_cmd_helo_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"etrn\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, ETRN_HELO_500_RESP)
	return reports



def etrn_cmd_helo_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"etrn a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, ETRN_HELO_554_RESP_PART1+ip_addr+ETRN_HELO_554_RESP_PART2)
	return reports


def etrn_cmd_helo_sent_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"etrn a a  \n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, ETRN_HELO_500_RESP)

	return reports

###################################################################################################################################

def mail_cmd_helo_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail \n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, MAIL_501_RESP)

	return reports


def mail_cmd_helo_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail sdsds\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, MAIL_501_RESP)

	return reports



def mail_cmd_helo_sent_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from:\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, MAIL_501_RESP)

	return reports



def mail_cmd_helo_sent_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from:a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports



def mail_cmd_helo_sent_test5(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports



def mail_cmd_helo_sent_test6(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail \tfrom: \ta \tsdsfdsfdsfdsfdsf\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports



def mail_cmd_helo_sent_test7(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail \tfrom:a sadsads s       asdsa   \n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports

###################################################################################################

def etrn_cmd_helo_mail_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"etrn\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, ETRN_HELO_MAIL_RESP)

	return reports


def etrn_cmd_helo_mail_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"etrn\t  \t \r adasd asdasdasd \r\t\t\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, ETRN_HELO_MAIL_RESP)

	return reports

##########################################################################33

def noop_cmd_helo_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"noop\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports


def noop_cmd_helo_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"\t\t\tnoop  sdfsdfdsf  sdfsdf\t\t\t\r\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	return reports

###########################################################################

def vrfy_cmd_helo_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"vrfy\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, VRFY_RESP)

	return reports


def vrfy_cmd_helo_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"\t\t\tvrfy  sdfsdfdsf  sdfsdf\t\t\t\r\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, VRFY_RESP)

	return reports

##########################################################################

def quit_cmd_helo_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"quit\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, QUIT_RESP)

	return reports


def quit_cmd_helo_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"\t\t\tquit  sdfsdfdsf  sdfsdf\t\t\t\r\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, QUIT_RESP)

	return reports


###################################################################################################

def mail_cmd_helo_mail_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"mail\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, MAIL_HELO_MAIL_RESP)

	return reports


def mail_cmd_helo_mail_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"mail\t  \t \r adasd asdasdasd \r\t\t\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, MAIL_HELO_MAIL_RESP)

	return reports

###################################################################################################

def data_cmd_helo_mail_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"data\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, DATA_554_RESP)

	return reports


def data_cmd_helo_mail_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"data\t  \t \r adasd asdasdasd \r\t\t\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, DATA_554_RESP)

	return reports


###################################################################################################

def auth_cmd_helo_mail_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"auth\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_HELO_MAIL_RESP)

	return reports


def auth_cmd_helo_mail_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"auth\t  \t \r adasd asdasdasd \r\t\t\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, AUTH_HELO_MAIL_RESP)

	return reports

###################################################################################################

def rcpt_cmd_helo_mail_sent_test1(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"rcpt\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_501_RESP)

	return reports


def rcpt_cmd_helo_mail_sent_test2(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_501_RESP)

	return reports


def rcpt_cmd_helo_mail_sent_test3(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_501_RESP)

	return reports



def rcpt_cmd_helo_mail_sent_test4(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	byte_list = list(range(256))
	byte_list.remove(10)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"sdfsdfsdfds\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_501_RESP)

	return reports


def rcpt_cmd_helo_mail_sent_test5(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	byte_list = list(range(256))
	byte_list.remove(10)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"to:\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_501_RESP)

	return reports


def rcpt_cmd_helo_mail_sent_test6(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	byte_list = list(range(256))
	byte_list.remove(10)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"to:asas\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_554_RESP_PART1+ip_addr+RCPT_554_RESP_PART2)

	return reports



def rcpt_cmd_helo_mail_sent_test7(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	byte_list = list(range(256))
	byte_list.remove(10)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6), b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),b"to:",gen_rand_bytes(TOKEN_SEPARATORS,8),b"asas\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_554_RESP_PART1+ip_addr+RCPT_554_RESP_PART2)

	return reports


def rcpt_cmd_helo_mail_sent_test8(server_sock):
	ip_addr = get_ip_addr2(server_sock)
	reports = [gen_connect_report(ip_addr)]
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3], WELCOME_RESP)

	cmd = b"ehlo a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response[0:3],EHLO_250_RESP)

	cmd = b"mail from: a\n"
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, OK_RESP)

	byte_list = list(range(256))
	byte_list.remove(10)

	cmd = b"".join([gen_rand_bytes(TOKEN_SEPARATORS,6),
		b"rcpt",gen_rand_bytes(TOKEN_SEPARATORS,6),
		b"to:",gen_rand_bytes(TOKEN_SEPARATORS,8),b"asas",
		gen_rand_bytes(byte_list,6000),b"\n"])
	send_to_sock(server_sock, cmd)
	response = recv_from_sock(server_sock)
	str_cmp(response, RCPT_554_RESP_PART1+ip_addr+RCPT_554_RESP_PART2)

	return reports
