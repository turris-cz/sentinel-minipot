/*
 *  Turris:Sentinel Minipot - password Honeypot
 *  Copyright (C) 2019-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <signal.h>
#include <event.h>
#include <unistd.h>
#include <strings.h>
#include <base64c.h>

#include "utils.h"
#include "char_consts.h"
#include "minipot_pipe.h"
#include "smtp_commands.gperf.c"
#include "sasl_mechanisms.gperf.c"

#define MAX_CONN_COUNT 5
#define CONN_TIMEOUT (60 * 5)
#define INACT_TIMEOUT (60 * 3)
#define ERROR_LIMIT 20
#define TOKEN_BUFF_LEN 16384
#define DECODE_BUFF_LEN TOKEN_BUFF_LEN
#define LOGIN_USER_LEN DECODE_BUFF_LEN
#define TOKENS_LEN (TOKEN_BUFF_LEN / 2)
#define HOSTNAME_LEN 32

#define TYPE "smtp"
#define CONNECT_EV "connect"
#define LOGIN_EV "login"
#define INVALID_EV "invalid"

#define LOGIN_USER "username"
#define LOGIN_PASS "password"
#define SASL_MECH "mechanism"
#define SASL_LOGIN "login"
#define SASL_PLAIN "plain"

#define TOUT_RESP_PART1 "421 4.4.2 "
#define TOUT_RESP_PART2 " Error: timeout exceeded\r\n"

#define WELCOME_RESP_PART1 "220 "
#define WELCOME_RESP_PART2 " ESMTP Postfix (Debian/GNU)\r\n"
#define TOO_LONG_DATA_RESP "500 5.5.0 Error: line too long\r\n"

#define TOO_MUCH_ERR_RESP_PART1 "421 4.7.0 "
#define TOO_MUCH_ERR_RESP_PART2 " Error: too many errors\r\n"

#define EMPTY_LINE_RESP "500 5.5.2 Error: bad syntax\r\n"
#define UNKNOWN_CMD_RESP "502 5.5.2 Error: command not recognized\r\n"

#define EHLO_250_RESP_PART1 "250-"
#define EHLO_250_RESP_PART2 "\r\n250-PIPELINING\r\n250-SIZE 26214400\r\n250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n"
#define EHLO_501_RESP "501 Syntax: EHLO hostname\r\n"

#define HELO_250_RESP_PART1 "250 "
#define HELO_250_RESP_PART2 "\r\n"
#define HELO_501_RESP "501 Syntax: HELO hostname\r\n"

#define ETRN_EXPECT_HELO_RESP "503 Error: send HELO/EHLO first\r\n"
#define ETRN_HELO_554_RESP_PART1 "554 5.7.1 <unknown["
#define ETRN_HELO_554_RESP_PART2 "]>: Client host rejected: Access denied\r\n"
#define ETRN_HELO_500_RESP "500 Syntax: ETRN domain\r\n"
#define ETRN_HELO_MAIL_RESP "503 Error: MAIL transaction in progress\r\n"

#define OK_RESP "250 2.0.0 Ok\r\n"

#define QUIT_RESP "221 2.0.0 Bye\r\n"

#define RSET_501_RESP "501 5.5.4 Syntax: RSET\r\n"

#define VRFY_RESP "502 5.5.1 VRFY command is disabled\r\n"

#define DATA_503_RESP "503 5.5.1 Error: need RCPT command\r\n"
#define DATA_554_RESP "554 5.5.1 Error: no valid recipients\r\n"

#define RCPT_503_RESP "503 5.5.1 Error: need MAIL command\r\n"
#define RCPT_554_RESP_PART1 "554 5.7.1 <unknown["
#define RCPT_554_RESP_PART2 "]>: Client host rejected: Access denied\r\n"
#define RCPT_501_RESP "501 5.5.4 Syntax: RCPT TO:<address>\r\n"
#define RCPT_TO_STR "to:"

#define MAIL_EXPECT_HELO_RESP "503 5.5.1 Error: send HELO/EHLO first\r\n"
#define MAIL_HELO_MAIL_RESP "503 5.5.1 Error: nested MAIL command\r\n"
#define MAIL_501_RESP "501 5.5.4 Syntax: MAIL FROM:<address>\r\n"
#define MAIL_FROM_STR "from:"

#define AUTH_HELO_MAIL_RESP "503 5.5.1 Error: MAIL transaction in progress\r\n"
#define AUTH_EXPECT_HELO_RESP "503 5.5.1 Error: send HELO/EHLO first\r\n"
#define AUTH_501_RESP "501 5.5.4 Syntax: AUTH mechanism\r\n"
#define AUTH_INVLD_SASL_MECH "535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n"
#define AUTH_PLAIN_ASK_DATA_RESP "334 \r\n"
#define AUTH_LOG_ASK_USER_RESP "334 VXNlcm5hbWU6\r\n"
#define AUTH_INIT_RESP_ERROR "535 5.7.8 Error: authentication failed: Invalid base64 data in initial response\r\n"
#define AUTH_PLAIN_INIT_RESP_RESP "535 5.7.8 Error: authentication failed:\r\n"
#define AUTH_LOG_ASK_FOR_PASSW "334 UGFzc3dvcmQ6\r\n"

#define PROC_DATA_EXPCT_LOG_USER_EMPTY_LINE "535 5.7.8 Error: authentication failed: VXNlcm5hbWU6\r\n"
#define PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE "535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n"
#define PROC_DATA_AUTH_ABOR "501 5.7.0 Authentication aborted\r\n"

#define PROC_DATA_INVALID_B64 "535 5.7.8 Error: authentication failed: Invalid base64 data in continued response\r\n"

enum prot_state {
	EXPECT_HELO,
	HELO_SENT,
	HELO_MAIL_SENT,
	EXPECT_PLAIN_DATA,
	EXPECT_LOGIN_USER,
	EXPECT_LOGIN_PASSW,
};

struct conn_data {
	int fd;
	struct event *read_ev;
	struct event *con_tout_ev;
	struct event *inac_tout_ev;
	char *ipaddr_str;
	uint8_t *token_buff;
	uint8_t *token_buff_wrt_ptr;
	size_t token_buff_free_space;
	size_t error_cnt;
	enum prot_state prot_state;
	uint8_t *log_user;
	size_t log_user_len;
};

static int exit_code;
static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buff;
static struct event *accept_ev;
static char *dcode_buff;
static int dcoded_data_len;
static struct token *tokens;
static size_t tokens_cnt;
static char host_name[HOSTNAME_LEN] = {};

static void free_conn_data(struct conn_data *conn_data) {
	free(conn_data->ipaddr_str);
	free(conn_data->token_buff);
	free(conn_data->log_user);
	event_free(conn_data->inac_tout_ev);
	event_free(conn_data->con_tout_ev);
	event_free(conn_data->read_ev);
}

static int alloc_conn_data(struct conn_data *conn_data) {
	conn_data->read_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (conn_data->read_ev == NULL)
		goto err1;
	conn_data->con_tout_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (conn_data->con_tout_ev == NULL)
		goto err2;
	conn_data->inac_tout_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (conn_data->inac_tout_ev == NULL)
		goto err3;
	conn_data->ipaddr_str = malloc(sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
	if (conn_data->ipaddr_str == NULL)
		goto err4;
	conn_data->token_buff = malloc(sizeof(*conn_data->token_buff) * TOKEN_BUFF_LEN);
	if (conn_data->token_buff == NULL)
		goto err5;
	conn_data->log_user = malloc(sizeof(*conn_data->log_user) * LOGIN_USER_LEN);
	if (conn_data->log_user == NULL)
		goto err6;
	conn_data->fd = -1;
	return 0;

	err6:
	free(conn_data->token_buff);

	err5:
	free(conn_data->ipaddr_str);

	err4:
	event_free(conn_data->inac_tout_ev);

	err3:
	event_free(conn_data->con_tout_ev);

	err2:
	event_free(conn_data->read_ev);

	err1:
	return -1;
}

static void free_conn_data_pool(size_t size, struct conn_data *conn_data) {
	for (size_t i = 0; i < size; i++)
		free_conn_data(&conn_data[i]);
}

static int alloc_conn_data_pool(struct conn_data **conn_data) {
	struct conn_data *data = malloc(sizeof(*data) * MAX_CONN_COUNT);
	for (size_t i = 0; i < MAX_CONN_COUNT; i++) {
		if (alloc_conn_data(&data[i]) != 0) {
			free_conn_data_pool(i, data);
			return -1;
		}
	}
	*conn_data = data;
	return 0;
}

static int alloc_glob_res() {
	ev_base = event_base_new();
	if (ev_base == NULL)
		goto err1;
	if (alloc_conn_data_pool(&conn_data_pool) !=0 )
		goto err2;
	read_buff = malloc(sizeof(*read_buff) * BUFSIZ);
	if (read_buff == NULL)
		goto err3;
	accept_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (accept_ev == NULL)
		goto err4;
	tokens = malloc(sizeof(*tokens) * TOKENS_LEN);
	if (tokens == NULL)
		goto err5;
	dcode_buff = malloc(sizeof(*dcode_buff) * DECODE_BUFF_LEN);
	if (dcode_buff == NULL)
		goto err6;
	return 0;

	err6:
	free(tokens);

	err5:
	event_free(accept_ev);

	err4:
	free(read_buff);

	err3:
	free_conn_data_pool(MAX_CONN_COUNT, conn_data_pool);

	err2:
	event_base_free(ev_base);

	err1:
	return -1;
}

static void free_glob_res() {
	event_free(accept_ev);
	free_conn_data_pool(MAX_CONN_COUNT, conn_data_pool);
	event_base_free(ev_base);
	free(read_buff);
	free(tokens);
	free(dcode_buff);
}

static void rset_token_buff(struct conn_data *conn_data) {
	conn_data->token_buff_wrt_ptr = conn_data->token_buff;
	conn_data->token_buff_free_space = TOKEN_BUFF_LEN;
}

static void reset_conn_data(struct conn_data *conn_data) {
	conn_data->error_cnt = 0;
	conn_data->prot_state = EXPECT_HELO;
	conn_data->log_user_len = 0;
	memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
	rset_token_buff(conn_data);
}

static struct conn_data *get_conn_data(int fd) {
	struct conn_data *ret = NULL;
	size_t i = 0;
	for (; i < MAX_CONN_COUNT; i++) {
		if (conn_data_pool[i].fd == -1) {
			if (ret == NULL) {
				// reserve slot
				conn_data_pool[i].fd = fd;
				reset_conn_data(&conn_data_pool[i]);
				ret = &conn_data_pool[i];
			} else // We break later to check if there is at least one more free slot
				break;
		}
	}
	if (i == MAX_CONN_COUNT)
		event_del(accept_ev);
	return ret;
}

static void close_conn(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - closed connection, fd: %d\n",conn_data->fd);
	event_del(conn_data->read_ev);
	event_del(conn_data->con_tout_ev);
	event_del(conn_data->inac_tout_ev);
	close(conn_data->fd);
	conn_data->fd = -1;
	event_add(accept_ev, NULL);
}

static inline int send_resp(struct conn_data *conn_data, char *mesg) {
	if (send_all(conn_data->fd, mesg, strlen(mesg)) != 0) {
		DEBUG_PRINT("smtp - error - could not send to peer\n");
		return -1;
	} else {
		return 0;
	}
}

static int error_incr(struct conn_data *conn_data) {
	conn_data->error_cnt++;
	if (conn_data->error_cnt == ERROR_LIMIT) {
		DEBUG_PRINT("smtp - error limit reached\n");
		char *mesg;
		concat_mesg(&mesg, 3, TOO_MUCH_ERR_RESP_PART1, host_name, TOO_MUCH_ERR_RESP_PART2);
		send_resp(conn_data, mesg);
		free(mesg);
		return -1;
	} else {
		return 0;
	}
}

static inline int send_and_err_incr(struct conn_data *conn_data, char *mesg) {
	FLOW_GUARD(send_resp(conn_data, mesg));
	return error_incr(conn_data);
}

static inline void report(struct proxy_msg *proxy_msg, const char *err_msg) {
	if (proxy_report(report_fd, proxy_msg) !=0) {
		DEBUG_PRINT("%s", err_msg);
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
};

static void report_connect(struct conn_data *conn_data) {
	struct proxy_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = CONNECT_EV,
		.data = NULL,
		.data_len = 0,
	};
	report(&msg, "smtp - error - couldn't report connect\n");
}

static void report_invalid(struct conn_data *conn_data) {
	struct proxy_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = INVALID_EV,
		.data = NULL,
		.data_len = 0,
	};
	report(&msg, "smtp - error - couldn't report invalid\n");
}

static void report_login_login(struct conn_data *conn_data) {
	if (check_serv_data(conn_data->log_user, conn_data->log_user_len) ||
		check_serv_data(dcode_buff, dcoded_data_len)) {
		report_invalid(conn_data);
		return;
	}
	struct uint8_t_pair data[] = {
		{LOGIN_USER, strlen(LOGIN_USER), conn_data->log_user, conn_data->log_user_len},
		// we don't need store password for reporting - it is in dcode buffer
		{LOGIN_PASS, strlen(LOGIN_PASS), dcode_buff, dcoded_data_len},
		{SASL_MECH, strlen(SASL_MECH), SASL_LOGIN, strlen(SASL_LOGIN)},
	};
	struct proxy_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.data = data,
		.action = LOGIN_EV,
		.data_len = sizeof(data) / sizeof(*data),
	};
	report(&msg, "smtp - error - couldn't report login login\n");
}

static void report_login_plain(struct conn_data *conn_data) {
	char *authzid = dcode_buff;
	// find first null
	char *null_byte = memchr(authzid, NUL, dcoded_data_len);
	if (null_byte == NULL)
		goto err;
	size_t authzid_len = null_byte - authzid;
	char *authcid = null_byte + 1;
	// find second null
	null_byte = memchr(authcid, NUL, dcoded_data_len - authzid_len - 1);
	if (null_byte == NULL)
		goto err;
	size_t authcid_len = null_byte - authcid;
	char *password = null_byte + 1;
	size_t password_len = dcoded_data_len - authzid_len - authcid_len - 2;
	if (authcid_len == 0 ||
		check_serv_data(authcid, authcid_len) ||
		check_serv_data(password, password_len))
		goto err;
	struct uint8_t_pair data[] = {
		{LOGIN_USER, strlen(LOGIN_USER), authcid, authcid_len},
		{LOGIN_PASS, strlen(LOGIN_PASS), password, password_len},
		{SASL_MECH, strlen(SASL_MECH), SASL_PLAIN, strlen(SASL_PLAIN)},
	};
	struct proxy_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.data = data,
		.action = LOGIN_EV,
		.data_len = sizeof(data) / sizeof(*data),
	};
	report(&msg, "smtp - error - couldn't report login plain\n");
	return;
	err:
	report_invalid(conn_data);
}


static int vrfy_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - vrfy cmd\n");
	return send_and_err_incr(conn_data, VRFY_RESP);
}

static int noop_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - noop cmd\n");
	FLOW_GUARD(send_resp(conn_data, OK_RESP));
	return 0;
}

static int quit_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - quit cmd\n");
	send_resp(conn_data, QUIT_RESP);
	return -1;
}

static int ehlo_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - ehlo cmd\n");
	if (tokens_cnt > 1) {
		conn_data->prot_state = HELO_SENT;
		char *mesg;
		concat_mesg(&mesg, 3, EHLO_250_RESP_PART1, host_name, EHLO_250_RESP_PART2);
		int ret = send_resp(conn_data, mesg);
		free(mesg);
		return ret;
	} else {
		return send_and_err_incr(conn_data, EHLO_501_RESP);
	}
}

static int helo_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - helo cmd\n");
	if (tokens_cnt > 1 ) {
		conn_data->prot_state = HELO_SENT;
		char *mesg;
		concat_mesg(&mesg, 3, HELO_250_RESP_PART1, host_name, HELO_250_RESP_PART2);
		int ret = send_resp(conn_data, mesg);
		free(mesg);
		return ret;
	} else {
		return send_and_err_incr(conn_data, HELO_501_RESP);
	}
}

static int rset_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - rset cmd\n");
	if (tokens_cnt > 1) {
		return send_and_err_incr(conn_data, RSET_501_RESP);
	} else {
		if (conn_data->prot_state == HELO_MAIL_SENT)
			conn_data->prot_state = HELO_SENT;
		return send_resp(conn_data, OK_RESP);
	}
}

static int data_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - data cmd\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
		case HELO_SENT:
			return send_and_err_incr(conn_data, DATA_503_RESP);
		case HELO_MAIL_SENT:
			return send_and_err_incr(conn_data, DATA_554_RESP);
		default:
			DEBUG_PRINT("smtp - ehlo cmd - default\n");
			return -1;
	}
}

static int mail_cmd_helo_sent_params(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - mail cmd helo sent params\n");
	// at least 2 tokens
	if (tokens_cnt < 2) {
		DEBUG_PRINT("smtp - mail cmd helo sent tokens cnt < 2 ");
		return -1;
	} else {
		if ((tokens[1].len) < strlen(MAIL_FROM_STR)) {
			return send_and_err_incr(conn_data, MAIL_501_RESP);
		} else if ((tokens[1].len) == strlen(MAIL_FROM_STR)) {
			// match param
			if (strncasecmp(tokens[1].start_ptr, MAIL_FROM_STR, strlen(MAIL_FROM_STR)) != 0) {
				return send_and_err_incr(conn_data, MAIL_501_RESP);
			} else {
				// check for more tokens
				if (tokens_cnt >= 3) {
					conn_data->prot_state = HELO_MAIL_SENT;
					return send_resp(conn_data, OK_RESP);
				} else {
					return send_and_err_incr(conn_data, MAIL_501_RESP);
				}
			}
		} else {
			// match param
			if (strncasecmp(tokens[1].start_ptr, MAIL_FROM_STR, strlen(MAIL_FROM_STR)) != 0) {
				return send_and_err_incr(conn_data, MAIL_501_RESP);
			} else {
				conn_data->prot_state = HELO_MAIL_SENT;
				return send_resp(conn_data, OK_RESP);
			}
		}
	}
}

static int mail_cmd_helo_sent(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - mail cmd helo sent\n");
	// tokens cnt at least 1
	switch (tokens_cnt) {
		case 0:
			DEBUG_PRINT("smtp - mail cmd helo sent tokens cnt is 0\n");
			return -1;
		case 1:
			// missing from:
			return send_and_err_incr(conn_data, MAIL_501_RESP);
		default:
			return mail_cmd_helo_sent_params(conn_data);
	}
}

static int mail_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - mail cmd\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
			return send_and_err_incr(conn_data,MAIL_EXPECT_HELO_RESP);
		case HELO_SENT:
			return mail_cmd_helo_sent(conn_data);
		case HELO_MAIL_SENT:
			return send_and_err_incr(conn_data, MAIL_HELO_MAIL_RESP);
		default:
			DEBUG_PRINT("smtp - mail cmd - default\n");
			return -1;
	}
}

static int rcpt_cmd_helo_mail_sent_params(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - rcpt cmd helo mail sent params\n");
	// at least 2 tokens
	if (tokens_cnt < 2) {
		DEBUG_PRINT("smtp - rcpt cmd helo mail sent tokens cnt < 2 ");
		return -1;
	} else {
		if ((tokens[1].len) < strlen(RCPT_TO_STR)) {
			return send_and_err_incr(conn_data, RCPT_501_RESP);
		} else if ((tokens[1].len) == strlen(RCPT_TO_STR)) {
			// match param
			if (strncasecmp(tokens[1].start_ptr, RCPT_TO_STR, strlen(RCPT_TO_STR)) != 0) {
				return send_and_err_incr(conn_data, RCPT_501_RESP);
			} else {
				// check for more tokens
				if (tokens_cnt >= 3) {
					char *mesg;
					concat_mesg(&mesg, 3, RCPT_554_RESP_PART1, conn_data->ipaddr_str, RCPT_554_RESP_PART2);
					int ret = send_and_err_incr(conn_data, mesg);
					free(mesg);
					return ret;
				} else {
					return send_and_err_incr(conn_data, RCPT_501_RESP);
				}
			}
		} else {
			// match param
			if (strncasecmp(tokens[1].start_ptr, RCPT_TO_STR, strlen(RCPT_TO_STR)) != 0) {
				return send_and_err_incr(conn_data, RCPT_501_RESP);
			} else {
				char *mesg;
				concat_mesg(&mesg, 3, RCPT_554_RESP_PART1, conn_data->ipaddr_str, RCPT_554_RESP_PART2);
				int ret = send_and_err_incr(conn_data, mesg);
				free(mesg);
				return ret;
			}
		}
	}
}

static int rcpt_cmd_helo_mail_sent(struct conn_data *conn_data) {
   DEBUG_PRINT("smtp - rcpt cmd helo mail sent\n");
	// tokens cnt at least 1
	switch (tokens_cnt) {
		case 0:
			DEBUG_PRINT("smtp - rcpt cmd helo mail sent tokens cnt is 0\n");
			return -1;
		case 1:
			// missing to:
			return send_and_err_incr(conn_data, RCPT_501_RESP);
		default:
			return rcpt_cmd_helo_mail_sent_params(conn_data);
	}
}

static int rcpt_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - rctp cmd\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
		case HELO_SENT:
			return send_and_err_incr(conn_data, RCPT_503_RESP);
		case HELO_MAIL_SENT:
			return rcpt_cmd_helo_mail_sent(conn_data);
		default:
			DEBUG_PRINT("smtp -rcptcmd - default\n");
			return -1;
	}
}

static int etrn_cmd_helo_sent(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - etrn cmd helo sent\n");
	// tokens cnt at least 1
	switch (tokens_cnt) {
		case 0:
			DEBUG_PRINT("smtp - etrn cmd helo sent tokens cnt is 0\n");
			return -1;
		case 1:
			// missing param:
			return send_and_err_incr(conn_data, ETRN_HELO_500_RESP);
		case 2:{
			char *mesg;
			concat_mesg(&mesg, 3, ETRN_HELO_554_RESP_PART1, conn_data->ipaddr_str, ETRN_HELO_554_RESP_PART2);
			int ret = send_and_err_incr(conn_data, mesg);
			free(mesg);
			return ret;
		}
		default:
			// to much params
			return send_and_err_incr(conn_data, ETRN_HELO_500_RESP);
	}
}

static int etrn_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - etrn cmd\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
			return send_and_err_incr(conn_data, ETRN_EXPECT_HELO_RESP);
		case HELO_SENT:
			return etrn_cmd_helo_sent(conn_data);
		case HELO_MAIL_SENT:
			return send_and_err_incr(conn_data, ETRN_HELO_MAIL_RESP);
		default:
			DEBUG_PRINT("smtp - error - etrn cmd - default");
			return -1;
	}
}

static int auth_cmd_helo_sent_init_resp(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - auth cmd helo sent init resp\n");
	struct sasl_mechanism *mech = sasl_mech_lookup(tokens[1].start_ptr, tokens[1].len);
	if (mech == NULL) {
		// invalid sasl
		report_invalid(conn_data);
		return send_and_err_incr(conn_data, AUTH_INVLD_SASL_MECH);
	} else {
		if (!base64_verify(tokens[2].start_ptr, tokens[2].len)) {
			//valid base 64 string
			dcoded_data_len = base64_decode(tokens[2].start_ptr, tokens[2].len, dcode_buff);
			switch (mech->abr) {
				case PLAIN:
					report_login_plain(conn_data);
					return send_and_err_incr(conn_data, AUTH_PLAIN_INIT_RESP_RESP);
				case LOGIN:
					conn_data->prot_state = EXPECT_LOGIN_PASSW;
					memcpy(conn_data->log_user, dcode_buff, dcoded_data_len);
					conn_data->log_user_len = (size_t) dcoded_data_len;
					return send_resp(conn_data, AUTH_LOG_ASK_FOR_PASSW);
				default:
					DEBUG_PRINT("smtp - auth cmd No init resp - default\n");
					return -1;
			}
		} else {
			// invalid base64 string
			report_invalid(conn_data);
			return send_and_err_incr(conn_data, AUTH_INIT_RESP_ERROR);
		}
	}
}

static int auth_cmd_helo_sent_only_sasl(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - auth cmd helo sent only sasl\n");
	struct sasl_mechanism *mech = sasl_mech_lookup(tokens[1].start_ptr, tokens[1].len);
	if (mech == NULL) {
		// invalid sasl
		report_invalid(conn_data);
		return send_and_err_incr(conn_data, AUTH_INVLD_SASL_MECH);
	} else {
		switch (mech->abr) {
			case PLAIN:
				conn_data->prot_state = EXPECT_PLAIN_DATA;
				return send_resp(conn_data, AUTH_PLAIN_ASK_DATA_RESP);
			case LOGIN:
				conn_data->prot_state = EXPECT_LOGIN_USER;
				return send_resp(conn_data, AUTH_LOG_ASK_USER_RESP);
			default:
				DEBUG_PRINT("smtp - auth cmd helo sent only sasl - default\n");
				return -1;
		}
	}
}

static int auth_cmd_helo_sent(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - auth cmd helo sent\n");
	// tokens cnt is at least 1
	switch (tokens_cnt) {
		case 0:
			DEBUG_PRINT("smtp - auth cmd helo sent - tokens cnt is 0\n");
			return -1;
		case 1:
			// missing sasl
			return send_and_err_incr(conn_data, AUTH_501_RESP);
		case 2:
			// only sasl
			return auth_cmd_helo_sent_only_sasl(conn_data);
		case 3:
			// sasl and init response
			return auth_cmd_helo_sent_init_resp(conn_data);
		default:
			// more params - error
			return send_and_err_incr(conn_data, AUTH_501_RESP);
	}
}

static int auth_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - auth cmd\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
			return send_and_err_incr(conn_data, AUTH_EXPECT_HELO_RESP);
		case HELO_SENT:
			return auth_cmd_helo_sent(conn_data);
		case HELO_MAIL_SENT:
			return send_and_err_incr(conn_data, AUTH_HELO_MAIL_RESP);
		default:
			DEBUG_PRINT("smtp - auth cmd - default\n");
			return -1;
	}
}

static int proc_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - proc cmd\n");
	// strip LF
	conn_data->token_buff_free_space += 1;
	if (TOKEN_BUFF_LEN == conn_data->token_buff_free_space) {
		return send_and_err_incr(conn_data, EMPTY_LINE_RESP);
	}
	else {
		uint8_t sep[] = {HT, VT, FF, SP, CR};
		tokens_cnt = tokenize(conn_data->token_buff, TOKEN_BUFF_LEN - conn_data->token_buff_free_space,
			tokens, TOKENS_LEN, sep, sizeof(sep) / sizeof(*sep));
		if (tokens_cnt == 0) {
			return send_and_err_incr(conn_data, EMPTY_LINE_RESP);
		} else {
			struct smtp_command *cmd = smtp_command_lookup(tokens[0].start_ptr, tokens[0].len);
			if (cmd == NULL) {
				return send_and_err_incr(conn_data, UNKNOWN_CMD_RESP);
			} else {
				switch (cmd->comand_abr) {
					case EHLO:
						return ehlo_cmd(conn_data);
					case HELO_SENT:
						return helo_cmd(conn_data);
					case MAIL:
						return mail_cmd(conn_data);
					case RCPT:
						return rcpt_cmd(conn_data);
					case DATA:
						return data_cmd(conn_data);
					case RSET:
						return rset_cmd(conn_data);
					case VRFY:
						return vrfy_cmd(conn_data);
					case NOOP:
						return noop_cmd(conn_data);
					case QUIT:
						return quit_cmd(conn_data);
					case AUTH:
						return auth_cmd(conn_data);
					case ETRN:
						return etrn_cmd(conn_data);
					default:
						DEBUG_PRINT("smtp - proc cmd - default\n");
						return -1;
				}
			}
		}
	}
}

static int proc_auth_data_empty(struct conn_data *conn_data) {
	report_invalid(conn_data);
	switch (conn_data->prot_state) {
		case EXPECT_PLAIN_DATA:
			conn_data->prot_state = HELO_SENT;
			return send_and_err_incr(conn_data, AUTH_PLAIN_INIT_RESP_RESP);
		case EXPECT_LOGIN_USER:
			conn_data->prot_state = HELO_SENT;
			return send_and_err_incr(conn_data, PROC_DATA_EXPCT_LOG_USER_EMPTY_LINE);
		case EXPECT_LOGIN_PASSW:
			conn_data->prot_state = HELO_SENT;
			return send_and_err_incr(conn_data, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE);
		default:
			DEBUG_PRINT("smtp - proc auth data empty - default\n");
			return -1;
	}
}

static int proc_auth_data(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - proc auth data\n");
	// strip LF
	conn_data->token_buff_free_space += 1;
	if (TOKEN_BUFF_LEN == conn_data->token_buff_free_space)
		// only LF - empty data
		return proc_auth_data_empty(conn_data);
	if (conn_data->token_buff[TOKEN_BUFF_LEN - conn_data->token_buff_free_space - 1] == CR) {
		// strip CR
		conn_data->token_buff_free_space += 1;
		if (TOKEN_BUFF_LEN == conn_data->token_buff_free_space)
			// only CRLF - empty data
			return proc_auth_data_empty(conn_data);
	}
	if ((TOKEN_BUFF_LEN - conn_data->token_buff_free_space) == 1 && *conn_data->token_buff == STAR) {
		// aborted authentication
		conn_data->prot_state = HELO_SENT;
		report_invalid(conn_data);
		return send_resp(conn_data, PROC_DATA_AUTH_ABOR);
	} else {
		if (!base64_verify(conn_data->token_buff, TOKEN_BUFF_LEN - conn_data->token_buff_free_space)) {
			dcoded_data_len = base64_decode(conn_data->token_buff, TOKEN_BUFF_LEN - conn_data->token_buff_free_space, dcode_buff);
			switch (conn_data->prot_state) {
				case EXPECT_PLAIN_DATA:
					report_login_plain(conn_data);
					conn_data->prot_state = HELO_SENT;
					return send_and_err_incr(conn_data, AUTH_PLAIN_INIT_RESP_RESP);
				case EXPECT_LOGIN_USER:
					memcpy(conn_data->log_user, dcode_buff, dcoded_data_len);
					conn_data->log_user_len = (size_t) dcoded_data_len;
					conn_data->prot_state = EXPECT_LOGIN_PASSW;
					return send_resp(conn_data, AUTH_LOG_ASK_FOR_PASSW);
				case EXPECT_LOGIN_PASSW:
					report_login_login(conn_data);
					conn_data->prot_state = HELO_SENT;
					return send_and_err_incr(conn_data, PROC_DATA_EXPCT_LOG_PASSW_EMPTY_LINE);
				default:
					DEBUG_PRINT("smtp - proc auth data - default\n");
					return -1;
			}
		} else {
			// invalid base 64 string
			conn_data->prot_state = HELO_SENT;
			report_invalid(conn_data);
			return send_and_err_incr(conn_data, PROC_DATA_INVALID_B64);
		}
	}
}

static int check_prot_state(struct conn_data *conn_data) {
	DEBUG_PRINT("smtp - check prot state\n");
	switch (conn_data->prot_state) {
		case EXPECT_HELO:
		case HELO_SENT:
		case HELO_MAIL_SENT:
			return proc_cmd(conn_data);
		case EXPECT_PLAIN_DATA:
		case EXPECT_LOGIN_USER:
		case EXPECT_LOGIN_PASSW:
			return proc_auth_data(conn_data);
		default:
			DEBUG_PRINT("smtp - check prot state - default\n");
			return -1;
	}
}

static void proc_bytes(struct conn_data *conn_data, uint8_t *buff, size_t buff_len) {
	DEBUG_PRINT("smtp - proc bytes - start\n");
	while (buff_len > 0) {
		size_t bytes_to_buff;
		uint8_t *cmd_separator = memchr(buff, LF, buff_len);
		if (cmd_separator != NULL)
			// including the separator
			bytes_to_buff = cmd_separator - buff + 1;
		else
			bytes_to_buff = buff_len;
		if (bytes_to_buff <= conn_data->token_buff_free_space) {
			memcpy(conn_data->token_buff_wrt_ptr, buff, bytes_to_buff);
			conn_data->token_buff_wrt_ptr += bytes_to_buff;
			conn_data->token_buff_free_space -= bytes_to_buff;
			if (cmd_separator != NULL) {
				// process data
				if (check_prot_state(conn_data) != 0) {
					// processing error
					close_conn(conn_data);
					break;
				} else {
					// processing ok
					rset_token_buff(conn_data);
				}
			} else {
				// wait for more data
				break;
			}
		} else {
			if (send_and_err_incr(conn_data, TOO_LONG_DATA_RESP) != 0) {
				close_conn(conn_data);
				break;
			} else {
				rset_token_buff(conn_data);
			}
		}
		buff += bytes_to_buff;
		buff_len -= bytes_to_buff;
	}
	DEBUG_PRINT("smtp - proc bytes - stop\n");
}

static void on_timeout(int fd, short ev, void *arg){
	DEBUG_PRINT("smtp - timeout\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	char *mesg;
	concat_mesg(&mesg, 3, TOUT_RESP_PART1, host_name, TOUT_RESP_PART2);
	send_resp(conn_data, mesg);
	free(mesg);
	close_conn(conn_data);
}

static void on_recv(int fd, short ev, void *arg) {
	DEBUG_PRINT("smtp - on receive\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	ssize_t amount = recv(fd, read_buff, BUFSIZ, 0);
	switch (amount) {
		case -1:
			if (errno == EAGAIN)
				return;
			DEBUG_PRINT("smtp - error on connection %d: %s\n", fd, strerror(errno));
		case 0:
			close_conn(conn_data);
			return;
	}
	// reset inactivity timer
	struct timeval tm = {INACT_TIMEOUT, 0};
	evtimer_add(conn_data->inac_tout_ev, &tm);
	proc_bytes(conn_data, read_buff, (size_t) amount);
}

static void on_accept(int listen_fd, short ev, void *arg) {
	DEBUG_PRINT("smtp - on accept\n");
	struct sockaddr_storage conn_addr;
	socklen_t conn_addr_len = sizeof(conn_addr);
	int conn_fd = accept(listen_fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
	if (conn_fd < 0) {
		DEBUG_PRINT("smtp - error - accept\n");
		return;
	}
	if (setnonblock(conn_fd) != 0) {
		DEBUG_PRINT("smtp - error - couldnt set nonblock\n");
		close(conn_fd);
		return;
	}
	struct conn_data *conn_data = get_conn_data(conn_fd);
	if (conn_data == NULL) {
		DEBUG_PRINT("smtp - accept - no free slots\n");
		// no free slots
		close(conn_fd);
		return;
	}
	if (sockaddr_to_string(&conn_addr, conn_data->ipaddr_str) != 0) {
		DEBUG_PRINT("smtp - sock addr to string - unknown socket family\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
		return;
	}
	char *mesg;
	concat_mesg(&mesg, 3, WELCOME_RESP_PART1, host_name, WELCOME_RESP_PART2);
	int ret = send_resp(conn_data, mesg);
	free(mesg);
	if (ret != 0) {
		close(conn_data->fd);
		conn_data->fd = -1;
		return;
	}
	event_assign(conn_data->read_ev, ev_base, conn_data->fd, EV_READ | EV_PERSIST, on_recv, conn_data);
	event_add(conn_data->read_ev, NULL);
	evtimer_assign(conn_data->con_tout_ev, ev_base, on_timeout, conn_data);
	struct timeval tm = {CONN_TIMEOUT, 0};
	evtimer_add(conn_data->con_tout_ev, &tm);
	evtimer_assign(conn_data->inac_tout_ev, ev_base, on_timeout, conn_data);
	tm = (struct timeval) {INACT_TIMEOUT, 0};
	evtimer_add(conn_data->inac_tout_ev, &tm);
	report_connect(conn_data);
	DEBUG_PRINT("smtp - accepted connection %d\n", conn_data->fd);
}

static void gen_host_name() {
	srand(time(NULL));
	size_t pos = 0;
	host_name[pos++] = 'm';
	host_name[pos++] = 'x';
	host_name[pos++] = (rand() % 10) + 48;
	host_name[pos++] = '.';
	for (int i = 0; i < 5 + (rand() % 15); i++) {
		switch (rand() % 3) {
			case 0:
				host_name[pos++] = (rand() % 10) + 48;
				break;
			case 1:
				host_name[pos++] = (rand() % 26) + 65;
				break;
			case 2:
				host_name[pos++] = (rand() % 26) + 97;
				break;
		}
	}
	host_name[pos++] = '.';
	switch (rand() % 4) {
		case 0:
			host_name[pos++] = 'c';
			host_name[pos++] = 'o';
			host_name[pos++] = 'm';
			break;
		case 1:
			host_name[pos++] = 'o';
			host_name[pos++] = 'r';
			host_name[pos++] = 'g';
			break;
		case 2:
			host_name[pos++] = 'n';
			host_name[pos++] = 'e';
			host_name[pos++] = 't';
			break;
		case 3:
			host_name[pos++] = 'c';
			host_name[pos++] = 'z';
			break;
	}
}

int handle_smtp(int listen_fd, int pipe_write_fd) {
	exit_code = EXIT_SUCCESS;
	report_fd = pipe_write_fd;
	// to supress evenet base logging
	event_set_log_callback(ev_base_discard_cb);
	if (alloc_glob_res() != 0 ) {
		DEBUG_PRINT("smtp - error - couldn't allocate global resources\n");
		return EXIT_FAILURE;
	}
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, on_sigint, ev_base);
	if (sigint_ev == NULL) {
		DEBUG_PRINT("smtp - error - couldn't allocate sigint ev\n");
		exit_code = EXIT_FAILURE;
		goto sigint_ev_err;
	}
	gen_host_name();
	signal(SIGPIPE, SIG_IGN);
	event_assign(accept_ev, ev_base, listen_fd, EV_READ | EV_PERSIST, on_accept, NULL);
	event_add(accept_ev, NULL);
	event_add(sigint_ev, NULL);
	event_base_dispatch(ev_base);
	event_free(sigint_ev);

	sigint_ev_err:
	free_glob_res();
	return exit_code;
}
