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

#include <event2/event.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>

#include "char_consts.h"
#include "utils.h"
#include "minipot_pipe.h"
#include "ftp_commands.gperf.c"

#define MAX_CONN_COUNT 5
#define CONN_TIMEOUT (60 * 5)
#define INACT_TIMEOUT (60 * 3)

#define CMD_BUFF_LEN 4096
#define USER_BUFF_LEN CMD_BUFF_LEN

#define CONNECT_EV "connect"
#define LOGIN_EV "login"
#define INVALID_EV "invalid"
#define TYPE "ftp"

#define LOGIN_USER "username"
#define LOGIN_PASS "password"

#define LOG_ATMPS_CNT 100

#define WELOME_RESP "220 (vsFTPd 3.0.3)\r\n"
#define TIMEOUT_RESP "421 Timeout.\r\n"
#define OTHER_RESP "530 Please login with USER and PASS.\r\n"
#define TOO_LONG_CMD_RESP "500 Input line too long.\r\n"
#define USER_RESP "331 Please specify the password.\r\n"
#define FEAT_RESP "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n"
#define OPTS_501_RESP "501 Option not understood.\r\n"
#define OPTS_200_RESP "200 Always in UTF8 mode.\r\n"
#define PASS_530_RESP "530 Login incorrect.\r\n"
#define PASS_503_RESP "503 Login with USER first.\r\n"
#define QUIT_RESP "221 Goodbye.\r\n"

#define UTF8_ON_OPT "utf8 on"

struct conn_data {
	int fd;
	struct event *read_ev;
	struct event *con_tout_ev;
	struct event *inac_tout_ev;
	uint8_t *ipaddr_str;
	uint8_t *cmd_buff;
	uint8_t *cmd_buff_wrt_ptr;
	size_t cmd_buff_free_len;
	int try_count;
	bool user_provided;
	uint8_t *user;
	size_t user_len;
};

static int exit_code;
static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buff;
static struct event *accept_ev;

static void free_conn_data(struct conn_data *conn_data) {
	free(conn_data->cmd_buff);
	free(conn_data->user);
	free(conn_data->ipaddr_str);
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
	conn_data->user = malloc(sizeof(*conn_data->user) * USER_BUFF_LEN);
	if (conn_data->user == NULL)
		goto err5;
	conn_data->cmd_buff = malloc(sizeof(*conn_data->cmd_buff) * CMD_BUFF_LEN);
	if (conn_data->cmd_buff == NULL)
		goto err6;
	conn_data->fd = -1;
	return 0;

	err6:
	free(conn_data->user);

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
	if(accept_ev == NULL)
		goto err4;
	return 0;

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
}

static void reset_cmd_buff(struct conn_data *conn_data) {
	conn_data->cmd_buff_wrt_ptr = conn_data->cmd_buff;
	conn_data->cmd_buff_free_len = CMD_BUFF_LEN;
}

static inline void reset_conn_data(struct conn_data *conn_data) {
	conn_data->try_count = 0;
	conn_data->user_provided = false;
	conn_data->user_len = 0;
	memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
	reset_cmd_buff(conn_data);
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
	DEBUG_PRINT("ftp - closed connection, fd: %d\n",conn_data->fd);
	event_del(conn_data->read_ev);
	event_del(conn_data->con_tout_ev);
	event_del(conn_data->inac_tout_ev);
	close(conn_data->fd);
	conn_data->fd = -1;
	event_add(accept_ev, NULL);
}

static inline int send_resp(struct conn_data *conn_data, char *mesg) {
	if (send_all(conn_data->fd, mesg, strlen(mesg)) != 0) {
		DEBUG_PRINT("ftp - error - could not send to peer\n");
		return -1;
	} else {
		return 0;
	}
}

static void report_login(struct conn_data *conn_data, uint8_t *param, size_t param_len) {
	struct uint8_t_pair data[] = {
		{LOGIN_USER, strlen(LOGIN_USER), conn_data->user, conn_data->user_len},
		// we don't need store password for reporting - it is command buffer
		{LOGIN_PASS, strlen(LOGIN_PASS), param, param_len},
	};
	struct proxy_msg msg;
	msg.ts = time(NULL);
	msg.type = TYPE;
	msg.ip = conn_data->ipaddr_str;
	msg.action = LOGIN_EV;
	msg.data = data;
	msg.data_len = sizeof(data) / sizeof(*data);
	if (proxy_report(report_fd, &msg) !=0) {
		DEBUG_PRINT("ftp - error - couldn't report login\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
}

static void report_invalid(struct conn_data *conn_data) {
	struct proxy_msg msg;
	msg.ts = time(NULL);
	msg.type = TYPE;
	msg.ip = conn_data->ipaddr_str;
	msg.action = INVALID_EV;
	msg.data = NULL;
	msg.data_len = 0;
	if (proxy_report(report_fd, &msg) !=0) {
		DEBUG_PRINT("ftp - error - couldn't report invalid\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
}

static void report_connect(struct conn_data *conn_data) {
	struct proxy_msg msg;
	msg.ts = time(NULL);
	msg.type = TYPE;
	msg.ip = conn_data->ipaddr_str;
	msg.action = CONNECT_EV;
	msg.data = NULL;
	msg.data_len = 0;
	if (proxy_report(report_fd, &msg) !=0) {
		DEBUG_PRINT("ftp - error - couldn't report connect\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
}

static int user_cmd(struct conn_data *conn_data, uint8_t *param, size_t param_len) {
	DEBUG_PRINT("ftp - user cmd\n");
	if (param_len > 0) {
		conn_data->user_provided = true;
		memcpy(conn_data->user, param, param_len);
		conn_data->user_len = param_len;
	}
	return send_resp(conn_data, USER_RESP);
}

static int pass_cmd(struct conn_data *conn_data,  uint8_t *param, size_t param_len) {
	DEBUG_PRINT("ftp - pass cmd\n");
	if (conn_data->user_provided) {
		conn_data->user_provided = false;
		report_login(conn_data, param, param_len);
		if (send_resp(conn_data,PASS_530_RESP))
			return -1;
		conn_data->try_count++;
		if (conn_data->try_count == LOG_ATMPS_CNT) {
			DEBUG_PRINT("ftp - pass cmd - login attempt limit reached\n");
			// close connection
			return -1;
		}
		return 0;
	} else {
		report_invalid(conn_data);
		return send_resp(conn_data, PASS_503_RESP);
	}
}

static int opts_cmd(struct conn_data *conn_data,  uint8_t *param, size_t param_len) {
	DEBUG_PRINT("ftp - opts cmd\n");
	if (param_len > 0)
		if (strncasecmp(param, UTF8_ON_OPT,param_len) != 0)
			return send_resp(conn_data, OPTS_501_RESP);
		else
			return send_resp(conn_data, OPTS_200_RESP);
	else
		return send_resp(conn_data, OPTS_501_RESP);
}

static int proc_cmd(struct conn_data *conn_data) {
	DEBUG_PRINT("ftp - detect cmd\n");
	// strip LF
	conn_data->cmd_buff_free_len += 1;
	if (CMD_BUFF_LEN == conn_data->cmd_buff_free_len)
		// empty command
		return 0;
	size_t cmd_str_len = CMD_BUFF_LEN - conn_data->cmd_buff_free_len;
	// strip CR if part of command separator
	if (conn_data->cmd_buff[cmd_str_len - 1] == CR) {
		cmd_str_len -= 1;
		if (cmd_str_len == 0)
			// empty command
			return 0;
	}
	size_t cmd_code_len = cmd_str_len;
	uint8_t *param = NULL;
	size_t param_len = 0;
	uint8_t *delim = memchr(conn_data->cmd_buff, SP, cmd_str_len);
	if (delim) {
		cmd_code_len = delim - conn_data->cmd_buff;
		param_len = cmd_str_len - cmd_code_len - 1;
		if (param_len)
			param = delim + 1;
	}
	struct ftp_command *cmd = ftp_command_lookup(conn_data->cmd_buff, cmd_code_len);
	if (cmd == NULL) {
		DEBUG_PRINT("ftp - other cmd\n");
		return send_resp(conn_data, OTHER_RESP);
	} else {
		switch (cmd->comand_abr) {
			case USER:
				return user_cmd(conn_data, param, param_len);
			case PASS:
				return pass_cmd(conn_data, param, param_len);
			case QUIT:
				DEBUG_PRINT("ftp - quit cmd\n");
				send_resp(conn_data, QUIT_RESP);
				return -1;
			case FEAT:
				DEBUG_PRINT("ftp -feat cmd\n");
				return send_resp(conn_data, FEAT_RESP);
			case OPTS:
				return opts_cmd(conn_data, param, param_len);
			default:
				DEBUG_PRINT("ftp - detect cmd - default\n");
				return -1;
		}
	}
}

static void proc_bytes(struct conn_data *conn_data, uint8_t *buff, size_t buff_len) {
	DEBUG_PRINT("ftp - proc bytes - start\n");
	while (buff_len > 0) {
		size_t bytes_to_buff;
		uint8_t *cmd_separator = memchr(buff, LF, buff_len);
		if (cmd_separator != NULL)
			// including the separator
			bytes_to_buff = cmd_separator - buff + 1;
		else
			bytes_to_buff = buff_len;
		if (bytes_to_buff <= conn_data->cmd_buff_free_len) {
			memcpy(conn_data->cmd_buff_wrt_ptr, buff, bytes_to_buff);
			conn_data->cmd_buff_wrt_ptr += bytes_to_buff;
			conn_data->cmd_buff_free_len -= bytes_to_buff;
			if (cmd_separator != NULL) {
				if (proc_cmd(conn_data) != 0) {
					close_conn(conn_data);
					break;
				} else {
					// continue
					reset_cmd_buff(conn_data);
				}
			} else {
				// wait for more data
				break;
			}
		} else {
			if (send_resp(conn_data, TOO_LONG_CMD_RESP) != 0) {
				close_conn(conn_data);
				break;
			} else {
				reset_cmd_buff(conn_data);
			}
		}
		buff += bytes_to_buff;
		buff_len -= bytes_to_buff;
	}
	DEBUG_PRINT("ftp - proc bytes - stop\n");
}

static void on_timeout(int fd, short ev, void *arg){
	DEBUG_PRINT("ftp - timeout\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	send_resp(conn_data, TIMEOUT_RESP);
	close_conn(conn_data);
}

static void on_recv(int fd, short ev, void *arg) {
	DEBUG_PRINT("ftp - on receive\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	ssize_t amount = recv(fd, read_buff, BUFSIZ, 0);
	switch (amount) {
		case -1:
			if (errno == EAGAIN)
				return;
			DEBUG_PRINT("ftp - error on connection %d: %s\n", fd, strerror(errno));
		case 0:
			close_conn(conn_data);
			return;
	}
	struct timeval tm = {INACT_TIMEOUT, 0};
	evtimer_add(conn_data->inac_tout_ev, &tm);
	proc_bytes(conn_data, read_buff, (size_t) amount);
}

static void on_accept(int listen_fd, short ev, void *arg) {
	DEBUG_PRINT("ftp - on accept\n");
	struct sockaddr_storage conn_addr;
	socklen_t conn_addr_len = sizeof(conn_addr);
	int conn_fd = accept(listen_fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
	if (conn_fd < 0) {
		DEBUG_PRINT("ftp - error - accept\n");
		return;
	}
	if (setnonblock(conn_fd) != 0) {
		DEBUG_PRINT("ftp - error - couldnt set nonblock\n");
		close(conn_fd);
		return;
	}
	struct conn_data *conn_data = get_conn_data(conn_fd);
	if (conn_data == NULL) {
		DEBUG_PRINT("ftp - accept - no free slots\n");
		// no free slots
		close(conn_fd);
		return;
	}
	if (sockaddr_to_string(&conn_addr, conn_data->ipaddr_str) != 0) {
		DEBUG_PRINT("ftp - sock addr to string - unknown socket family\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
		return;
	}
	if (send_resp(conn_data, WELOME_RESP) != 0) {
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
	DEBUG_PRINT("ftp - accepted connection %d\n", conn_data->fd);
}

int handle_ftp(int listen_fd, int pipe_write_fd) {
	exit_code = EXIT_SUCCESS;
	report_fd = pipe_write_fd;
	// to supress evenet base logging
	event_set_log_callback(ev_base_discard_cb);
	if (alloc_glob_res() != 0 ) {
		DEBUG_PRINT("ftp - error - couldn't allocate global resources\n");
		return EXIT_FAILURE;
	}
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, on_sigint, ev_base);
	if (sigint_ev == NULL) {
		DEBUG_PRINT("ftp - error - couldn't allocate sigint ev\n");
		exit_code = EXIT_FAILURE;
		goto sigint_ev_err;
	}
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
