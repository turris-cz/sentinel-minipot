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

#include <unistd.h>
#include <signal.h>
#include <event.h>
#include <string.h>

#include "utils.h"
#include "minipot_pipe.h"
#include "char_consts.h"

#define MAX_CONN_COUNT 5
#define CONN_TIMEOUT (60 * 5)
#define INACT_TIMEOUT (60 * 3)

#define MAX_LINE_LEN 1024
#define MAX_ATTEMPTS 20

#define CONNECT_EV "connect"
#define LOGIN_EV "login"
#define TYPE "telnet"

#define LOGIN_USER "username"
#define LOGIN_PASS "password"

#define ASK_FOR_USER "login: \xff\xf9"
#define ASK_FOR_PASSW "password: \xff\xf9"
#define PROTOCOL_ERR "Protocol error\r\n\xff\xf9"
#define INCORR_LOGIN "Login incorrect\n"

enum expect {
	EXPECT_NONE,
	EXPECT_CMD,
	EXPECT_OPCODE,
	EXPECT_PARAMS,
	EXPECT_PARAMS_END,
	EXPECT_LF
};

enum command {
	CMD_SE = 240,
	CMD_NOP = 241,
	CMD_DM = 242,
	CMD_BREAK = 243,
	CMD_IP = 244,
	CMD_AO = 245,
	CMD_AYT = 246,
	CMD_EC = 247,
	CMD_EL = 248,
	CMD_GA = 249,
	CMD_SB = 250,
	CMD_WILL = 251,
	CMD_WONT = 252,
	CMD_DO = 253,
	CMD_DONT = 254,
	CMD_IAC = 255
};

enum position {
	WANT_LOGIN,
	WANT_PASSWORD,
};

struct conn_data {
	int fd;
	struct event *read_ev;
	struct event *con_tout_ev;
	struct event *inac_tout_ev;
	char *ipaddr_str;
	// Local context - like expecting a command specifier as the next character, etc.
	enum expect expect;
	// What was the last verb used for option negotiation
	enum command neg_verb;
	// Global state
	enum position position;
	size_t attempts;
	uint8_t *user;
	// here we need to store the user len
	size_t user_len;
	uint8_t *passw;
	// dont need passw len - it is same as line len
	uint8_t *line_start_ptr;
	uint8_t *line_wrt_ptr;
};

static int exit_code;
static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buff;
static struct event *accept_ev;

static void free_conn_data(struct conn_data *conn_data) {
	free(conn_data->passw);
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
	conn_data->user = malloc(sizeof(*conn_data->user) * MAX_LINE_LEN);
	if (conn_data->user == NULL)
		goto err5;
	conn_data->passw = malloc(sizeof(*conn_data->passw) * MAX_LINE_LEN);
	if (conn_data->passw == NULL)
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

static void reset_conn_data(struct conn_data *conn_data) {
	conn_data->expect = EXPECT_NONE;
	conn_data->position = WANT_LOGIN;
	conn_data->attempts = 0;
	conn_data->line_wrt_ptr = conn_data->user;
	conn_data->line_start_ptr = conn_data->user;
	conn_data->user_len = 0;
	memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
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
	DEBUG_PRINT("telnet - closed connection, fd: %d\n",conn_data->fd);
	event_del(conn_data->read_ev);
	event_del(conn_data->con_tout_ev);
	event_del(conn_data->inac_tout_ev);
	close(conn_data->fd);
	conn_data->fd = -1;
	event_add(accept_ev, NULL);
}

static void report_connect(struct conn_data *conn_data) {
	struct proxy_data data;
	data.ts = time(NULL);
	data.type = TYPE;
	data.ip = conn_data->ipaddr_str;
	data.action = CONNECT_EV;
	data.data = NULL;
	data.data_len = 0;
	if (proxy_report(report_fd, &data) !=0) {
		DEBUG_PRINT("telnet - error - couldn't report connect\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
}

static void report_login(struct conn_data *conn_data) {
	size_t passw_len;
	if (conn_data->line_start_ptr == conn_data->line_wrt_ptr)
		passw_len = 0;
	else
		passw_len = conn_data->line_wrt_ptr - conn_data->line_start_ptr;
	struct uint8_t_pair auth[] = {
		{LOGIN_USER, strlen(LOGIN_USER), conn_data->user, conn_data->user_len},
		{LOGIN_PASS, strlen(LOGIN_PASS), conn_data->passw, passw_len},
	};
	struct proxy_data data;
	data.ts = time(NULL);
	data.type = TYPE;
	data.ip = conn_data->ipaddr_str;
	data.action = LOGIN_EV;
	data.data = auth;
	data.data_len = sizeof(auth) / sizeof(*auth);
	if (proxy_report(report_fd, &data) != 0) {
		DEBUG_PRINT("telnet - error - couldn't report login\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
	}
}

static inline int send_resp(struct conn_data *conn_data, char *mesg) {
	if (send_all(conn_data->fd, mesg, strlen(mesg)) != 0) {
		DEBUG_PRINT("telnet - error - could not send to peer\n");
		return -1;
	}
	return 0;
}

static int proc_line(struct conn_data *conn_data) {
	DEBUG_PRINT("telnet - proc line\n");
	switch (conn_data->position) {
		case WANT_LOGIN:
			if (conn_data->line_start_ptr == conn_data->line_wrt_ptr)
				conn_data->user_len = 0;
			else
				conn_data->user_len = conn_data->line_wrt_ptr - conn_data->line_start_ptr;
			conn_data->line_wrt_ptr = conn_data->passw;
			conn_data->line_start_ptr = conn_data->passw;
			conn_data->position = WANT_PASSWORD;
			return send_resp(conn_data, ASK_FOR_PASSW);
		case WANT_PASSWORD:
			report_login(conn_data);
			conn_data->line_wrt_ptr = conn_data->user;
			conn_data->line_start_ptr = conn_data->user;
			conn_data->position = WANT_LOGIN;
			FLOW_GUARD(send_resp(conn_data, INCORR_LOGIN));
			conn_data->attempts++;
			if (conn_data->attempts == MAX_ATTEMPTS)
				return -1;
			else
				return send_resp(conn_data, ASK_FOR_USER);
		default:
			DEBUG_PRINT("telnet - proc line - default\n");
			return -1;
	}
}

static int cmd_handle(struct conn_data *conn_data, uint8_t cmd) {
	switch (cmd) {
		case CMD_SE:
			// Unexpected subnegotiation end
			// this should not be here, it should appear in EXPECT_PARAMS_END
			send_resp(conn_data, PROTOCOL_ERR);
			return -1;
		case CMD_NOP:
			// NOP
		case CMD_DM:
			// Data Mark - not implemented and ignored
		case CMD_BREAK:
			// Break - just strange character
		case CMD_AO:
			// Abort output - not implemented
		case CMD_AYT:
			// Are You There - not implemented
		case CMD_GA:
			// Go Ahead - not interesting to us
			conn_data->expect = EXPECT_NONE;
			return 0;
		case CMD_SB:
			// Subnegotiation parameters
			conn_data->expect = EXPECT_PARAMS;
			return 0;
		case CMD_WILL:
		case CMD_WONT:
		case CMD_DO:
		case CMD_DONT:
			conn_data->expect = EXPECT_OPCODE;
			conn_data->neg_verb = cmd;
			return 0;
		case CMD_IP:
			// Interrupt process - abort connection
			send_resp(conn_data, PROTOCOL_ERR);
			return -1;
		case CMD_EC:
			// Erase character
			if (conn_data->line_wrt_ptr > conn_data->line_start_ptr) {
				conn_data->line_wrt_ptr--;
			}
			conn_data->expect = EXPECT_NONE;
			return 0;
		case CMD_EL:
			// Erase Line - ignored
			conn_data->line_wrt_ptr = conn_data->line_start_ptr;
			return 0;
		default:
			// Unknown command
			send_resp(conn_data, PROTOCOL_ERR);
			return -1;
	}
}

static int char_handle(struct conn_data *conn_data, uint8_t ch) {
	switch (conn_data->expect) {
		case EXPECT_NONE:
			break;
		case EXPECT_CMD:
			return cmd_handle(conn_data, ch);
		case EXPECT_OPCODE: {
				if (conn_data->neg_verb == CMD_WILL || conn_data->neg_verb == CMD_DO) {
					// Refuse the option
					// WILL->DON'T, DO->WON'T
					uint8_t cmd = (conn_data->neg_verb ^ (CMD_WILL ^ CMD_DO)) + 1;
					char message[3] = {CMD_IAC, cmd, ch};
					return send_all(conn_data->fd, message, sizeof(message));
				} else {
					// it's off, so this is OK, no reaction
					conn_data->expect = EXPECT_NONE;
					return 0;
				}
			}
		case EXPECT_PARAMS:
			if (ch == CMD_IAC)
				conn_data->expect = EXPECT_PARAMS_END;
			return 0;
		case EXPECT_PARAMS_END:
			if (ch == CMD_SE)
				conn_data->expect = EXPECT_NONE;
			else
				conn_data->expect = EXPECT_PARAMS;
			return 0;
		case EXPECT_LF:
			if (ch == LF)
				FLOW_GUARD(proc_line(conn_data));
			conn_data->expect = EXPECT_NONE;
			return 0;
		default:
			break;
	}
	// We are in a normal mode, decide if we see anything special
	switch (ch) {
		case CMD_IAC:
			conn_data->expect = EXPECT_CMD;
			break;
		case CR:
			conn_data->expect = EXPECT_LF;
			break;
		default:
			if (conn_data->line_wrt_ptr - conn_data->line_start_ptr < MAX_LINE_LEN)
				*(conn_data->line_wrt_ptr++) = ch;
			break;
	}
	return 0;
}

static void on_timeout(int fd, short ev, void *arg){
	DEBUG_PRINT("telnet - timeout\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	close_conn(conn_data);
}

static void on_recv(int fd, short ev, void *arg) {
	DEBUG_PRINT("telnet - on receive\n");
	struct conn_data *conn_data = (struct conn_data *)arg;
	ssize_t amount = recv(fd, read_buff, BUFSIZ, 0);
	switch (amount) {
		case -1:
			if (errno == EAGAIN)
				return;
			DEBUG_PRINT("telnet - error on connection %d: %s\n", fd, strerror(errno));
		case 0:
			close_conn(conn_data);
			return;
	}
	struct timeval tm = {INACT_TIMEOUT, 0};
	evtimer_add(conn_data->inac_tout_ev, &tm);
	// process bytes
	for (size_t i = 0; i < (size_t) amount; i++)
		if (char_handle(conn_data, read_buff[i]) != 0) {
			close_conn(conn_data);
			return;
		}
}

static void on_accept(int listen_fd, short ev, void *arg) {
	DEBUG_PRINT("telnet - on accept\n");
	struct sockaddr_storage conn_addr;
	socklen_t conn_addr_len = sizeof(conn_addr);
	int conn_fd = accept(listen_fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
	if (conn_fd < 0) {
		DEBUG_PRINT("telnet - error - accept\n");
		return;
	}
	if (setnonblock(conn_fd) != 0) {
		DEBUG_PRINT("telnet - error - couldnt set nonblock\n");
		close(conn_fd);
		return;
	}
	struct conn_data *conn_data = get_conn_data(conn_fd);
	if (conn_data == NULL) {
		DEBUG_PRINT("telnet - accept - no free slots\n");
		// no free slots
		close(conn_fd);
		return;
	}
	if (sockaddr_to_string(&conn_addr, conn_data->ipaddr_str) != 0) {
		DEBUG_PRINT("telnet - sock addr to string - unknown socket family\n");
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
		return;
	}
	if (send_resp(conn_data, ASK_FOR_USER) != 0) {
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
	DEBUG_PRINT("telnet - accepted connection %d\n", conn_data->fd);
}

void handle_telnet(uint16_t port, int pipe_write_fd) {
	exit_code = EXIT_SUCCESS;
	report_fd = pipe_write_fd;
	int listen_fd;
	if (setup_sock(&listen_fd) != 0) {
		DEBUG_PRINT("telnet - error - couldn't setup socket\n");
		exit_code = EXIT_FAILURE;
		goto socket_err1;
	}
	if (bind_to_port(listen_fd, port) != 0) {
		DEBUG_PRINT("telnet - error - couldn't  bind to port fd: %d\n", listen_fd);
		exit_code = EXIT_FAILURE;
		goto socket_err2;
	}
	if (listen(listen_fd, 5) != 0) {
		DEBUG_PRINT("telnet - error - couldn't listen on port fd: %d\n", listen_fd);
		exit_code = EXIT_FAILURE;
		goto socket_err2;
	}
	if (alloc_glob_res() != 0 ) {
		DEBUG_PRINT("telnet - error - couldn't allocate global resources\n");
		exit_code = EXIT_FAILURE;
		goto socket_err2;
	}
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, on_sigint, ev_base);
	if (sigint_ev == NULL) {
		DEBUG_PRINT("telnet - error - couldn't allocate sigint ev\n");
		exit_code = EXIT_FAILURE;
		goto sigint_ev_err;
	}
	signal(SIGPIPE, SIG_IGN);
	// to supress evenet base logging
	event_set_log_callback(ev_base_discard_cb);
	event_assign(accept_ev, ev_base, listen_fd, EV_READ | EV_PERSIST, on_accept, NULL);
	event_add(accept_ev, NULL);
	event_add(sigint_ev, NULL);
	event_base_dispatch(ev_base);
	event_free(sigint_ev);

	sigint_ev_err:
	free_glob_res();

	socket_err2:
	close(listen_fd);

	socket_err1:
	close(report_fd);
	exit(exit_code);
}
