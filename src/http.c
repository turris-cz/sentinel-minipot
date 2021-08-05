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
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <base64c.h>

#include "utils.h"
#include "char_consts.h"
#include "minipot_pipe.h"
#include "http_header.gperf.c"
#include "http_tr_enc.gperf.c"
#include "log.h"

#define MAX_CONN_COUNT 5
#define INACT_TOUT 20
#define KEEP_ALIVE_TOUT 5
#define TOKEN_BUFF_LEN 8192
#define TOKENS_LEN (TOKEN_BUFF_LEN / 2)
#define METHOD_LEN TOKEN_BUFF_LEN
#define URL_LEN TOKEN_BUFF_LEN
#define USER_AG_LEN TOKEN_BUFF_LEN
#define AUTH_LEN TOKEN_BUFF_LEN
#define HEADER_LIMIT 100
#define MESSAGES_LIMIT 100

#define CONNECT_EV "connect"
#define MSG_EV "message"
#define LOGIN_EV "login"
#define INVALID_EV "invalid"

#define TYPE "http"

#define METHOD "method"
#define URL "url"
#define USER_AG "user_agent"
#define USERNAME "username"
#define PASSWORD "password"

#define HTTP_VERSION "HTTP/"

#define URI_TOO_LONG_PART1 "HTTP/1.1 414 Request-URI Too Long\r\nDate: "
// IMPORTANT - when changing length of the body - the Content-Length header value MUST BE changed accordingly !!!
#define URI_TOO_LONG_PART2 "\r\nServer: Apache/2.4\r\nContent-Length: 254\r\n\
Connection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>414 Request-URI Too Long</title>\n\
</head><body>\n<h1>Request-URI Too Long</h1>\n<p>The requested URL\'s length exceeds the capacity\nlimit for this server.<br />\n</p>\n<hr>\n</body></html>\n"

#define BAD_REQ_PART1 "HTTP/1.1 400 Bad Request\r\nDate: "
// IMPORTANT - when changing length of the body - the Content-Length header value MUST BE changed accordingly !!!
#define BAD_REQ_PART2 "\r\nServer: Apache/2.4\r\nContent-Length: 231\r\nConnection: close\r\n\
Content-Type: text/html; charset=iso-8859-1\r\n\r\n\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>400 Bad Request</title>\n\
</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n</p>\n<hr>\n</body></html>\n"

#define UNAUTH_REQ_PART1 "HTTP/1.1 401 Unauthorized\r\nDate: "
// IMPORTANT - when changing length of the body - the Content-Length header value MUST BE changed accordingly !!!
#define UNAUTH_REQ_PART2 "\r\nServer: Apache/2.4\r\nWWW-Authenticate: Basic realm=\"Authentication Required\"\r\n\
Content-Length: 386\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>401 Unauthorized</title>\n</head><body>\n<h1>Unauthorized</h1>\n<p>\
This server could not verify that you\nare authorized to access the document\nrequested.  Either you supplied the wrong\n\
credentials (e.g., bad password), or your\nbrowser doesn\'t understand how to supply\nthe credentials required.</p>\n<hr>\n</body></html>\n"

#define TIME_FORMAT "%a, %d %b %Y %T GMT"
#define TIME_STRING_SIZE 128  // This is arbitrary number (not that time output changed given by locale)
#define BASIC_AUTH_SCHEME "Basic"

enum state {
	PROC_REQ_LINE,
	PROC_HEADER,
	PROC_CHUNK_SIZE,
	PROC_TRAILER,
	PROC_BODY,
	PROC_CHUNK,
	PROC_CHUNK_END,
};

struct conn_data {
	int fd;
	struct event *read_ev;
	struct event *keep_alive_tout_ev;
	struct event *inac_tout_ev;
	uint8_t *ipaddr_str;
	uint8_t *token_buff;
	uint8_t *token_buff_wrt_ptr;
	size_t token_buff_free_len;
	enum state state;
	uint8_t *method;
	size_t method_len;
	uint8_t *url;
	size_t url_len;
	uint8_t *user_ag;
	size_t user_ag_len;
	uint8_t *auth;
	size_t auth_len;
	size_t header_cnt;
	size_t msg_cnt;
	int64_t con_len;
	bool trans_enc_head_received;
	struct http_transfer_encoding *trans_enc;
	int64_t chunk_size;
};

static int exit_code;
static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buff;
static struct event *accept_ev;
static struct token *tokens;
static size_t tokens_cnt;
static char *dcode_buff;
static int dcoded_data_len;
static msgpack_sbuffer *sbuff_report;
static msgpack_sbuffer *sbuff_data;

static void free_conn_data(struct conn_data *conn_data) {
	TRACE_FUNC;
	free(conn_data->ipaddr_str);
	free(conn_data->token_buff);
	free(conn_data->method);
	free(conn_data->url);
	free(conn_data->user_ag);
	free(conn_data->auth);
	event_free(conn_data->inac_tout_ev);
	event_free(conn_data->keep_alive_tout_ev);
	event_free(conn_data->read_ev);
}

static int alloc_conn_data(struct conn_data *conn_data) {
	TRACE_FUNC;
	conn_data->read_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (conn_data->read_ev == NULL)
		goto err1;
	conn_data->keep_alive_tout_ev = event_new(NULL, 0, 0, NULL, NULL);
	if (conn_data->keep_alive_tout_ev == NULL)
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
	conn_data->method = malloc(sizeof(*conn_data->method) * METHOD_LEN);
	if (conn_data->method == NULL)
		goto err6;
	conn_data->url = malloc(sizeof(*conn_data->url) * URL_LEN);
	if (conn_data->url == NULL)
		goto err7;
	conn_data->user_ag = malloc(sizeof(*conn_data->user_ag) * USER_AG_LEN);
	if (conn_data->user_ag == NULL)
		goto err8;
	conn_data->auth = malloc(sizeof(*conn_data->auth) * AUTH_LEN);
	if (conn_data->auth == NULL)
		goto err9;
	conn_data->fd = -1;
	return 0;

	err9:
	free(conn_data->user_ag);

	err8:
	free(conn_data->url);

	err7:
	free(conn_data->method);

	err6:
	free(conn_data->token_buff);

	err5:
	free(conn_data->ipaddr_str);

	err4:
	event_free(conn_data->inac_tout_ev);

	err3:
	event_free(conn_data->keep_alive_tout_ev);

	err2:
	event_free(conn_data->read_ev);

	err1:
	return -1;
}

static void free_conn_data_pool(size_t size, struct conn_data *conn_data) {
	TRACE_FUNC;
	for (size_t i = 0; i < size; i++)
		free_conn_data(&conn_data[i]);
}

static int alloc_conn_data_pool(struct conn_data **conn_data) {
	TRACE_FUNC;
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
	TRACE_FUNC;
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
	dcode_buff = malloc(sizeof(*dcode_buff) * TOKEN_BUFF_LEN);
	if (tokens == NULL)
		goto err6; 
	sbuff_report = msgpack_sbuffer_new();
	if (sbuff_report == NULL)
		goto err7;
	msgpack_sbuffer_init(sbuff_report);
	sbuff_data = msgpack_sbuffer_new();
	if (sbuff_data == NULL)
		goto err8;
	msgpack_sbuffer_init(sbuff_data);
	return 0;

	err8:
	msgpack_sbuffer_free(sbuff_report);

	err7:
	free(dcode_buff);

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
	error("Couldn't allocate global resources");
	return -1;
}

static void free_glob_res() {
	TRACE_FUNC;
	event_free(accept_ev);
	free_conn_data_pool(MAX_CONN_COUNT, conn_data_pool);
	event_base_free(ev_base);
	free(read_buff);
	free(tokens);
	free(dcode_buff);
	msgpack_sbuffer_free(sbuff_report);
	msgpack_sbuffer_free(sbuff_data);
}

static void reset_token_buff(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	conn_data->token_buff_wrt_ptr = conn_data->token_buff;
	conn_data->token_buff_free_len = TOKEN_BUFF_LEN;
}

static void reset_mesg_limits(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	conn_data->state = PROC_REQ_LINE;
	conn_data->method_len = 0;
	conn_data->url_len = 0;
	conn_data->user_ag_len = 0;
	conn_data->auth_len = 0;
	conn_data->header_cnt = 0;
	conn_data->con_len = 0;
	conn_data->trans_enc = NULL;
	conn_data->trans_enc_head_received = false;
	conn_data->chunk_size = 0;
}

static inline void reset_conn_data(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	reset_mesg_limits(conn_data);
	conn_data->msg_cnt = 0;
	memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
	reset_token_buff(conn_data);
}

static struct conn_data *get_conn_data(int fd) {
	TRACE_FUNC_FD(fd);
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
	TRACE_FUNC_FD(conn_data->fd);
	event_del(conn_data->read_ev);
	event_del(conn_data->keep_alive_tout_ev);
	event_del(conn_data->inac_tout_ev);
	info("Connection with FD: %d was closed",conn_data->fd);
	close(conn_data->fd);
	conn_data->fd = -1;
	event_add(accept_ev, NULL);
}

static inline int send_resp(struct conn_data *conn_data, char *mesg) {
	TRACE_FUNC_FD(conn_data->fd);
	if (send_all(conn_data->fd, mesg, strlen(mesg)) != 0)
		return -1;
	return 0;
}

/*
 * Allocates exact needed amount of memory and fills buffer with string time representation
 */
static void fill_time(char **buff) {
	TRACE_FUNC;
	time_t rawtime;
	time(&rawtime);
	struct tm *timeinfo = gmtime(&rawtime);
	char *time_str = malloc(TIME_STRING_SIZE);
	strftime(time_str, TIME_STRING_SIZE, TIME_FORMAT, timeinfo);
	*buff = time_str;
}

static int send_bad_req(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	char *time_str;
	fill_time(&time_str);
	char *mesg;
	concat_str(&mesg, 3, BAD_REQ_PART1, time_str, BAD_REQ_PART2);
	int ret = send_resp(conn_data, mesg);
	free(time_str);
	free(mesg);
	return ret;
}

static int send_uri_too_long(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	char *time_str;
	fill_time(&time_str);
	char *mesg;
	concat_str(&mesg, 3, URI_TOO_LONG_PART1, time_str, URI_TOO_LONG_PART2);
	int ret = send_resp(conn_data, mesg);
	free(time_str);
	free(mesg);
	return ret;
}

static int send_unauth(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	char *time_str;
	fill_time(&time_str);
	char *mesg;
	concat_str(&mesg, 3, UNAUTH_REQ_PART1, time_str, UNAUTH_REQ_PART2);
	int ret = send_resp(conn_data, mesg);
	free(time_str);
	free(mesg);
	return ret;
}

#define FLOW_GUARD_WITH_RESP(cmd, conn_data) do { \
		if (cmd) { \
			send_bad_req(conn_data); \
			return -1; \
		} \
	} while (0)

static void report(struct sentinel_msg *sentinel_msg) {
	TRACE_FUNC;
	msgpack_sbuffer_clear(sbuff_data);
	msgpack_sbuffer_clear(sbuff_report);
	if (pack_sentinel_msg(sbuff_report, sbuff_data, sentinel_msg))
		goto err;
	if (!send_to_master(report_fd, sbuff_report->data, sbuff_report->size))
		return;
err:
	exit_code = EXIT_FAILURE;
	event_base_loopbreak(ev_base);
};

static void report_connect(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	struct sentinel_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = CONNECT_EV,
		.data = NULL,
		.data_len = 0,
	};
	report(&msg);
}

static void report_invalid(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	struct sentinel_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = INVALID_EV,
		.data = NULL,
		.data_len = 0,
	};
	report(&msg);
}

static void report_message(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	if (check_serv_data(conn_data->url, conn_data->url_len) ||
		check_serv_data(conn_data->user_ag, conn_data->user_ag_len)) {
		report_invalid(conn_data);
		return;
	}
	struct uint8_t_pair data[] = {
		{METHOD, strlen(METHOD), conn_data->method, conn_data->method_len},
		{URL, strlen(URL), conn_data->url, conn_data->url_len},
		// MUST BE THE LAST ONE - IT IS OPTIONAL !!!
		{USER_AG, strlen(USER_AG), conn_data->user_ag, conn_data->user_ag_len},
	};
	struct sentinel_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = MSG_EV,
		.data = data,
	};
	// method, url + optional user
	msg.data_len = conn_data->user_ag_len == 0 ? 2 : 3;
	report(&msg);
}

static void report_login(struct conn_data *conn_data, char *username, size_t username_len,
							char *password, size_t password_len) {
	TRACE_FUNC_FD(conn_data->fd);
	if (username_len == 0 ||
		check_serv_data(username, username_len) ||
		check_serv_data(password, password_len) ||
		check_serv_data(conn_data->url, conn_data->url_len) ||
		check_serv_data(conn_data->user_ag, conn_data->user_ag_len)) {
		report_invalid(conn_data);
		return;
	}
	struct uint8_t_pair data[] = {
		{METHOD, strlen(METHOD), conn_data->method, conn_data->method_len},
		{URL, strlen(URL), conn_data->url, conn_data->url_len},
		{USERNAME, strlen(USERNAME), username, username_len},
		{PASSWORD, strlen(PASSWORD), password, password_len},
		// MUST BE THE LAST ONE - IT IS OPTIONAL !!!
		{USER_AG, strlen(USER_AG), conn_data->user_ag, conn_data->user_ag_len},
	};
	struct sentinel_msg msg = {
		.ts = time(NULL),
		.type = TYPE,
		.ip = conn_data->ipaddr_str,
		.action = LOGIN_EV,
		.data = data,
	};
	// method, url, username, password + optional user agent
	msg.data_len = conn_data->user_ag_len == 0 ? 4 : 5;
	report(&msg);
}

/*
Return length of the trailing white spaces in the end of the string.
Returns at most len.
*/
size_t get_trail_ws_len(uint8_t *str, size_t len) {
	TRACE_FUNC;
	size_t ws_len = 0;
	for (size_t i = 0; i < len; i++)
		if (str[len - i - 1] != SP && str[len - i - 1] != HT)
			break;
		else
			ws_len++;
	return ws_len;
}

/*
Return length of the preceding whitespaces at the beginning of string.
Returns at most len.
*/
size_t get_prec_ws_len(uint8_t *str, size_t len) {
	TRACE_FUNC;
	size_t ws_len = 0;
	for (size_t i = 0; i < len; i++)
		if (str[i] != SP && str[i] != HT)
			break;
		else
			ws_len++;
	return ws_len;
}

static inline void skip_bytes(int64_t *to_skip, uint8_t **buff, size_t *bytes_to_proc) {
	TRACE_FUNC;
	size_t diff = MY_MIN(*to_skip, *bytes_to_proc);
	*bytes_to_proc -= diff;
	*to_skip -= diff;
	*buff += diff;
}

static void proc_auth_data(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	uint8_t sep[] = {HT, SP};
	tokens_cnt = tokenize(conn_data->auth, conn_data->auth_len, tokens, TOKENS_LEN, sep, sizeof(sep) / sizeof(*sep));
	if (tokens_cnt != 2 ||
		strlen(BASIC_AUTH_SCHEME) != tokens[0].len ||
		strncmp(BASIC_AUTH_SCHEME, tokens[0].start_ptr, strlen(BASIC_AUTH_SCHEME)) ||
		base64_verify(tokens[1].start_ptr, tokens[1].len))
		// wrong scheme or data
		goto err;

	dcoded_data_len = base64_decode(tokens[1].start_ptr, tokens[1].len, dcode_buff);
	char *delim = memchr(dcode_buff, DOUBLE_DOT, dcoded_data_len);
	if (delim == NULL)
		// wrong format of decoded data
		goto err;

	char *username = dcode_buff;
	size_t username_len = delim - dcode_buff;
	char *password = delim + 1;
	size_t password_len = dcoded_data_len - username_len - 1;
	report_login(conn_data, username, username_len, password, password_len);
	return;

	err:
	report_invalid(conn_data);
}

static int on_mesg_end(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	if (conn_data->auth_len > 0)
		proc_auth_data(conn_data);
	else
		report_message(conn_data);
	reset_mesg_limits(conn_data);
	FLOW_GUARD(send_unauth(conn_data));
	conn_data->msg_cnt++;
	FLOW_GUARD(conn_data->msg_cnt == MESSAGES_LIMIT);
	return 0;
}

static int proc_chunk(struct conn_data *conn_data, uint8_t **buffer, size_t *bytes_to_proc) {
	TRACE_FUNC_FD(conn_data->fd);
	skip_bytes(&conn_data->chunk_size, buffer, bytes_to_proc);
	if (conn_data->chunk_size == 0)
		conn_data->state = PROC_CHUNK_END;
	return 0;
}

static int proc_body(struct conn_data *conn_data, uint8_t **buffer, size_t *bytes_to_proc) {
	TRACE_FUNC_FD(conn_data->fd);
	skip_bytes(&conn_data->con_len, buffer, bytes_to_proc);
	if (conn_data->con_len == 0)
		return on_mesg_end(conn_data);
	return 0;
}

static int proc_chunk_end(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
	// must be empty line
	FLOW_GUARD_WITH_RESP(token_len != 0, conn_data);
	conn_data->state = PROC_CHUNK_SIZE;
	return 0;
}

static int check_method(uint8_t *method, size_t len) {
	TRACE_FUNC;
	for (size_t i = 0; i < len; i++)
		if (method[i] <= 32 || method[i] >= 127 )
			return -1;
	return 0;
}

static int check_url(uint8_t *url, size_t len) {
	TRACE_FUNC;
	for (size_t i = 0; i < len; i++)
		if (url[i] <= 32 || url[i] == 127 )
			return -1;
	return 0;
}

static int check_version(uint8_t *version, size_t len) {
	TRACE_FUNC;
	if (len != 8 ||
		strncmp(version, HTTP_VERSION, strlen(HTTP_VERSION)) != 0 ||
		version[5] < '0' || version[5] > '9' ||
		version[6] != '.' ||
		version[7] < '0' || version[7] > '9' )
		return -1;
	return 0;
}

static int proc_req_line(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
	uint8_t *first_sp = memchr(conn_data->token_buff, SP, token_len);
	FLOW_GUARD_WITH_RESP(first_sp == NULL, conn_data);
	size_t rest_len = token_len - (first_sp - conn_data->token_buff) - 1;
	uint8_t *second_sp = memchr(first_sp + 1, SP, rest_len);
	FLOW_GUARD_WITH_RESP(second_sp == NULL, conn_data);
	FLOW_GUARD_WITH_RESP((first_sp + 1) == second_sp, conn_data);
	uint8_t *method_ptr = conn_data->token_buff;
	size_t method_len =  first_sp - conn_data->token_buff;
	uint8_t *url_ptr = first_sp + 1;
	size_t url_len = second_sp - url_ptr;
	uint8_t *version_ptr = second_sp + 1;
	size_t version_len = token_len - (second_sp - conn_data->token_buff) - 1;
	FLOW_GUARD_WITH_RESP(check_version(version_ptr, version_len), conn_data);
	FLOW_GUARD_WITH_RESP(check_method(method_ptr, method_len), conn_data);
	FLOW_GUARD_WITH_RESP(check_url(url_ptr, url_len), conn_data);
	memcpy(conn_data->method, method_ptr, method_len);
	conn_data->method_len = method_len;
	memcpy(conn_data->url, url_ptr, url_len);
	conn_data->url_len = url_len;
	conn_data->state = PROC_HEADER;
	return 0;
}

static int check_header_name(uint8_t *name, size_t len) {
	TRACE_FUNC;
	for (size_t i = 0; i < len; i++)
		if (name[i] <= 32 || name[i] >= 127 || name[i] == 34 || name[i] == 40 ||
			name[i] == 41 || name[i] == 44 || name[i] == 47 ||
			(name[i] >= 58 && name[i] <= 64) || (name[i] >= 91 && name[i] <= 93) ||
			name[i] == 123 || name[i] == 125)
			return -1;
	return 0;
}

static int check_header_val(uint8_t *val, size_t len) {
	TRACE_FUNC;
	for (size_t i = 0; i < len; i++)
		if ((val[i] <= 8) || (val[i] >= 10 && val[i] <= 31) || val[i] == 127)
			return -1;
	return 0;
}

static int proc_con_len_head(struct conn_data *conn_data, uint8_t *val, size_t len) {
	TRACE_FUNC_FD(conn_data->fd);
	if (conn_data->con_len > 0)
		// the value has been already assigned - error
		conn_data->con_len = -1;
	if (conn_data->con_len == 0) {
		uint8_t sep[] = {HT, SP};
		tokens_cnt = tokenize(val, len, tokens, TOKENS_LEN, sep, sizeof(sep) / sizeof(*sep));
		FLOW_GUARD_WITH_RESP(tokens_cnt != 1, conn_data);
		// we have to create c-string for strtoll
		// in this stage it is safe
		*((uint8_t*)(tokens[0].start_ptr) + tokens[0].len) = 0 ;
		char *end_ptr;
		errno = 0;
		int64_t result = strtoll(tokens[0].start_ptr, &end_ptr, 10);
		if (errno != 0 || //conversion error
			end_ptr == (char *)tokens[0].start_ptr || // no digits
			result < 0) // negative value
			conn_data->con_len = -1;
		else
			conn_data->con_len = result;
	}
	return 0;
}

static int proc_trans_enc_head(struct conn_data *conn_data, uint8_t *val, size_t len) {
	TRACE_FUNC_FD(conn_data->fd);
	conn_data->trans_enc_head_received = true;
	uint8_t sep[] = {HT, SP, COMMA};
	tokens_cnt = tokenize(val, len, tokens, TOKENS_LEN, sep, sizeof(sep) / sizeof(*sep));
	for (size_t i = 0; i < tokens_cnt; i++)
		conn_data->trans_enc = http_transfer_encoding_lookup(tokens[i].start_ptr, tokens[i].len);
	return 0;
}

static int proc_auth_head(struct conn_data *conn_data, uint8_t *val, size_t len) {
	TRACE_FUNC_FD(conn_data->fd);
	uint8_t *val_start_ptr = val;
	size_t val_len = len;
	size_t prec_ws_len = get_prec_ws_len(val_start_ptr, val_len);
	val_start_ptr += prec_ws_len;
	val_len -= prec_ws_len;
	val_len -= get_trail_ws_len(val_start_ptr, val_len);
	memcpy(conn_data->auth, val_start_ptr, val_len);
	conn_data->auth_len = val_len;
	return 0;
}

static int proc_user_ag_head(struct conn_data *conn_data, uint8_t *val, size_t len) {
	TRACE_FUNC_FD(conn_data->fd);
	uint8_t *val_start_ptr = val;
	size_t val_len = len;
	size_t prec_ws_len = get_prec_ws_len(val_start_ptr, val_len);
	val_start_ptr += prec_ws_len;
	val_len -= prec_ws_len;
	val_len -= get_trail_ws_len(val_start_ptr, val_len);
	memcpy(conn_data->user_ag, val_start_ptr, val_len);
	conn_data->user_ag_len = val_len;
	return 0;
}

static int proc_header(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
	if (token_len == 0) {
		// empty line
		if (conn_data->trans_enc_head_received == true) {
			if (conn_data->trans_enc != NULL &&
				conn_data->trans_enc->transfer_encoding_type == CHUNKED) {
				// chunked body
				conn_data->state = PROC_CHUNK_SIZE;
				return 0;
			} else {
				// error
				send_bad_req(conn_data);
				return -1;
			}
		} else {
			if (conn_data->con_len == -1) {
				// error
				send_bad_req(conn_data);
				return -1;
			} else if (conn_data->con_len == 0) {
				// no body - end of the message here
				return on_mesg_end(conn_data);
			} else {
				// normal body
				conn_data->state = PROC_BODY;
				return 0;
			}
		}
	} else {
		conn_data->header_cnt++;
		FLOW_GUARD_WITH_RESP(conn_data->header_cnt == HEADER_LIMIT, conn_data);
		uint8_t *double_dot = memchr(conn_data->token_buff, DOUBLE_DOT, token_len);
		FLOW_GUARD_WITH_RESP(double_dot == NULL, conn_data);
		uint8_t *header_name_str = conn_data->token_buff;
		size_t header_name_str_len = double_dot - conn_data->token_buff;
		uint8_t *header_val_str = double_dot + 1;
		size_t header_val_str_len = token_len - (double_dot - conn_data->token_buff) - 1;
		FLOW_GUARD_WITH_RESP(check_header_name(header_name_str, header_name_str_len), conn_data);
		FLOW_GUARD_WITH_RESP(check_header_val(header_val_str, header_val_str_len), conn_data);
		struct http_header *header = http_header_name_lookup(header_name_str, header_name_str_len);
		if (header != NULL) {
			// known header
			switch (header->header_type) {
				case AUTHORIZATION:
					return proc_auth_head(conn_data, header_val_str, header_val_str_len);
				case USER_AGENT:
					return proc_user_ag_head(conn_data, header_val_str, header_val_str_len);
				case CONTENT_LENGTH:
					return proc_con_len_head(conn_data, header_val_str, header_val_str_len);
				case TRANSFER_ENCODING:
					return proc_trans_enc_head(conn_data, header_val_str, header_val_str_len);
				default:
					error("Invalid header name on connection with FD: %d",
						conn_data->fd);
					return -1;
			}
		}
		return 0;
	}
}

static int check_chunk_size_ext(uint8_t *ext,  size_t len) {
	TRACE_FUNC;
	for (size_t i = 0; i < len; i++)
		if (ext[i] < 32 || ext[i] >= 127 )
			return -1;
	return 0;
}

static int proc_chunk_size(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
	FLOW_GUARD_WITH_RESP(token_len == 0, conn_data);
	size_t chunk_size_str_len = token_len;
	uint8_t *semicolon = memchr(conn_data->token_buff, SEMICOLON, token_len);
	if (semicolon != NULL) {
		chunk_size_str_len = semicolon - conn_data->token_buff + 1;
		FLOW_GUARD_WITH_RESP(check_chunk_size_ext(semicolon + 1, token_len - chunk_size_str_len), conn_data);
	}
	// parse chunk size
	// we have to create c-string for strtoll
	// in this stage it is safe
	conn_data->token_buff[chunk_size_str_len] = 0;
	char *end_ptr;
	errno = 0;
	int64_t result = strtoll(conn_data->token_buff, &end_ptr, 16);
	FLOW_GUARD_WITH_RESP((errno != 0 || // conversion error
		end_ptr == (char *)conn_data->token_buff || // no digits
		result < 0), // negative value
		conn_data);
	conn_data->chunk_size = result;
	if (result == 0)
		conn_data->state = PROC_TRAILER;
	else
		conn_data->state = PROC_CHUNK;
	return 0;
}

static int proc_trailer(struct conn_data *conn_data) {
	TRACE_FUNC_FD(conn_data->fd);
	size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
	if (token_len == 0) {
		// end of message
		return on_mesg_end(conn_data);
	} else {
		// some trailer = header
		// here should not be headers we are interested in
		// treat them as unknown headers
		conn_data->header_cnt++;
		FLOW_GUARD_WITH_RESP(conn_data->header_cnt == HEADER_LIMIT, conn_data);
		uint8_t *double_dot = memchr(conn_data->token_buff, DOUBLE_DOT, token_len);
		FLOW_GUARD_WITH_RESP(double_dot == NULL, conn_data);
		uint8_t *header_name_str = conn_data->token_buff;
		size_t header_name_str_len = double_dot - conn_data->token_buff;
		uint8_t *header_val_str = double_dot + 1;
		size_t header_val_str_len = token_len - (double_dot - conn_data->token_buff) - 1;
		FLOW_GUARD_WITH_RESP(check_header_name(header_name_str, header_name_str_len), conn_data);
		FLOW_GUARD_WITH_RESP(check_header_val(header_val_str, header_val_str_len), conn_data);
		return 0;
	}
}

static int proc_line(struct conn_data *conn_data, uint8_t **buffer, size_t *bytes_to_proc) {
	TRACE_FUNC_FD(conn_data->fd);
	uint8_t *line_sep = memchr(*buffer, LF, *bytes_to_proc);
	size_t bytes_to_buff = line_sep != NULL ? (line_sep - *buffer + 1) : *bytes_to_proc;
	if (bytes_to_buff <= conn_data->token_buff_free_len) {
		memcpy(conn_data->token_buff_wrt_ptr, *buffer, bytes_to_buff);
		conn_data->token_buff_wrt_ptr += bytes_to_buff;
		conn_data->token_buff_free_len -= bytes_to_buff;
		if (line_sep != NULL) {
			// we found LF, check for CR
			size_t token_len = TOKEN_BUFF_LEN - conn_data->token_buff_free_len;
			FLOW_GUARD_WITH_RESP(((token_len < 2) || (conn_data->token_buff[token_len - 2] != CR)), conn_data);
			// strip CRLF from line buffer
			conn_data->token_buff_free_len += 2;
			switch (conn_data->state) {
				case PROC_REQ_LINE:
					FLOW_GUARD(proc_req_line(conn_data));
					break;
				case PROC_HEADER:
					FLOW_GUARD(proc_header(conn_data));
					break;
				case PROC_CHUNK_SIZE:
					FLOW_GUARD(proc_chunk_size(conn_data));
					break;
				case PROC_TRAILER:
					FLOW_GUARD(proc_trailer(conn_data));
					break;
				case PROC_CHUNK_END:
					FLOW_GUARD(proc_chunk_end(conn_data));
					break;
				default:
					error("Invalid state on connection with FD: %d", conn_data->fd);
					return -1;
			}
			reset_token_buff(conn_data);
		}
	} else {
		switch (conn_data->state) {
			case PROC_REQ_LINE:
				send_uri_too_long(conn_data);
				break;
			case PROC_HEADER:
			case PROC_CHUNK_SIZE:
			case PROC_TRAILER:
			case PROC_CHUNK_END:
				send_bad_req(conn_data);
				break;
			default:
				error("Invalid state on connection with FD: %d", conn_data->fd);
				break;
		}
		return -1;
	}
	*buffer += bytes_to_buff;
	*bytes_to_proc -= bytes_to_buff;
	return 0;
}

static void proc_bytes(struct conn_data *conn_data, uint8_t *buff, size_t buff_len) {
	TRACE_FUNC_P("FD: %d - start", conn_data->fd);
	bool run = true;
	while (buff_len > 0 && run) {
		switch (conn_data->state) {
			case PROC_REQ_LINE:
			case PROC_HEADER:
			case PROC_CHUNK_SIZE:
			case PROC_TRAILER:
			case PROC_CHUNK_END:
				if (proc_line(conn_data, &buff, &buff_len) != 0) {
					close_conn(conn_data);
					run = false;
				}
				break;
			case PROC_BODY:
				if (proc_body(conn_data, &buff, &buff_len) != 0) {
					close_conn(conn_data);
					run = false;
				}
				break;
			case PROC_CHUNK:
				if (proc_chunk(conn_data, &buff, &buff_len) != 0) {
					close_conn(conn_data);
					run = false;
				}
				break;
			default:
				error("Invalid state on connection with FD: %d", conn_data->fd);
				close_conn(conn_data);
				run = false;
				break;
		}
	}
	TRACE_FUNC_P("FD: %d - stop", conn_data->fd);
}

static void on_timeout(int fd, short ev, void *arg){
	TRACE_FUNC_FD(fd);
	struct conn_data *conn_data = (struct conn_data *)arg;
	close_conn(conn_data);
}

static void on_recv(int fd, short ev, void *arg) {
	TRACE_FUNC_FD(fd);
	struct conn_data *conn_data = (struct conn_data *)arg;
	ssize_t amount = recv(fd, read_buff, BUFSIZ, 0);
	switch (amount) {
		case -1:
			if (errno == EAGAIN)
				return;
			info("Receive error on connection with FD: %d", fd);
		case 0:
			close_conn(conn_data);
			return;
	}
	event_del(conn_data->inac_tout_ev);
	// reset keep alive timer
	struct timeval tm = {KEEP_ALIVE_TOUT, 0};
	evtimer_add(conn_data->keep_alive_tout_ev, &tm);
	proc_bytes(conn_data, read_buff, (size_t) amount);
}

static void on_accept(int listen_fd, short ev, void *arg) {
	TRACE_FUNC;
	struct sockaddr_storage conn_addr;
	socklen_t conn_addr_len = sizeof(conn_addr);
	int conn_fd = accept(listen_fd, (struct sockaddr *)&conn_addr, &conn_addr_len);
	if (conn_fd < 0) {
		info("No free conn_data slots. Refusing connection");
		return;
	}
	if (setnonblock(conn_fd) != 0) {
		close(conn_fd);
		return;
	}
	struct conn_data *conn_data = get_conn_data(conn_fd);
	if (conn_data == NULL) {
		info("No free conn_data slots. Closing connection with FD :%d", conn_fd);
		close(conn_fd);
		return;
	}
	if (sockaddr2str(&conn_addr, conn_data->ipaddr_str) != 0) {
		exit_code = EXIT_FAILURE;
		event_base_loopbreak(ev_base);
		return;
	}
	event_assign(conn_data->read_ev, ev_base, conn_data->fd, EV_READ | EV_PERSIST, on_recv, conn_data);
	event_add(conn_data->read_ev, NULL);
	evtimer_assign(conn_data->inac_tout_ev, ev_base, on_timeout, conn_data);
	struct timeval tm = {INACT_TOUT, 0};
	evtimer_add(conn_data->inac_tout_ev, &tm);
	evtimer_assign(conn_data->keep_alive_tout_ev, ev_base, on_timeout, conn_data);
	report_connect(conn_data);
	info("Accepted connection with FD: %d", conn_data->fd);
}

int handle_http(int listen_fd, int pipe_write_fd) {
	TRACE_FUNC;
	exit_code = EXIT_SUCCESS;
	report_fd = pipe_write_fd;
	// to supress event base logging
	event_set_log_callback(ev_base_discard_cb);
	if (alloc_glob_res() != 0 )
		return EXIT_FAILURE;
	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, on_sigint, ev_base);
	if (sigint_ev == NULL) {
		error("Couldn't create sigint event");
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
