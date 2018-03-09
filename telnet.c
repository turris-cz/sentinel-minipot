#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <event.h>
#include <arpa/inet.h>
#include <msgpack.h>

#include "telnet.h"

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
	WAIT_DENIAL
};

#define S_LINE_MAX 256

struct conn_data {
    bool used;
    int fd;
    enum expect expect; // Local context - like expecting a command specifier as the next character, etc.
    enum command neg_verb; // What was the last verb used for option negotiation
    enum position position; // Global state
    struct event read_ev;
    struct event denial_timeout_ev;
    int attempts;
    char ipaddr_str[INET6_ADDRSTRLEN];
    char username[S_LINE_MAX + 1], password[S_LINE_MAX + 1];
    char *line_base, *line;
};

int setnonblock(int fd){
    int flags;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

const size_t denial_timeout = 1;
const size_t max_attempts = 3;

#define CONN_COUNT 100

struct conn_data conn_data_pool[CONN_COUNT];

void conn_data_reset(){
    for (unsigned i=0; i<CONN_COUNT; i++) conn_data_pool[i].used=false;
}

struct conn_data * alloc_conn_data(){
    for (unsigned i=0; i<CONN_COUNT; i++) {
        if(!conn_data_pool[i].used) {
            conn_data_pool[i].used=true;
            return &conn_data_pool[i];
        }
    }
    return NULL;
}

void free_conn_data(struct conn_data * conn){
    if (!conn) return;
    conn->used=false;
}

int report_fd;

void send_string(char * str){
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_str(&pk, strlen(str));
    msgpack_pack_str_body(&pk, str, strlen(str));
    int rc = write(report_fd, sbuf.data, sbuf.size);
}

void report_connected(const char * ipaddr_str){
    char buffer[1024];
    int bytes=snprintf(buffer, sizeof(buffer), "%s connected", ipaddr_str);
    buffer[bytes]=0;
    send_string(buffer);
}

void report_login_attempt(const char * ipaddr_str, char * username, char * password){
    char buffer[1024];
    int bytes=snprintf(buffer, sizeof(buffer), "%s tried login %s:%s", ipaddr_str, username, password);
    buffer[bytes]=0;
    send_string(buffer);
}

static bool send_all(struct conn_data *conn, const uint8_t *data, size_t amount) {
	while (amount) {
		ssize_t sent = send(conn->fd, data, amount, MSG_NOSIGNAL);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
			return false;
		}
		data += sent;
		amount -= sent;
	}
	return true;
}

static bool ask_for_login(struct conn_data *conn) {
    const char *prompt="login: \xff\xf9";
	return send_all(conn, prompt, strlen(prompt));
}

static bool ask_for_password(struct conn_data *conn) {
    const char *prompt="password: \xff\xf9";
	return send_all(conn, prompt, strlen(prompt));
}

static void do_close(struct conn_data *conn) {
    if (conn->position == WAIT_DENIAL) event_del(&conn->denial_timeout_ev);
    event_del(&conn->read_ev);
    close(conn->fd);
    free_conn_data(conn);
    //free(conn);
}

static bool protocol_error(struct conn_data *conn, const char *message) {
// 	ulog(LLOG_DEBUG, "Telnet protocol error %s\n", message);
	size_t len = strlen(message);
    uint8_t *message_eol = (uint8_t *)malloc(len+4); // '\r', '\n', IAC, GA
	memcpy(message_eol, message, len);
	message_eol[len] = '\r';
	message_eol[len+1] = '\n';
	message_eol[len+2] = CMD_IAC;
	message_eol[len+3] = CMD_GA;
	send_all(conn, message_eol, len + 4);
    free(message_eol);
	return false;
}

static void send_denial(int fd, short event, void *data) {
	struct conn_data *conn = data;
	conn->position = WANT_LOGIN;
	conn->line = conn->line_base = conn->username;
	const char *wrong = "Login incorrect\n";
	if (!send_all(conn, (const uint8_t *)wrong, strlen(wrong))) {
		do_close(conn);
		return;
	}
	if (++ conn->attempts == max_attempts) {
		do_close(conn);
		return;
	}
	if (!ask_for_login(conn)) {
		do_close(conn);
		return;
	}
}

static bool process_line(struct conn_data *conn) {
	switch (conn->position) {
		case WANT_LOGIN:
			*conn->line = '\0';
			conn->line = conn->line_base = conn->password;
			if (!ask_for_password(conn)) return false;
			conn->position = WANT_PASSWORD;
			break;
		case WANT_PASSWORD:
			*conn->line = '\0';
			report_login_attempt(conn->ipaddr_str, conn->username, conn->password);
            conn->line = conn->line_base = NULL;
            evtimer_set(&conn->denial_timeout_ev, send_denial, conn);
			conn->position = WAIT_DENIAL;
            struct timeval tv;
            tv.tv_sec = denial_timeout;
            tv.tv_usec = 0;
            evtimer_add(&conn->denial_timeout_ev, &tv);
			break;
		case WAIT_DENIAL:
            break;
	}
	return true;
}

static bool cmd_handle(struct conn_data *conn, uint8_t cmd) {
	switch (cmd) {
		case CMD_SE: // Subnegotiation end - this should not be here, it should appear in EXPECT_PARAMS_END
			return protocol_error(conn, "Unexpected SE");
		case CMD_NOP: // NOP
		case CMD_DM: // Data Mark - not implemented and ignored
		case CMD_BREAK: // Break - just strange character
		case CMD_AO: // Abort output - not implemented
		case CMD_AYT: // Are You There - not implemented
		case CMD_GA: // Go Ahead - not interesting to us
			conn->expect = EXPECT_NONE;
			return true;
		case CMD_SB: // Subnegotiation parameters
			conn->expect = EXPECT_PARAMS;
			return true;
		case CMD_WILL:
		case CMD_WONT:
		case CMD_DO:
		case CMD_DONT:
			conn->expect = EXPECT_OPCODE;
			conn->neg_verb = cmd;
			return true;
		case CMD_IP: // Interrupt process - abort connection
			return protocol_error(conn, "Interrupted");
		case CMD_EC: // Erase character
			if (conn->line && conn->line > conn->line_base)
				conn->line --;
			conn->expect = EXPECT_NONE;
			return true;
		case CMD_EL: // Erase Line - ignored
			conn->line = conn->line_base;
			return true;
		default:
			return protocol_error(conn, "Unknown telnet command\n");
	}
}

static bool char_handle(struct conn_data *conn, uint8_t ch) {
	switch (conn->expect) {
		case EXPECT_NONE:
			break;
		case EXPECT_CMD:
			return cmd_handle(conn, ch);
		case EXPECT_OPCODE: {
			if (conn->neg_verb == CMD_WILL || conn->neg_verb == CMD_DO) {
				// Refuse the option
				uint8_t cmd = (conn->neg_verb ^ (CMD_WILL ^ CMD_DO)) + 1; // WILL->DON'T, DO->WON'T
				uint8_t message[3] = { CMD_IAC, cmd, ch };
				if (!send_all(conn, message, sizeof message))
					return false;
			} // else - it's off, so this is OK, no reaction
			conn->expect = EXPECT_NONE;
			return true;
		}
		case EXPECT_PARAMS:
			if (ch == CMD_IAC)
				conn->expect = EXPECT_PARAMS_END;
			return true;
		case EXPECT_PARAMS_END:
			if (ch == CMD_SE)
				conn->expect = EXPECT_NONE;
			else
				conn->expect = EXPECT_PARAMS;
			return true;
		case EXPECT_LF:
			if (ch == '\n')
				if (!process_line(conn))
					return false;
			conn->expect = EXPECT_NONE;
			return true;
		default:
// 			insane("Invalid expected state %u\n", (unsigned)conn->expect);
            break;
	}
	// We are in a normal mode, decide if we see anything special
	switch (ch) {
		case CMD_IAC:
			conn->expect = EXPECT_CMD;
			break;
		case '\r':
			conn->expect = EXPECT_LF;
			break;
		default:
			if (conn->line && conn->line - conn->line_base + 1 < LINE_MAX)
				*(conn->line ++) = ch;
			break;
	}
	return true;
}

void sockaddr_to_string(struct sockaddr_storage * connection_addr, char * str){
    //str is assumed to be at least INET6_ADDRSTRLEN long
    struct in6_addr *v6;
    if (connection_addr->ss_family == AF_INET6) {
        v6 = &(((struct sockaddr_in6 *)connection_addr)->sin6_addr);
        if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 && v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
            inet_ntop(AF_INET, &v6->s6_addr32[3], str, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, v6, str, INET6_ADDRSTRLEN);
    } else if (connection_addr->ss_family == AF_INET)
        inet_ntop(AF_INET, &(((struct sockaddr_in *)connection_addr)->sin_addr), str, INET_ADDRSTRLEN);
}

void reset_conn_data(struct conn_data * conn, int connection_fd, struct sockaddr_storage * connection_addr){
    memset(conn,0,sizeof(conn));
    conn->expect = EXPECT_NONE;
    conn->position = WANT_LOGIN;
    conn->line = conn->line_base = conn->username;
    conn->fd = connection_fd;
    conn->attempts = 0;
    sockaddr_to_string(connection_addr, conn->ipaddr_str);
}

void on_recv(int fd, short ev, void *arg) {
    struct conn_data* conn = (struct conn_data*)arg;
    const size_t block = 1024;
    char buffer[block];
    ssize_t amount = recv(fd, buffer, block, MSG_DONTWAIT);
    switch (amount) {
        case -1: // Error
            if (errno == EWOULDBLOCK || errno == EAGAIN) return;
//             ulog(LLOG_DEBUG, "Error on telnet connection %p on tag %p with fd %d: %s\n", (void *)conn, (void *)tag, conn->fd, strerror(errno));
            // No break - fall through
        case 0: // Close
//             ulog(LLOG_DEBUG, "Closed telnet connection %p/%p/%d\n", (void *)conn, (void *)tag, conn->fd);
            do_close(conn);
            return;
        default:
            break;
    }
    const uint8_t *buf_ptr = buffer;
    for (ssize_t i = 0; i < amount; i ++)
        if (!char_handle(conn, buf_ptr[i])) {
            do_close(conn);
            return;
        }
}

void on_accept(int listen_fd, short ev, void *arg){
    int connection_fd;
    struct sockaddr_storage connection_addr;
    socklen_t connection_addr_len=sizeof(connection_addr);
    connection_fd = accept(listen_fd, (struct sockaddr *)&connection_addr, &connection_addr_len);
    if (connection_fd<0) return;
    if (setnonblock(connection_fd)!=0) {
        close(connection_fd);
        return;
    }
    //struct conn_data * conn = (struct conn_data*)malloc(sizeof(struct conn_data));
    struct conn_data * conn = alloc_conn_data();
    if (!conn) {
        close(connection_fd);
        return;
    }
    reset_conn_data(conn, connection_fd, &connection_addr);
    event_set(&conn->read_ev, connection_fd, EV_READ|EV_PERSIST, on_recv, conn);
    event_add(&conn->read_ev, NULL);
    if (!ask_for_login(conn)) {
        do_close(conn);
        return;
    }
    report_connected(conn->ipaddr_str);
}

static void signal_cb(evutil_socket_t sig, short events, void *user_data){
    printf("Caught an interrupt signal.\n");
    event_loopbreak();
}

void handle_telnet(int listen_fd, int reporting_fd){
    report_fd = reporting_fd;
    conn_data_reset();
    event_init();
    struct event ev_accept;
    event_set(&ev_accept, listen_fd, EV_READ|EV_PERSIST, on_accept, NULL);
    event_add(&ev_accept, NULL);
    struct event signal_event;
    evsignal_set(&signal_event, SIGINT, signal_cb, NULL);
    event_add(&signal_event, NULL);
    event_dispatch();
}
