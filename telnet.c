/*
 * Copyright 2018, CZ.NIC z.s.p.o. (http://www.nic.cz/)
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is part of sentinel-minipot.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <event.h>
#include <arpa/inet.h>
#include <msgpack.h>
#include <errno.h>

#include "telnet.h"
#include "utils.h"
#include "messages.h"

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

struct conn_data {
    int fd;
    enum expect expect;         // Local context - like expecting a command specifier as the next character, etc.
    enum command neg_verb;      // What was the last verb used for option negotiation
    enum position position;     // Global state
    struct event read_ev;
    struct event denial_timeout_ev;
    int attempts;
    char ipaddr_str[INET6_ADDRSTRLEN];
    char username[S_LINE_MAX + 1], password[S_LINE_MAX + 1];
    char *line_base, *line;
};

static void clear_conn_data(struct conn_data *conn) {
    memset(conn, 0, sizeof(*conn));
    conn->expect = EXPECT_NONE;
    conn->position = WANT_LOGIN;
    conn->line = conn->line_base = conn->username;
}

struct conn_data *conn_data_pool;

int report_fd;
struct event_base *ev_base;

static struct conn_data *alloc_conn_data(int connection_fd) {
    unsigned i = 0;
    // not used structs have fd set to -1, we don't need separate flags
    while (i < MAX_CONN_COUNT && conn_data_pool[i].fd != -1)
        i++;
    if (i >= MAX_CONN_COUNT) {
        DEBUG_PRINT("no free struct conn_data - connection limit reached\n");
        return NULL;
    }
    clear_conn_data(&conn_data_pool[i]);
    conn_data_pool[i].fd = connection_fd;
    return &conn_data_pool[i];
}

static void free_conn_data(struct conn_data *conn) {
    conn->fd = -1;
}

static void report_connected(const char *ipaddr_str) {
    unsigned len;
    len = 0;  // no data
    write(report_fd, &len, sizeof(len));
    len = strlen("connect");
    write(report_fd, &len, sizeof(len));
    write(report_fd, "connect", len);
    len = strlen(ipaddr_str);
    write(report_fd, &len, sizeof(len));
    write(report_fd, ipaddr_str, len);
}

static void report_login_attempt(const char *ipaddr_str, char *username, char *password) {
    unsigned len;
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 2);
    PACK_STR(&pk, "username");
    PACK_STR(&pk, username);
    PACK_STR(&pk, "password");
    PACK_STR(&pk, password);
    len = sbuf.size;
    write(report_fd, &len, sizeof(len));
    write(report_fd, sbuf.data, len);
    msgpack_sbuffer_destroy(&sbuf);
    len = strlen("connect");
    write(report_fd, &len, sizeof(len));
    write(report_fd, "connect", len);
    len = strlen(ipaddr_str);
    write(report_fd, &len, sizeof(len));
    write(report_fd, ipaddr_str, len);
}

static bool send_all(struct conn_data *conn, const char *data, size_t amount) {
    while (amount) {
        ssize_t sent = send(conn->fd, data, amount, MSG_NOSIGNAL);
        if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            return false;
        }
        data += sent;
        amount -= sent;
    }
    return true;
}

static bool ask_for_login(struct conn_data *conn) {
    const char prompt[] = "login: \xff\xf9";
    return send_all(conn, prompt, sizeof(prompt));
}

static bool ask_for_password(struct conn_data *conn) {
    const char prompt[] = "password: \xff\xf9";
    return send_all(conn, prompt, sizeof(prompt));
}

static void do_close(struct conn_data *conn) {
    if (conn->position == WAIT_DENIAL)
        event_del(&conn->denial_timeout_ev);
    event_del(&conn->read_ev);
    close(conn->fd);
    free_conn_data(conn);
}

static bool protocol_error(struct conn_data *conn, const char *message) {
    DEBUG_PRINT("Telnet protocol error %s\n", message);
    const char *msg = "Protocol error\r\n\xff\xf9";
    send_all(conn, msg, strlen(msg));
    return false;
}

static void send_denial(int fd, short event, void *data) {
    struct conn_data *conn = data;
    conn->position = WANT_LOGIN;
    conn->line = conn->line_base = conn->username;
    const char *wrong = "Login incorrect\n";
    if (!send_all(conn, wrong, strlen(wrong)))
        goto error;
    if (++conn->attempts == MAX_ATTEMPTS)
        goto error;
    if (!ask_for_login(conn))
        goto error;
    return;
error:
    do_close(conn);
}

static bool process_line(struct conn_data *conn) {
    switch (conn->position) {
        case WANT_LOGIN:
            *conn->line = '\0';
            conn->line = conn->line_base = conn->password;
            if (!ask_for_password(conn))
                return false;
            conn->position = WANT_PASSWORD;
            break;
        case WANT_PASSWORD:
            *conn->line = '\0';
            report_login_attempt(conn->ipaddr_str, conn->username, conn->password);
            conn->line = conn->line_base = NULL;
            evtimer_assign(&conn->denial_timeout_ev, ev_base, send_denial, conn);
            conn->position = WAIT_DENIAL;
            struct timeval tv;
            tv.tv_sec = DENIAL_TIMEOUT;
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
        case CMD_SE:           // Subnegotiation end - this should not be here, it should appear in EXPECT_PARAMS_END
            return protocol_error(conn, "Unexpected SE");
        case CMD_NOP:          // NOP
        case CMD_DM:           // Data Mark - not implemented and ignored
        case CMD_BREAK:        // Break - just strange character
        case CMD_AO:           // Abort output - not implemented
        case CMD_AYT:          // Are You There - not implemented
        case CMD_GA:           // Go Ahead - not interesting to us
            conn->expect = EXPECT_NONE;
            return true;
        case CMD_SB:           // Subnegotiation parameters
            conn->expect = EXPECT_PARAMS;
            return true;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
            conn->expect = EXPECT_OPCODE;
            conn->neg_verb = cmd;
            return true;
        case CMD_IP:           // Interrupt process - abort connection
            return protocol_error(conn, "Interrupted");
        case CMD_EC:           // Erase character
            if (conn->line && conn->line > conn->line_base)
                conn->line--;
            conn->expect = EXPECT_NONE;
            return true;
        case CMD_EL:           // Erase Line - ignored
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
                    uint8_t cmd = (conn->neg_verb ^ (CMD_WILL ^ CMD_DO)) + 1;   // WILL->DON'T, DO->WON'T
                    char message[3] = { CMD_IAC, cmd, ch };
                    if (!send_all(conn, message, sizeof message))
                        return false;
                }               // else - it's off, so this is OK, no reaction
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
            if (conn->line && conn->line - conn->line_base + 1 < S_LINE_MAX)
                *(conn->line++) = ch;
            break;
    }
    return true;
}

static void sockaddr_to_string(struct sockaddr_storage *connection_addr, char *str) {
    // str is assumed to be at least INET6_ADDRSTRLEN long
    struct in6_addr *v6;
    if (connection_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *connection_addr6 = (struct sockaddr_in6 *)connection_addr;
        v6 = &(connection_addr6->sin6_addr);
        if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 && v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
            // IPv4-mapped IPv6 address - ::FFFF:<IPv4-address>
            inet_ntop(AF_INET, &v6->s6_addr32[3], str, INET_ADDRSTRLEN);
        else
            inet_ntop(AF_INET6, v6, str, INET6_ADDRSTRLEN);
    } else if (connection_addr->ss_family == AF_INET) {
        struct sockaddr_in *connection_addr4 = (struct sockaddr_in *)connection_addr;
        inet_ntop(AF_INET, &connection_addr4->sin_addr, str, INET_ADDRSTRLEN);
    }
}

#define RECV_BUFFER_SIZE 1024
static void on_recv(int fd, short ev, void *arg) {
    struct conn_data *conn = (struct conn_data *)arg;
    char buffer[RECV_BUFFER_SIZE];
    ssize_t amount = recv(fd, buffer, RECV_BUFFER_SIZE, MSG_DONTWAIT);
    switch (amount) {
        case -1:               // Error
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            DEBUG_PRINT("Error on telnet connection %d: %s\n", fd, strerror(errno));
            // No break - fall through
        case 0:                // Close
            DEBUG_PRINT("Closed telnet connection %d\n", fd);
            do_close(conn);
            return;
        default:
            break;
    }
    const char *buf_ptr = buffer;
    for (ssize_t i = 0; i < amount; i++)
        if (!char_handle(conn, buf_ptr[i])) {
            do_close(conn);
            return;
        }
}

static void on_accept(int listen_fd, short ev, void *arg) {
    int connection_fd;
    struct sockaddr_storage connection_addr;
    socklen_t connection_addr_len = sizeof(connection_addr);
    connection_fd = accept(listen_fd, (struct sockaddr *)&connection_addr, &connection_addr_len);
    if (connection_fd < 0)
        return;
    if (setnonblock(connection_fd) != 0) {
        close(connection_fd);
        return;
    }
    struct conn_data *conn = alloc_conn_data(connection_fd);
    if (!conn) {
        close(connection_fd);
        return;
    }
    sockaddr_to_string(&connection_addr, conn->ipaddr_str);
    DEBUG_PRINT("Accepted telnet connection %d\n", connection_fd);
    event_assign(&conn->read_ev, ev_base, connection_fd, EV_READ | EV_PERSIST, on_recv, conn);
    event_add(&conn->read_ev, NULL);
    if (!ask_for_login(conn)) {
        do_close(conn);
        return;
    }
    report_connected(conn->ipaddr_str);
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
    event_base_loopbreak(ev_base);
}

void handle_telnet(unsigned port, int reporting_fd) {
    int listen_fd;
    int flag;
    struct sockaddr_in6 listen_addr;
    listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_ERR(listen_fd < 0, "socket");
    flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(port);
    CHECK_ERR(bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0, "bind");
    CHECK_ERR(listen(listen_fd, 5) < 0, "listen");
    conn_data_pool = malloc(sizeof(*conn_data_pool)*MAX_CONN_COUNT);
    for (unsigned i = 0; i < MAX_CONN_COUNT; i++)
        conn_data_pool[i].fd = -1;
    ev_base = event_base_new();
    report_fd = reporting_fd;
    struct event *ev_accept = event_new(ev_base, listen_fd, EV_READ | EV_PERSIST, on_accept, NULL);
    event_add(ev_accept, NULL);
    struct event *signal_event = event_new(ev_base, SIGINT, EV_SIGNAL | EV_PERSIST, sigint_handler, NULL);
    event_add(signal_event, NULL);
    event_base_dispatch(ev_base);
    free(conn_data_pool);
}
