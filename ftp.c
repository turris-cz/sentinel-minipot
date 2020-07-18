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

#include <event.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "ftp.h"
#include "utils.h"
#include "ftp_commands.gperf.c"

enum syntax_state {
    RESET_CMD_BUFF,
    BUFFER_CMD,
    CHECK_CMD_END,
    PROCESS_CMD,
    SYNTAX_ERROR,
};

enum semantics_state {
    INIT,
    EXPECT_PASS,
};

struct conn_data {
    int fd;
    struct event *read_ev;
    struct event *timeout_ev;
    uint8_t *ipaddr_str;
    uint8_t *token_buffer;
    uint8_t *token_write_ptr;
    size_t token_buffer_free_space;
    int try_count;
    int try_limit;
    enum syntax_state syntax_state;
    bool syntax_run;
    enum semantics_state semantics_state;
    struct ftp_command *command;
    uint8_t *user;
    uint8_t *password;
};

static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buffer;
static struct timeval *conn_timeout;

static inline void report_login(struct conn_data *conn_data) {
    struct strpair data[] = {
        {"user", conn_data->user},
        {"password", conn_data->password},
    };
    if (!proxy_report(report_fd, data, sizeof(data) / sizeof(*data), "login", conn_data->ipaddr_str))
        DEBUG_PRINT("ftp error - could not report login\n");
}

static inline void report_connect(struct conn_data *conn_data) {
    if (!proxy_report(report_fd, NULL, 0, "connect", conn_data->ipaddr_str))
        DEBUG_PRINT("ftp error - could not report syntax error\n");
}

static inline void send_response(struct conn_data *conn_data, uint8_t *response) {
    if (!send_all(conn_data->fd, response, strlen(response)))
        DEBUG_PRINT("ftp error - could not send response\n");
}

static inline void clear_token_buffer(struct conn_data *conn_data) {
    memset(conn_data->token_buffer, 0, sizeof(*conn_data->token_buffer) * FTP_TOKEN_BUFFER_LEN);
    conn_data->token_write_ptr = conn_data->token_buffer;
    // leave space for terminating byte
    conn_data->token_buffer_free_space = FTP_TOKEN_BUFFER_LEN - 1;
}

static inline void clear_user(struct conn_data *conn_data) {
    memset(conn_data->user, 0, sizeof(*conn_data->user) * FTP_USER_LEN);
}

static inline void clear_password(struct conn_data *conn_data) {
    memset(conn_data->password, 0, sizeof(*conn_data->password) * FTP_PASSWORD_LEN);
}

static inline void clear_ip_addr(struct conn_data *conn_data) {
    memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
}

static inline void reset_conn_data(struct conn_data *conn_data) {
    conn_data->syntax_run = false;
    conn_data->syntax_state = RESET_CMD_BUFF;
    conn_data->semantics_state = INIT;
    conn_data->command = NULL;
    conn_data->try_count = 0;
}

static struct conn_data *get_conn_data(int connection_fd) {
    unsigned i = 0;
    // not used structs have fd set to -1, we don't need separate flags
    while (i < FTP_MAX_CONN_COUNT && conn_data_pool[i].fd != -1)
        i++;
    if (i >= FTP_MAX_CONN_COUNT) {
        DEBUG_PRINT("ftp - no free struct conn_data - connection limit reached\n");
        return NULL;
    }
    reset_conn_data(&conn_data_pool[i]);
    conn_data_pool[i].fd = connection_fd;
    conn_data_pool[i].try_limit = range_rand(FTP_CRED_MIN_RANGE, FTP_CRED_MAX_RANGE);
    return &conn_data_pool[i];
}

static void do_close(struct conn_data *conn_data) {
    DEBUG_PRINT("ftp - close, fd: %d\n",conn_data->fd);
    event_del(conn_data->read_ev);
    event_del(conn_data->timeout_ev);
    close(conn_data->fd);
    conn_data->fd = -1;
}

static void reset_cmd_buff(struct conn_data *conn_data) {
    clear_token_buffer(conn_data);
    conn_data->syntax_run = true;
    conn_data->syntax_state = BUFFER_CMD;
}

static void buffer_cmd(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    size_t chr_cnt_to_delim = *size_to_proc;
    uint8_t *token_end_ptr = strchr(*buffer, '\x0D');
    if (token_end_ptr)
        chr_cnt_to_delim = (size_t) (token_end_ptr - *buffer);
    if (conn_data->token_buffer_free_space >= chr_cnt_to_delim) {
        // copy to token buffer
        memcpy(conn_data->token_write_ptr, *buffer, chr_cnt_to_delim);
        conn_data->token_buffer_free_space -= chr_cnt_to_delim;
        conn_data->token_write_ptr += chr_cnt_to_delim;
        // shift read buffer
        *buffer += chr_cnt_to_delim;
        *size_to_proc -= chr_cnt_to_delim;
        if (token_end_ptr) {
            // we can go to another state
            conn_data->syntax_state = CHECK_CMD_END;
            // just skip CR byte
            *buffer += 1;
            *size_to_proc -=1;
        } else {
            // if token end was not found we just wait for next read 
            conn_data->syntax_run = false;
        }
    } else {
        // no space in token buffer for cmd
        // char limit reached
        conn_data->syntax_run = false;
        send_response(conn_data, FTP_421_RESP);
        do_close(conn_data);
    }
}

static void check_cmd_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    if (*size_to_proc == 0) {
        // if no bytes in buffer pause and stay in current state
        conn_data->syntax_run = false;
    } else {
        // check if first byte in buffer is LF
        if (**buffer == LF) {
            conn_data->syntax_state = PROCESS_CMD;
            // shift behind LF
            (*buffer)++;
            (*size_to_proc)--;
        } else {
            conn_data->syntax_state = SYNTAX_ERROR;
        }
    }
}

static void on_unrecognized_cmd(struct conn_data *conn_data) {
    conn_data->semantics_state = INIT;
    send_response(conn_data, FTP_500_RESP);
} 

static void on_user_cmd(struct conn_data *conn_data, uint8_t *params) {
    // must have parameter
    if (!params) {
        conn_data->semantics_state = INIT;
        send_response(conn_data, FTP_501_RESP);
    } else {
        if (conn_data->semantics_state == INIT)
            conn_data->semantics_state = EXPECT_PASS;
        clear_user(conn_data);
        copy_util(params, strlen(params), conn_data->user, FTP_USER_LEN - 1);
        send_response(conn_data, FTP_331_RESP);
    }
}

static void on_pass_cmd(struct conn_data *conn_data, uint8_t *params) {
    // must have parameter
    if (!params) {
        conn_data->semantics_state = INIT;
        send_response(conn_data, FTP_501_RESP);
    } else {
        if (conn_data->semantics_state == INIT) {
            send_response(conn_data, FTP_503_RESP);
        } else if (conn_data->semantics_state == EXPECT_PASS) {
            clear_password(conn_data);
            copy_util(params, strlen(params), conn_data->password, FTP_PASSWORD_LEN - 1);
            conn_data->try_count++;
            if (conn_data->try_count == conn_data->try_limit) {
                send_response(conn_data, FTP_421_RESP);
                report_login(conn_data);
                do_close(conn_data);
            } else {
                conn_data->semantics_state = INIT;
                send_response(conn_data, FTP_530_RESP);
                report_login(conn_data);
            }
        } else {
            DEBUG_PRINT("ftp - on pass cmd - unknown state\n");
        }
    }
}

static void on_rein_cmd(struct conn_data *conn_data,uint8_t *params) {
    // must have no parameters
    conn_data->semantics_state = INIT;
    if (params)
        send_response(conn_data, FTP_501_RESP);
    else
        send_response(conn_data, FTP_220_REIN_RESP);
}

static void on_quit_cmd(struct conn_data *conn_data, uint8_t *params) {    
    // must have no parameterss
    // also goes to INIT state but it has no meaning because we are going to close the connection
    if (params) {
        send_response(conn_data, FTP_501_RESP);
    } else {
        send_response(conn_data, FTP_221_RESP);
        do_close(conn_data);
    }
}

static void on_help_cmd(struct conn_data *conn_data, uint8_t *params) {
    conn_data->semantics_state = INIT;
    send_response(conn_data, FTP_530_RESP);
}

static void on_feat_cmd(struct conn_data *conn_data, uint8_t *params) {
    // must have no parameters
    conn_data->semantics_state = INIT;
    if (params)
        send_response(conn_data, FTP_501_RESP);
    else
        send_response(conn_data, FTP_211_FEAT_RESP);
}

static void on_noop_cmd(struct conn_data *conn_data, uint8_t *params) {
    // no params
    conn_data->semantics_state = INIT;
    if (params)
        send_response(conn_data, FTP_501_RESP);
    else
        send_response(conn_data, FTP_200_RESP);
}

static void on_unused_cmd(struct conn_data *conn_data, uint8_t *params) {
    conn_data->semantics_state = INIT;
    send_response(conn_data, FTP_530_RESP);
}

static void proc_cmd(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    uint8_t *token = conn_data->token_buffer;
    // find SP if any - delimeter of comand and parameters
    uint8_t *delim = strchr(token, '\x20');
    uint8_t *params_ptr = NULL;
    if (delim) {
        // terminate command code from its parameters
        *delim = 0;
        delim++;
        params_ptr = delim;
    }
    conn_data->command = ftp_command_lookup(token, strlen(token));
    if (!conn_data->command) {
        on_unrecognized_cmd(conn_data);
    } else {
        switch (conn_data->command->comand_abr) {
            case USER:
                on_user_cmd(conn_data, params_ptr);
                break;
            case PASS:
                on_pass_cmd(conn_data, params_ptr);
                break;
            case REIN:
                on_rein_cmd(conn_data, params_ptr);
                break;
            case QUIT:
                on_quit_cmd(conn_data, params_ptr);
                break;
            case NOOP:
                on_noop_cmd(conn_data, params_ptr);
                break;
            case HELP:
                on_help_cmd(conn_data, params_ptr);
                break;
            case FEAT:
                on_feat_cmd(conn_data, params_ptr);
                break;
            case ACCT: case ALLO: case APPE: case CDUP: case CWD: case DELE:
            case EPRT: case EPSV: case LIST: case LPRT: case LPSV: case MDTM:
            case MKD: case MLSD: case MLST: case MODE: case NLST: case OPTS:
            case PASV: case PORT: case PWD: case REST: case RETR: case RMD:
            case RNFR: case RNTO: case SITE: case SIZE: case SMNT: case STAT:
            case STOR: case STOU: case STRU: case SYST: case TYPE: case ABOR:
                on_unused_cmd(conn_data, params_ptr);
                break;
            default:
                DEBUG_PRINT("ftp - proc_cmd - default state\n");
                break;
        }
    }
    conn_data->syntax_state = RESET_CMD_BUFF;
    if (*size_to_proc > 0)
        conn_data->syntax_run = true;
    else
        conn_data->syntax_run = false;
}   

static void syntax_error(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    send_response(conn_data, FTP_421_RESP);
    do_close(conn_data);
    conn_data->syntax_run = false;
}

static void proc_buffer(struct conn_data *conn_data, uint8_t *buffer, size_t size) {
    DEBUG_PRINT("ftp - proc buffer - start\n");
    uint8_t *buffer_ptr = buffer;
    size_t elems_to_process = size;
    conn_data->syntax_run = true;
    while (conn_data->syntax_run) {
        switch (conn_data->syntax_state) {
            case RESET_CMD_BUFF:
                DEBUG_PRINT("ftp - reset cmd buffer");
                reset_cmd_buff(conn_data);
                break;
            case BUFFER_CMD:
                DEBUG_PRINT("ftp - buffer cmd\n");
                buffer_cmd(conn_data, &buffer_ptr, &elems_to_process);
                break;
            case CHECK_CMD_END:
                DEBUG_PRINT("ftp - check cmd\n");
                check_cmd_end(conn_data, &buffer_ptr, &elems_to_process);
                break;
            case PROCESS_CMD:
                DEBUG_PRINT("ftp - process cmd\n");
                proc_cmd(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case SYNTAX_ERROR:
                DEBUG_PRINT("ftp - syntax error\n");
                syntax_error(conn_data,&buffer_ptr,&elems_to_process);
                break;
            default:
                DEBUG_PRINT("ftp - proc buffer - default\n");
                conn_data->syntax_run = false;
                break;
        }
    }
    DEBUG_PRINT("ftp - proc buffer - end\n");
}

static void on_recv(int fd, short ev, void *arg) {
    struct conn_data *conn_data = (struct conn_data *)arg;
    memset(read_buffer, 0, sizeof(*read_buffer) * BUFSIZ);
    // MSG_DONTWAIT - nonblocking
    ssize_t amount = recv(fd, read_buffer, BUFSIZ, MSG_DONTWAIT);
    switch (amount) {
        case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            DEBUG_PRINT("ftp - Error on connection %d: %s\n", fd, strerror(errno));
            // No break - fall through
        case 0:
            DEBUG_PRINT("ftp - Closed connection %d\n", fd);
            do_close(conn_data);
            return;
        default:
            break;
    }
    proc_buffer(conn_data,read_buffer,(size_t)amount);
}

static void on_conn_timeout(int fd, short ev, void *arg){
    DEBUG_PRINT("ftp - conn timeout\n");
    struct conn_data *conn_data = (struct conn_data *)arg;
    do_close(conn_data);
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
    struct conn_data *conn_data = get_conn_data(connection_fd);
    if (!conn_data) {
        // no free slots
        close(connection_fd);
        return;
    }
    clear_ip_addr(conn_data);
    sockaddr_to_string(&connection_addr, conn_data->ipaddr_str);
    DEBUG_PRINT("ftp - accepted connection %d\n", connection_fd);
    event_assign(conn_data->read_ev, ev_base, connection_fd, EV_READ | EV_PERSIST, on_recv, conn_data);
    event_add(conn_data->read_ev, NULL);
    evtimer_assign(conn_data->timeout_ev, ev_base, on_conn_timeout, conn_data);
    evtimer_add(conn_data->timeout_ev, conn_timeout);
    send_response(conn_data, FTP_220_WELCOME_RESP);
    report_connect(conn_data);
}

// SIGINT signal - sent by terminal
static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
    event_base_loopbreak(ev_base);
}

static void alloc_conn_data_pool() {
    conn_data_pool = malloc(sizeof(*conn_data_pool)*FTP_MAX_CONN_COUNT);
    for (unsigned i = 0; i < FTP_MAX_CONN_COUNT; i++) {
        conn_data_pool[i].read_ev = malloc(sizeof(*conn_data_pool[i].read_ev));
        conn_data_pool[i].timeout_ev = malloc(sizeof(*conn_data_pool[i].timeout_ev));
        conn_data_pool[i].ipaddr_str = malloc(sizeof(*conn_data_pool[i].ipaddr_str) * IP_ADDR_LEN);
        conn_data_pool[i].token_buffer = malloc(sizeof(*conn_data_pool[i].token_buffer) * FTP_TOKEN_BUFFER_LEN);
        conn_data_pool[i].user = malloc(sizeof(*conn_data_pool[i].user) * FTP_USER_LEN);
        conn_data_pool[i].password = malloc(sizeof(*conn_data_pool[i].password) * FTP_PASSWORD_LEN);
        conn_data_pool[i].fd = -1;
    }
}

static void free_conn_data_pool() {
    for (unsigned i = 0; i < FTP_MAX_CONN_COUNT; i++) {
        free(conn_data_pool[i].read_ev);
        free(conn_data_pool[i].timeout_ev);
        free(conn_data_pool[i].ipaddr_str);
        free(conn_data_pool[i].token_buffer);
        free(conn_data_pool[i].user);
        free(conn_data_pool[i].password);
    }
    free(conn_data_pool);
}

void handle_ftp(unsigned port, int reporting_fd) {
    DEBUG_PRINT("ftp - running\n");
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_ERR(listen_fd < 0, "socket");
    int flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    // IPv6 or mapped IPv4 address
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    struct sockaddr_in6 listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(port);
    CHECK_ERR(bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0, "bind");
    CHECK_ERR(listen(listen_fd, 5) < 0, "listen");
    signal(SIGPIPE, SIG_IGN);
    alloc_conn_data_pool();
    ev_base = event_base_new();
    report_fd = reporting_fd;
    conn_timeout = malloc(sizeof(*conn_timeout));
    conn_timeout->tv_sec = FTP_CONN_TIMEOUT;
    conn_timeout->tv_usec = 0;
    read_buffer = malloc(sizeof(*read_buffer) * BUFSIZ);
    struct event *ev_accept = event_new(ev_base, listen_fd, EV_READ | EV_PERSIST, on_accept, NULL);
    event_add(ev_accept, NULL);
    struct event *signal_event = event_new(ev_base, SIGINT, EV_SIGNAL | EV_PERSIST, sigint_handler, NULL);
    event_add(signal_event, NULL);
    event_base_dispatch(ev_base);
    free_conn_data_pool();
    event_free(ev_accept);
    event_free(signal_event);
    event_base_free(ev_base);
    free(conn_timeout);
    free(read_buffer);
}
