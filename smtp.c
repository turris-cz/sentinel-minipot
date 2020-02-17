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

#define _GNU_SOURCE

#include <signal.h>
#include <event.h>
#include <unistd.h>
#include <b64/cdecode.h>

#include "smtp.h"
#include "utils.h"
#include "smtp_commands.gperf.c"
#include "sasl_mechanisms.gperf.c"

enum syntax_state {
    BUFFER_CMD,
    CHECK_CMD_END,
    PROCESS_CMD,
    SYNTAX_ERROR,
};

enum semantics_state {
    INIT,
    EXPECT_PL_DATA,
    EXPECT_LOG_USER,
    EXPECT_LOG_PASSW,
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
    struct smtp_command *command;
    enum semantics_state semantics_state;
    struct sasl_mechanism *auth_mech;
    // login athentication mechanism
    uint8_t *log_user;
    uint8_t *log_passw;
    // plain authentication mechanism
    uint8_t *plain_authzid;
    uint8_t *plain_authcid;
    uint8_t *plain_passw;
};

static int report_fd;
static struct event_base *ev_base;
static struct conn_data *conn_data_pool;
static uint8_t *read_buffer;
static struct timeval *conn_timeout;
static uint8_t *decode_buff;

static inline void report_plain_auth(struct conn_data *conn_data) {
    struct strpair data[] = {
        {"authzid", conn_data->plain_authzid},
        {"authcid", conn_data->plain_authcid},
        {"passw", conn_data->plain_passw},
    };
    if (!proxy_report(report_fd, data, sizeof(data) / sizeof(*data), "plauth", conn_data->ipaddr_str))
        DEBUG_PRINT("smtp error - could not report plain auth\n");
}

static inline void report_login_auth(struct conn_data *conn_data) {
    struct strpair data[] = {
        {"user", conn_data->log_user},
        {"passw", conn_data->log_passw},
    };
    if (!proxy_report(report_fd, data, sizeof(data) / sizeof(*data), "logauth", conn_data->ipaddr_str)) {
        DEBUG_PRINT("smtp error - could not report login auth\n");
    }
}

static inline void report_connect(struct conn_data *conn_data) {
    if (!proxy_report(report_fd, NULL, 0, "connect", conn_data->ipaddr_str))
        DEBUG_PRINT("smtp error - could not report syntax error\n");
}

static inline void send_response(struct conn_data *conn_data, uint8_t *response) {
    if (!send_all(conn_data->fd, response, strlen(response)))
        DEBUG_PRINT("smtp - could not send response\n");
}

static inline void clear_token_buffer(struct conn_data *conn_data) {
    memset(conn_data->token_buffer, 0, sizeof(*conn_data->token_buffer) * SMTP_TOKEN_BUFF_LEN);
    conn_data->token_write_ptr = conn_data->token_buffer;
    // it ensures we always work with NULL terminated uint8_t
    conn_data->token_buffer_free_space = SMTP_TOKEN_BUFF_LEN - 1;
}

static void clear_conn_data(struct conn_data *conn_data) {
    conn_data->fd = -1;
    memset(conn_data->read_ev, 0, sizeof(*conn_data->read_ev));
    memset(conn_data->timeout_ev, 0, sizeof(*conn_data->timeout_ev));
    memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * IP_ADDR_LEN);
    clear_token_buffer(conn_data);
    conn_data->try_count = 0;
    conn_data->try_limit = 0;
    conn_data->syntax_state = BUFFER_CMD;
    conn_data->syntax_run = false;
    conn_data->command = NULL;
    conn_data->semantics_state = INIT;
    conn_data->auth_mech = NULL;
    conn_data->auth_mech = NULL;
    memset(conn_data->log_user, 0, sizeof(*conn_data->token_buffer) * SMTP_LOGIN_USER_LEN);
    memset(conn_data->log_passw, 0, sizeof(*conn_data->token_buffer) * SMTP_LOGIN_PASSW_LEN);
    memset(conn_data->plain_authzid, 0, sizeof(*conn_data->plain_authzid) * SMTP_PLAIN_AUTHZID_LEN);
    memset(conn_data->plain_authcid, 0, sizeof(*conn_data->plain_authcid) * SMTP_PLAIN_AUTHCID_LEN);
    memset(conn_data->plain_passw, 0, sizeof(*conn_data->plain_passw) * SMTP_PLAIN_PASSW_LEN);
}

static struct conn_data *get_conn_data(int connection_fd) {
    unsigned i = 0;
    // not used structs have fd set to -1, we don't need separate flags
    while (i < SMTP_MAX_CONN_COUNT && conn_data_pool[i].fd != -1)
        i++;
    if (i >= SMTP_MAX_CONN_COUNT) {
        DEBUG_PRINT("smtp - no free struct conn_data - connection limit reached\n");
        return NULL;
    }
    clear_conn_data(&conn_data_pool[i]);
    conn_data_pool[i].fd = connection_fd;
    conn_data_pool[i].try_limit = range_rand(SMTP_CRED_MIN_RANGE, SMTP_CRED_MAX_RANGE);
    return &conn_data_pool[i];
}

static void do_close(struct conn_data *conn_data) {
    DEBUG_PRINT("smtp - close connection , fd: %d\n",conn_data->fd);
    event_del(conn_data->read_ev);
    event_del(conn_data->timeout_ev);
    close(conn_data->fd);
    conn_data->fd = -1;
}

static void buffer_cmd(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    size_t chr_cnt_to_delim = *size_to_proc;
    uint8_t *token_end_ptr = strchr(*buffer, '\x0D');
    if (token_end_ptr)
        chr_cnt_to_delim = (size_t) (token_end_ptr - *buffer);
    if (conn_data->token_buffer_free_space >= chr_cnt_to_delim) {
        // there is a space in token buffer
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
            // just skip
            *buffer += 1;
            *size_to_proc -=1;
        } else {
            // if token end was not found we just wait for next read 
            conn_data->syntax_run = false;
        }
        DEBUG_PRINT("here1\n");
    } else {
        DEBUG_PRINT("here2\n");
        // no space in token buffer for cmd
        // char limit reached
        conn_data->syntax_run = false;
        send_response(conn_data, SMTP_421_REP);
        do_close(conn_data);
    }
}

static void check_cmd_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    enum syntax_state ret = conn_data_pool->syntax_state;
    bool to_run = true;
    if (*size_to_proc == 0) {
        // if no bytes in buffer pause
        to_run = false;
        goto end;
    }
    // check if first byte in buffer is our uint8_tacter
    if (**buffer == '\x0A') {
        ret = PROCESS_CMD;
        // shift buffer
        (*buffer)++;
        (*size_to_proc)--;
    } else {
        ret = SYNTAX_ERROR;
    }
    end:
    conn_data->syntax_state = ret;
    conn_data->syntax_run = to_run;
}

static void on_init_helo_cmd(struct conn_data *conn_data, uint8_t *params) {
    if (params) {
        uint8_t *p = skip_prec_ws(params, strlen(params));
        strip_trail_ws(p, strlen(p));
        if (is_empty_str(p))
            send_response(conn_data, SMTP_501_HELO_REP);
        else
            send_response(conn_data, SMTP_250_HELO_REP);
    } else {
        send_response(conn_data, SMTP_501_HELO_REP);
    }
}

static void on_init_ehlo_cmd(struct conn_data *conn_data, uint8_t *params) {
    if (params) {
        uint8_t *p = skip_prec_ws(params, strlen(params));
        strip_trail_ws(p, strlen(p));
        if (is_empty_str(p))
            send_response(conn_data, SMTP_501_HELO_REP);
        else
            send_response(conn_data, SMTP_250_EHLO_REP);
    } else {
        send_response(conn_data, SMTP_501_HELO_REP);
    }
}

static void on_init_auth_login(struct conn_data *conn_data, uint8_t *param) {
    if (param) {
        // check for initial response
        uint8_t *p = skip_prec_ws(param, strlen(param));
        strip_trail_ws(p, strlen(p));
        
        if (!is_empty_str(p)) {
            // initial response
            if (base64_is_valid(p, strlen(p))) {
                // valid base64 data
                // reset decode buffer
                memset(decode_buff, 0, sizeof(*decode_buff) * SMTP_DECODE_BUFF_LEN);
                base64_decodestate s;
                base64_init_decodestate(&s);
                /* we have to ensure that decode buffer has enought space for decoded data !!!
                since p and decode buffer has same length is is ok. Decoded data has 3/4 length of encoded data. */
                int result = base64_decode_block(p, strlen(p), decode_buff, &s);
                if (result < 1 )
                    return;
                memset(conn_data->log_user, 0, sizeof(*conn_data->log_user) * SMTP_LOGIN_USER_LEN);
                // save username for later, LEAVE space for string terminator
                copy_util(decode_buff, strlen(decode_buff),conn_data->log_user, SMTP_LOGIN_USER_LEN - 1);
                // ask for password
                send_response(conn_data, SMTP_334_LOG_PASS_REP);
                conn_data->semantics_state = EXPECT_LOG_PASSW;
            } else {
                // invalid base64 data
                send_response(conn_data, SMTP_501_554_REP);
            }
        } else {
            send_response(conn_data, SMTP_501_554_REP);
        }
    } else {
        // no initial response
        // ask for username
        send_response(conn_data, SMTP_334_LOG_USER_REP);
        conn_data->semantics_state = EXPECT_LOG_USER;
    }
}


static void decode_plain_auth_data(struct conn_data *conn_data, uint8_t *data) {
    // reset decode buffer
    memset(decode_buff, 0, sizeof(*decode_buff) * SMTP_DECODE_BUFF_LEN);
    base64_decodestate s;
    base64_init_decodestate(&s);
    /* We have to ensure that decode buffer has enought space for decoded data !!!
    Decoded data has 3/4 length of encoded data.
    Encoded data length can be at maximum same length as decode buffer length minus few uint8_ts for "AUTH PLAIN " string.
    It also should ensure there is at least one terminating null at the end of decoded data. */
    int result = base64_decode_block(data, strlen(data), decode_buff, &s);
    if (result < 1)
        return;
    uint8_t *first_null = strchr(decode_buff, '\x00');
    uint8_t *second_null = NULL;
    if (first_null) {
        if (first_null < decode_buff + result) {
            second_null = strchr(first_null + 1, '\x00');
            if (second_null) {
                if (second_null < decode_buff + result) {
                    uint8_t *authzid = decode_buff;
                    uint8_t *authcid = first_null + 1;
                    uint8_t *passw = second_null + 1;
                    // leave space for terminating uint8_t
                    memset(conn_data->plain_authzid, 0, sizeof(*conn_data->plain_authzid) * SMTP_PLAIN_AUTHZID_LEN);
                    memset(conn_data->plain_authcid, 0, sizeof(*conn_data->plain_authcid) * SMTP_PLAIN_AUTHCID_LEN);
                    memset(conn_data->plain_passw, 0, sizeof(*conn_data->plain_passw) * SMTP_PLAIN_PASSW_LEN);
                    copy_util(authzid, strlen(authzid), conn_data->plain_authzid, SMTP_PLAIN_AUTHZID_LEN - 1);
                    copy_util(authcid, strlen(authcid), conn_data->plain_authcid, SMTP_PLAIN_AUTHCID_LEN - 1);
                    copy_util(passw, strlen(passw), conn_data->plain_passw, SMTP_PLAIN_PASSW_LEN - 1);
                }
            } else {
                // this is teoreticaly not possible
                DEBUG_PRINT("smtp error - decode plain auth data - no fisrt null found\n");
            }
        }
    } else {
        // this is not teoretically possible
        DEBUG_PRINT("smtp error - on_init_auth_plain - no fisrt null found\n");
    }
}

static void on_init_auth_plain(struct conn_data *conn_data, uint8_t *param) {
    // check for initial response
    // trailing whitespaces are tolerated !!
    if (param) {
        uint8_t *init_resp = skip_prec_ws(param, strlen(param));
        strip_trail_ws(init_resp, strlen(init_resp));
        if (!is_empty_str(init_resp)) {
            // initial response present
            if (base64_is_valid(init_resp, strlen(init_resp))) {
                decode_plain_auth_data(conn_data, init_resp);
                /* authcid and passw must have at least one uint8_t */
                if (strlen(conn_data->plain_authcid) == 0 || strlen(conn_data->plain_passw) == 0) {
                    // invalid data
                    send_response(conn_data, SMTP_501_554_REP);
                } else {
                    report_plain_auth(conn_data);
                    conn_data->try_count++;
                    if (conn_data->try_count == conn_data->try_limit) {
                        conn_data->try_count = 0;
                        send_response(conn_data, SMTP_421_REP);
                        // close
                        do_close(conn_data);
                    } else {    
                        send_response(conn_data, SMTP_535_578_REP);
                    }
                }
            } else {
                // invalid base64 data
                send_response(conn_data, SMTP_501_554_REP);
            }
        } else {
            send_response(conn_data, SMTP_334_PL_REP);
            conn_data->semantics_state = EXPECT_PL_DATA;
        }
    } else {
        // no initial response
        // ask for data
        send_response(conn_data, SMTP_334_PL_REP);
        conn_data->semantics_state = EXPECT_PL_DATA;
    }
}

static void on_init_auth_cmd(struct conn_data *conn_data, uint8_t *param) {
    if (param) {

        // trailing whitespaces are tolerated
        uint8_t *p = skip_prec_ws(param, strlen(param));
        strip_trail_ws(p, strlen(p));

        if (!is_empty_str(p)) {
            // split auth scheme from possible initial response
            uint8_t *init_resp = NULL;
            uint8_t *delim = strchr(p, '\x20');
            if (delim) {
                *delim = '\x00';
                init_resp = delim + 1;
            }
            // find authentication scheme
            conn_data->auth_mech = sasl_mech_lookup(p, strlen(p));
            if (!conn_data->auth_mech) {
                // no defined scheme found
                send_response(conn_data, SMTP_504_576_REP);
            } else {
                switch (conn_data->auth_mech->abr) {
                    case LOGIN:
                        DEBUG_PRINT("smtp - on init auth login\n");
                        on_init_auth_login(conn_data, init_resp);
                        break;
                    case PLAIN:
                        DEBUG_PRINT("smtp - on init auth plain\n");
                        on_init_auth_plain(conn_data, init_resp);
                        break;
                    default:
                        DEBUG_PRINT("smtp - on_init_auth_cmd - default\n");
                        break;
                }
            }
            
        } else {
            // no auth scheme defined
            send_response(conn_data, SMTP_504_576_REP);
        }

    } else {
        // no auth scheme defined
        send_response(conn_data, SMTP_504_576_REP);
    }
}


static void on_init(struct conn_data *conn_data) {
    // find if there are any parameters
    // SP delimeters cmd from parameters
    uint8_t *param = NULL;
    uint8_t *delim = strchr(conn_data->token_buffer, '\x20');
    if (delim) {
        // terminate command code from its parameters
        *delim = '\x00';
        param = delim + 1;
    }
    conn_data->command = smtp_command_lookup(conn_data->token_buffer, strlen(conn_data->token_buffer));
    if (!conn_data->command) {
        // no cmd matched
        send_response(conn_data, SMTP_500_REP);
    } else {
        switch (conn_data->command->comand_abr) {
            case HELP: case MAIL: case RCPT: case DATA:
            case VRFY: case EXPN: case BURL:
                DEBUG_PRINT("smtp - init -unused commands\n");
                send_response(conn_data, SMTP_530_570_REP);
                break;
            case NOOP:
                DEBUG_PRINT("smtp - init - noop\n");
                send_response(conn_data, SMTP_250_200_NOOP_REP);
                break;
            case RSET:
                DEBUG_PRINT("smtp - init - rset\n");
                send_response(conn_data, SMTP_250_200_RSET_REP);
                break;
            case EHLO:
                DEBUG_PRINT("smtp - ehlo\n");
                on_init_ehlo_cmd(conn_data, param);
                break;
            case HELO:
                DEBUG_PRINT("smtp - helo\n");
                on_init_helo_cmd(conn_data, param);
                break;
            case AUTH:
                DEBUG_PRINT("smtp - auth\n");
                on_init_auth_cmd(conn_data, param);
                break;
            case QUIT:
                DEBUG_PRINT("smtp - quit\n");
                send_response(conn_data, SMTP_221_200_REP);
                do_close(conn_data);
                break;
            default:
                DEBUG_PRINT("smtp - on_init - default\n");
                break;
        }
    }
}

static void on_expect_pl_data(struct conn_data *conn_data) {
    // trailing whitespaces are tolerated
    uint8_t *data = skip_prec_ws(conn_data->token_buffer, strlen(conn_data->token_buffer));
    strip_trail_ws(data, strlen(data));
    if(base64_is_valid(data, strlen(data))) {
        decode_plain_auth_data(conn_data, data);
        /* authcid and passw must have at least one uint8_t */
        if (strlen(conn_data->plain_authcid) == 0 || strlen(conn_data->plain_passw) == 0) {
            // invalid data
            send_response(conn_data, SMTP_501_554_REP);
        } else {
            report_plain_auth(conn_data);
            conn_data->try_count++;
            if (conn_data->try_count == conn_data->try_limit) {
                conn_data->try_count = 0;
                send_response(conn_data, SMTP_421_REP);
                // close
                do_close(conn_data);
            } else {
                send_response(conn_data, SMTP_535_578_REP);
            }
        }
    } else {
        send_response(conn_data, SMTP_501_554_REP);
    }
    conn_data->semantics_state = INIT;
}

static void on_expect_log_user(struct conn_data *conn_data) {
    uint8_t *user = skip_prec_ws(conn_data->token_buffer, strlen(conn_data->token_buffer));
    strip_trail_ws(user, strlen(user));
    if (base64_is_valid(user, strlen(user))) {
        // reset decode buffer
        memset(decode_buff, 0, sizeof(*decode_buff) * SMTP_DECODE_BUFF_LEN);
        base64_decodestate s;
        base64_init_decodestate(&s);
        /* we have to ensure that decode buffer has enought space for decoded data !!!
        since p and decode buffer has same length is is ok. Decoded data has 3/4 length of encoded data. */
        int result = base64_decode_block(user, strlen(user), decode_buff, &s);
        if (result >= 1) {
            // reset username
            memset(conn_data->log_user, 0, sizeof(*conn_data->log_user) * SMTP_LOGIN_USER_LEN);
            // save username for later, LEAVE space for string terminator
            copy_util(decode_buff, strlen(decode_buff), conn_data->log_user, SMTP_LOGIN_USER_LEN - 1);
        }
        /* Don't say that username is invalid here. Say it adter password is processed. */
    }
    // ask for password
    send_response(conn_data, SMTP_334_LOG_PASS_REP);
    conn_data->semantics_state = EXPECT_LOG_PASSW;
}

static void on_expect_log_passw(struct conn_data *conn_data) {
    uint8_t *password = skip_prec_ws(conn_data->token_buffer, strlen(conn_data->token_buffer));
    strip_trail_ws(password, strlen(password));
    if (base64_is_valid(password, strlen(password))) {
        // reset decode buffer
        memset(decode_buff, 0, sizeof(*decode_buff) * SMTP_DECODE_BUFF_LEN);
        base64_decodestate s;
        base64_init_decodestate(&s);
        /* we have to ensure that decode buffer has enought space for decoded data !!!
        since p and decode buffer has same length is is ok. Decoded data has 3/4 length of encoded data. */
        int result = base64_decode_block(password, strlen(password), decode_buff, &s);
        DEBUG_PRINT(" res %d\n", result);
        if (result >= 1) {
            // reet password
            memset(conn_data->log_passw, 0, sizeof(*conn_data->log_passw) * SMTP_LOGIN_PASSW_LEN);
            // leave space for terminating byte
            copy_util(decode_buff, strlen(decode_buff), conn_data->log_passw, SMTP_LOGIN_PASSW_LEN - 1);
        }
        if (strlen(conn_data->log_user) > 0 && strlen(conn_data->log_passw) > 0) {
            report_login_auth(conn_data);
            conn_data->try_count++;
            if (conn_data->try_count == conn_data->try_limit) {
                conn_data->try_count = 0;
                send_response(conn_data, SMTP_421_REP);
                // close
                do_close(conn_data);
            } else {
                send_response(conn_data, SMTP_535_578_REP);
            }
        } else {
            DEBUG_PRINT("here1\n");
            send_response(conn_data, SMTP_501_554_REP);
        }
    } else {
        DEBUG_PRINT("here2");
        send_response(conn_data, SMTP_501_554_REP);
    }
    conn_data->semantics_state = INIT;
}


static void proc_cmd(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    switch (conn_data->semantics_state) {
            case INIT:
                DEBUG_PRINT("smtp - proc cmd - on init\n");
                on_init(conn_data);
                break;
            case EXPECT_PL_DATA:
                DEBUG_PRINT("smtp - proc cmd - on plain data\n");
                on_expect_pl_data(conn_data);
                break;
            case EXPECT_LOG_USER:
                DEBUG_PRINT("smtp - proc cmd - on login user\n");
                on_expect_log_user(conn_data);
                break;
            case EXPECT_LOG_PASSW:
                DEBUG_PRINT("smtp - proc cmd - on login password\n");
                on_expect_log_passw(conn_data);
                break;
            default:
                DEBUG_PRINT("smtp - proc_cmd - default\n");
                break;
    }
    clear_token_buffer(conn_data);
    conn_data->syntax_state = BUFFER_CMD;
    if (*size_to_proc > 0)
        conn_data->syntax_run = true;
    else
        conn_data->syntax_run = false;
}

static void syntax_error(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    conn_data->syntax_run = false;
    send_response(conn_data, SMTP_500_REP);
    send_response(conn_data, SMTP_421_REP);
    do_close(conn_data);
}

static void proc_buffer(struct conn_data *conn_data, uint8_t *buffer, size_t size) {
    DEBUG_PRINT("smtp - proc buffer - start\n");
    uint8_t *buffer_ptr = buffer;
    size_t elems_to_process = size;
    conn_data->syntax_run = true;
    while(conn_data->syntax_run) {
        switch (conn_data->syntax_state) {
            case BUFFER_CMD:
                DEBUG_PRINT("smtp - buffer cmd\n");
                buffer_cmd(conn_data, &buffer_ptr, &elems_to_process);
                break;
            case CHECK_CMD_END:
                DEBUG_PRINT("smtp - check cmd\n");
                check_cmd_end(conn_data, &buffer_ptr, &elems_to_process);
                break;
            case PROCESS_CMD:
                DEBUG_PRINT("smtp - process cmd\n");
                proc_cmd(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case SYNTAX_ERROR:
                DEBUG_PRINT("smtp - syntax error\n");
                syntax_error(conn_data,&buffer_ptr,&elems_to_process);
                break;
            default:
                DEBUG_PRINT("smtp - proc buffer - default\n");
                conn_data->syntax_run = false;
                break;
        }
    }
    DEBUG_PRINT("smtp - proc buffer - end\n");
}

static void on_recv(int fd, short ev, void *arg) {
    struct conn_data *conn_data = (struct conn_data *)arg;
    memset(read_buffer, 0, sizeof(*read_buffer) * BUFSIZ);
    ssize_t amount = recv(fd, read_buffer, BUFSIZ, MSG_DONTWAIT);
    switch (amount) {
        case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            DEBUG_PRINT("smtp - error on connection %d: %s\n", fd, strerror(errno));
            // No break - fall through
        case 0:
            do_close(conn_data);
            return;
        default:
            break;
    }
    proc_buffer(conn_data,read_buffer, (size_t)amount);
}

static void on_conn_timeout(int fd, short ev, void *arg){
    DEBUG_PRINT("smtp - conn timeout\n");
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
    DEBUG_PRINT("smtp - accepted connection %d\n", connection_fd);
    sockaddr_to_string(&connection_addr, conn_data->ipaddr_str);
    event_assign(conn_data->read_ev, ev_base, connection_fd, EV_READ | EV_PERSIST, on_recv, conn_data);
    event_add(conn_data->read_ev, NULL);
    evtimer_assign(conn_data->timeout_ev, ev_base, on_conn_timeout, conn_data);
    evtimer_add(conn_data->timeout_ev, conn_timeout);
    report_connect(conn_data);
    send_response(conn_data, SMTP_220_WELCOME_REP);
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
    event_base_loopbreak(ev_base);
}

static void alloc_conn_data_pool() {
    conn_data_pool = malloc(sizeof(*conn_data_pool)*SMTP_MAX_CONN_COUNT);
    for (unsigned i = 0; i < SMTP_MAX_CONN_COUNT; i++) {
        conn_data_pool[i].read_ev = malloc(sizeof(*conn_data_pool[i].read_ev));
        conn_data_pool[i].timeout_ev = malloc(sizeof(*conn_data_pool[i].timeout_ev));
        conn_data_pool[i].ipaddr_str = malloc(sizeof(*conn_data_pool[i].ipaddr_str) * IP_ADDR_LEN);
        conn_data_pool[i].token_buffer = malloc(sizeof(*conn_data_pool[i].token_buffer) * SMTP_TOKEN_BUFF_LEN);
        conn_data_pool[i].fd = -1;
        conn_data_pool[i].log_user = malloc(sizeof(*conn_data_pool[i].log_user) * SMTP_LOGIN_USER_LEN);
        conn_data_pool[i].log_passw = malloc(sizeof(*conn_data_pool[i].log_passw) * SMTP_LOGIN_PASSW_LEN);
        conn_data_pool[i].plain_authzid = malloc(sizeof(*conn_data_pool[i].plain_authzid) * SMTP_PLAIN_AUTHZID_LEN);
        conn_data_pool[i].plain_authcid = malloc(sizeof(*conn_data_pool[i].plain_authcid) * SMTP_PLAIN_AUTHCID_LEN);
        conn_data_pool[i].plain_passw = malloc(sizeof(*conn_data_pool[i].plain_passw) * SMTP_PLAIN_PASSW_LEN);
    }
}

static void free_conn_data_pool() {
    for (unsigned i = 0; i < SMTP_MAX_CONN_COUNT; i++) {
        free(conn_data_pool[i].read_ev);
        free(conn_data_pool[i].timeout_ev);
        free(conn_data_pool[i].ipaddr_str);
        free(conn_data_pool[i].token_buffer);
        free(conn_data_pool[i].log_user);
        free(conn_data_pool[i].log_passw);
        free(conn_data_pool[i].plain_authzid);
        free(conn_data_pool[i].plain_authcid);
        free(conn_data_pool[i].plain_passw);
    }
    free(conn_data_pool);
}

void handle_smtp(unsigned port, int reporting_fd) {
    DEBUG_PRINT("smtp - running\n");
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_ERR(listen_fd < 0, "socket");
    int flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
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
    conn_timeout->tv_sec = SMTP_CONN_TIMEOUT;
    conn_timeout->tv_usec = 0;
    read_buffer = malloc(sizeof(*read_buffer) * BUFSIZ);
    decode_buff = malloc(sizeof(*decode_buff) * SMTP_DECODE_BUFF_LEN);
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
    free(decode_buff);
}
