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
#include <time.h>
#include <b64/cdecode.h>
#include <ctype.h>

#include "http.h"
#include "utils.h"
#include "messages.h"
#include "http_method.gperf.c"
#include "http_header.gperf.c"
#include "http_tr_enc.gperf.c"

enum state {
    PROCESS_METHOD,
    PARSE_METHOD,
    PROCESS_URL,
    PROCESS_HTTP_VERSION,
    PROCESS_START_LINE_END,
    IS_HEADERS_END1,
    IS_HEADERS_END2,
    PROCESS_HEADER,
    PROCESS_HEADER_END,
    PARSE_HEADER,
    HEADERS_END,
    PROCESS_BODY,
    PROCESS_CHUNK_SIZE,
    PROCESS_CHUNK_SIZE_END,
    PARSE_CHUNK_SIZE,
    PROCESS_CHUNK,
    PROCESS_CHUNK_END1,
    PROCESS_CHUNK_END2,
    HAS_TRAILER,
    PROCESS_CHUNKED_BODY_END,
    PROCESS_TRAILER,
    PROCESS_TRAILER_END,
    PARSE_TRAILER,
    MESSAGE_END,
    SYNTAX_ERROR,
};

struct conn_data {
    int fd;
    struct event *read_ev;
    struct event *timeout_ev;
    uint8_t *ipaddr_str;
    // state automaton
    enum state state;
    bool run;
    // HTTP data
    // general buffer for particular tokens of message
    uint8_t *token_buffer;
    uint8_t *token_buffer_write_ptr;
    size_t token_buffer_free_space;
    struct http_method *http_method;
    uint8_t *url;
    uint8_t *url_write_ptr;
    size_t url_free_space;
    struct http_header *header_name;
    // if multiple authorization headers are processed
    // -> the old value is overriden
    uint8_t *user_id;
    uint8_t *password;
    // if multiple user-agent headers are processed
    // -> the old value is overriden
    uint8_t *user_agent;
    // transfer encoding header value is list of values
    // multiple encodings can be listed
    // transfer encoding header can also arrive multiple times
    struct http_transfer_encoding **transfer_encoding;
    size_t transfer_encoding_write_index;
    // conent length header value is list of values
    // more details above
    // !! signed to be able to express error during conversion
    long int *content_len;
    size_t content_len_write_index;

    size_t body_len_to_skip;
    size_t chunk_size_to_skip;
    // total numbers of characters read from connection
    size_t char_read_count;
    // after try limit is reached -> sent 403 forbidden
    int try_limit;
    int try_counter;
};

static struct conn_data *conn_data_pool;
// communication with parent process
static int report_fd;
static struct event_base *ev_base;
// uses BUFSIZ macro - at least 256 bytes
static uint8_t *read_buffer;
static struct timeval *conn_timeout;
// temporal storage for decoded credentials token
uint8_t *decode_buffer;

static inline void report_connect(struct conn_data *conn_data) {
    if (!proxy_report(report_fd, NULL, 0, "connect", conn_data->ipaddr_str)) {
        DEBUG_PRINT("http error - could not report connect");
        kill(getppid(),SIGINT);
    }
}

static void report_message(struct conn_data *conn_data) {
    struct strpair data[] = {
        {"method", conn_data->http_method->name},
        {"url", conn_data->url},
        {"user-id", conn_data->user_id},
        {"password", conn_data->password},
        {"user-agent",conn_data->user_agent},
    };
    if (!proxy_report(report_fd, data, sizeof(data) / sizeof(*data), "message", conn_data->ipaddr_str)) {
        DEBUG_PRINT("http error - could not report login");
        kill(getppid(),SIGINT);
    }
}

static inline void clear_token_buff(struct conn_data *conn_data) {
    memset(conn_data->token_buffer, 0, sizeof(*conn_data->token_buffer) * HTTP_MAX_TOKEN_BUFFER_LEN);
    conn_data->token_buffer_write_ptr = conn_data->token_buffer;
    conn_data->token_buffer_free_space = HTTP_MAX_TOKEN_BUFFER_LEN - 1;
}

static inline void clear_content_len(struct conn_data *conn_data) {
    memset(conn_data->content_len,0,sizeof(*conn_data->content_len) * HTTP_CONTENT_LENGTH_SIZE);
    conn_data->content_len_write_index = 0;
}

static inline void clear_transfer_encoding(struct conn_data *conn_data) {
    memset(conn_data->transfer_encoding,0,sizeof(*conn_data->transfer_encoding) * HTTP_TRANSFER_ENCODING_SIZE);
    conn_data->transfer_encoding_write_index = 0;
}

static inline void clear_url(struct conn_data *conn_data) {
    memset(conn_data->url, 0, sizeof(*conn_data->url) * HTTP_MAX_URI_LEN);
    conn_data->url_write_ptr = conn_data->url;
    conn_data->url_free_space = HTTP_MAX_URI_LEN - 1;
}

static void clear_conn_data(struct conn_data *conn_data) {
    conn_data->fd = -1;
    memset(conn_data->read_ev, 0, sizeof(*conn_data->read_ev));
    memset(conn_data->timeout_ev, 0, sizeof(*conn_data->timeout_ev));
    memset(conn_data->ipaddr_str, 0, sizeof(*conn_data->ipaddr_str) * INET6_ADDRSTRLEN);
    conn_data->state = PROCESS_METHOD;
    conn_data->run = false;
    clear_token_buff(conn_data);
    conn_data->http_method = NULL;
    clear_url(conn_data);
    conn_data->header_name = NULL;
    memset(conn_data->user_id, 0, sizeof(*conn_data->user_id) * HTTP_MAX_TOKEN_BUFFER_LEN);
    memset(conn_data->password, 0, sizeof(*conn_data->password) * HTTP_MAX_TOKEN_BUFFER_LEN);
    memset(conn_data->user_agent, 0, sizeof(*conn_data->user_agent) * HTTP_MAX_TOKEN_BUFFER_LEN);
    clear_content_len(conn_data);
    clear_transfer_encoding(conn_data);
    conn_data->char_read_count = 0;
    conn_data->try_limit = 0;
    conn_data->try_counter = 0;
    conn_data->body_len_to_skip = 0;
    conn_data->chunk_size_to_skip = 0;
}

static struct conn_data *get_conn_data(int connection_fd) {
    unsigned i = 0;
    // not used structs have fd set to -1, we don't need separate flags
    while (i < HTTP_MAX_CONN_COUNT && conn_data_pool[i].fd != -1)
        i++;
    if (i >= HTTP_MAX_CONN_COUNT) {
        DEBUG_PRINT("http - no free struct conn_data - connection limit reached\n");
        return NULL;
    }
    clear_conn_data(&conn_data_pool[i]);
    conn_data_pool[i].fd = connection_fd;
    conn_data_pool[i].try_limit = range_rand(HTTP_CRED_MIN_RANGE, HTTP_CRED_MAX_RANGE);
    return &conn_data_pool[i];
}

static void do_close(struct conn_data *conn_data) {
    DEBUG_PRINT("http - do close, fd: %d\n",conn_data->fd);
    // delete events from base
    event_del(conn_data->read_ev);
    event_del(conn_data->timeout_ev);
    close(conn_data->fd);
    // put conn_data back to pool
    conn_data->fd = -1;
}

static inline void send_response(struct conn_data *conn_data, uint8_t *response) {
    if (!send_all(conn_data->fd, response, strlen(response))) {
        // if not possible send to peer, close connection
        DEBUG_PRINT("http - could not send response\n");
        conn_data->run = false;
        do_close(conn_data);
    }
}

static void ask_for_credentials(struct conn_data *conn_data) {
    if (conn_data->try_counter < conn_data->try_limit) {
        // ask for login
        send_response(conn_data, HTTP_401_REP);
        conn_data->try_counter++;
    } else {
        // send forbiden
        send_response(conn_data, HTTP_403_REP);
        do_close(conn_data);
    }
}

static void do_reply(struct conn_data *conn_data) {
    switch (conn_data->http_method->method_type) {
        case GET: case HEAD:
            ask_for_credentials(conn_data);
            break;
        case POST: case PUT: case DELETE: case CONNECT: case OPTIONS: case TRACE: case PATCH:
            send_response(conn_data, HTTP_405_REP);
            break;
        default:
            DEBUG_PRINT("http - Error! Send reply unknown state!\n");
            break;
    }
}


/* return true if token delim found or false if NOT found
if store_buffer_write_ptr & store_buffer_free_space is NULL we just SHIFT read buffer behind end of token */
static bool buffer_token(uint8_t delim, uint8_t **store_buffer_write_ptr, size_t *store_buffer_free_space, uint8_t **read_buffer, size_t *size_to_read, uint8_t* token_name) {
    bool ret = false;
    // if token end is not found - token len is read buffer size
    size_t token_len = *size_to_read;
    if (token_len == 0)
        return ret;
    size_t read_buffer_shift = 0;
    // find delim
    // uint8_t *token_end_ptr = strchr(*read_buffer, delim);
    uint8_t *token_end_ptr = memchr(*read_buffer, delim, token_len);
    if (token_end_ptr) {
        // token end found -> go to next state
        token_len = (int)(token_end_ptr - *read_buffer);
        // we want to shift behind delim
        read_buffer_shift += 1;
        ret = true;
    }
    if (store_buffer_write_ptr && store_buffer_free_space) {
        // copy token to its buffer
        if (*store_buffer_free_space > 0) {
            int copy_len;
            // check for free space in store buffer
            if (token_len <= *store_buffer_free_space) {
                // all token fits in the store buffer
                copy_len = token_len;
            } else {
                // not all data fits in store buffer
                copy_len = *store_buffer_free_space;
                // DEBUG_PRINT("Skipped data in %s\n", token_name);
            }
            memcpy(*store_buffer_write_ptr, *read_buffer, copy_len);
            *store_buffer_write_ptr += sizeof(**store_buffer_write_ptr) * copy_len;
            *store_buffer_free_space -= copy_len;

        } else {
            // no space in store buffer
            DEBUG_PRINT("http - No space skip data in %s\n", token_name);
        }
    } else {
        // we skip intentionaly
        DEBUG_PRINT("http - Intentional skip data in %s\n", token_name);
    }
    // shift by token len
    read_buffer_shift += token_len;
    *read_buffer += sizeof(**read_buffer) * read_buffer_shift;
    *size_to_read -= read_buffer_shift;
    return ret;
}

static void check_byte(uint8_t uint8_t_to_check, enum state succes_state, enum state failure_state,
                            struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // by default stay in current state
    enum state ret = conn_data_pool->state;
    bool to_run = true;
    if (*size_to_read == 0) {
        // if no uint8_ts in buffer pause
        to_run = false;
        goto end;
    }
    // check if first uint8_t in buffer is our uint8_tacter
    if (**buffer == uint8_t_to_check) {
        ret = succes_state;
        // shift buffer
        (*buffer)++;
        (*size_to_read)--;
    } else {
        ret = failure_state;
    }
    end:
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void skip_bytes(size_t *size_to_skip, struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read ) {
    size_t to_skip;
    if (*size_to_skip >= *size_to_read) {
        // skip all buffer
        to_skip = (unsigned long int)*size_to_read;
    } else {
        // skip only part
        to_skip = *size_to_skip;
    }
    // skip
    *buffer += sizeof(**buffer) * to_skip;
    *size_to_read -= (int)to_skip;
    *size_to_skip -= to_skip;
}

static void proc_method(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // if token end not found - stay in current state and stop
    enum state ret = PROCESS_METHOD;
    bool to_run = false;
    if (buffer_token('\x20', &(conn_data->token_buffer_write_ptr), &(conn_data->token_buffer_free_space), buffer, size_to_read, "METHOD")) {
        // token end found in read buffer -> go to next state and run
        ret = PARSE_METHOD;
        to_run = true;
    }
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void parse_method(struct conn_data *conn_data,uint8_t **buffer, size_t *size_to_read) {
    // if token end not found - stay in current state
    enum state ret = SYNTAX_ERROR;
    bool to_run = true;
    conn_data->http_method = http_method_lookup(conn_data->token_buffer, strlen(conn_data->token_buffer));
    if (conn_data->http_method)
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_URL;
    clear_token_buff(conn_data);
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_url(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // if token end not found - stay in current state
    enum state ret = PROCESS_URL;
    bool to_run = false;
    // we could use token buffer here, but just want to copy URL token
    if (buffer_token('\x20', &(conn_data->url_write_ptr), &(conn_data->url_free_space), buffer,size_to_read, "URL")) {
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_HTTP_VERSION;
        to_run = true;
    }
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_http_version(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // if token end not found - stay in current state
    enum state ret = PROCESS_HTTP_VERSION;
    bool to_run = false;
    // we don't care about http version token content
    if (buffer_token('\x0D', NULL, NULL, buffer, size_to_read, "VERSION")) {
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_START_LINE_END;
        to_run = true;
    }
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_start_line_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',IS_HEADERS_END1,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void is_headers_end1(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0D',IS_HEADERS_END2,PROCESS_HEADER,conn_data,buffer,size_to_read);
}

static void is_headers_end2(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',HEADERS_END,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void proc_header(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // if token end not found - stay in current state
    enum state ret = PROCESS_HEADER;
    bool to_run = false;
    if (buffer_token('\x0D', &(conn_data->token_buffer_write_ptr), &(conn_data->token_buffer_free_space), buffer, size_to_read, "HEADER")) {
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_HEADER_END;
        to_run = true;
    }
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_header_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',PARSE_HEADER,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static bool process_authorization(struct conn_data *conn_data, uint8_t *header_val) {
    DEBUG_PRINT("process authorization\n");
    header_val = skip_prec_ws(header_val, strlen(header_val));
    strip_trail_ws(header_val, strlen(header_val));
    // find SP delimiting Basic keyword with encoded credentials
    uint8_t *delim = strchr(header_val, '\x20');
    if (!delim) {
        DEBUG_PRINT("http - proces authorization error - mising space between Basic and credentials\n");
        return false;
    }
    *delim = '\x00';
    if (strcasecmp(header_val,"basic")) {
        DEBUG_PRINT("http - proces authorization error - basic token doesnt match\n");
        return false;
    }
    header_val = delim+1;
    // reset decode buffer
    if (!base64_is_valid(header_val,strlen(header_val))) {
        DEBUG_PRINT("http - Error! process authorization - not valid base64 string\n");
        return false;
    }
    memset(decode_buffer,0,sizeof(*decode_buffer) * HTTP_MAX_TOKEN_BUFFER_LEN);
    base64_decodestate s;
    base64_init_decodestate(&s);
    int result = base64_decode_block(header_val, strlen(header_val), decode_buffer, &s);
    // find double dot - user-id : password delimeter
    delim = strchr(decode_buffer, '\x3A');
    if (!delim) {
        DEBUG_PRINT("http - Error! process authoriztion - missing double dot :\n");
        return false;
    }
    // reset user-id field
    memset(conn_data->user_id,0,sizeof(*(conn_data->user_id)) * HTTP_MAX_TOKEN_BUFFER_LEN);
    copy_util(decode_buffer, (size_t)(delim - decode_buffer), conn_data->user_id, HTTP_MAX_TOKEN_BUFFER_LEN);
    // reset password field
    memset(conn_data->password,0,sizeof(*(conn_data->password)) * HTTP_MAX_TOKEN_BUFFER_LEN);
    copy_util(delim, strlen(++delim), conn_data->password, HTTP_MAX_TOKEN_BUFFER_LEN);
    return true;
}

static bool proc_user_agent(struct conn_data *conn_data, uint8_t *header_val) {
    header_val = skip_prec_ws(header_val, strlen(header_val));
    strip_trail_ws(header_val, strlen(header_val));
    copy_util(header_val, strlen(header_val), conn_data->user_agent, HTTP_MAX_TOKEN_BUFFER_LEN);
    return true;
}

static void inline handle_con_len_value(struct conn_data *conn_data, char *header_val) {
    char *end_ptr;
    errno = 0;
    long int result = strtol(header_val, &end_ptr,10);
    if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) ||
        (result == 0 && errno != 0) ||
        result < 0 ||
        end_ptr == header_val)
        // conversion error or negative value
        result = -1;
    if (conn_data->content_len_write_index < HTTP_CONTENT_LENGTH_SIZE)
        (conn_data->content_len)[(conn_data->content_len_write_index)++] = result;
}

static bool proc_content_length(struct conn_data *conn_data, uint8_t *header_val) {
    // a message can contain multiple content-length headers or one header with coma seprated values
    // check for multiple values
    uint8_t *coma_ptr = strchr(header_val,',');
    if (coma_ptr) {
        // coma has been found
        do {
            *coma_ptr = '\x00';
            handle_con_len_value(conn_data,(char*)header_val);
            header_val = coma_ptr+1;
        } while(coma_ptr = strchr(header_val,','));
    }
    // only one value or last value
    handle_con_len_value(conn_data,(char*)header_val);
    return true;
}

static void inline handle_tran_enc_value(struct conn_data *conn_data, uint8_t *val) {
    val = skip_prec_ws(val, strlen(val));
    strip_trail_ws(val, strlen(val));
    if (conn_data->transfer_encoding_write_index < HTTP_TRANSFER_ENCODING_SIZE) {
        (conn_data->transfer_encoding)[(conn_data->transfer_encoding_write_index)++] = http_transfer_encoding_lookup(val,strlen(val));
    }
}

static bool proc_transfer_encoding(struct conn_data *conn_data, uint8_t *header_val) {
    // a message can contain multiple content-length headers or one header with coma seprated values
    // the chunked encoding must be the last encoding otherwise -> 400 bad request
    uint8_t *coma_ptr = strchr(header_val,',');
    if (coma_ptr) {
        // more encodings
        do {
            *coma_ptr = '\x00';
            handle_tran_enc_value(conn_data,header_val);
            header_val = coma_ptr+1;
        } while (coma_ptr = strchr(header_val,','));
    }

    // only one value or last value
    handle_tran_enc_value(conn_data,header_val);
    return true;
}

static void parse_header(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    bool to_run = true;
    enum state ret = SYNTAX_ERROR;
    uint8_t *read_ptr = conn_data->token_buffer;
    // check for SP and HTAB - no ws should be here
    if (*read_ptr == '\x20' || *read_ptr == '\x09') {
        ret = IS_HEADERS_END1;
        goto end;
    }
    // find header name end - double dot :
    uint8_t *token_delim = strchr(read_ptr, '\x3A');
    if (!token_delim) {
        // double dot : not found -> it always should be there
        // syntax error
        DEBUG_PRINT("http - Error! parse header - double dot not found\n");
        goto end;
    }
    // replace delim by end of string
    *token_delim = '\x00';
    // match header name
    conn_data->header_name = http_header_name_lookup(read_ptr, strlen(read_ptr));
    if (!conn_data->header_name) {
        // known header name not found -> ignore header
        ret = IS_HEADERS_END1;
        goto end;
    }
    // first uint8_t of header value string
    uint8_t *header_val = ++token_delim;
    switch (conn_data->header_name->header_type) {
        case USER_AGENT:
            if (proc_user_agent(conn_data, header_val))
                ret = IS_HEADERS_END1;
            break;
        case AUTHORIZATION:
            if (process_authorization(conn_data, header_val))
                ret = IS_HEADERS_END1;
            break;
        case CONTENT_LENGTH:
            if (proc_content_length(conn_data, header_val))
                ret = IS_HEADERS_END1;
            break;
        case TRANSFER_ENCODING:
            if (proc_transfer_encoding(conn_data, header_val))
                ret = IS_HEADERS_END1;
            break;
        default:
            // theoreticaly not possiblle
            // goes to SYNTAX ERROR
            DEBUG_PRINT("http - Error! Recognized unknown header val\n");
            break;
    }
    end:
    clear_token_buff(conn_data);
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void headers_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // determines how to deal with message body
    bool to_run = true;
    enum state ret = MESSAGE_END;
    // check if transfer encoding header was captured
    if (conn_data->transfer_encoding_write_index > 0) {
        ret = SYNTAX_ERROR;
        // 1.check if we received transfer encoding and if chunked encoding is last
        for (size_t i = 0; i < (conn_data->transfer_encoding_write_index - 1); i++) {
            // check if list has a valid values
            if (conn_data->transfer_encoding[i]) {
                if (conn_data->transfer_encoding[i]->transfer_encoding_type == CHUNKED)
                    // if chunked encoding is included before last value - error
                    // chunked encoding must be last and applied only once
                    goto end;
            } else {
                // invalid value
                goto end;
            }
        }
        // check last value written to the list
        if (conn_data->transfer_encoding[conn_data->transfer_encoding_write_index - 1])
            if (conn_data->transfer_encoding[conn_data->transfer_encoding_write_index - 1]->transfer_encoding_type == CHUNKED)
                // do chunked encoding
                ret = PROCESS_CHUNK_SIZE;
        goto end;
    }
    // check if conntent length header was captured
    if (conn_data->content_len_write_index) {
        // 2. check if it has a content len - all values must be >= 0
        // in case of multiple values all must be same
        if (conn_data->content_len[0] < 0) {
            // do close
            ret = SYNTAX_ERROR;
            goto end;
        }
        for (size_t i = 1; i < conn_data->content_len_write_index; i++)
            if (conn_data->content_len[i] != conn_data->content_len[0]) {
                // do close
                ret = SYNTAX_ERROR;
                goto end;
            }
        // fixed len body
        ret = PROCESS_BODY;
        conn_data->body_len_to_skip = (unsigned long int) conn_data->content_len[0];
    }
    end:
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_body(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    enum state ret = PROCESS_BODY;
    bool to_run = true;
    if (conn_data->body_len_to_skip == 0) {
        // we skip all body -> message end
        ret = MESSAGE_END;
        goto end;
    }
    if (*size_to_read == 0) {
        // if nothing is in buffer pause and stay in state
        to_run = false;
        goto end;
    }
    skip_bytes(&(conn_data->body_len_to_skip),conn_data,buffer,size_to_read);
    end:
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_chunk_size(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    enum state ret = PROCESS_CHUNK_SIZE;
    bool to_run = false;
    // find CR
    if (buffer_token('\x0D', &(conn_data->token_buffer_write_ptr), &(conn_data->token_buffer_free_space), buffer, size_to_read, "chunk size")) {
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_CHUNK_SIZE_END;
        to_run = true;
    }
    end:
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_chunk_size_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',PARSE_CHUNK_SIZE,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void parse_chunk_size(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // WARNING !!! chunk extension can follow chunk size
    // but we dont care about them
    // chunksize is defined in HEXADECIMAL format !!!
    enum state ret = SYNTAX_ERROR;
    bool to_run = true;
    char *end_ptr;
    errno = 0;
    conn_data->chunk_size_to_skip = strtoul(conn_data->token_buffer,&end_ptr,16);
    if ((errno == ERANGE && conn_data->chunk_size_to_skip == ULONG_MAX) ||
        (conn_data->chunk_size_to_skip == 0 && errno != 0) ||
        end_ptr == (char*)conn_data->token_buffer)
        // conversion error
        goto end;
    if (conn_data->chunk_size_to_skip == 0)
        ret = HAS_TRAILER;
    else
        ret = PROCESS_CHUNK;
    end:
    clear_token_buff(conn_data);
    conn_data->run = to_run;
    conn_data->state = ret;
}

static void proc_chunk(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    enum state ret = PROCESS_CHUNK;
    bool to_run = true;
    if (conn_data->chunk_size_to_skip == 0) {
        // we skip whole chunk
        ret = PROCESS_CHUNK_END1;
        goto end;
    }
    if (*size_to_read == 0) {
        // if nothing is in buffer pause and stay in state
        to_run = false;
        goto end;
    }
    skip_bytes(&conn_data->chunk_size_to_skip,conn_data,buffer,size_to_read);
    end:
    conn_data->state = ret;
    conn_data->run = to_run;
}

static void proc_chunk_end1(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0D',PROCESS_CHUNK_END2,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void proc_chunk_end2(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',PROCESS_CHUNK_SIZE,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void has_trailer(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0D',PROCESS_CHUNKED_BODY_END,PROCESS_TRAILER,conn_data,buffer,size_to_read);
}

static void proc_chunked_body_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',MESSAGE_END,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void proc_trailer(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    enum state ret = PROCESS_TRAILER;
    bool to_run = false;
    if (buffer_token('\x0D', NULL, NULL, buffer, size_to_read, "chunk")) {
        // token end found in read buffer -> go to next state and run
        ret = PROCESS_TRAILER_END;
        to_run = true;
    }
    conn_data->run = to_run;
    conn_data->state = ret;
}

static void proc_trailer_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    check_byte('\x0A',PARSE_TRAILER,SYNTAX_ERROR,conn_data,buffer,size_to_read);
}

static void parse_trailer(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    // trailer is hedaer which can follow chunked body
    // only a certain headers are allowed here according to standart
    // but we are not interested in those headers
    enum state ret = HAS_TRAILER;
    bool to_run = true;
    conn_data->run = to_run;
    conn_data->state = ret;
}

static void message_end(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    report_message(conn_data);
    do_reply(conn_data);
    // reset buffers for a new message
    conn_data->state = PROCESS_METHOD;
    conn_data->char_read_count = 0;
    clear_url(conn_data);
    clear_transfer_encoding(conn_data);
    clear_content_len(conn_data);
    conn_data->body_len_to_skip = 0;
    conn_data->chunk_size_to_skip = 0;

    // start process new message
    if (*size_to_read > 0)
        // new message in rest of the buffer
        conn_data->run = true;
    else
        // wait for new buffer read
        conn_data->run = false;
}

static void syntax_error(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_read) {
    send_response(conn_data, HTTP_400_REP);
    do_close(conn_data);
    conn_data->run = false;
}

static void on_default(struct conn_data *conn_data, uint8_t **buffer, size_t *size_to_proc) {
    DEBUG_PRINT("http - default\n");
    do_close(conn_data);
    conn_data->run = false;
}

static void proc_buffer(struct conn_data *conn_data, uint8_t *buffer, size_t size) {
    DEBUG_PRINT("http - proc buffer - start\n");
    uint8_t *buffer_ptr = buffer;
    size_t elems_to_process = size;
    conn_data->run = true;
    while (conn_data->run)
    {
        switch (conn_data->state) {
            case PROCESS_METHOD:
                DEBUG_PRINT("http - process method\n");
                proc_method(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PARSE_METHOD:
                DEBUG_PRINT("http - parse method\n");
                parse_method(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_URL:
                DEBUG_PRINT("http - process url\n");
                proc_url(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_HTTP_VERSION:
                DEBUG_PRINT("http - process http version\n");
                proc_http_version(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_START_LINE_END:
                DEBUG_PRINT("http - process start line end\n");
                proc_start_line_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case IS_HEADERS_END1:
                DEBUG_PRINT("http - is headers end 1\n");
                is_headers_end1(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case IS_HEADERS_END2:
                DEBUG_PRINT("http - is headers end 2\n");
                is_headers_end2(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_HEADER:
                DEBUG_PRINT("http - process header\n");
                proc_header(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_HEADER_END:
                DEBUG_PRINT("http - process header end\n");
                proc_header_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PARSE_HEADER:
                DEBUG_PRINT("http - parse header\n");
                parse_header(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case HEADERS_END:
                DEBUG_PRINT("http - headers end\n");
                headers_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_BODY:
                DEBUG_PRINT("http - process body\n");
                proc_body(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNK_SIZE:
                DEBUG_PRINT("http - process chunk size\n");
                proc_chunk_size(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNK_SIZE_END:
                DEBUG_PRINT("http - process chunk size end\n");
                proc_chunk_size_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PARSE_CHUNK_SIZE:
                DEBUG_PRINT("http - parse chunk size\n");
                parse_chunk_size(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNK:
                DEBUG_PRINT("http - process chunk\n");
                proc_chunk(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNK_END1:
                DEBUG_PRINT("http - process chunk end1\n");
                proc_chunk_end1(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNK_END2:
                DEBUG_PRINT("http - process chunk end2\n");
                proc_chunk_end2(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case HAS_TRAILER:
                DEBUG_PRINT("http - has trailer\n");
                has_trailer(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_CHUNKED_BODY_END:
                DEBUG_PRINT("http - process chunked body end\n");
                proc_chunked_body_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_TRAILER:
                DEBUG_PRINT("http - process trailer\n");
                proc_trailer(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PROCESS_TRAILER_END:
                DEBUG_PRINT("http - process trailer end\n");
                proc_trailer_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case PARSE_TRAILER:
                DEBUG_PRINT("http - parse trailer\n");
                parse_trailer(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case MESSAGE_END:
                DEBUG_PRINT("http - message end\n");
                message_end(conn_data,&buffer_ptr,&elems_to_process);
                break;
            case SYNTAX_ERROR:
                DEBUG_PRINT("http - syntax error\n");
                syntax_error(conn_data,&buffer_ptr,&elems_to_process);
                break;
            default:
                DEBUG_PRINT("http - parse method\n");
                on_default(conn_data,&buffer_ptr,&elems_to_process);
                break;
        }
    }
    DEBUG_PRINT("http - proces buffer - end\n");
}

static void on_recv(int fd, short ev, void *arg) {
    struct conn_data *conn_data = (struct conn_data *)arg;
    // Reset read buffer before read
    memset(read_buffer, 0, sizeof(*read_buffer) * BUFSIZ);
    // MSG_DONTWAIT - nonblocking
    ssize_t amount = recv(fd, read_buffer, BUFSIZ, MSG_DONTWAIT);
    switch (amount) {
        case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            DEBUG_PRINT("http - Error on http connection %d: %s\n", fd, strerror(errno));
            // No break - fall through
        case 0:
            DEBUG_PRINT("http - Closed http connection %d\n", fd);
            do_close(conn_data);
            return;
        default:
            break;
    }
    conn_data->char_read_count += amount;
    if (conn_data->char_read_count > HTTP_MAX_REQ_MESG_LEN) {
        // max request message length reached
        DEBUG_PRINT("http - maximal message length reached\n");
        // send_400(conn_data);
        send_response(conn_data, HTTP_400_REP);
        // report_syntax_error(conn_data);
        do_close(conn_data);
        return;
    }
    proc_buffer(conn_data,read_buffer,(size_t)amount);
}

static void on_conn_timeout(int fd, short ev, void *arg){
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
    // from connection pool
    struct conn_data *conn_data = get_conn_data(connection_fd);
    if (!conn_data) {
        // no free slots
        close(connection_fd);
        return;
    }
    sockaddr_to_string(&connection_addr, conn_data->ipaddr_str);
    DEBUG_PRINT("http - Accepted http connection %d\n", connection_fd);
    event_assign(conn_data->read_ev, ev_base, connection_fd, EV_READ | EV_PERSIST, on_recv, conn_data);
    event_add(conn_data->read_ev, NULL);
    evtimer_assign(conn_data->timeout_ev, ev_base, on_conn_timeout, conn_data);
    evtimer_add(conn_data->timeout_ev, conn_timeout);
    report_connect(conn_data);
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
    // DEBUG_PRINT("SIGINT in HTTP\n");
    event_base_loopbreak(ev_base);
}

static void alloc_conn_data_pool() {
    conn_data_pool = malloc(sizeof(*conn_data_pool)*HTTP_MAX_CONN_COUNT);
    for (unsigned i = 0; i < HTTP_MAX_CONN_COUNT; i++) {
        conn_data_pool[i].read_ev = malloc(sizeof(*conn_data_pool[i].read_ev));
        conn_data_pool[i].timeout_ev = malloc(sizeof(*conn_data_pool[i].timeout_ev));
        conn_data_pool[i].ipaddr_str = malloc(sizeof(*conn_data_pool[i].ipaddr_str) * HTTP_IP_ADDR_LEN);
        conn_data_pool[i].token_buffer = malloc(sizeof(*conn_data_pool[i].token_buffer) * HTTP_MAX_TOKEN_BUFFER_LEN);
        conn_data_pool[i].url = malloc(sizeof(*conn_data_pool[i].url) * HTTP_MAX_URI_LEN);
        conn_data_pool[i].user_id = malloc(sizeof(*conn_data_pool[i].user_id) * HTTP_MAX_TOKEN_BUFFER_LEN);
        conn_data_pool[i].password = malloc(sizeof(*conn_data_pool[i].password) * HTTP_MAX_TOKEN_BUFFER_LEN);
        conn_data_pool[i].user_agent = malloc(sizeof(*conn_data_pool[i].user_agent) * HTTP_MAX_TOKEN_BUFFER_LEN);
        conn_data_pool[i].transfer_encoding = malloc(sizeof(*conn_data_pool[i].transfer_encoding) * HTTP_TRANSFER_ENCODING_SIZE);
        conn_data_pool[i].content_len = malloc(sizeof(*conn_data_pool[i].content_len) * HTTP_CONTENT_LENGTH_SIZE);
        conn_data_pool[i].fd = -1;
    }
}

static void free_conn_data_pool() {
    for (unsigned i = 0; i < HTTP_MAX_CONN_COUNT; i++) {
        free(conn_data_pool[i].read_ev);
        free(conn_data_pool[i].timeout_ev);
        free(conn_data_pool[i].ipaddr_str);
        free(conn_data_pool[i].token_buffer);
        free(conn_data_pool[i].url);
        free(conn_data_pool[i].user_id);
        free(conn_data_pool[i].password);
        free(conn_data_pool[i].user_agent);
        free(conn_data_pool[i].transfer_encoding);
        free(conn_data_pool[i].content_len);
    }
    free(conn_data_pool);
}

void handle_http(unsigned port, int reporting_fd) {
    DEBUG_PRINT("http - running\n");
    // sockect
    // AF_INET6 - IPv6
    // SOCK_STREAM - sequenced, reliable, two-way, connection-based byte streams
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK_ERR(listen_fd < 0, "socket");
    int flag = 1;
    // SOL_SOCKET - set option on socket level
    // SO_REUSEADDR - reuse of local address
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    // IPPROTO_IPV6 - set option on IPv6 level
    // IPV6_V6ONLY - send and receive packets to and from an IPv6 address
    // or an IPv4-mapped IPv6 address
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    // IPv6 socket address
    struct sockaddr_in6 listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    // IPv6
    listen_addr.sin6_family = AF_INET6;
    // unspecified IP address
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(port);
    CHECK_ERR(bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0, "bind");
    // max 5 pending connections
    // NONBLOCKING
    CHECK_ERR(listen(listen_fd, 5) < 0, "listen");
    signal(SIGPIPE, SIG_IGN);
    alloc_conn_data_pool();
    ev_base = event_base_new();
    report_fd = reporting_fd;
    conn_timeout = malloc(sizeof(*conn_timeout));
    conn_timeout->tv_sec = HTTP_REQ_MSG_TIMEOUT;
    conn_timeout->tv_usec = 0;
    read_buffer = malloc(sizeof(*read_buffer) * BUFSIZ);
    decode_buffer = malloc(sizeof(*decode_buffer) * HTTP_MAX_TOKEN_BUFFER_LEN);
    // event base setting
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
    free(decode_buffer);
}
