/*
 *  Turris:Sentinel Minipot - Telnet password honeypot for Sentinel
 *  Copyright (C) 2018 CZ.NIC z.s.p.o. (https://www.nic.cz/)
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

#include <czmq.h>
#include <msgpack.h>
#include <event.h>

#include "utils.h"
#include "messages.h"

msgpack_sbuffer **messages;
int messages_max;
int messages_waiting;
zsock_t *proxy_sock;
const char *topic;

static void send_data(char *buf, size_t len) {
    zmsg_t *msg = zmsg_new();
    zmsg_addstr(msg, topic);
    zmsg_addmem(msg, buf, len);
    zmsg_send(&msg, proxy_sock);
    zmsg_destroy(&msg);
}

void log_send_waiting() {
    if (messages_waiting == 0)
        return;
    // arrays in msgpack header have header which contains number of element. Then elements follows.
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pk, messages_waiting);  // pack array header
    for (unsigned i = 0; i < messages_waiting; i++) {
        // normally, one would expect msgpack_pack_bin(&pk, messages[i].len) here - to append header for the binary
        // but we don't want that here - Data received already have its header. Doing that would result in corrupt msgpack.
        msgpack_pack_bin_body(&pk, messages[i]->data, messages[i]->size);  // just pack binary, without header
    }
    messages_waiting = 0;
    send_data(sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
}

static void send_waiting_messages_timer(int fd, short event, void *data) {
    log_send_waiting();
}

void log_init(struct event_base *ev_base, const char *socket, const char *topic_) {
    messages = malloc(sizeof(*messages) * MAX_WAITING_MESSAGES);
    messages_max = MAX_WAITING_MESSAGES;
    proxy_sock = zsock_new(ZMQ_PUSH);
    zsock_connect(proxy_sock, "%s", socket);
    topic = topic_;
    struct event *timer_event = event_new(ev_base, 0, EV_PERSIST, send_waiting_messages_timer, NULL);
    struct timeval tv;
    tv.tv_sec = MAX_WAIT_TIME;
    tv.tv_usec = 0;
    evtimer_add(timer_event, &tv);
}

void log_exit() {
    log_send_waiting();
    zsock_destroy(&proxy_sock);
    free(messages);
}

void log_add(msgpack_sbuffer *sbuf) {
    if (messages_waiting == messages_max)
        log_send_waiting();
    messages[messages_waiting++] = sbuf;
}


void reset_pipe_data(struct pipe_data_t *msg) {
    msg->state = Data;
    msg->remaining = 0;
    msg->sbuf = msgpack_sbuffer_new();
    msgpack_packer_init(&msg->pk, msg->sbuf, msgpack_sbuffer_write);
}

void handle_pipe_protocol(char **buffer, ssize_t *nbytes, struct pipe_data_t *msg) {
    // each message from minipots (children) has 3 parts - data, action, ip
    // each part is preceeded by int (4B) containing the length, then the data follows
    //  data (first part) can contain arbitrary data - it should be valid msgpack struct (map or just string/int/...)
    //  first part is allowed to be 0 length - when no additional data is needed
    if (msg->remaining == 0) {
        assert(*nbytes >= 4);  // this should never happen if child minipot process behaves normally
        unsigned len = *((unsigned *)*buffer);
        msg->remaining = len;
        *buffer += 4;
        *nbytes -= 4;
        switch (msg->state) {
            case Data:
                msgpack_pack_map(&msg->pk, (len != 0)?5:4);
                PACK_STR(&msg->pk, "type");
                PACK_STR(&msg->pk, msg->name);
                PACK_STR(&msg->pk, "ts");
                msgpack_pack_int(&msg->pk, time(NULL));
                if (len != 0) {
                    PACK_STR(&msg->pk, "data");
                    msgpack_pack_str(&msg->pk, len);
                } else {
                    msg->state = Action;  // no data, so skip straight to action
                }
                break;
            case Action:
                PACK_STR(&msg->pk, "action");
                msgpack_pack_str(&msg->pk, len);
                break;
            case Ip:
                PACK_STR(&msg->pk, "ip");
                msgpack_pack_str(&msg->pk, len);
                break;
        }
    } else {
        unsigned len = msg->remaining < *nbytes ? msg->remaining : *nbytes;
        msgpack_pack_str_body(&msg->pk, *buffer, len);
        if (msg->remaining <= len) {
            msg->remaining = 0;
            *nbytes -= len;
            *buffer += len;
            switch (msg->state) {
                case Data: msg->state = Action; break;
                case Action: msg->state = Ip; break;
                case Ip: log_add(msg->sbuf); reset_pipe_data(msg); break;
            }
        } else {
            msg->remaining -= *nbytes;
            *buffer += *nbytes;
            *nbytes = 0;
        }
    }
}
