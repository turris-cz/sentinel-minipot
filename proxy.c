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
#include <czmq.h>

#include "minipot_config.h"
#include "utils.h"

#define PROXY_MAX_WAITING_MESSAGES 10
#define PROXY_MAX_WAIT_TIME 10

// this is just reference to event base from main.c - no ownership here
static struct event_base *event_base;
static const char *topic;
static zsock_t *proxy_sock;
static size_t messages_waiting;
static msgpack_sbuffer messages[PROXY_MAX_WAITING_MESSAGES];
static msgpack_sbuffer sbuf;
static msgpack_packer pk;
static struct event *proxy_timer_ev;

/*
 * Returns true if sent was successful and false otherwise.
 */
static bool proxy_send_waiting() {
	bool ret = true;
	if (messages_waiting == 0)
		return ret;
	msgpack_pack_array(&pk, messages_waiting);
	for (size_t i = 0; i < messages_waiting; i++) {
		// don't pack header, these are already serialized data
		msgpack_pack_str_body(&pk, messages[i].data, messages[i].size);
		msgpack_sbuffer_clear(&messages[i]);
	}
	messages_waiting = 0;
	zmsg_t *msg = zmsg_new();
	if (msg == NULL) {
		ret = false;
		goto err;
	}
	if (zmsg_addstr(msg, topic) ||
		zmsg_addmem(msg, sbuf.data, sbuf.size) ||
		zmsg_send(&msg, proxy_sock)) {
			zmsg_destroy(&msg);
			ret = false;
	}
	// in case zmsg was sent it should be destroyed by send procedure
	err:
	msgpack_sbuffer_clear(&sbuf);
	return ret;
}


static void proxy_timer_handler(int fd, short event, void *data) {
	if (!proxy_send_waiting()) {
		DEBUG_PRINT("master - couldn't sent to proxy\n");
		event_base_loopbreak(event_base);
	}
}

int proxy_init(struct event_base *ev_base, struct configuration *conf) {
	proxy_sock = zsock_new(ZMQ_PUSH);
	if (proxy_sock == NULL)
		return -1;
	if (zsock_connect(proxy_sock, "%s", conf->socket) != 0){
		zsock_destroy(&proxy_sock);
		return -1;
	}
	event_base = ev_base;
	topic = conf->topic;
	messages_waiting = 0;
	for (size_t i = 0; i < PROXY_MAX_WAITING_MESSAGES; i++)
		msgpack_sbuffer_init(&messages[i]);
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	proxy_timer_ev = event_new(ev_base, 0, EV_PERSIST, proxy_timer_handler, NULL);
	struct timeval tv = {PROXY_MAX_WAIT_TIME, 0};
	evtimer_add(proxy_timer_ev, &tv);
	return 0;
}

void proxy_exit() {
	// we dont care about send succes we are exiting anyways
	proxy_send_waiting();
	zsock_destroy(&proxy_sock);
	for (size_t i = 0; i < PROXY_MAX_WAITING_MESSAGES; i++)
		msgpack_sbuffer_destroy(&messages[i]);
	msgpack_sbuffer_destroy(&sbuf);
	event_free(proxy_timer_ev);
}

void proxy_add(msgpack_sbuffer *sbuf) {
	if (messages_waiting == PROXY_MAX_WAITING_MESSAGES)
		if (!proxy_send_waiting()) {
			DEBUG_PRINT("master - couldn't sent to proxy\n");
			event_base_loopbreak(event_base);
			return;
		}
	msgpack_sbuffer_write(&messages[messages_waiting++], sbuf->data, sbuf->size);
}
