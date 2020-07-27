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
#include <msgpack.h>

#include "utils.h"
#include "service_data.h"

#define PROXY_MAX_WAITING_MESSAGES 10
#define PROXY_MAX_WAIT_TIME 10

#define LEN_LEN SIZEOF_MEMBER(msgpack_sbuffer, size)

enum pipe_state {
	PS_BUFF_LEN,
	PS_BUFF_DATA,
	PS_BUFF_NUM_STATES //number of pipe states
};

struct pipe_data {
	struct event *read_ev;
	// this buffers serve for processing data from minipots
	// first length of data is sent, the data then follows
	// see minipot_pipe.c for minipot end
	enum pipe_state state;
	union {
		uint8_t bytes[SIZEOF_MEMBER(msgpack_sbuffer, size)]; // this holds length of the data
			// - it needs to be buffered first to determine the data length
		TYPEOF_MEMBER(msgpack_sbuffer, size) full;
	} len;
	// help variables for length buffering
	size_t len_free_len;
	uint8_t *len_write_ptr;
	// data are msgpack sbuffer - buffering is handled by msgpack_sbuffer_write
	msgpack_sbuffer sbuffer;
};

static struct event_base *ev_base;
static struct event *sigint_ev;
static struct event *sigterm_ev;
static struct event *proxy_timer_ev;
static zsock_t *proxy_sock;
static const char *topic;
static size_t messages_waiting;
static msgpack_sbuffer messages[PROXY_MAX_WAITING_MESSAGES];
static msgpack_sbuffer sbuf;
static msgpack_packer pk;
static struct pipe_data *pipes_data;
static size_t pipes_count;
static int retcode;

static void reset_pipe_buff(struct pipe_data *pipe_data ) {
	pipe_data->len_write_ptr = pipe_data->len.bytes;
	pipe_data->len_free_len = sizeof(pipe_data->len.full);
	msgpack_sbuffer_clear(&pipe_data->sbuffer);
	pipe_data->state = PS_BUFF_LEN;
}

static void buff_len(struct pipe_data *pipe_data, uint8_t **buff, size_t *size_to_proc) {
	size_t to_copy = MY_MIN(*size_to_proc, pipe_data->len_free_len);
	memcpy(pipe_data->len_write_ptr, *buff, to_copy);
	// shift read buffer
	*size_to_proc -= to_copy;
	*buff += to_copy;
	// shift len buffer
	pipe_data->len_write_ptr += to_copy;
	pipe_data->len_free_len -= to_copy;
	if (pipe_data->len_free_len == 0)
		pipe_data->state = PS_BUFF_DATA;
}

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

static void proxy_add(msgpack_sbuffer *sbuf) {
	if (messages_waiting == PROXY_MAX_WAITING_MESSAGES)
		if (!proxy_send_waiting()) {
			DEBUG_PRINT("master pipe - couldn't sent to proxy\n");
			retcode = MP_ERR_PROXY_SENT;
			event_base_loopbreak(ev_base);
			return;
		}
	msgpack_sbuffer_write(&messages[messages_waiting++], sbuf->data, sbuf->size);
}

static void buff_data(struct pipe_data *data, uint8_t **buff, size_t *size_to_proc) {
	size_t missing_data = data->len.full - data->sbuffer.size;
	size_t copy_len = MY_MIN(missing_data, *size_to_proc);
	msgpack_sbuffer_write(&data->sbuffer, *buff, copy_len);
	// shift read buffer
	*size_to_proc -= copy_len;
	*buff += copy_len;
	if ((data->len.full - data->sbuffer.size) == 0) {
		proxy_add(&data->sbuffer);
		reset_pipe_buff(data);
		data->state = PS_BUFF_LEN;
	}
}

static void pipe_read(int fd, short ev, void *arg) {
	struct pipe_data *data = (struct pipe_data *) arg;
	uint8_t buffer[BUFSIZ];
	ssize_t nbytes = read(fd, buffer, BUFSIZ);
	switch (nbytes) {
		case -1:
			if (errno == EAGAIN)
				return;
			DEBUG_PRINT("master pipe - read - error receiving from pipe\n");
			retcode = MP_ERR_PIPE_READ;
			event_base_loopbreak(ev_base);
			return;
		case 0:
			DEBUG_PRINT("master pipe - read - closed pipe from child\n");
			event_base_loopbreak(ev_base);
			return;
	}
	uint8_t *buff_ptr = &buffer[0];
	while (nbytes > 0) {
		switch (data->state) {
			case PS_BUFF_LEN:
				buff_len(data, &buff_ptr, &nbytes);
				break;
			case PS_BUFF_DATA:
				buff_data(data, &buff_ptr, &nbytes);
				break;
			default:
				DEBUG_PRINT("master pipe - read - default\n");
				retcode = MP_ERR_PIPE_PROTOCOL;
				event_base_loopbreak(ev_base);
				break;
		}
	}
}

static void proxy_timer_handler(int fd, short event, void *data) {
	if (!proxy_send_waiting()) {
		DEBUG_PRINT("master pipe - couldn't sent to proxy\n");
		retcode = MP_ERR_PROXY_SENT;
		event_base_loopbreak(ev_base);
	}
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
	DEBUG_PRINT("master pipe - caught SIGINT or SIGTERM\n");
	event_base_loopbreak(ev_base);
}

int master_pipe_alloc(struct configuration *conf) {
	proxy_sock = zsock_new(ZMQ_PUSH);
	if (proxy_sock == NULL)
		return MP_ERR_PIPE_MALLOC;
	// to supress event base logging
	event_set_log_callback(ev_base_discard_cb);
	ev_base = event_base_new();
	sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, sigint_handler, NULL);
	sigterm_ev = event_new(ev_base, SIGTERM, EV_SIGNAL, sigint_handler, NULL);
	proxy_timer_ev = event_new(ev_base, 0, EV_PERSIST, proxy_timer_handler, NULL);
	pipes_data = malloc(sizeof(*pipes_data) * conf->minipots_count);
	pipes_count = 0;
	return MP_ERR_OK;
}

void master_pipe_free() {
	// we dont care about send succes we are exiting anyways
	proxy_send_waiting();
	zsock_destroy(&proxy_sock);
	for (size_t i = 0; i < PROXY_MAX_WAITING_MESSAGES; i++)
		msgpack_sbuffer_destroy(&messages[i]);
	msgpack_sbuffer_destroy(&sbuf);
	event_free(proxy_timer_ev);
	event_free(sigterm_ev);
	event_free(sigint_ev);
	for (size_t i =  0; i < pipes_count; i++) {
		event_free(pipes_data[i].read_ev);
		msgpack_sbuffer_destroy(&pipes_data[i].sbuffer);
	}
	free(pipes_data);
	event_base_free(ev_base);
}

void master_pipe_register_child(int read_fd) {
	pipes_data[pipes_count].read_ev = event_new(ev_base, read_fd, EV_READ | EV_PERSIST, pipe_read, &pipes_data[pipes_count]);
	event_add(pipes_data[pipes_count].read_ev, NULL);
	msgpack_sbuffer_init(&pipes_data[pipes_count].sbuffer);
	reset_pipe_buff(&pipes_data[pipes_count]);
	pipes_count++;
}

int master_pipe_run(struct configuration *conf) {
	if (zsock_connect(proxy_sock, "%s", conf->socket) != 0){
		zsock_destroy(&proxy_sock);
		return MP_ERR_PROXY_CONN;
	}
	topic = conf->topic;
	event_add(sigint_ev, NULL);
	event_add(sigterm_ev, NULL);
	struct timeval tv = {PROXY_MAX_WAIT_TIME, 0};
	evtimer_add(proxy_timer_ev, &tv);
	messages_waiting = 0;
	for (size_t i = 0; i < PROXY_MAX_WAITING_MESSAGES; i++)
		msgpack_sbuffer_init(&messages[i]);
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
	retcode = MP_ERR_OK;
	event_base_dispatch(ev_base);
	return retcode;
}

void master_pipe_break() {
	retcode = MP_ERR_CHILD;
	event_base_loopbreak(ev_base);
}
