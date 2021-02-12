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
#include "log.h"
#include "master_pipe.h"

#define LEN_LEN SIZEOF_MEMBER(msgpack_sbuffer, size)

enum pipe_state {
	PS_BUFF_LEN,
	PS_BUFF_DATA,
	PS_BUFF_NUM_STATES // number of pipe states
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
static zsock_t *proxy_sock;
static const char *topic;
static struct pipe_data *pipes_data;
static size_t pipes_count;
static int retcode;

static void buff_len(struct pipe_data *pipe_data, uint8_t **buff,
	size_t *size_to_proc) {
	TRACE_FUNC;
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

static void reset_pipe_buff(struct pipe_data *pipe_data ) {
	TRACE_FUNC;
	pipe_data->len_write_ptr = pipe_data->len.bytes;
	pipe_data->len_free_len = sizeof(pipe_data->len.full);
	msgpack_sbuffer_clear(&pipe_data->sbuffer);
	pipe_data->state = PS_BUFF_LEN;
}

static int send_data(struct pipe_data *data) {
	TRACE_FUNC;
	int ret = 0;
	zmsg_t *msg = zmsg_new();
	if (msg == NULL ||
			zmsg_addstr(msg, topic) ||
			zmsg_addmem(msg, data->sbuffer.data, data->sbuffer.size) ||
			zmsg_send(&msg, proxy_sock)) {
		error("Couldn't send data to Proxy");
		zmsg_destroy(&msg);
		ret = -1;
	}
	errno = 0; // reset errno set by czmq to allow correct LogC functionality
	// in case zmsg was sent it should be destroyed by send procedure
	msgpack_sbuffer_clear(&data->sbuffer);
	return ret;
}

static void buff_data(struct pipe_data *data, uint8_t **buff, size_t *size_to_proc) {
	TRACE_FUNC;
	size_t missing_data = data->len.full - data->sbuffer.size;
	size_t copy_len = MY_MIN(missing_data, *size_to_proc);
	msgpack_sbuffer_write(&data->sbuffer, *buff, copy_len);
	// shift read buffer
	*size_to_proc -= copy_len;
	*buff += copy_len;
	if ((data->len.full - data->sbuffer.size) == 0) {
		if (send_data(data))
			master_pipe_break(MP_ERR_PROXY_SENT);
		reset_pipe_buff(data);
		data->state = PS_BUFF_LEN;
	}
}

static void pipe_read(int fd, short ev, void *arg) {
	TRACE_FUNC;
	struct pipe_data *data = (struct pipe_data *) arg;
	uint8_t buffer[BUFSIZ];
	ssize_t nbytes = read(fd, buffer, BUFSIZ);
	switch (nbytes) {
		case -1:
			if (errno == EAGAIN)
				return;
			error("Reading from pipe FD: %d failed", fd);
			master_pipe_break(MP_ERR_PIPE_READ);
			return;
		case 0:
			info("Pipe FD: %d closed from child", fd);
			master_pipe_break(MP_ERR_OK);
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
				error("Pipe FD: %d read unknown state", fd);
				master_pipe_break(MP_ERR_PIPE_PROTOCOL);
				break;
		}
	}
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
	errno = 0; // reset errno set by ??? to allow correct LogC functionality
	TRACE_FUNC;
	master_pipe_break(MP_ERR_OK);
}

int master_pipe_alloc(struct configuration *conf) {
	TRACE_FUNC;
	proxy_sock = zsock_new(ZMQ_PUSH);
	// send blocks for max 5s
	zsock_set_sndtimeo(proxy_sock, 5000);
	// leave 5s for sending remanining messages before socket destroy
	zsock_set_linger(proxy_sock, 5000);
	errno = 0; // reset errno set by czmq to allow correct LogC functionality
	if (proxy_sock == NULL)
		return MP_ERR_PIPE_MALLOC;
	// to supress event base logging
	event_set_log_callback(ev_base_discard_cb);
	ev_base = event_base_new();
	sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, sigint_handler, NULL);
	sigterm_ev = event_new(ev_base, SIGTERM, EV_SIGNAL, sigint_handler, NULL);
	pipes_data = malloc(sizeof(*pipes_data) * conf->minipots_count);
	pipes_count = 0;
	return MP_ERR_OK;
}

void master_pipe_free() {
	TRACE_FUNC;
	zsock_destroy(&proxy_sock);
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
	TRACE_FUNC;
	pipes_data[pipes_count].read_ev = event_new(ev_base, read_fd,
		EV_READ | EV_PERSIST, pipe_read, &pipes_data[pipes_count]);
	event_add(pipes_data[pipes_count].read_ev, NULL);
	msgpack_sbuffer_init(&pipes_data[pipes_count].sbuffer);
	reset_pipe_buff(&pipes_data[pipes_count]);
	pipes_count++;
	
}

static int send_welcome_msg() {
	TRACE_FUNC;
	int ret = 0;
	zmsg_t *msg = zmsg_new();
	if (msg == NULL ||
			zmsg_addstr(msg, topic) ||
			zmsg_send(&msg, proxy_sock)) {
		error("Couldn't send welcome message");
		zmsg_destroy(&msg);
		ret = -1;
	}
	errno = 0; // reset errno set by czmq to allow correct LogC functionality
	// in case zmsg was sent it should be destroyed by send procedure
	return ret;
}

int master_pipe_run(struct configuration *conf) {
	TRACE_FUNC;
	topic = conf->topic;
	if (zsock_connect(proxy_sock, "%s", conf->socket) || send_welcome_msg()) {
		error("Couldn't connect to ZMQ socket");
		zsock_destroy(&proxy_sock);
		return MP_ERR_PROXY_CONN;
	}
	errno = 0; // reset errno probably set by czmq to allow correct LogC functionality
	event_add(sigint_ev, NULL);
	event_add(sigterm_ev, NULL);
	retcode = MP_ERR_OK;
	event_base_dispatch(ev_base);
	return retcode;
}

void master_pipe_break(int ret) {
	TRACE_FUNC;
	retcode = ret;
	event_base_loopbreak(ev_base);
}
