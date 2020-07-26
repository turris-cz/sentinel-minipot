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

#include <argp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <event2/event.h>
#include <errno.h>
#include <msgpack.h>

#include "child.h"
#include "minipot_config.h"
#include "proxy.h"
#include "cli_opts.h"
#include "utils.h"

enum minipot_error {
	MP_ERR_OK,
	MP_ERR_CLI,
	MP_ERR_SERVICE,
	MP_ERR_PROXY,
	MP_ERR_MALLOC,
	MP_ERR_NUM_CODES // number of minipot errors
};

enum pipe_state {
	PS_BUFF_LEN,
	PS_BUFF_DATA,
	PS_BUFF_NUM_STATES //number of pipe states
};

struct pipe_data{
	enum pipe_state state;
	uint8_t *len;
	uint8_t *len_write_ptr;
	size_t len_free_len;
	msgpack_sbuffer sbuffer;
};

struct service_data {
	pid_t child_pid;
	int pipe[2];
	struct event *read_ev;
	struct pipe_data pipe_data;
	struct child_data child_data;
};

static struct event_base *ev_base;

static void sigchld_handler(int sig) {
	int status;
	pid_t pid;
	int saved_errno = errno;
	// wait for any child process, if no child process exited return immediately
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		DEBUG_PRINT("child process %d exited with code %d.\n", pid, WEXITSTATUS(status));
		if (status != EXIT_SUCCESS) {
			event_base_loopbreak(ev_base);
		}
	}
	errno = saved_errno;
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
	DEBUG_PRINT("master - caught SIGINT or SIGTERM\n");
	event_base_loopbreak(ev_base);
}

static void reset_pipe_buff(struct pipe_data *pipe_data ) {
	pipe_data->len_write_ptr = pipe_data->len;
	pipe_data->len_free_len = sizeof(pipe_data->sbuffer.size);
	msgpack_sbuffer_clear(&pipe_data->sbuffer);
	pipe_data->state = PS_BUFF_LEN;
}

static int init_pipe_data(struct pipe_data *pipe_data) {
	pipe_data->len = malloc(sizeof(pipe_data->sbuffer.size));
	if (pipe_data->len == NULL)
		return -1;
	msgpack_sbuffer_init(&pipe_data->sbuffer);
	reset_pipe_buff(pipe_data);
	return 0;
}

static void destroy_pipe_data(struct pipe_data *pipe_data) {
	free(pipe_data->len);
	msgpack_sbuffer_destroy(&pipe_data->sbuffer);
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

static void buff_data(struct pipe_data *pipe_data, uint8_t **buff, size_t *size_to_proc) {
	size_t data_len = *((size_t *)pipe_data->len);
	size_t missing_data = data_len - pipe_data->sbuffer.size;
	size_t copy_len;
	if (*size_to_proc <= missing_data)
		copy_len = *size_to_proc;
	else
		copy_len = missing_data;
	// write to pipe buffer
	msgpack_sbuffer_write(&pipe_data->sbuffer, *buff, copy_len);
	// shift read buffer
	*size_to_proc -= copy_len;
	*buff += copy_len;
	// update missing data
	missing_data = data_len - pipe_data->sbuffer.size;
	if (missing_data == 0) {
		proxy_add(&pipe_data->sbuffer);
		reset_pipe_buff(pipe_data);
		pipe_data->state = PS_BUFF_LEN;
	}
}

static void proc_pipe_data(uint8_t *buff, size_t len, struct pipe_data *pipe_data) {
	while (len > 0) {
		switch (pipe_data->state) {
			case PS_BUFF_LEN:
				buff_len(pipe_data, &buff, &len);
				break;
			case PS_BUFF_DATA:
				buff_data(pipe_data, &buff, &len);
				break;
			default:
				DEBUG_PRINT("master - proc pipe data - default\n");
				event_base_loopbreak(ev_base);
				break;
		}
	}
}

static void pipe_read(int fd, short ev, void *arg) {
	struct pipe_data *pipe_data = (struct pipe_data *) arg;
	uint8_t buffer[BUFSIZ];
	ssize_t nbytes = read(fd, buffer, BUFSIZ);
	switch (nbytes) {
		case -1:
			if (errno == EAGAIN)
				return;
			DEBUG_PRINT("master - pipe read - error receiving from pipe\n");
			event_base_loopbreak(ev_base);
			return;
		case 0:
			DEBUG_PRINT("master - pipe read - closed pipe from child\n");
			event_base_loopbreak(ev_base);
			return;
	}
	proc_pipe_data(buffer, (size_t) nbytes, pipe_data);
}


static int start_service(struct service_data *service_data) {
	if (pipe(service_data->pipe) < 0)
		return -1;
	service_data->child_pid = fork();
	if (service_data->child_pid == -1) {
		close(service_data->pipe[1]);
		close(service_data->pipe[0]);
		return -1;
	}
	if (service_data->child_pid == 0)
		exit(handle_child(&service_data->child_data));
	close(service_data->pipe[1]);
	setnonblock(service_data->pipe[0]);
	event_assign(service_data->read_ev, ev_base, service_data->pipe[0], EV_READ | EV_PERSIST, pipe_read, &service_data->pipe_data);
	event_add(service_data->read_ev, NULL);
	return 0;
}

static void free_minipot(struct service_data *serv_data) {
	destroy_pipe_data(&serv_data->pipe_data);
	event_free(serv_data->read_ev);
}

static void destroy_minipot(struct service_data *serv_data) {
	kill(serv_data->child_pid, SIGINT);
	close(serv_data->pipe[0]);
	free_minipot(serv_data);
}

static void destroy_minipots(size_t minipots_count, struct service_data *serv_data) {
	for (size_t i = 0; i < minipots_count; i++)
		destroy_minipot(&serv_data[i]);
}

static int deploy_minipot(struct service_data *data, struct minipot_conf *conf, const char *user) {
	if (init_pipe_data(&data->pipe_data) != 0)
		return -1;
	data->read_ev = event_new(NULL, 0, 0, NULL, NULL);
	data->child_data.port = conf->port;
	data->child_data.type = conf->port;
	data->child_data.user = user;
	data->child_pid = -1;
	if (start_service(data) != 0) {
		free_minipot(data);
		return -1;
	}
	return 0;
}

static int deploy_minipots(struct configuration *conf, struct service_data *serv_data) {
	for (size_t i = 0; i < conf->minipots_count; i++) {
		if (deploy_minipot(&serv_data[i], &conf->minipots_conf[i], conf->user) != 0) {
			destroy_minipots(i, serv_data);
			return -1;
		}
		DEBUG_PRINT("master - %zd. service running, PID: %d\n", i + 1, serv_data[i].child_pid);
	}
	return 0;
}

int main(int argc, char **argv) {
	int retcode = MP_ERR_OK;
	fclose(stdin);
	struct configuration conf = {
		.user = DEFAULT_USER,
		.topic = DEFAULT_TOPIC,
		.socket = DEFAULT_LOCAL_SOCKET,
		.minipots_count = 0,
	};

	if (load_cli_opts(argc, argv, &conf) != 0)
		return MP_ERR_CLI;

	DEBUG_PRINT("Master process PID: %d\n", getpid());
	// to supress event base logging
	event_set_log_callback(ev_base_discard_cb);
	ev_base = event_base_new();
	struct service_data *service_data_pool = malloc(sizeof(*service_data_pool) * conf.minipots_count);
	if (service_data_pool == NULL) {
		retcode = MP_ERR_MALLOC;
		goto err_data_pool;
	}

	signal(SIGCHLD, sigchld_handler);
	if (deploy_minipots(&conf, service_data_pool) != 0) {
		DEBUG_PRINT("master -  couldn't start service\n");
		retcode = MP_ERR_SERVICE;
		goto err_service;
	}

	if (proxy_init(ev_base, &conf) != 0) {
		DEBUG_PRINT("master - couldn't connect to proxy\n");
		retcode = MP_ERR_PROXY;
		goto err_proxy;
	}

	struct event *sigint_ev = event_new(ev_base, SIGINT, EV_SIGNAL, sigint_handler, NULL);
	event_add(sigint_ev, NULL);
	struct event *sigterm_ev = event_new(ev_base, SIGTERM, EV_SIGNAL, sigint_handler, NULL);
	event_add(sigterm_ev, NULL);
	event_base_dispatch(ev_base);
	event_free(sigint_ev);
	event_free(sigterm_ev);
	proxy_exit();

	err_proxy:
	destroy_minipots(conf.minipots_count, service_data_pool);

	err_service:
	free(service_data_pool);

	err_data_pool:
	event_base_free(ev_base);

	return retcode;
}
