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
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#include "minipot_config.h"
#include "master_pipe.h"
#include "child.h"
#include "cli_opts.h"
#include "utils.h"

static void sigchld_handler(int sig) {
	int status;
	pid_t pid;
	int saved_errno = errno;
	// wait for any child process, if no child process exited return immediately
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		DEBUG_PRINT("master - child process %d exited with code %d.\n", pid, WEXITSTATUS(status));
		if (status != EXIT_SUCCESS)
			master_pipe_break();
	}
	errno = saved_errno;
}

static void destroy_minipots(size_t count, struct service_data *serv_data) {
	for (size_t i = 0; i < count; i++) {
		kill(serv_data[i].child_pid, SIGINT);
		close(serv_data[i].pipe[0]); // close read end
	}
}

static int deploy_minipot(struct service_data *data, struct minipot_conf *conf, const char *user) {
	data->child_pid = -1;
	data->user = user;
	data->port = conf->port;
	data->type = conf->type;
	if (pipe(data->pipe) < 0)
		return -1;
	data->child_pid = fork();
	if (data->child_pid == -1) {
		close(data->pipe[1]);
		close(data->pipe[0]);
		return -1;
	}
	if (data->child_pid == 0)
		exit(handle_child(data));
	close(data->pipe[1]); // close write end
	// read end setup
	setnonblock(data->pipe[0]);
	master_pipe_register_child(data->pipe[0]);
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
	fclose(stdin);
	struct configuration conf = {
		.user = DEFAULT_USER,
		.topic = DEFAULT_TOPIC,
		.socket = DEFAULT_LOCAL_SOCKET,
		.minipots_count = 0,
	};
	int retcode = load_cli_opts(argc, argv, &conf);
	if (retcode != MP_ERR_OK)
		return retcode;
	DEBUG_PRINT("Master process PID: %d\n", getpid());
	struct service_data *service_data_pool = malloc(sizeof(*service_data_pool) * conf.minipots_count);
	retcode = master_pipe_alloc(&conf);
	if (retcode != MP_ERR_OK)
		goto err_pipe_malloc;
	signal(SIGCHLD, sigchld_handler);
	retcode = deploy_minipots(&conf, service_data_pool);
	if (retcode != MP_ERR_OK)
		goto err_service;
	retcode = master_pipe_run(&conf);
	destroy_minipots(conf.minipots_count, service_data_pool);

	err_service:
	master_pipe_free();

	err_pipe_malloc:
	free(service_data_pool);
	return retcode;
}
