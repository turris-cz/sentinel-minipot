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
#include <sys/prctl.h>
#include <string.h>

#include "minipot_config.h"
#include "master_pipe.h"
#include "child.h"
#include "cli_opts.h"
#include "utils.h"

static const char *minipot_t_enum_str[] = {"minipot [FTP]", "minipot [HTTP]",
	"minipot [SMTP]", "minipot [Telnet]"};
static const char *master = "minipot [Master]";

static void sigchld_handler(int sig) {
	TRACE_FUNC;
	int status;
	pid_t pid;
	int saved_errno = errno;
	// wait for any child process, if no child process exited return immediately
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		info("Child process with PID: %d exited with code %d.",
			pid, WEXITSTATUS(status));
		if (status != EXIT_SUCCESS)
			master_pipe_break();
	}
	errno = saved_errno;
}

static void destroy_minipots(size_t count, struct service_data *serv_data) {
	TRACE_FUNC;
	for (size_t i = 0; i < count; i++) {
		kill(serv_data[i].child_pid, SIGINT);
		close(serv_data[i].pipe[0]); // close read end
	}
}

static int deploy_minipot(struct service_data *data, struct minipot_conf *conf, const char *user) {
	TRACE_FUNC;
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
	if (data->child_pid == 0) {
		// set logger and process name for easier debuging
		char *name;
		size_t len;
		FILE *tmp = open_memstream(&name, &len);
		fprintf(tmp, "%s PID [%d]", minipot_t_enum_str[conf->type], getpid());
		fclose(tmp);
		log_sentinel_minipots->name = name;
		prctl(PR_SET_NAME, minipot_t_enum_str[conf->type]);
		int ret = handle_child(data);
		free(name);
		exit(ret);
	}
	close(data->pipe[1]); // close write end
	// read end setup
	setnonblock(data->pipe[0]);
	master_pipe_register_child(data->pipe[0]);
	info("listening on data from %s with PID [%d] on pipe read end with FD: %d",
		minipot_t_enum_str[conf->type], data->child_pid, data->pipe[0]);
	return 0;
}

static int deploy_minipots(struct configuration *conf, struct service_data *serv_data) {
	TRACE_FUNC;
	for (size_t i = 0; i < conf->minipots_count; i++)
		if (deploy_minipot(&serv_data[i], &conf->minipots_conf[i], conf->user) != 0) {
			destroy_minipots(i, serv_data);
			return -1;
		}
	return 0;
}

int main(int argc, char **argv) {
	// set logger and process name for easier debuging
	char *name;
	size_t len;
	FILE *tmp = open_memstream(&name, &len);
	fprintf(tmp, "%s PID [%d]", master, getpid());
	fclose(tmp);
	log_sentinel_minipots->name = name;
	prctl(PR_SET_NAME, master);
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
	free(name);
	return retcode;
}
