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

#include <sys/prctl.h>
#include <signal.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "child.h"
#include "utils.h"
#include "telnet.h"
#include "http.h"
#include "ftp.h"
#include "smtp.h"

static int setup_sock(int *fd) {
	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (*fd == -1)
		return -1;
	int flag = 1;
	if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
		goto err;
	flag = 0;
	if (setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0)
		goto err;
	if (setnonblock(*fd) != 0)
		goto err;
	return 0;

	err:
	close(*fd);
	return -1;
}

static int bind_to_port(int fd, uint16_t port) {
	struct sockaddr_in6 listen_addr;
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin6_family = AF_INET6;
	listen_addr.sin6_addr = in6addr_any;
	listen_addr.sin6_port = htons(port);
	if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0)
		return -1;
	return 0;
}

static int drop_privileges(const char *username) {
	if (!geteuid()) { // Chroot and change user and group only if we are root
		struct passwd *user = getpwnam(username);
		if (!user || chroot("/var/empty") || chdir("/") ||
			setresgid(user->pw_gid, user->pw_gid, user->pw_gid) ||
			setgroups(1, &user->pw_gid) ||
			setresuid(user->pw_uid, user->pw_uid, user->pw_uid) ||
			(geteuid() == 0) || (getegid() == 0) ) {
			return -1;
		}
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	return 0;
}

int handle_child(struct service_data *data) {
	int exit_code = EXIT_SUCCESS;
	int listen_fd;
	if (setup_sock(&listen_fd) != 0) {
		DEBUG_PRINT("child - error - couldn't setup socket\n");
		return EXIT_FAILURE;
	}
	if (bind_to_port(listen_fd, data->port) != 0) {
		DEBUG_PRINT("child - error - couldn't  bind to port fd: %d\n", listen_fd);
		exit_code = EXIT_FAILURE;
		goto close_listen_fd;
	}
	if (listen(listen_fd, 5) != 0) {
		DEBUG_PRINT("child - error - couldn't listen on port fd: %d\n", listen_fd);
		exit_code = EXIT_FAILURE;
		goto close_listen_fd;
	}
	if (drop_privileges(data->user) != 0) {
		DEBUG_PRINT("child - could not drop privildges\n");
		exit_code = EXIT_FAILURE;
		goto close_listen_fd;
	}
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	close(data->pipe[0]); // close pipe read end
	setlocale(LC_ALL, "C"); // Unset any locale to hide system locales
	switch (data->type) {
		case MP_TYPE_TELNET:
			prctl(PR_SET_NAME, "Minipot [Telnet]");
			exit_code = handle_telnet(listen_fd, data->pipe[1]);
			break;
		case MP_TYPE_HTTP:
			prctl(PR_SET_NAME, "Minipot [HTTP]");
			exit_code = handle_http(listen_fd, data->pipe[1]);
			break;
		case MP_TYPE_FTP:
			prctl(PR_SET_NAME, "Minipot [FTP]");
			exit_code = handle_ftp(listen_fd, data->pipe[1]);
			break;
		case MP_TYPE_SMTP:
			prctl(PR_SET_NAME, "Minipot [SMTP]");
			exit_code = handle_smtp(listen_fd, data->pipe[1]);
			break;
		default:
			DEBUG_PRINT("child - unknown minipot type\n");
			exit_code = EXIT_FAILURE;
			break;
	}
	close(data->pipe[1]); // close pipe write end

	close_listen_fd:
	close(listen_fd);
	return exit_code;
}
