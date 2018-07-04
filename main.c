/*
 * Copyright 2018, CZ.NIC z.s.p.o. (http://www.nic.cz/)
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file is part of sentinel-minipot.
 */

#define _GNU_SOURCE             // to have definitions setresgid and setresuid...
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <event.h>
#include <errno.h>

#include <msgpack.h>

#include "default.h"
#include "utils.h"
#include "messages.h"
#include "telnet.h"

static void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        fprintf(stderr, "Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
}

static void sigint_handler(evutil_socket_t sig, short events, void *user_data) {
    DEBUG_PRINT("Caught SIGINT, exiting...\n");
    event_base_loopbreak((struct event_base *)user_data);
}

static void drop_privileges(const char *username) {
    struct passwd *user;
    if (!geteuid()) {
        CHECK_ERR(!(user = getpwnam(username)), "getpwnam");
        CHECK_ERR(chroot("/var/empty"), "chroot");
        CHECK_ERR(chdir("/"), "chdir");
        CHECK_ERR(setresgid(user->pw_gid, user->pw_gid, user->pw_gid), "setresgid");
        CHECK_ERR(setgroups(1, &user->pw_gid), "setgroups");
        CHECK_ERR(setresuid(user->pw_uid, user->pw_uid, user->pw_uid), "setresgid");
        CHECK_ERR((geteuid() == 0 || getegid() == 0), "can't drop root privileges");
    }
    CHECK_ERR(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(NO_NEW_PRIVS)");
}

void pipe_read(int fd, short ev, void *arg) {
    struct pipe_data_t *pipe_data = (struct pipe_data_t *)arg;
    char buffer[MSG_MAX_SIZE];
    ssize_t nbytes = read(fd, buffer, MSG_MAX_SIZE);
    printf("recvd %ld\n", nbytes);
    switch (nbytes) {
        case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                return;
            fprintf(stderr, "error receiving from pipe\n");
            return;
        case 0:
            fprintf(stderr, "closed pipe from child\n");
            return;
        default:
            break;
    }
    char * buffer_pos = buffer;
    while (nbytes > 0) {
        handle_pipe_protocol(&buffer_pos, &nbytes, pipe_data);
    }
}

pid_t start_service(struct event_base *ev_base, unsigned port, const char *user, void (*handle_fn)(int, int), const char *name) {
    pid_t child;
    int pipes[2];
    CHECK_ERR(pipe(pipes) < 0, "pipe");
    child = fork();
    CHECK_ERR(child == -1, "fork");
    if (child == 0) {
        drop_privileges(user);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipes[0]);
        (*handle_fn)(port, pipes[1]);
        exit(0);
    }
    close(pipes[1]);
    setnonblock(pipes[0]);
    struct pipe_data_t *pipe_data = malloc(sizeof(struct pipe_data_t));
    pipe_data->name = name;
    reset_pipe_data(pipe_data);
    struct event *ev = event_new(ev_base, pipes[0], EV_READ | EV_PERSIST, pipe_read, pipe_data);
    event_add(ev, NULL);
    return child;
}

int main(int argc, char *argv[]) {
    struct event_base *ev_base = event_base_new();
    unsigned telnet_port = DEFAULT_TELNET_PORT;
    const char *local_socket = DEFAULT_LOCAL_SOCKET;
    const char *topic = DEFAULT_TOPIC;
    const char *user = DEFAULT_USER;
    char opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"telnet", required_argument, 0, 'T'},
        {"local_socket", required_argument, 0, 's'},
        {"topic", required_argument, 0, 't'},
        {"user", required_argument, 0, 'u'},
        {0, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, "s:t:u:T:", long_options, &option_index)) != (char)-1) {
        switch (opt) {
            case 'T':
                telnet_port = atoi(optarg);
                break;
            case 's':
                local_socket = optarg;
                break;
            case 't':
                topic = optarg;
                break;
            case 'u':
                user = optarg;
                break;
            default:           /* '?' */
                fprintf(stderr, "Usage: %s [-T telnet_port] [-s socket] [-t topic] [-u user]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    close(STDIN_FILENO);
    signal(SIGCHLD, sigchld_handler);
    int telnet_proc_pid = start_service(ev_base, telnet_port, user, handle_telnet, "telnet");
    log_init(ev_base, local_socket, topic);
    struct event *sigint_event = event_new(ev_base, SIGINT, EV_SIGNAL | EV_PERSIST, sigint_handler, ev_base);
    event_add(sigint_event, NULL);
    struct event *sigterm_event = event_new(ev_base, SIGTERM, EV_SIGNAL | EV_PERSIST, sigint_handler, ev_base);
    event_add(sigterm_event, NULL);
    // run event loop...
    event_base_dispatch(ev_base);
    // ...interrupted, cleaning up
    kill(telnet_proc_pid, SIGINT);
    log_exit();
    return 0;
}
