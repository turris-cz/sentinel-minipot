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


#define _GNU_SOURCE             // to have definitions setresgid and setresuid...

#define ARGP_ERROR_PORT_OUT_RAN -1
#define MAX_MINIPOT_COUNT 32

#include <argp.h>
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
#include "http.h"

enum minipot_type {
    TELNET,
    HTTP,
    FTP,
    SMTP,
};

struct arguments {
    char *user;
    char *topic;
    char *socket;
    uint8_t minipots_count;
    uint8_t minipots_size;
    int32_t *minipots_ports;
    enum minipot_type *minipots_types;
};

struct service_data {
    pid_t pid;
    struct pipe_data_t *pipe_data;
    struct event *pipe_read_ev;
};

static long int parse_port(char *str) {
    char *end_ptr;
    errno = 0;
    long int result = strtol(str, &end_ptr,10);
    if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) || // port value out of range of long int
        (result == 0 && errno != 0) || // another conversion error
        (result < 0 || result > 65535) || // port out of range
        end_ptr == str) // no digits
        return -1;
    else
        return result;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'u':
            arguments->user = arg;
            break;
        case 't':
            arguments->topic = arg;
            break;
        case 's':
            arguments->socket = arg;
            break;
        case 'T':
            if (arguments->minipots_count == arguments->minipots_size) {
                fprintf(stderr, "Maximal minipot count reached! Minipot ignored!\n");
                return 0;
            }
            arguments->minipots_ports[arguments->minipots_count] = (int32_t) parse_port(arg);
            if (arguments->minipots_ports[arguments->minipots_count] < 0)
                return ARGP_ERROR_PORT_OUT_RAN;
            arguments->minipots_types[arguments->minipots_count] = TELNET;
            arguments->minipots_count++;
            break;
        case 'H':
            if (arguments->minipots_count == arguments->minipots_size) {
                fprintf(stderr, "Maximal minipot count reached! Minipot ignored!\n");
                return 0;
            }
            arguments->minipots_ports[arguments->minipots_count] = (int32_t) parse_port(arg);
            if (arguments->minipots_ports[arguments->minipots_count] < 0)
                return ARGP_ERROR_PORT_OUT_RAN;
            arguments->minipots_types[arguments->minipots_count] = HTTP;
            arguments->minipots_count++;
            break;
        case 'F':
            if (arguments->minipots_count == arguments->minipots_size) {
                fprintf(stderr, "Maximal minipot count reached! Minipot ignored!\n");
                return 0;
            }
            arguments->minipots_ports[arguments->minipots_count] = (int32_t) parse_port(arg);
            if (arguments->minipots_ports[arguments->minipots_count] < 0)
                return ARGP_ERROR_PORT_OUT_RAN;
            arguments->minipots_types[arguments->minipots_count] = FTP;
            arguments->minipots_count++;
            break;
        case 'S':
            if (arguments->minipots_count == arguments->minipots_size) {
                fprintf(stderr, "Maximal minipot count reached! Minipot ignored!\n");
                return 0;
            }
            arguments->minipots_ports[arguments->minipots_count] = (int32_t) parse_port(arg);
            if (arguments->minipots_ports[arguments->minipots_count] < 0)
                return ARGP_ERROR_PORT_OUT_RAN;
            arguments->minipots_types[arguments->minipots_count] = SMTP;
            arguments->minipots_count++;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        fprintf(stderr, "Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
    // child process should only die during initialization.
    // This likely means some misconfiguration (e.g. binding on low port without root)
    // and have to be fixed. So exit the whole application (continuing with dead child
    // process likely hides some error - this process can't do anything useful anyway).
    exit(EXIT_FAILURE);
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

static void pipe_read(int fd, short ev, void *arg) {
    struct pipe_data_t *pipe_data = (struct pipe_data_t *)arg;
    char buffer[MSG_MAX_SIZE];
    ssize_t nbytes = read(fd, buffer, MSG_MAX_SIZE);
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
    char *buffer_pos = buffer;
    while (nbytes > 0)
        handle_pipe_protocol(&buffer_pos, &nbytes, pipe_data);
}

static void start_service(struct service_data *service_data, struct event_base *ev_base, unsigned port, const char *user, void (*handle_fn)(unsigned, int), const char *name) {
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
        exit(EXIT_SUCCESS);
    }
    close(pipes[1]);
    setnonblock(pipes[0]);
    service_data->pipe_data->name = name;
    reset_pipe_data(service_data->pipe_data);
    event_assign(service_data->pipe_read_ev, ev_base, pipes[0], EV_READ | EV_PERSIST, pipe_read, service_data->pipe_data);
    event_add(service_data->pipe_read_ev, NULL);
    service_data->pid = child;
}

int main(int argc, char *argv[]) {
    const char doc[] = "minipots";
    struct argp_option options[] = {
        {"user", 'u', "USER", 0, "User to drop priviledges", 0},
        {"topic", 't', "TOPIC", 0, "Topic for communication with proxy", 0},
        {"socket", 's', "SOCKET", 0, "Local socket for interprocess communication", 0},
        {"telnet", 'T', "TELNET_PORT", 0, "Port for Telnet minipot", 0},
        {"http", 'H', "HTTP_PORT", 0, "Port for HTTP minipot", 0},
        {"ftp", 'F', "FTP_PORT", 0, "Port for FTP minipot", 0},
        {"smtp", 'S', "SMTP_PORT", 0, "Port for SMTP minipot", 0},
        {0},
    };
    struct argp arg_parser = {options, parse_opt, 0, doc, 0, 0, 0};
    struct arguments arguments;
    arguments.user = DEFAULT_USER;
    arguments.topic = DEFAULT_TOPIC;
    arguments.socket = DEFAULT_LOCAL_SOCKET;
    arguments.minipots_count = 0;
    arguments.minipots_size = MAX_MINIPOT_COUNT;
    arguments.minipots_ports = malloc(arguments.minipots_size * sizeof(*arguments.minipots_ports));
    arguments.minipots_types = malloc(arguments.minipots_size * sizeof(*arguments.minipots_types));
    switch (argp_parse(&arg_parser, argc, argv, ARGP_NO_EXIT , 0, &arguments)) {
        case ARGP_ERR_UNKNOWN:
            fprintf(stderr, "Error - argp unknown error\n");
            goto early_end;
        case ARGP_ERROR_PORT_OUT_RAN:
            fprintf(stderr, "Error - port must be 0-65535\n");
            goto early_end;
        default:
            // only remaining is 0 = OK -> continue
            break;
    }
    if (arguments.minipots_count < 1) {
        fprintf(stderr, "At least one minipot must be defined !!!\n");
        goto early_end;
    }
    close(STDIN_FILENO);
    signal(SIGCHLD, sigchld_handler);
    struct event_base *ev_base = event_base_new();
    log_init(ev_base, arguments.socket, arguments.topic);
    struct service_data *service_data_pool = calloc(sizeof(*service_data_pool), arguments.minipots_count);
    for (size_t i = 0; i < arguments.minipots_count; i++) {
        service_data_pool[i].pipe_data = malloc(sizeof(*service_data_pool[i].pipe_data));
        service_data_pool[i].pipe_read_ev = malloc(sizeof(*service_data_pool[i].pipe_read_ev));
        switch (arguments.minipots_types[i]) {
            case TELNET:
                start_service(&service_data_pool[i], ev_base, arguments.minipots_ports[i], arguments.user, handle_telnet, "telnet");
                break;
            case HTTP:
                start_service(&service_data_pool[i], ev_base, arguments.minipots_ports[i], arguments.user, handle_http, "http");
                break;
            case FTP:
                break;
            case SMTP:
                break;
            default:
                // teoreticaly not possible
                service_data_pool[i].pid = -1;
                DEBUG_PRINT("%s","unknown minipot type\n");
                break;
        }
    }
    struct event *sigint_event = event_new(ev_base, SIGINT, EV_SIGNAL | EV_PERSIST, sigint_handler, ev_base);
    event_add(sigint_event, NULL);
    struct event *sigterm_event = event_new(ev_base, SIGTERM, EV_SIGNAL | EV_PERSIST, sigint_handler, ev_base);
    event_add(sigterm_event, NULL);
    event_base_dispatch(ev_base);
    for (size_t i = 0; i < arguments.minipots_count; i++)
        if (service_data_pool[i].pid != -1)
            kill(service_data_pool[i].pid, SIGINT);
    log_exit();
    event_free(sigint_event);
    event_free(sigterm_event);
    event_base_free(ev_base);
    for (size_t i = 0; i < arguments.minipots_count; i++) {
        free(service_data_pool[i].pipe_data);
        free(service_data_pool[i].pipe_read_ev);
    }
    free(service_data_pool);
    early_end:
    free(arguments.minipots_types);
    free(arguments.minipots_ports);
    return 0;
}
