#define _GNU_SOURCE  // to have definitions setresgid and setresuid...
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

#include "utils.h"
#include "zmq_log.h"
#include "telnet.h"


static void SIGCHLD_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) fprintf(stderr, "Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
}

static void drop_privileges(const char * username) {
    struct passwd *user;
    if (!geteuid()) {
        user = getpwnam(username);
        if (!user) {
            perror("getpwnam");
            exit(EXIT_FAILURE);
        }
        if (chroot("/var/empty")) {
            perror("chroot");
            exit(EXIT_FAILURE);
        }
        if (chdir("/")) {
            perror("chdir");
            exit(EXIT_FAILURE);
        }
        if (setresgid(user->pw_gid, user->pw_gid, user->pw_gid)) {
            perror("setresgid");
            exit(EXIT_FAILURE);
        }
        if (setgroups(1, &user->pw_gid)) {
            perror("setgroups");
            exit(EXIT_FAILURE);
        }
        if (setresuid(user->pw_uid, user->pw_uid, user->pw_uid)) {
            perror("setresuid");
            exit(EXIT_FAILURE);
        }
        if (!geteuid() || !getegid()) {
            fprintf(stderr, "Mysteriously still running as root... Goodbye.\n");
            exit(EXIT_FAILURE);
        }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }
}

void pipe_read(int fd, short ev, void *arg) {
    char buffer[MSG_MAX_SIZE];
    // 4096 is PIPE_BUF, meaning that messages up to 4096 are atomic and thus read by one read()
    // if we need larger messages, the receiving logic must be changed (possibly more calls to read)
    assert(MSG_MAX_SIZE <= 4096 && "for messages larger than 4096, pipe_read must be changed");
    ssize_t nbytes = read(fd, buffer, MSG_MAX_SIZE);
    switch (nbytes) {
    case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN) return;
            fprintf(stderr, "error receiving from pipe\n");
            return;
        case 0:
            fprintf(stderr, "closed pipe from child\n");
            return;
        default:
            break;
    }
    log_add(buffer, nbytes);
}

static void SIGINT_handler(evutil_socket_t sig, short events, void *user_data) {
    DEBUG_PRINT("Caught SIGINT, exiting...\n");
    event_base_loopbreak((struct event_base*)user_data);
}

pid_t start_telnet(struct event_base* ev_base, unsigned port, const char * user) {
    int listen_fd;
    int flag;
    struct sockaddr_in6 listen_addr;
    listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }
    flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(port);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }
    pid_t child;
    int pipes[2];
    if  (pipe(pipes) < 0) {
        perror("pipe");
        exit(1);
    }
    child = fork();
    if (child == -1) {
        perror("fork");
        exit(1);
    }
    if (child == 0) {
        drop_privileges(user);
        if (getppid() == 1) kill(getpid(), SIGINT);
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipes[0]);
        handle_telnet(listen_fd, pipes[1]);
        exit(0);
    }
    close(pipes[1]);
    close(listen_fd);
    setnonblock(pipes[0]);
    struct event * ev = event_new(ev_base, pipes[0], EV_READ|EV_PERSIST, pipe_read, NULL);
    event_add(ev, NULL);
    return child;
}

int main(int argc, char *argv[]) {
    struct event_base* ev_base = event_base_new();
    unsigned telnet_port = 23;
    const char * local_socket = "ipc:///tmp/sentinel_pull.sock";
    const char * topic = "sentinel/collect/flows";
    const char * user = "nobody";
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
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-T telnet_port] [-s socket] [-t topic] [-u user]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    close(STDIN_FILENO);
    signal(SIGCHLD, SIGCHLD_handler);
    int telnet_proc_pid = start_telnet(ev_base, telnet_port, user);
    log_init(ev_base, local_socket, topic);
    struct event * sigint_event = event_new(ev_base, SIGINT, EV_SIGNAL|EV_PERSIST, SIGINT_handler, ev_base);
    event_add(sigint_event, NULL);
    struct event * sigterm_event = event_new(ev_base, SIGTERM, EV_SIGNAL|EV_PERSIST, SIGINT_handler, ev_base);
    event_add(sigterm_event, NULL);
    // run event loop...
    event_base_dispatch(ev_base);
    // ...interrupted, cleaning up
    kill(telnet_proc_pid, SIGINT);
    log_exit();
    return 0;
}
