#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <event.h>
#include <msgpack.h>
#include <errno.h>

#include "utils.h"
#include "zmq_log.h"
#include "telnet.h"

/*
 * A child has exited.
 */
static void SIGCHLD_handler(int sig){
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) fprintf(stderr, "Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
}


/*
 * Drop root, chroot and drop privs.
 */
static void drop_privileges()
{
    struct passwd *user;
    if (!geteuid()) {
        user = getpwnam("nobody");
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

void pipe_read(int fd, short ev, void *arg){
    char buffer[1024];
    ssize_t nbytes = read(fd, buffer, 1024);
    switch(nbytes){
	case -1:
            if (errno == EWOULDBLOCK || errno == EAGAIN) return;
            fprintf(stderr, "error receiving from pipe\n");
            exit(1);
        case 0:
            fprintf(stderr, "closed pipe\n"); 
            exit(1); //this should not happen
        default:
            break;
    }
    char * buf_copy=(char*)malloc(nbytes);
    memcpy(buf_copy, buffer, nbytes);
    log_add(buf_copy, nbytes);
    DEBUG_PRINT("%lu bytes from honeypot subprocess; ## %.*s\n", nbytes, (unsigned)nbytes, buffer);
}

static void send_waiting_messages_timer(int fd, short event, void *data){
    log_send_waiting();
}

static void sigint_cb(evutil_socket_t sig, short events, void *user_data){
    event_loopbreak();
}

int main(int argc, char *argv[]){
    int listen_fd, flag;
    struct sockaddr_in6 listen_addr;
    pid_t child;
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    close(STDIN_FILENO);
    listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    flag = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_addr = in6addr_any;
    listen_addr.sin6_port = htons(23);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }
    int pipes[2];
    if  (pipe(pipes)<0)  { perror(" Main error with pipes \n"); exit(2); }
    prctl(PR_SET_NAME, "honeypot_main");
    signal(SIGCHLD, SIGCHLD_handler);
    child = fork();
    if (!child){
        drop_privileges();
        if (getppid() == 1) kill(getpid(), SIGINT);
        prctl(PR_SET_PDEATHSIG, SIGINT);
        close(pipes[0]);
        prctl(PR_SET_NAME, "honeypot_telnet");
        handle_telnet(listen_fd, pipes[1]);
        exit(0);
    }
    close(listen_fd);
    close(pipes[1]);
    log_init("ipc:///tmp/sentinel_pull.sock", "sentinel/collect/flows");
    event_init();
    struct event ev;
    setnonblock(pipes[0]);
    event_set(&ev, pipes[0], EV_READ|EV_PERSIST, pipe_read, NULL);
    event_add(&ev, NULL);
    struct event signal_event;
    evsignal_set(&signal_event, SIGINT, sigint_cb, NULL);
    event_add(&signal_event, NULL);
    struct event timer_event;
    event_set(&timer_event, 0, EV_PERSIST, send_waiting_messages_timer, NULL);
    struct timeval tv;
    tv.tv_sec = MAX_WAIT_TIME;
    tv.tv_usec = 0;
    evtimer_add(&timer_event, &tv);
    event_dispatch();
    log_exit();
    return 0;
}
