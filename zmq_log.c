#include <czmq.h>
#include <msgpack.h>
#include <event.h>

#include "utils.h"
#include "zmq_log.h"


struct msg_t{
    char data[MSG_MAX_SIZE+1];
    unsigned len;
};
struct msg_t messages[MAX_WAITING_MESSAGES];
int messages_waiting;
zsock_t *proxy_sock;
const char * topic;

static void send_waiting_messages_timer(int fd, short event, void *data){
    log_send_waiting();
}

void log_init(struct event_base* ev_base, const char * socket, const char * topic_){
    proxy_sock = zsock_new (ZMQ_PUSH);
    zsock_connect(proxy_sock, "%s", socket);
    topic=topic_;
    struct event * timer_event=event_new(ev_base, 0, EV_PERSIST, send_waiting_messages_timer, NULL);
    struct timeval tv;
    tv.tv_sec = MAX_WAIT_TIME;
    tv.tv_usec = 0;
    evtimer_add(timer_event, &tv);
}

void log_exit(){
    log_send_waiting();
    zsock_destroy (&proxy_sock);
}

static void send_data(char * buf, size_t len){
    zmsg_t * msg=zmsg_new();
    zmsg_addstr (msg, topic);
    zmsg_addmem (msg, buf, len);
    zmsg_send(&msg, proxy_sock);
    zmsg_destroy (&msg);
}

void log_send_waiting(){
    if (messages_waiting==0) return;
    //arrays in msgpack header have header which contains number of element. Then elements follows.
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pk, messages_waiting); //pack array header
    for (unsigned i=0; i<messages_waiting; i++) {
//         msgpack_pack_bin(&pk, messages[i].len); - this would append header for bin. We don't want that. Data received already have its header.
        msgpack_pack_bin_body(&pk, messages[i].data, messages[i].len); //just pack them, without header
    }
    messages_waiting=0;
    send_data(sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
}

void log_add(char * msg, unsigned len){
    assert(len<=MSG_MAX_SIZE);
    if (messages_waiting+1>=MAX_WAITING_MESSAGES) {
        log_send_waiting();
    }
    memcpy(messages[messages_waiting].data, msg, len);
    messages[messages_waiting].len=len;
    messages_waiting++;
}
