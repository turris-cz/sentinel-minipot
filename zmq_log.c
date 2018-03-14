#include "utils.h"
#include "zmq_log.h"
#include <czmq.h>
#include <msgpack.h>


struct msg_t{
    char * data;
    unsigned len;
};
struct msg_t messages[MAX_WAITING_MESSAGES];
int messages_waiting;
zsock_t *proxy_sock;
const char * topic;

void log_init(const char * socket, const char * topic_){
    proxy_sock = zsock_new (ZMQ_PUSH);
    zsock_connect(proxy_sock, "%s", socket);
    topic=topic_;
}

void log_exit(){
    log_send_waiting();
    zsock_destroy (&proxy_sock);
}

static void send_data(char * buf, size_t len){
    zmsg_t * msg=zmsg_new();
    zmsg_addstr (msg, topic);
    zmsg_addmem (msg, buf, len);
    int res=zmsg_send (&msg, proxy_sock);
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
        free(messages[i].data);
        messages[i].data=NULL;
    }
    messages_waiting=0;
    send_data(sbuf.data, sbuf.size);
    printf("sending message: ");
    for (unsigned j=0; j<sbuf.size; j++) printf("%02hhx ",sbuf.data[j]);
    printf("\n");
    msgpack_sbuffer_destroy(&sbuf);
}

void log_add(char * msg, unsigned len){
    if (messages_waiting+1>=MAX_WAITING_MESSAGES) {
        log_send_waiting();
    }
    for (unsigned i=0; i<MAX_WAITING_MESSAGES; i++){
        if (!messages[i].data) {
            printf("adding message: ");
            for (unsigned j=0; j<len; j++) printf("%02hhx ",msg[j]);
            printf("\n");
            messages[i].data=msg;
            messages[i].len=len;
            messages_waiting++;
            return;
        }
    }
}
